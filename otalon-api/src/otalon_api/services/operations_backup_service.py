"""Local backup manifest, archive verification, and guarded restore service.

This service creates bounded, redacted, host-persisted backup archives and a
verifiable checksum manifest, and gates restore execution behind an explicit
non-dry-run + typed-confirmation + compatible-precheck + fresh-backup contract.

Safety posture (WAVE F): a database restore is *destructive*. The live
unattended run never executes it — ``restore`` defaults to ``dry_run=True`` and
the injected ``restore_executor`` is ``None`` in production wiring, so a real
restore raises ``RestoreNotAvailable`` instead of touching data. Tests inject a
fake executor to prove that a correctly confirmed, compatible, non-stale,
non-dry-run request invokes only the mapped narrow restore callable.
"""

from __future__ import annotations

import hashlib
import json
import tempfile
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from otalon_api.settings import Settings

# A restore executor receives the validated scope and returns an opaque,
# JSON-serialisable result. It is only ever invoked from the confirmed,
# non-dry-run branch. Production wiring passes ``None`` (no live restore).
RestoreExecutor = Callable[[list[str]], dict[str, Any]]

STALE_BACKUP_SECONDS = 7 * 24 * 3600
MAX_ARCHIVE_BYTES = 256 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 10000

# Config-backup source is an ALLOWLIST of real configuration paths under the
# suite source root — not the whole repository. Each entry is resolved relative
# to ``BACKUP_CONFIG_SOURCE``; missing entries are skipped so the archive stays
# bounded and never sweeps in node_modules, build output, secrets or runtime
# data.
_CONFIG_ALLOWLIST: tuple[str, ...] = (
    "otalon-api/config/config.json",
    "otalon-ui/config/labels.json",
    "otalon-ui/config/layout_profiles.json",
    "otalon-clas/config/config.json",
    "otalon-scan/config/config.json",
    "otalon-mcp/config/config.json",
    "otalon-ai/config/config.json",
    "otalon-capture/config/config_pcap.json",
    "docker-compose.yml",
    ".env.compose.sample",
    ".env.sample",
)


class RestoreNotAvailable(RuntimeError):
    """Raised when a real restore is requested but no executor is wired."""


class InfluxBackupNotAvailable(RuntimeError):
    """Raised when no supported operator-owned InfluxDB snapshot is configured."""


class OperationsBackupService:
    """Persist verifiable backup manifests and gate restore execution."""

    def __init__(
        self,
        directory: Path,
        restore_executor: RestoreExecutor | None = None,
        settings: Settings | None = None,
    ) -> None:
        """Initialize a local manifest directory and optional restore executor.

        Args:
            directory: Suite-owned, host-persisted directory for archives.
            restore_executor: Narrow restore callable. ``None`` in production so
                a real restore fails closed instead of mutating data.
            settings: Typed application settings supplying the backup source
                roots. Defaults to a freshly resolved ``Settings`` so existing
                two-argument call sites keep working.
        """
        if directory.exists() and directory.is_symlink():
            raise ValueError("backup directory must not be a symlink")
        self._directory = directory.resolve()
        if any(parent.is_symlink() for parent in (self._directory, *self._directory.parents) if parent.exists()):
            raise ValueError("backup directory path must not contain symlinks")
        self._restore_executor = restore_executor
        resolved = settings if settings is not None else Settings.from_config_json()
        self._config_root = Path(resolved.backup_config_source)
        # (relative arcname, absolute source) so each config file keeps a unique,
        # collision-free path inside the archive (every subproject has its own
        # config.json).
        self._config_sources = tuple((relative, self._config_root / relative) for relative in _CONFIG_ALLOWLIST)
        self._allowed_scopes: dict[str, tuple[Path, ...]] = {
            "postgresql": (Path(resolved.backup_postgres_source),),
            "models": (Path(resolved.model_dir),),
            "baselines": (Path(resolved.pcap_baseline_dir),),
            "pcap_archive": (Path(resolved.pcap_archive_dir),),
        }

    def create_manifest(self, scope: list[str]) -> dict[str, Any]:
        """Create a bounded, redacted local archive and checksum manifest.

        Args:
            scope: One or more allowlisted backup scopes.

        Returns:
            The persisted manifest with archive path, size, sha256 and
            verification status.

        Raises:
            ValueError: For unknown scopes or fail-closed source problems
                (missing/empty/symlinked/oversize/traversal).
        """
        normalized = self._normalize_scope(scope)
        unknown = set(normalized) - self._known_scopes()
        if unknown:
            raise ValueError(f"Unsupported backup scope: {sorted(unknown)}")
        if "influx" in normalized:
            raise InfluxBackupNotAvailable(self._influx_requirement())
        self._directory.mkdir(parents=True, exist_ok=True)
        if self._directory.is_symlink():
            raise ValueError("backup directory must not be a symlink")
        artifact_id = uuid.uuid4().hex
        archive = self._directory / f"otalon-backup-{artifact_id}.zip"
        with tempfile.NamedTemporaryFile(dir=self._directory, prefix="backup-", suffix=".zip", delete=False) as temp:
            temp_path = Path(temp.name)
        try:
            self._write_archive(temp_path, sorted(set(normalized)))
            if temp_path.stat().st_size > MAX_ARCHIVE_BYTES:
                raise ValueError("backup exceeds maximum archive size")
            temp_path.replace(archive)
        finally:
            temp_path.unlink(missing_ok=True)
        archive_bytes = archive.stat().st_size
        raw = archive.read_bytes()
        manifest: dict[str, Any] = {
            "artifact_id": artifact_id,
            "artifact_name": archive.name,
            "scope": sorted(set(normalized)),
            "created_at": datetime.now(timezone.utc).isoformat(),
            "archive": str(archive),
            "archive_bytes": archive_bytes,
            "sha256": hashlib.sha256(raw).hexdigest(),
            "verified": self._verify_archive(archive, archive_bytes),
        }
        manifest_path = self._directory / f"{artifact_id}.json"
        manifest_path.write_text(json.dumps(manifest, sort_keys=True), encoding="utf-8")
        self._directory.joinpath("latest.json").write_text(json.dumps(manifest, sort_keys=True), encoding="utf-8")
        return manifest

    def _normalize_scope(self, scope: list[str]) -> list[str]:
        """Expand operator shorthand while retaining canonical scope names."""
        requested = {"postgresql" if item == "database" else item for item in scope}
        if "FULL" in requested:
            requested.remove("FULL")
            requested.update(self._backup_capable_scopes())
        return sorted(requested)

    def catalog(self) -> list[dict[str, Any]]:
        """Return selectable, re-verified backup metadata newest first."""
        entries: list[dict[str, Any]] = []
        for path in sorted(self._directory.glob("*.json")):
            if path.name == "latest.json":
                continue
            try:
                manifest = json.loads(path.read_text(encoding="utf-8"))
                verified = self._verify_archive(
                    Path(str(manifest.get("archive", ""))),
                    int(manifest.get("archive_bytes", -1)),
                    str(manifest.get("sha256", "")),
                )
                entries.append(
                    {
                        "artifact_id": manifest.get("artifact_id", path.stem),
                        "artifact_name": manifest.get("artifact_name", Path(str(manifest.get("archive", ""))).name),
                        "created_at": manifest.get("created_at"),
                        "scope": manifest.get("scope", []),
                        "archive_bytes": manifest.get("archive_bytes", 0),
                        "verified": verified,
                    }
                )
            except (OSError, TypeError, ValueError, json.JSONDecodeError):
                continue
        return sorted(entries, key=lambda item: str(item.get("created_at", "")), reverse=True)

    def scope_catalog(self) -> list[dict[str, Any]]:
        """Return backup scopes and their evidence-producing capability state."""
        return [
            {
                "scope": name,
                "available": name != "influx",
                "backup_supported": name != "influx",
                "restore_supported": False,
                "detail": self._influx_requirement() if name == "influx" else "Local archive with SHA-256 verification",
            }
            for name in sorted(self._known_scopes())
        ]

    def select(self, artifact_id: str | None) -> dict[str, Any] | None:
        """Return selected catalog artifact, or newest artifact when omitted."""
        if artifact_id is None:
            return self.latest()
        for item in self.catalog():
            if item["artifact_id"] == artifact_id:
                path = self._directory / f"{artifact_id}.json"
                return json.loads(path.read_text(encoding="utf-8"))
        return None

    def _known_scopes(self) -> set[str]:
        """Return catalog scopes, including recognized unavailable scopes."""
        return {"config", "influx", *self._allowed_scopes}

    def _backup_capable_scopes(self) -> set[str]:
        """Return scopes this deployment can archive locally."""
        return {"config", *self._allowed_scopes}

    def _write_archive(self, temp_path: Path, scopes: list[str]) -> None:
        """Write the bounded archive, validating and bounding every member."""
        members = 0
        with zipfile.ZipFile(temp_path, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
            for name in scopes:
                if name == "config":
                    members = self._add_config(bundle, members)
                else:
                    members = self._add_tree(bundle, name, self._allowed_scopes[name][0], members)
            if members == 0:
                raise ValueError("backup produced no content")

    def _add_config(self, bundle: zipfile.ZipFile, members: int) -> int:
        """Add allowlisted, redaction-checked config files; fail closed if none exist.

        Each file keeps its allowlist-relative path under ``config/`` so config
        files that share a basename (every subproject has a ``config.json``) do
        not collide inside the archive.
        """
        added = members
        present = False
        for relative, source in self._config_sources:
            if source.is_symlink() or not source.is_file():
                continue
            present = True
            added += 1
            if added > MAX_ARCHIVE_MEMBERS:
                raise ValueError("backup contains too many files")
            bundle.writestr(f"config/{relative}", self._safe_config_bytes(source))
        if not present:
            raise ValueError("Backup source is unavailable: config")
        return added

    def _add_tree(self, bundle: zipfile.ZipFile, name: str, source: Path, members: int) -> int:
        """Add a whole directory/file scope with bounded, traversal-checked members."""
        self._validate_source(source, name)
        added = members
        if source.is_file():
            added += 1
            bundle.write(source, arcname=f"{name}/{source.name}")
            return added
        for item in source.rglob("*"):
            resolved = item.resolve()
            if source.resolve() not in resolved.parents and resolved != source.resolve():
                raise ValueError("backup path escapes source")
            if item.is_file() and not item.is_symlink():
                added += 1
                if added > MAX_ARCHIVE_MEMBERS:
                    raise ValueError("backup contains too many files")
                bundle.write(item, arcname=f"{name}/{item.relative_to(source)}")
        return added

    @staticmethod
    def _safe_config_bytes(source: Path) -> bytes:
        """Return config bytes, redacting secrets when the file is JSON."""
        from otalon_api.domain.operations.redaction import redact_sensitive, redact_text

        raw = source.read_bytes()
        if source.suffix == ".json":
            try:
                return json.dumps(redact_sensitive(json.loads(raw)), sort_keys=True).encode("utf-8")
            except (ValueError, TypeError):
                return raw
        text = redact_text(raw.decode("utf-8", errors="replace"))
        return (text or "").encode("utf-8")

    def latest(self) -> dict[str, Any] | None:
        """Return the latest persisted manifest re-verified against disk."""
        path = self._directory / "latest.json"
        if not path.is_file():
            return None
        manifest: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
        archive = Path(str(manifest.get("archive", "")))
        verified = self._verify_archive(
            archive,
            int(manifest.get("archive_bytes", -1)),
            str(manifest.get("sha256", "")),
        )
        created = datetime.fromisoformat(str(manifest["created_at"]))
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        manifest["verified"] = verified
        manifest["age_seconds"] = max(0, int((datetime.now(timezone.utc) - created).total_seconds()))
        manifest["stale"] = manifest["age_seconds"] > STALE_BACKUP_SECONDS
        return manifest

    @staticmethod
    def _validate_source(source: Path, name: str) -> None:
        """Fail closed for missing, empty, symlinked, or unsafe backup sources."""
        if source.is_symlink() or not source.exists():
            raise ValueError(f"Backup source is unavailable: {name}")
        if source.is_dir() and not any(source.iterdir()):
            raise ValueError(f"Backup source is empty: {name}")

    @staticmethod
    def _verify_archive(archive: Path, size: int, checksum: str | None = None) -> bool:
        """Verify archive existence, size, checksum, and bounded ZIP members."""
        if not archive.is_file() or archive.is_symlink() or archive.stat().st_size != size:
            return False
        if checksum and hashlib.sha256(archive.read_bytes()).hexdigest() != checksum:
            return False
        try:
            with zipfile.ZipFile(archive) as bundle:
                if len(bundle.infolist()) > MAX_ARCHIVE_MEMBERS:
                    return False
                return all(
                    not Path(item.filename).is_absolute() and ".." not in Path(item.filename).parts
                    for item in bundle.infolist()
                )
        except (OSError, zipfile.BadZipFile):
            return False

    def restore_precheck(
        self, scope: list[str], confirmation: str | None, artifact_id: str | None = None
    ) -> dict[str, Any]:
        """Return compatibility gates and whether typed confirmation is valid."""
        aliases = {"database": "postgresql"}
        requested = {aliases.get(name, name) for name in scope}
        unknown = requested - self._known_scopes()
        if unknown:
            raise ValueError(f"Unsupported restore scope: {sorted(unknown)}")
        if "influx" in requested:
            return {
                "compatible": False,
                "migrations": "unknown",
                "database_restore": False,
                "confirmation_required": "RESTORE INFLUX",
                "confirmed": confirmation == "RESTORE INFLUX",
                "backup_available": False,
                "backup_stale": False,
                "full_backup": False,
                "executed": False,
                "capability": "unavailable",
                "detail": self._influx_requirement(),
            }
        database = "postgresql" in requested
        required = "RESTORE DATABASE" if database else "RESTORE"
        latest = self.select(artifact_id)
        backup_scope = {aliases.get(str(name), str(name)) for name in (latest or {}).get("scope", [])}
        return {
            "compatible": bool(latest and latest.get("verified") and requested <= backup_scope),
            "migrations": "none detected",
            "database_restore": database,
            "confirmation_required": required,
            "confirmed": confirmation == required,
            "backup_available": bool(latest),
            "backup_stale": bool(latest and latest.get("stale")),
            "full_backup": bool(latest and set(latest.get("scope", [])) >= self._backup_capable_scopes()),
            "executed": False,
        }

    def restore(
        self,
        scope: list[str],
        confirmation: str | None,
        dry_run: bool = True,
        artifact_id: str | None = None,
    ) -> dict[str, Any]:
        """Run a restore precheck and only execute behind fail-closed gates.

        A real restore requires ALL of: ``dry_run=False``, a compatible + not
        stale verified backup, the exact typed confirmation, and a wired
        ``restore_executor``. Production wiring passes no executor, so the live
        path raises :class:`RestoreNotAvailable` instead of mutating data. The
        default ``dry_run=True`` keeps the live channel non-destructive.

        Args:
            scope: One or more allowlisted restore scopes.
            confirmation: Typed confirmation phrase.
            dry_run: When ``True`` (default) only the precheck is returned.

        Returns:
            The precheck plus ``executed`` state and any executor result.

        Raises:
            ValueError: On unknown scope, missing confirmation, or stale/absent backup.
            RestoreNotAvailable: When a real restore is requested with no executor.
        """
        precheck = self.restore_precheck(scope, confirmation, artifact_id)
        if dry_run:
            return precheck
        if not precheck["confirmed"]:
            raise ValueError(f"Typed confirmation must be '{precheck['confirmation_required']}'")
        if not precheck["backup_available"] or not precheck["compatible"]:
            raise ValueError("Restore requires a verified, compatible backup")
        if precheck["backup_stale"]:
            raise ValueError("Restore blocked: the latest verified backup is stale")
        if self._restore_executor is None:
            raise RestoreNotAvailable("Live restore execution is disabled in this deployment")
        result = self._restore_executor(sorted(set(scope)))
        return precheck | {"executed": True, "result": result}

    @staticmethod
    def _influx_requirement() -> str:
        """Describe operator prerequisite for a truthful InfluxDB backup."""
        return (
            "InfluxDB 3 Core has no built-in backup command. An operator must "
            "produce and verify a consistent object-storage snapshot using the "
            "documented order (snapshots, dbs, wal, catalog, checkpoint) during "
            "a controlled maintenance window; API restore remains disabled."
        )
