"""Persistence layer for trained ML models, scalers, and metadata.

Models are stored as **versioned artifact directories** with a single
atomic ``current.json`` manifest pointer per module:

```
{MODEL_DIR}/{module}_classifier/
    versions/<version>/model.joblib
    versions/<version>/model.joblib.integrity.json
    versions/<version>/meta.json
    current.json            # {"version": "<version>"}  (atomic pointer)
```

Every joblib artifact is written through
:func:`otalon_clas.common.artifact_integrity.dump_sealed` and read back
through :func:`~otalon_clas.common.artifact_integrity.load_verified`, so
a bundle whose bytes changed after publication is refused instead of
being unpickled (CLAS-048). The check is **fail-closed**: an artifact
without a sidecar — including one deployed before CLAS-048 — raises
:class:`~otalon_clas.common.artifact_integrity.ArtifactIntegrityError`
and is brought forward only by the explicit operator ``seal`` command.
An integrity refusal is never downgraded to the legacy-flat fallback:
falling back would let anyone who tampers with the published version
steer the process onto a different artifact of their choosing.

The model and its metadata live in the SAME version directory and are
fsynced before the manifest is flipped, so publication is coherent: a
reader either sees the whole previous version or the whole new version,
never a joblib from one training paired with metadata from another
(audit B-04 / F6). Two independent flat-file renames — which are NOT
atomic as a pair — are no longer used for publication.

Backward compatibility: on load, when no manifest exists the store falls
back to the legacy flat files ``{module}_classifier.joblib`` +
``{module}_classifier_meta.json`` and, when present, migrates them into a
versioned layout so the next publish is manifest-based. The legacy flat
files continue to be written as a mirror for external readers that have
not yet learned about the manifest.

For callers that only need to know whether a module already has a
deployed classifier (e.g. the runtime "retrain existing classifiers"
scope), :meth:`ModelStore.has_model` is a non-mutating existence probe
that recognises both layouts without loading the joblib or migrating
legacy flat files merely to test existence.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any

import joblib  # type: ignore[import-untyped]  # joblib ships no py.typed stubs
from loguru import logger

from otalon_clas.common.artifact_integrity import (
    ArtifactIntegrityError,
    dump_sealed,
    load_verified,
    sidecar_path,
    write_integrity_sidecar,
)

_CURRENT_MANIFEST: str = "current.json"

_LEGACY_FLAT_VERSION: str = "legacy-flat"
"""``_version`` stamped on metadata loaded from the legacy flat files.

Marks a degraded load so a fallback is distinguishable from a healthy
manifest-based one (audit QUA-12).
"""


class ModelStore:
    """Load and save ML artifacts (model, scaler, metadata) on disk.

    Args:
        models_dir: Path to the directory where model files are stored.
            The directory is created on first write if it does not exist.
    """

    def __init__(self, models_dir: str) -> None:
        """Initialize the model store.

        Args:
            models_dir: Filesystem path for model persistence.
        """
        self._base = Path(models_dir)

    # -- Legacy flat paths (compat mirror + migration source) -------------

    def _joblib_path(self, module_name: str) -> Path:
        """Return the legacy flat joblib file path for a module."""
        return self._base / f"{module_name}_classifier.joblib"

    def _meta_path(self, module_name: str) -> Path:
        """Return the legacy flat metadata JSON file path for a module."""
        return self._base / f"{module_name}_classifier_meta.json"

    # -- Versioned layout -------------------------------------------------

    def _module_root(self, module_name: str) -> Path:
        """Return the versioned root directory for a module."""
        return self._base / f"{module_name}_classifier"

    def _versions_dir(self, module_name: str) -> Path:
        """Return the ``versions/`` directory for a module."""
        return self._module_root(module_name) / "versions"

    def _manifest_path(self, module_name: str) -> Path:
        """Return the ``current.json`` manifest path for a module."""
        return self._module_root(module_name) / _CURRENT_MANIFEST

    def save(
        self,
        module_name: str,
        model: Any,
        scaler: Any,
        metadata: dict[str, Any],
        protocol_map: dict[str, int] | None = None,
        feature_columns: list[str] | None = None,
        *,
        keep_backup: bool = True,
        force_publish_class_set_shrink: bool = False,
    ) -> bool:
        """Persist a trained model + scaler + metadata as a coherent version.

        Writes the joblib bundle and metadata JSON into a fresh version
        directory, fsyncs them, then atomically flips ``current.json`` to
        point at the new version with a single ``os.replace`` — the only
        publication commit point. If anything fails before the manifest
        flip, the prior manifest (and therefore the prior model) is left
        intact (audit B-04). The legacy flat files are also refreshed as a
        best-effort compatibility mirror after the manifest flip.

        Args:
            module_name: Logical name identifying the model.
            model: The trained ML estimator (must be joblib-serializable).
            scaler: The fitted scaler (e.g. :class:`StandardScaler`).
            metadata: Arbitrary metadata dictionary (must be JSON-serializable).
            protocol_map: Optional ``protocol-string -> integer code``
                mapping persisted inside the bundle and metadata.
            feature_columns: Ordered list of feature column names.
            keep_backup: Retained for API compatibility. Versioned layout
                keeps prior versions on disk regardless, providing the
                rollback source; the flag only gates the legacy ``.bak``
                mirror.
        """
        new_classes = self._class_names(metadata)
        previous_metadata = self.current_metadata(module_name)
        previous_classes = self._class_names(previous_metadata or {})
        if previous_classes and len(new_classes) < len(previous_classes):
            message = (
                "Module '{}': refusing to publish classifier with {} classes "
                "(previously {}); set force_publish_class_set_shrink=true to override"
            )
            if not force_publish_class_set_shrink:
                logger.warning(message, module_name, len(new_classes), len(previous_classes))
                return False
            logger.warning("FORCED " + message, module_name, len(new_classes), len(previous_classes))

        module_root = self._module_root(module_name)
        versions_dir = self._versions_dir(module_name)
        versions_dir.mkdir(parents=True, exist_ok=True)

        version = f"{int(time.time() * 1000)}_{os.getpid()}"
        version_dir = versions_dir / version
        version_dir.mkdir(parents=True, exist_ok=False)

        bundle: dict[str, Any] = {"model": model, "scaler": scaler}
        if protocol_map is not None:
            bundle["protocol_map"] = dict(protocol_map)
        if feature_columns is not None:
            bundle["feature_columns"] = list(feature_columns)

        meta_payload = dict(metadata)
        meta_payload["_version"] = version
        if protocol_map is not None:
            meta_payload["protocol_map"] = dict(protocol_map)
        if feature_columns is not None:
            meta_payload["feature_columns"] = list(feature_columns)

        model_file = version_dir / "model.joblib"
        meta_file = version_dir / "meta.json"
        dump_sealed(bundle, model_file)
        meta_file.write_text(json.dumps(meta_payload, indent=2, default=str))
        self._fsync_dir(version_dir)
        logger.debug("Wrote model version {} to {}", version, version_dir)

        self._flip_manifest(module_root, version)
        logger.info(
            "Published model version {} for '{}' via atomic manifest flip",
            version,
            module_name,
        )

        self._mirror_legacy_flat(module_name, bundle, meta_payload, keep_backup)
        # Retain prior versions so an in-flight publication can roll back by
        # restoring the exact durable manifest pointer.
        return True

    def _flip_manifest(self, module_root: Path, version: str) -> None:
        """Atomically point ``current.json`` at *version* via one os.replace."""
        manifest = module_root / _CURRENT_MANIFEST
        tmp = module_root / f"{_CURRENT_MANIFEST}.tmp"
        tmp.write_text(json.dumps({"version": version}))
        os.replace(tmp, manifest)
        self._fsync_dir(module_root)

    def _mirror_legacy_flat(
        self,
        module_name: str,
        bundle: dict[str, Any],
        meta_payload: dict[str, Any],
        keep_backup: bool,
    ) -> None:
        """Refresh the legacy flat files as a best-effort compat mirror.

        Failures here never affect the already-published versioned model.

        The flat layout cannot rename an artifact and its integrity
        sidecar as one atomic pair — that limitation is precisely why the
        versioned layout exists. The stale sidecar is therefore removed
        *before* the artifact is replaced, so a reader that hits the
        window sees "no integrity metadata" (a clean fail-closed refusal)
        rather than a digest mismatch that would read like tampering.
        """
        try:
            self._base.mkdir(parents=True, exist_ok=True)
            joblib_path = self._joblib_path(module_name)
            meta_path = self._meta_path(module_name)
            tmp_joblib = self._base / f"{module_name}_classifier.joblib.tmp"
            tmp_meta = self._base / f"{module_name}_classifier_meta.json.tmp"
            joblib.dump(bundle, tmp_joblib)
            tmp_meta.write_text(json.dumps(meta_payload, indent=2, default=str))
            if keep_backup:
                if joblib_path.exists():
                    self._backup_with_sidecar(joblib_path, self._base / f"{module_name}_classifier.joblib.bak")
                if meta_path.exists():
                    meta_path.replace(self._base / f"{module_name}_classifier_meta.json.bak")
            sidecar_path(joblib_path).unlink(missing_ok=True)
            os.replace(tmp_joblib, joblib_path)
            os.replace(tmp_meta, meta_path)
            write_integrity_sidecar(joblib_path)
        except Exception:
            logger.warning(
                "Module '{}': legacy flat-file mirror failed (versioned model " "already published; ignoring)",
                module_name,
            )

    @staticmethod
    def _backup_with_sidecar(source: Path, target: Path) -> None:
        """Move an artifact to a ``.bak`` name, taking its sidecar along.

        A backup that loses its integrity metadata is unloadable under
        the fail-closed policy, which would silently turn the rollback
        copy into dead weight.
        """
        source.replace(target)
        source_sidecar = sidecar_path(source)
        if source_sidecar.exists():
            source_sidecar.replace(sidecar_path(target))

    def _read_manifest_version(self, module_name: str) -> str | None:
        """Return the version named by the manifest, or ``None``."""
        manifest = self._manifest_path(module_name)
        if not manifest.exists():
            return None
        try:
            data = json.loads(manifest.read_text())
            version = data.get("version")
            return str(version) if version else None
        except (json.JSONDecodeError, OSError):
            return None

    def publication_pointer(self, module_name: str) -> str | None:
        """Return current version pointer for exact publication rollback."""
        return self._read_manifest_version(module_name)

    def restore_publication_pointer(self, module_name: str, version: str | None) -> None:
        """Restore an earlier version pointer without re-saving artifacts.

        The rollback target is loaded before the manifest is flipped, so
        a version that fails its integrity check raises rather than
        becoming the published model.
        """
        if version is None:
            self._manifest_path(module_name).unlink(missing_ok=True)
            return
        if not self._load_version(module_name, version):
            raise FileNotFoundError(f"Model version not found: {module_name}/{version}")
        self._flip_manifest(self._module_root(module_name), version)

    def _prune_old_versions(self, module_name: str, *, keep_version: str) -> None:
        """Delete all but the current version directory (best-effort)."""
        versions_dir = self._versions_dir(module_name)
        if not versions_dir.exists():
            return
        for child in versions_dir.iterdir():
            if child.name == keep_version or not child.is_dir():
                continue
            try:
                for f in child.iterdir():
                    f.unlink()
                child.rmdir()
            except OSError:
                logger.debug("Could not prune old model version {}", child)

    @staticmethod
    def _fsync_dir(path: Path) -> None:
        """fsync a directory so a rename/create is durable (best-effort)."""
        try:
            fd = os.open(str(path), os.O_RDONLY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        except OSError:
            pass

    def load(self, module_name: str) -> tuple[Any, Any, dict[str, Any]]:
        """Load a coherent (model, scaler, metadata) triple.

        Resolution order:

        1. The versioned ``current.json`` manifest → its version directory
           (the coherent, atomically-published pair).
        2. Legacy flat files, migrated into a versioned layout so the next
           publish is manifest-based.

        A model whose version directory is missing or whose joblib/meta
        pair is incomplete is treated as absent and the loader falls back
        rather than combining a mismatched pair (audit B-04).

        Args:
            module_name: Logical name identifying the model.

        Returns:
            Tuple ``(model, scaler, metadata)``.

        Raises:
            FileNotFoundError: If neither a manifest version nor legacy
                flat files yield a complete model.
            ArtifactIntegrityError: If an artifact that is present fails
                its write-time integrity check. This propagates instead
                of triggering the fallback, because a fallback would
                hand an attacker who corrupts one artifact the choice of
                which other artifact gets loaded (CLAS-048).
        """
        version = self._read_manifest_version(module_name)
        if version is not None:
            triple = self._load_version(module_name, version)
            if triple is not None:
                logger.info("Loaded model '{}' version {}", module_name, version)
                return triple
            logger.warning(
                "Module '{}': manifest points at incomplete version {}; " "falling back to legacy flat files",
                module_name,
                version,
            )

        return self._load_legacy_flat(module_name)

    def _load_version(self, module_name: str, version: str) -> tuple[Any, Any, dict[str, Any]] | None:
        """Load a specific version directory, or ``None`` if incomplete.

        An *incomplete* version (missing or unreadable files) yields
        ``None`` so the caller can fall back. A *failed integrity check*
        is not incompleteness — :class:`ArtifactIntegrityError` escapes
        this method deliberately and is not converted into a fallback.
        """
        version_dir = self._versions_dir(module_name) / version
        model_file = version_dir / "model.joblib"
        meta_file = version_dir / "meta.json"
        if not model_file.exists() or not meta_file.exists():
            return None
        try:
            artifacts = load_verified(model_file)
            metadata = json.loads(meta_file.read_text())
        except ArtifactIntegrityError:
            raise
        except (OSError, json.JSONDecodeError, EOFError, KeyError):
            return None
        if "model" not in artifacts or "scaler" not in artifacts:
            return None
        self._merge_bundle_into_meta(artifacts, metadata)
        return artifacts["model"], artifacts["scaler"], metadata

    def _load_legacy_flat(self, module_name: str) -> tuple[Any, Any, dict[str, Any]]:
        """Load and migrate legacy flat files into the versioned layout.

        The returned metadata is stamped ``_version = "legacy-flat"``. This
        path is reached either because no manifest exists or because the
        manifest pointed at an incomplete version — the latter is a
        degraded state, and without the stamp the caller could not tell a
        fallback load from a healthy manifest load, because the flat
        ``meta.json`` may still carry a stale ``_version`` from a previous
        publish (audit QUA-12).

        The flat artifact is integrity-checked like any other. A flat
        file left over from before CLAS-048 carries no sidecar and is
        rejected; sealing it is an explicit operator decision, because
        auto-sealing whatever is on disk would certify an attacker's
        file exactly as readily as a legitimate one.
        """
        joblib_path = self._joblib_path(module_name)
        meta_path = self._meta_path(module_name)
        if not joblib_path.exists():
            raise FileNotFoundError(f"Model file not found: {joblib_path}")
        if not meta_path.exists():
            raise FileNotFoundError(f"Metadata file not found: {meta_path}")

        artifacts = load_verified(joblib_path)
        metadata = json.loads(meta_path.read_text())
        self._merge_bundle_into_meta(artifacts, metadata)
        metadata["_version"] = _LEGACY_FLAT_VERSION
        logger.warning(
            "Module '{}': loaded LEGACY FLAT model from {} (no manifest version); " "metadata stamped _version={}",
            module_name,
            joblib_path,
            _LEGACY_FLAT_VERSION,
        )
        self._migrate_flat_to_versioned(module_name, artifacts, metadata)
        return artifacts["model"], artifacts["scaler"], metadata

    def _migrate_flat_to_versioned(
        self,
        module_name: str,
        artifacts: dict[str, Any],
        metadata: dict[str, Any],
    ) -> None:
        """Seed a versioned layout + manifest from legacy flat files."""
        if self._read_manifest_version(module_name) is not None:
            return
        try:
            versions_dir = self._versions_dir(module_name)
            versions_dir.mkdir(parents=True, exist_ok=True)
            version = f"migrated_{int(time.time() * 1000)}"
            version_dir = versions_dir / version
            version_dir.mkdir(parents=True, exist_ok=True)
            dump_sealed(artifacts, version_dir / "model.joblib")
            (version_dir / "meta.json").write_text(json.dumps(metadata, indent=2, default=str))
            self._fsync_dir(version_dir)
            self._flip_manifest(self._module_root(module_name), version)
            logger.info(
                "Migrated legacy flat model '{}' into versioned layout {}",
                module_name,
                version,
            )
        except Exception:
            logger.warning("Module '{}': flat->versioned migration failed", module_name)

    def has_model(self, module_name: str) -> bool:
        """Return True when a coherent persisted classifier artifact exists.

        A **non-mutating** existence probe that mirrors the two resolution
        layouts of :meth:`load` without loading the heavy joblib, without
        flipping any manifest, and — unlike :meth:`load` — without
        migrating legacy flat files into a versioned layout. It is used by
        the runtime classifier retrain to decide whether a module already
        has a deployed classifier to retrain, so a runtime "retrain
        existing classifiers" never silently creates a first-time model
        for a module that has none (CLAS-004 stays out of scope).

        The probe answers "is an artifact deployed here", not "is it
        loadable": it deliberately does not check the CLAS-048 integrity
        sidecar. Reporting a tampered or unsealed model as absent would
        make a retrain silently train a first-time model over it and
        erase the evidence; the refusal belongs at :meth:`load`, where it
        surfaces as an explicit error.

        Resolution order (existence only):

        1. The versioned ``current.json`` manifest points at a version
           directory whose ``model.joblib`` **and** ``meta.json`` both
           exist (an incomplete version counts as absent, matching the
           loader's coherence rule).
        2. Otherwise the legacy flat ``{module}_classifier.joblib`` **and**
           ``{module}_classifier_meta.json`` both exist.

        Args:
            module_name: Logical name identifying the model.

        Returns:
            True when a complete artifact pair is present under either
            layout, False otherwise.
        """
        version = self._read_manifest_version(module_name)
        if version is not None:
            version_dir = self._versions_dir(module_name) / version
            if (version_dir / "model.joblib").exists() and (version_dir / "meta.json").exists():
                return True
        return self._joblib_path(module_name).exists() and self._meta_path(module_name).exists()

    @staticmethod
    def _merge_bundle_into_meta(artifacts: dict[str, Any], metadata: dict[str, Any]) -> None:
        """Backfill protocol_map/feature_columns from the bundle if absent."""
        if "protocol_map" not in metadata and "protocol_map" in artifacts:
            metadata["protocol_map"] = artifacts["protocol_map"]
        if "feature_columns" not in metadata and "feature_columns" in artifacts:
            metadata["feature_columns"] = artifacts["feature_columns"]

    def list_models(self) -> list[dict[str, Any]]:
        """List all persisted models by reading their metadata files.

        Prefers each module's manifest version metadata; falls back to any
        legacy flat ``_meta.json`` files. Never loads the heavy joblib
        files.

        Returns:
            List of metadata dictionaries, one per discovered model.
        """
        if not self._base.exists():
            return []

        results: list[dict[str, Any]] = []
        seen: set[str] = set()

        for module_root in sorted(self._base.glob("*_classifier")):
            if not module_root.is_dir():
                continue
            module_name = module_root.name[: -len("_classifier")]
            version = self._read_manifest_version(module_name)
            if version is None:
                continue
            meta_file = module_root / "versions" / version / "meta.json"
            if not meta_file.exists():
                continue
            try:
                metadata = json.loads(meta_file.read_text())
                metadata["_meta_file"] = str(meta_file)
                results.append(metadata)
                seen.add(module_name)
            except (json.JSONDecodeError, OSError) as exc:
                logger.warning("Skipping corrupt metadata file {}: {}", meta_file, exc)

        for meta_file in sorted(self._base.glob("*_classifier_meta.json")):
            module_name = meta_file.name[: -len("_classifier_meta.json")]
            if module_name in seen:
                continue
            try:
                metadata = json.loads(meta_file.read_text())
                metadata["_meta_file"] = str(meta_file)
                results.append(metadata)
            except (json.JSONDecodeError, OSError) as exc:
                logger.warning("Skipping corrupt metadata file {}: {}", meta_file, exc)

        return results

    @staticmethod
    def _class_names(metadata: dict[str, Any]) -> set[str]:
        """Extract classifier class names from persisted metadata."""
        label_map = metadata.get("label_map", {})
        return {str(value) for value in label_map.values()}

    def current_metadata(self, module_name: str) -> dict[str, Any] | None:
        """Read metadata for currently published model without loading joblib."""
        version = self._read_manifest_version(module_name)
        path = (
            self._versions_dir(module_name) / version / "meta.json"
            if version is not None
            else self._meta_path(module_name)
        )
        if not path.exists():
            return None
        try:
            return json.loads(path.read_text())
        except (OSError, json.JSONDecodeError):
            return None
