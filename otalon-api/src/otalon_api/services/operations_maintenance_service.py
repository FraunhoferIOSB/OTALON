"""Safe, local maintenance contract services for Operations System."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
from pathlib import Path
from typing import Any

from otalon_api.domain.operations.redaction import redact_network_identifiers, redact_sensitive
from otalon_api.settings import Settings


class OperationsMaintenanceService:
    """Compute maintenance facts and create privacy-scoped local artifacts."""

    def __init__(self, settings: Settings) -> None:
        """Initialize the service with application settings."""
        self._settings = settings

    def storage(self) -> dict[str, Any]:
        """Return host, ringbuffer, and measured contributor storage facts."""
        mount_paths = {
            "/": self._settings.host_storage_root,
            "/home": self._settings.host_storage_home,
            "/var": self._settings.host_storage_var,
        }
        mounts = {mount: shutil.disk_usage(path) for mount, path in mount_paths.items() if os.path.exists(path)}
        usage = mounts.get("/")
        contributors = [
            self._footprint("InfluxDB", self._settings.host_influx_data_path),
            self._footprint("PostgreSQL", self._settings.host_postgres_data_path),
            self._footprint("models", self._settings.model_dir),
            self._footprint("logs", self._settings.host_log_path),
            self._footprint("PCAP archive", self._settings.pcap_archive_dir),
            self._footprint("backups", self._settings.backup_dir),
        ]
        buffer_path = Path(self._settings.pcap_buffer_dir)
        ring_size, ring_files = self._directory_size(buffer_path)
        cap_mb, file_cap = self._pcap_caps()
        contributors.append(self._footprint("PCAP ringbuffer", str(buffer_path)))
        contributor_response = [self._without_internal_size(item) for item in contributors]
        if usage is None:
            return {
                "host": {"unit": "GB", "mounts": {}},
                "ringbuffer": {
                    "unit": "GB",
                    "size_gb": None,
                    "cap_gb": None,
                    "files": None,
                    "file_cap": None,
                    "state": "unknown",
                },
                "contributors": contributor_response,
                "unattributed_gb": None,
            }
        used = usage.used
        accounted_gb = sum(item["size_gb"] for item in contributor_response)
        used_gb = used / 1_000_000_000
        return {
            "host": {
                "unit": "GB",
                "total_gb": round(usage.total / 1_000_000_000, 2),
                "used_gb": round(used_gb, 2),
                "free_gb": round(usage.free / 1_000_000_000, 2),
                "used_pct": round(used / usage.total * 100, 2) if usage.total else 0,
                "mount": "/",
                "fs": "unknown",
                "mounts": {
                    mount: {
                        "total_gb": round(value.total / 1_000_000_000, 2),
                        "used_gb": round(value.used / 1_000_000_000, 2),
                        "free_gb": round(value.free / 1_000_000_000, 2),
                        "used_pct": (round(value.used / value.total * 100, 2) if value.total else 0),
                        "purpose": self._mount_purpose(mount),
                    }
                    for mount, value in mounts.items()
                },
            },
            "ringbuffer": {
                "unit": "GB",
                "size_gb": round(ring_size / 1_000_000_000, 2),
                "cap_gb": round(cap_mb / 1000, 2) if cap_mb else None,
                "files": ring_files,
                "file_cap": file_cap or None,
                "state": "rotating",
            },
            "contributors": contributor_response,
            "unattributed_gb": round(max(0.0, used_gb - accounted_gb), 2),
        }

    def version(self) -> dict[str, Any]:
        """Return locally-known suite and component version metadata.

        Build metadata is read raw from the process environment on purpose
        (API-043): these values are injected by the image build / Compose at
        deploy time, are not part of this service's configuration, and the
        per-component names are constructed at runtime from the component
        list, so they cannot be typed Settings fields.
        """
        release = os.environ.get("OTALON_RELEASE", "unknown")
        digest = os.environ.get("OTALON_IMAGE_DIGEST", "unknown")
        build_ref = os.environ.get("OTALON_BUILD_REF", "unknown")
        names = (
            "otalon-api",
            "otalon-ui",
            "otalon-common",
            "otalon-clas",
            "otalon-scan",
            "otalon-mcp",
            "otalon-ai",
            "otalon-capture",
            "pcap_recorder",
        )
        return {
            "suite": {"version": release, "build_ref": build_ref, "digest": digest},
            "components": [
                {
                    "name": name,
                    "version": os.environ.get(f"{name.upper().replace('-', '_')}_VERSION", "unknown"),
                    "build_ref": os.environ.get(f"{name.upper().replace('-', '_')}_BUILD_REF", "unknown"),
                    "digest": os.environ.get(f"{name.upper().replace('-', '_')}_DIGEST", "unknown"),
                }
                for name in names
            ],
        }

    @staticmethod
    def _mount_purpose(mount: str) -> str:
        """Return the operator-facing purpose of a host mount."""
        purposes = {
            "/": "System / OS",
            "/home": "Suite checkout, user data, and models",
            "/var": "Docker images, volumes, databases, and logs",
        }
        return purposes.get(mount, "Host storage")

    async def health_check(self, postgres: Any, influx: Any) -> dict[str, Any]:
        """Run non-mutating dependency and filesystem checks."""
        findings: list[dict[str, str]] = []
        findings.append(await self._probe("postgresql", postgres.health_check, "Check PostgreSQL service"))
        findings.append(await self._probe("influxdb", influx.health_check, "Check InfluxDB service"))
        findings.extend(
            [
                self._finding(
                    "capture_link",
                    os.path.isdir(self._settings.pcap_buffer_dir),
                    "PCAP buffer mount is visible",
                    "Check recorder mount",
                ),
                self._finding(
                    "detection_cycle",
                    None,
                    "No detection-cycle probe is available",
                    "Check detection worker",
                ),
                self._finding(
                    "configuration_drift",
                    None,
                    "No drift source is available",
                    "Compare deployed configuration",
                ),
                self._finding(
                    "port_sanity",
                    None,
                    "No port-sanity probe is available",
                    "Check configured service ports",
                ),
                self._finding(
                    "permissions",
                    os.access("/", os.R_OK),
                    "Root filesystem readable",
                    "Check mount permissions",
                ),
            ]
        )
        statuses = {f["status"] for f in findings}
        state = "fail" if "fail" in statuses else "warn" if "warn" in statuses or "unknown" in statuses else "pass"
        return {"status": state, "findings": findings, "mutations": []}

    def support_preview(self) -> dict[str, Any]:
        """Describe the privacy boundary for locally-created support bundles."""
        return {
            "privacy_scope": "local-only; never uploaded automatically",
            "included": [
                "service logs",
                "non-secret configuration",
                "health results",
                "version manifest",
                "storage summary",
            ],
            "excluded": [
                "PCAPs",
                "InfluxDB contents",
                "PostgreSQL contents",
                "models",
                "chat/LLM payloads",
            ],
            "redacted": [
                "API keys",
                "tokens",
                "DSNs",
                "passwords",
                "cookies",
                "hostnames",
                "IP addresses",
            ],
        }

    def create_support_bundle(self, output_dir: Path) -> dict[str, Any]:
        """Write a redacted local archive without network access."""
        output_dir = self._safe_artifact_dir(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        payload = redact_network_identifiers(
            redact_sensitive(
                {
                    "version": self.version(),
                    "storage": self.storage(),
                    "privacy": self.support_preview(),
                }
            )
        )
        path = Path(tempfile.mkstemp(prefix="otalon-support-", suffix=".json", dir=output_dir)[1])
        path.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
        checksum = hashlib.sha256(path.read_bytes()).hexdigest()
        return {"path": str(path), "sha256": checksum, "uploaded": False}

    def _safe_artifact_dir(self, requested: Path) -> Path:
        """Resolve a requested directory only inside the suite artifact root."""
        root = Path(self._settings.operations_artifact_dir).resolve()
        candidate = requested.expanduser()
        if not candidate.is_absolute():
            candidate = root / candidate
        for lexical in (candidate, *candidate.parents):
            if lexical.exists() and lexical.is_symlink():
                raise ValueError("artifact path must not contain symlinks")
            if lexical == root:
                break
        candidate = candidate.resolve(strict=False)
        if root not in candidate.parents and candidate != root:
            raise ValueError("artifact directory is outside the suite-owned directory")
        if root.exists() and root.is_symlink():
            raise ValueError("artifact root must not be a symlink")
        probe = candidate
        while probe != root.parent:
            if probe.exists() and probe.is_symlink():
                raise ValueError("artifact path must not contain symlinks")
            if probe == root:
                break
            probe = probe.parent
        return candidate

    @staticmethod
    async def _probe(name: str, probe: Any, remediation: str) -> dict[str, str]:
        """Run a probe and preserve unknown when its evidence is unavailable."""
        try:
            value = probe()
            if hasattr(value, "__await__"):
                value = await value
            if value is True:
                return OperationsMaintenanceService._finding(name, True, f"{name} reachable", remediation)
            if value is False:
                return OperationsMaintenanceService._finding(name, False, "Probe failed", remediation)
            return OperationsMaintenanceService._finding(name, None, "Probe returned no evidence", remediation)
        except Exception:
            return OperationsMaintenanceService._finding(name, None, "Probe unavailable", remediation)

    def _pcap_caps(self) -> tuple[int, int]:
        """Read ringbuffer limits from the shipped Netcap configuration."""
        configured = Path(self._settings.pcap_config_path)
        candidates = (
            configured,
            Path(__file__).resolve().parents[4] / "otalon-capture/config/config_pcap.json",
        )
        for config in candidates:
            try:
                ring = json.loads(config.read_text(encoding="utf-8"))["pcap"]["ringbuffer"]
                return int(ring["max_total_size_mb"]), int(ring["max_file_count"])
            except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError):
                continue
        return 0, 0

    @staticmethod
    def _footprint(name: str, path: str) -> dict[str, Any]:
        size, _ = OperationsMaintenanceService._directory_size(Path(path))
        return {
            "name": name,
            "size_bytes": size,
            "oldest": None,
            "newest": None,
            "note": "best-effort local footprint",
        }

    @staticmethod
    def _directory_size(path: Path) -> tuple[int, int]:
        try:
            if not path.exists():
                return 0, 0
            if path.is_file():
                return path.stat().st_size, 1
            return sum(item.stat().st_size for item in path.rglob("*") if item.is_file()), sum(
                1 for item in path.rglob("*") if item.is_file()
            )
        except PermissionError:
            return 0, 0

    @staticmethod
    def _without_internal_size(item: dict[str, Any]) -> dict[str, Any]:
        return {key: value for key, value in item.items() if key != "size_bytes"} | {
            "size_gb": round(item["size_bytes"] / 1_000_000_000, 2),
        }

    @staticmethod
    def _finding(name: str, passed: bool | None, detail: str, remediation: str) -> dict[str, str]:
        status = "pass" if passed is True else "fail" if passed is False else "unknown"
        return {
            "name": name,
            "status": status,
            "detail": detail,
            "remediation": "" if passed is True else remediation,
        }
