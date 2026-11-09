"""Write-time integrity metadata for joblib model artifacts (CLAS-048).

``joblib.load`` deserializes pickles and therefore **executes code** from
the artifact it reads. Without a checksum produced when the artifact was
written, a loader cannot tell a model trained by this suite from a file
that was swapped underneath it. This module supplies that missing half:
every write goes through :func:`dump_sealed`, which stores the artifact
plus a sidecar integrity record, and every read goes through
:func:`load_verified`, which re-computes the digest and refuses to hand
the bytes to ``joblib.load`` unless it matches.

Sidecar layout — ``<artifact-name>.integrity.json`` next to the
artifact::

    {
      "schema": "otalon.artifact-integrity/1",
      "algorithm": "sha256",
      "digest": "<64 hex chars of the artifact bytes>",
      "size_bytes": 123456,
      "artifact": "model.joblib",
      "written_at": "2026-09-02T08:12:33.412000+00:00"
    }

Only ``schema``, ``algorithm`` and ``digest`` are load-bearing;
``size_bytes`` is a cheap pre-check and the remaining fields are for
operators reading the file by hand.

**Fail-closed policy.** A missing, unparsable or non-matching sidecar is
an :class:`ArtifactIntegrityError` — an artifact without write-time
metadata is treated exactly like a tampered one, never like a trusted
one. Pre-existing artifacts written before this module are therefore
*rejected* rather than silently migrated: an auto-migration would
compute the digest from whatever bytes are on disk at that moment, which
seals in an attacker's file just as happily as a legitimate one and
reduces the check to theatre. Deployed artifacts are brought forward by
an explicit operator action instead::

    python -m otalon_clas.common.artifact_integrity seal <artifact> ...

That command is deliberately manual and out-of-band: running it is the
operator asserting the bytes are the ones they trust.

Path containment (``.resolve()`` + allowed base directory) for the paths
these artifacts are read from is the sibling item CLAS-049 and stays
separate; this module verifies *content*, not *location*.
"""

from __future__ import annotations

import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import joblib  # type: ignore[import-untyped]  # joblib ships no py.typed stubs
from loguru import logger

INTEGRITY_SUFFIX: str = ".integrity.json"
"""Suffix appended to the full artifact filename for its sidecar."""

INTEGRITY_SCHEMA: str = "otalon.artifact-integrity/1"
"""Schema tag written into every sidecar; unknown tags are rejected."""

DIGEST_ALGORITHM: str = "sha256"
"""The only digest algorithm accepted by :func:`verify_artifact`."""

_CHUNK_BYTES: int = 1024 * 1024


class ArtifactIntegrityError(RuntimeError):
    """Raised when an artifact's integrity metadata is absent or wrong.

    Deliberately derived from :class:`RuntimeError` rather than
    :class:`OSError` so that existing "file missing / unreadable"
    fallback handlers around load sites do not swallow it and quietly
    degrade to an unverified path.
    """


def sidecar_path(artifact_path: str | Path) -> Path:
    """Return the sidecar path belonging to *artifact_path*.

    Args:
        artifact_path: Path of the model artifact.

    Returns:
        Sibling path with :data:`INTEGRITY_SUFFIX` appended to the full
        filename (``model.joblib`` -> ``model.joblib.integrity.json``),
        so an artifact and its own metadata can never collide with the
        sidecar of a differently-suffixed artifact of the same stem.
    """
    path = Path(artifact_path)
    return path.with_name(path.name + INTEGRITY_SUFFIX)


def compute_digest(artifact_path: str | Path) -> str:
    """Return the SHA-256 hex digest of the artifact's bytes.

    Args:
        artifact_path: Path of the file to hash.

    Returns:
        Lowercase hex digest string.

    Raises:
        OSError: If the file cannot be read.
    """
    digest = hashlib.sha256()
    with Path(artifact_path).open("rb") as handle:
        while chunk := handle.read(_CHUNK_BYTES):
            digest.update(chunk)
    return digest.hexdigest()


def write_integrity_sidecar(artifact_path: str | Path) -> Path:
    """Compute and persist the integrity record for an existing artifact.

    Args:
        artifact_path: Path of the artifact to seal. Must already exist
            in its final location, because the digest is taken from the
            bytes on disk.

    Returns:
        The path of the written sidecar.

    Raises:
        OSError: If the artifact cannot be read or the sidecar written.
    """
    path = Path(artifact_path)
    record: dict[str, Any] = {
        "schema": INTEGRITY_SCHEMA,
        "algorithm": DIGEST_ALGORITHM,
        "digest": compute_digest(path),
        "size_bytes": path.stat().st_size,
        "artifact": path.name,
        "written_at": datetime.now(timezone.utc).isoformat(),
    }
    target = sidecar_path(path)
    target.write_text(json.dumps(record, indent=2))
    logger.debug("Sealed artifact {} with {} digest", path, DIGEST_ALGORITHM)
    return target


def _read_sidecar(path: Path) -> dict[str, Any]:
    """Read and structurally validate a sidecar record."""
    sidecar = sidecar_path(path)
    if not sidecar.exists():
        raise ArtifactIntegrityError(
            f"Refusing to load {path}: no integrity metadata at {sidecar}. "
            f"Seal a trusted artifact with "
            f"'python -m otalon_clas.common.artifact_integrity seal {path}'."
        )
    try:
        record = json.loads(sidecar.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise ArtifactIntegrityError(
            f"Refusing to load {path}: unreadable integrity metadata {sidecar}: {exc}"
        ) from exc
    if not isinstance(record, dict):
        raise ArtifactIntegrityError(f"Refusing to load {path}: integrity metadata {sidecar} is not an object")
    if record.get("schema") != INTEGRITY_SCHEMA:
        raise ArtifactIntegrityError(
            f"Refusing to load {path}: unsupported integrity schema {record.get('schema')!r} in {sidecar}"
        )
    if record.get("algorithm") != DIGEST_ALGORITHM:
        raise ArtifactIntegrityError(
            f"Refusing to load {path}: unsupported digest algorithm {record.get('algorithm')!r} in {sidecar}"
        )
    return record


def verify_artifact(artifact_path: str | Path) -> None:
    """Verify an artifact against its sidecar, raising on any mismatch.

    Args:
        artifact_path: Path of the artifact to check.

    Raises:
        ArtifactIntegrityError: If the sidecar is missing, malformed, or
            does not describe the bytes currently on disk.
        FileNotFoundError: If the artifact itself does not exist.
    """
    path = Path(artifact_path)
    if not path.exists():
        raise FileNotFoundError(f"Artifact not found: {path}")

    record = _read_sidecar(path)
    expected = str(record.get("digest", ""))
    expected_size = record.get("size_bytes")
    actual_size = path.stat().st_size
    if isinstance(expected_size, int) and expected_size != actual_size:
        raise ArtifactIntegrityError(
            f"Refusing to load {path}: size {actual_size} bytes does not match "
            f"the sealed {expected_size} bytes (artifact modified since it was written)"
        )

    try:
        actual = compute_digest(path)
    except OSError as exc:
        raise ArtifactIntegrityError(
            f"Refusing to load {path}: artifact unreadable during verification: {exc}"
        ) from exc

    if actual != expected:
        raise ArtifactIntegrityError(
            f"Refusing to load {path}: {DIGEST_ALGORITHM} digest {actual} does not "
            f"match the sealed digest {expected} (artifact modified since it was written)"
        )


def load_verified(artifact_path: str | Path) -> Any:
    """Verify integrity metadata, then ``joblib.load`` the artifact.

    The verification happens **before** any deserialization, so a
    tampered artifact never reaches the pickle machinery.

    Args:
        artifact_path: Path of the artifact to load.

    Returns:
        The deserialized object.

    Raises:
        ArtifactIntegrityError: If verification fails.
        FileNotFoundError: If the artifact does not exist.
    """
    verify_artifact(artifact_path)
    return joblib.load(Path(artifact_path))


def dump_sealed(obj: Any, artifact_path: str | Path) -> Path:
    """``joblib.dump`` an object and write its integrity sidecar.

    Args:
        obj: The object to serialize.
        artifact_path: Destination path of the artifact.

    Returns:
        The path of the written sidecar.

    Raises:
        OSError: If the artifact or its sidecar cannot be written.
    """
    path = Path(artifact_path)
    joblib.dump(obj, path)
    return write_integrity_sidecar(path)


def _seal_cli(paths: list[str]) -> int:
    """Seal each given artifact, reporting one line per file."""
    if not paths:
        print("usage: python -m otalon_clas.common.artifact_integrity seal <artifact> [...]")
        return 2
    failures = 0
    for raw in paths:
        path = Path(raw)
        try:
            sidecar = write_integrity_sidecar(path)
        except OSError as exc:
            print(f"FAILED {path}: {exc}")
            failures += 1
            continue
        print(f"sealed {path} -> {sidecar}")
    return 1 if failures else 0


def _verify_cli(paths: list[str]) -> int:
    """Verify each given artifact, reporting one line per file."""
    if not paths:
        print("usage: python -m otalon_clas.common.artifact_integrity verify <artifact> [...]")
        return 2
    failures = 0
    for raw in paths:
        try:
            verify_artifact(raw)
        except (ArtifactIntegrityError, FileNotFoundError) as exc:
            print(f"INVALID {raw}: {exc}")
            failures += 1
            continue
        print(f"ok {raw}")
    return 1 if failures else 0


def main(argv: list[str]) -> int:
    """Entry point for the operator ``seal`` / ``verify`` commands.

    Args:
        argv: Argument list without the program name.

    Returns:
        Process exit code.
    """
    if not argv or argv[0] not in {"seal", "verify"}:
        print("usage: python -m otalon_clas.common.artifact_integrity {seal|verify} <artifact> [...]")
        return 2
    return _seal_cli(argv[1:]) if argv[0] == "seal" else _verify_cli(argv[1:])


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
