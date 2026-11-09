"""CLAS-048 — write-time integrity metadata for joblib artifacts.

``joblib.load`` executes code contained in the artifact, so a loader that
cannot distinguish the bytes it wrote from bytes someone else wrote is an
arbitrary-deserialization primitive. These tests pin the two halves of
the fix:

* every write produces a sidecar integrity record, and
* every read verifies it and **refuses** on mismatch or absence
  (fail-closed — an unsealed artifact is rejected, not trusted).

The central regression is :class:`TestTamperedArtifactIsRefused`: an
artifact whose bytes changed after it was written must never reach
``joblib.load``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import joblib  # type: ignore[import-untyped]
import pytest

from otalon_clas.common.artifact_integrity import (
    INTEGRITY_SUFFIX,
    ArtifactIntegrityError,
    compute_digest,
    dump_sealed,
    load_verified,
    sidecar_path,
    verify_artifact,
    write_integrity_sidecar,
)
from otalon_clas.common.model_store import ModelStore
from otalon_clas.ml.group_classifier.store import GroupClassifierStore

pytestmark = pytest.mark.unit


class _Payload:
    """Trivial picklable stand-in for a trained estimator."""

    def __init__(self, tag: str = "m") -> None:
        self.tag = tag

    def __eq__(self, other: object) -> bool:
        return isinstance(other, _Payload) and other.tag == self.tag


def _tamper(artifact: Path) -> None:
    """Rewrite an artifact with different (still valid joblib) content.

    Models the real threat: the file at the trusted path is replaced
    after it was written, so its bytes no longer match the sealed digest.
    """
    joblib.dump({"model": _Payload("attacker"), "scaler": _Payload("attacker")}, artifact)


def _save_via_model_store(store: ModelStore, module: str = "conn") -> None:
    store.save(
        module_name=module,
        model={"x": 1},
        scaler={"s": 2},
        metadata={"algo": "dt", "label_map": {"0": "benign", "1": "attack"}},
    )


def _version_dir(base: Path, module: str) -> Path:
    manifest = json.loads((base / f"{module}_classifier" / "current.json").read_text())
    return base / f"{module}_classifier" / "versions" / str(manifest["version"])


class TestSidecarShape:
    """The metadata format itself."""

    def test_sidecar_sits_next_to_the_artifact(self, tmp_path: Path) -> None:
        artifact = tmp_path / "model.joblib"
        assert sidecar_path(artifact) == tmp_path / ("model.joblib" + INTEGRITY_SUFFIX)

    def test_dump_sealed_writes_a_sha256_record(self, tmp_path: Path) -> None:
        artifact = tmp_path / "model.joblib"
        dump_sealed({"model": _Payload()}, artifact)

        record = json.loads(sidecar_path(artifact).read_text())
        assert record["schema"] == "otalon.artifact-integrity/1"
        assert record["algorithm"] == "sha256"
        assert record["digest"] == compute_digest(artifact)
        assert record["size_bytes"] == artifact.stat().st_size
        assert record["artifact"] == "model.joblib"
        assert record["written_at"]

    def test_round_trip_returns_the_original_object(self, tmp_path: Path) -> None:
        artifact = tmp_path / "model.joblib"
        dump_sealed({"model": _Payload("orig")}, artifact)
        assert load_verified(artifact) == {"model": _Payload("orig")}


class TestTamperedArtifactIsRefused:
    """The core CLAS-048 regression: modified bytes must not deserialize."""

    def test_load_verified_refuses_a_tampered_artifact(self, tmp_path: Path) -> None:
        artifact = tmp_path / "model.joblib"
        dump_sealed({"model": _Payload("trusted"), "scaler": _Payload("s")}, artifact)

        _tamper(artifact)

        with pytest.raises(ArtifactIntegrityError, match="does not match the sealed"):
            load_verified(artifact)

    def test_tampering_never_reaches_joblib_load(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Verification happens *before* any deserialization."""
        artifact = tmp_path / "model.joblib"
        dump_sealed({"model": _Payload("trusted")}, artifact)
        _tamper(artifact)

        def _explode(*_args: Any, **_kwargs: Any) -> Any:
            raise AssertionError("joblib.load must not be reached for a tampered artifact")

        monkeypatch.setattr("otalon_clas.common.artifact_integrity.joblib.load", _explode)
        with pytest.raises(ArtifactIntegrityError):
            load_verified(artifact)

    def test_a_forged_digest_in_the_sidecar_is_still_rejected(self, tmp_path: Path) -> None:
        """Editing only the sidecar cannot make foreign bytes acceptable."""
        artifact = tmp_path / "model.joblib"
        dump_sealed({"model": _Payload("trusted")}, artifact)
        _tamper(artifact)
        record = json.loads(sidecar_path(artifact).read_text())
        record["size_bytes"] = artifact.stat().st_size  # defeat the cheap pre-check
        sidecar_path(artifact).write_text(json.dumps(record))

        with pytest.raises(ArtifactIntegrityError, match="digest"):
            load_verified(artifact)

    def test_missing_sidecar_is_fail_closed(self, tmp_path: Path) -> None:
        artifact = tmp_path / "model.joblib"
        joblib.dump({"model": _Payload()}, artifact)  # unsealed, pre-CLAS-048 style

        with pytest.raises(ArtifactIntegrityError, match="no integrity metadata"):
            load_verified(artifact)

    def test_corrupt_sidecar_is_rejected(self, tmp_path: Path) -> None:
        artifact = tmp_path / "model.joblib"
        dump_sealed({"model": _Payload()}, artifact)
        sidecar_path(artifact).write_text("{not json")

        with pytest.raises(ArtifactIntegrityError, match="unreadable integrity metadata"):
            load_verified(artifact)

    def test_unknown_schema_is_rejected(self, tmp_path: Path) -> None:
        artifact = tmp_path / "model.joblib"
        dump_sealed({"model": _Payload()}, artifact)
        record = json.loads(sidecar_path(artifact).read_text())
        record["schema"] = "someone-elses/9"
        sidecar_path(artifact).write_text(json.dumps(record))

        with pytest.raises(ArtifactIntegrityError, match="unsupported integrity schema"):
            load_verified(artifact)

    def test_unknown_algorithm_is_rejected(self, tmp_path: Path) -> None:
        """No downgrade to a weaker digest the attacker can collide."""
        artifact = tmp_path / "model.joblib"
        dump_sealed({"model": _Payload()}, artifact)
        record = json.loads(sidecar_path(artifact).read_text())
        record["algorithm"] = "md5"
        sidecar_path(artifact).write_text(json.dumps(record))

        with pytest.raises(ArtifactIntegrityError, match="unsupported digest algorithm"):
            load_verified(artifact)

    def test_missing_artifact_raises_file_not_found(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            verify_artifact(tmp_path / "absent.joblib")

    def test_integrity_error_is_not_an_oserror(self) -> None:
        """Existing ``except OSError`` fallbacks must not swallow a refusal."""
        assert not issubclass(ArtifactIntegrityError, OSError)


class TestOperatorSeal:
    """Pre-existing artifacts are brought forward by an explicit action."""

    def test_seal_makes_a_legacy_artifact_loadable(self, tmp_path: Path) -> None:
        artifact = tmp_path / "model.joblib"
        joblib.dump({"model": _Payload("legacy")}, artifact)
        with pytest.raises(ArtifactIntegrityError):
            load_verified(artifact)

        write_integrity_sidecar(artifact)

        assert load_verified(artifact) == {"model": _Payload("legacy")}

    def test_seal_cli_seals_and_verify_cli_detects_tampering(self, tmp_path: Path) -> None:
        from otalon_clas.common.artifact_integrity import main

        artifact = tmp_path / "model.joblib"
        joblib.dump({"model": _Payload("legacy")}, artifact)

        assert main(["seal", str(artifact)]) == 0
        assert main(["verify", str(artifact)]) == 0

        _tamper(artifact)
        assert main(["verify", str(artifact)]) == 1


class TestModelStoreIntegrity:
    """The versioned + legacy-flat load sites in :class:`ModelStore`."""

    def test_save_seals_versioned_and_legacy_flat_artifacts(self, tmp_path: Path) -> None:
        store = ModelStore(models_dir=str(tmp_path))
        _save_via_model_store(store)

        versioned = _version_dir(tmp_path, "conn") / "model.joblib"
        flat = tmp_path / "conn_classifier.joblib"
        assert sidecar_path(versioned).exists()
        assert sidecar_path(flat).exists()
        verify_artifact(versioned)
        verify_artifact(flat)

    def test_tampered_versioned_artifact_is_refused(self, tmp_path: Path) -> None:
        store = ModelStore(models_dir=str(tmp_path))
        _save_via_model_store(store)

        _tamper(_version_dir(tmp_path, "conn") / "model.joblib")

        with pytest.raises(ArtifactIntegrityError):
            store.load("conn")

    def test_tampered_version_does_not_silently_fall_back_to_flat(self, tmp_path: Path) -> None:
        """A refusal must not degrade into loading some other artifact."""
        store = ModelStore(models_dir=str(tmp_path))
        _save_via_model_store(store)
        assert (tmp_path / "conn_classifier.joblib").exists()  # a viable fallback exists

        _tamper(_version_dir(tmp_path, "conn") / "model.joblib")

        with pytest.raises(ArtifactIntegrityError):
            store.load("conn")

    def test_tampered_legacy_flat_artifact_is_refused(self, tmp_path: Path) -> None:
        flat = tmp_path / "conn_classifier.joblib"
        dump_sealed({"model": {"x": 9}, "scaler": {"s": 10}}, flat)
        (tmp_path / "conn_classifier_meta.json").write_text(json.dumps({"label_map": {"0": "benign"}}))
        _tamper(flat)

        store = ModelStore(models_dir=str(tmp_path))
        with pytest.raises(ArtifactIntegrityError):
            store.load("conn")

    def test_unsealed_legacy_flat_artifact_is_refused(self, tmp_path: Path) -> None:
        """Fail-closed: pre-existing artifacts are rejected, not auto-sealed."""
        joblib.dump({"model": {"x": 9}, "scaler": {"s": 10}}, tmp_path / "conn_classifier.joblib")
        (tmp_path / "conn_classifier_meta.json").write_text(json.dumps({"label_map": {"0": "benign"}}))

        store = ModelStore(models_dir=str(tmp_path))
        with pytest.raises(ArtifactIntegrityError, match="no integrity metadata"):
            store.load("conn")

    def test_refusal_does_not_seal_the_rejected_artifact(self, tmp_path: Path) -> None:
        """A rejected load must not create metadata that blesses the bytes."""
        flat = tmp_path / "conn_classifier.joblib"
        joblib.dump({"model": {"x": 9}, "scaler": {"s": 10}}, flat)
        (tmp_path / "conn_classifier_meta.json").write_text(json.dumps({"label_map": {"0": "benign"}}))

        store = ModelStore(models_dir=str(tmp_path))
        with pytest.raises(ArtifactIntegrityError):
            store.load("conn")
        assert not sidecar_path(flat).exists()

    def test_migration_of_a_sealed_legacy_flat_model_seals_the_new_version(self, tmp_path: Path) -> None:
        flat = tmp_path / "conn_classifier.joblib"
        dump_sealed({"model": {"x": 9}, "scaler": {"s": 10}}, flat)
        (tmp_path / "conn_classifier_meta.json").write_text(json.dumps({"label_map": {"0": "benign"}}))

        store = ModelStore(models_dir=str(tmp_path))
        model, _scaler, _meta = store.load("conn")

        assert model == {"x": 9}
        migrated = _version_dir(tmp_path, "conn") / "model.joblib"
        verify_artifact(migrated)

    def test_restore_publication_pointer_refuses_a_tampered_version(self, tmp_path: Path) -> None:
        store = ModelStore(models_dir=str(tmp_path))
        _save_via_model_store(store)
        prior = store.publication_pointer("conn")
        assert prior is not None
        _tamper(tmp_path / "conn_classifier" / "versions" / prior / "model.joblib")
        _save_via_model_store(store)

        with pytest.raises(ArtifactIntegrityError):
            store.restore_publication_pointer("conn", prior)


class TestGroupClassifierStoreIntegrity:
    """The third load site: the alarm-group classifier bundle."""

    def _bundle_args(self) -> dict[str, Any]:
        return {
            "model": _Payload("rf"),
            "scaler": _Payload("scaler"),
            "feature_names": ["f1", "f2"],
            "classes": ["a", "b"],
            "metadata": {"cv": 0.9},
        }

    def test_save_seals_the_bundle(self, tmp_path: Path) -> None:
        store = GroupClassifierStore(tmp_path / "group_classifier.joblib")
        store.save(**self._bundle_args())

        verify_artifact(store.model_path)
        assert sidecar_path(store.model_path).exists()

    def test_round_trip_loads(self, tmp_path: Path) -> None:
        store = GroupClassifierStore(tmp_path / "group_classifier.joblib")
        store.save(**self._bundle_args())

        loaded = store.load()
        assert loaded.feature_names == ["f1", "f2"]
        assert loaded.classes == ["a", "b"]
        assert loaded.metadata == {"cv": 0.9}

    def test_tampered_bundle_is_refused(self, tmp_path: Path) -> None:
        store = GroupClassifierStore(tmp_path / "group_classifier.joblib")
        store.save(**self._bundle_args())

        _tamper(store.model_path)

        with pytest.raises(ArtifactIntegrityError):
            store.load()

    def test_unsealed_bundle_is_refused(self, tmp_path: Path) -> None:
        path = tmp_path / "group_classifier.joblib"
        joblib.dump({"model": _Payload(), "scaler": _Payload()}, path)

        store = GroupClassifierStore(path)
        with pytest.raises(ArtifactIntegrityError, match="no integrity metadata"):
            store.load()

    def test_missing_bundle_still_raises_file_not_found(self, tmp_path: Path) -> None:
        store = GroupClassifierStore(tmp_path / "absent.joblib")
        with pytest.raises(FileNotFoundError):
            store.load()
