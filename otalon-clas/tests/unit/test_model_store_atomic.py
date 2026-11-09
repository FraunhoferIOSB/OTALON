"""Unit tests for the coherent publication behaviour of :class:`ModelStore`.

Covers audit B-04 / F6 / task 8.4: versioned artifact + single atomic
manifest pointer, a loader that never combines a mismatched model/meta
pair and falls back safely, injected publication failure at each point
with rollback (the prior model stays intact), migration of legacy flat
files, and the in-process model swap into a :class:`ModuleBundle`.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from otalon_clas.common.model_store import ModelStore


def _save(store: ModelStore, module: str, x: int, algo: str) -> None:
    store.save(
        module_name=module,
        model={"x": x},
        scaler={"s": x + 1},
        metadata={"algo": algo, "label_map": {"0": "benign", "1": "attack"}},
        protocol_map={"tcp": 1},
        feature_columns=["f1"],
    )


def _save_classes(store: ModelStore, classes: list[str], *, force: bool = False) -> bool:
    """Save synthetic metadata with a controlled classifier class set."""
    return store.save(
        module_name="conn",
        model={"classes": classes},
        scaler={"s": 1},
        metadata={"label_map": {str(i): label for i, label in enumerate(classes)}},
        force_publish_class_set_shrink=force,
    )


def test_fewer_classes_are_not_published(tmp_path: Path) -> None:
    """A class-count shrink retains the previously published model."""
    store = ModelStore(models_dir=str(tmp_path))
    assert _save_classes(store, ["benign", "arp_scan", "dos"])
    assert not _save_classes(store, ["benign", "arp_scan"])
    model, _scaler, metadata = store.load("conn")
    assert model["classes"] == ["benign", "arp_scan", "dos"]
    assert len(metadata["label_map"]) == 3


def test_same_or_more_classes_are_published(tmp_path: Path) -> None:
    """Equal and expanded class sets remain publishable."""
    store = ModelStore(models_dir=str(tmp_path))
    assert _save_classes(store, ["benign", "arp_scan"])
    assert _save_classes(store, ["benign", "arp_scan"])
    assert _save_classes(store, ["benign", "arp_scan", "dos"])


def test_force_allows_class_count_shrink(tmp_path: Path) -> None:
    """Explicit force permits an intentional class-set shrink."""
    store = ModelStore(models_dir=str(tmp_path))
    assert _save_classes(store, ["benign", "arp_scan", "dos"])
    assert _save_classes(store, ["benign"], force=True)
    _model, _scaler, metadata = store.load("conn")
    assert metadata["label_map"] == {"0": "benign"}


def test_save_and_load_roundtrip_via_manifest(tmp_path: Path) -> None:
    """A saved model loads back coherently through the manifest pointer."""
    store = ModelStore(models_dir=str(tmp_path))
    _save(store, "mod", 1, "dt")

    manifest = tmp_path / "mod_classifier" / "current.json"
    assert manifest.exists()
    model, scaler, meta = store.load("mod")
    assert model == {"x": 1}
    assert scaler == {"s": 2}
    assert meta["algo"] == "dt"
    assert meta["label_map"] == {"0": "benign", "1": "attack"}


def test_second_save_flips_pointer_and_keeps_prior_version(tmp_path: Path) -> None:
    """A new publish flips the manifest; the load reflects the new version."""
    store = ModelStore(models_dir=str(tmp_path))
    _save(store, "mod", 1, "dt")
    _save(store, "mod", 2, "rf")

    model, _scaler, meta = store.load("mod")
    assert model == {"x": 2}
    assert meta["algo"] == "rf"


def test_restore_publication_pointer_restores_exact_prior_generation(tmp_path: Path) -> None:
    """Rollback selects durable prior generation without re-saving content."""
    store = ModelStore(models_dir=str(tmp_path))
    _save(store, "mod", 1, "dt")
    prior = store.publication_pointer("mod")
    _save(store, "mod", 2, "rf")

    store.restore_publication_pointer("mod", prior)

    model, _scaler, meta = store.load("mod")
    assert model == {"x": 1}
    assert meta["algo"] == "dt"


def test_no_temp_files_left_behind(tmp_path: Path) -> None:
    """Publication leaves no ``.tmp`` files in the module root."""
    store = ModelStore(models_dir=str(tmp_path))
    _save(store, "mod", 1, "dt")
    leftovers = list((tmp_path / "mod_classifier").glob("*.tmp"))
    assert leftovers == []


def test_manifest_failure_leaves_prior_model_intact(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """If the atomic manifest flip fails, the prior model still loads (B-04)."""
    store = ModelStore(models_dir=str(tmp_path))
    _save(store, "mod", 1, "dt")

    # Inject a failure exactly at the manifest-flip commit point.
    def _boom(module_root: Path, version: str) -> None:
        raise OSError("disk full during manifest flip")

    monkeypatch.setattr(store, "_flip_manifest", _boom)
    with pytest.raises(OSError):
        _save(store, "mod", 2, "rf")

    # The prior version is still the published one; no mismatched pair.
    model, _scaler, meta = store.load("mod")
    assert model == {"x": 1}
    assert meta["algo"] == "dt"


def test_loader_falls_back_when_version_dir_incomplete(tmp_path: Path) -> None:
    """A manifest pointing at an incomplete version falls back, not crashes."""
    store = ModelStore(models_dir=str(tmp_path))
    _save(store, "mod", 1, "dt")  # seeds legacy flat mirror too

    # Corrupt the current version: delete its meta.json so the pair is broken.
    manifest = json.loads((tmp_path / "mod_classifier" / "current.json").read_text())
    version = manifest["version"]
    (tmp_path / "mod_classifier" / "versions" / version / "meta.json").unlink()

    # Load must fall back to the legacy flat mirror rather than pairing a
    # model with missing metadata.
    model, _scaler, meta = store.load("mod")
    assert model == {"x": 1}
    assert meta["algo"] == "dt"


def test_load_missing_model_raises(tmp_path: Path) -> None:
    """Loading a never-saved module raises FileNotFoundError."""
    store = ModelStore(models_dir=str(tmp_path))
    with pytest.raises(FileNotFoundError):
        store.load("never")


def test_legacy_flat_files_are_migrated_on_load(tmp_path: Path) -> None:
    """A pre-existing flat model (no manifest) is migrated to versioned.

    The flat artifact is sealed, i.e. an operator has vouched for it via
    the CLAS-048 ``seal`` command; an unsealed one is refused rather than
    migrated (pinned in ``tests/unit/test_artifact_integrity.py``).
    """
    from otalon_clas.common.artifact_integrity import dump_sealed

    # Simulate a legacy deployment: only flat files, no versioned layout.
    (tmp_path).mkdir(parents=True, exist_ok=True)
    dump_sealed({"model": {"x": 9}, "scaler": {"s": 10}}, tmp_path / "mod_classifier.joblib")
    (tmp_path / "mod_classifier_meta.json").write_text(json.dumps({"algo": "legacy", "label_map": {"0": "benign"}}))

    store = ModelStore(models_dir=str(tmp_path))
    model, _scaler, meta = store.load("mod")
    assert model == {"x": 9}
    assert meta["algo"] == "legacy"
    # After the migrating load, a manifest now exists.
    assert (tmp_path / "mod_classifier" / "current.json").exists()


def test_has_model_true_for_versioned_manifest(tmp_path: Path) -> None:
    """has_model recognises a coherently published versioned model."""
    store = ModelStore(models_dir=str(tmp_path))
    _save(store, "conn", 1, "dt")
    assert store.has_model("conn") is True


def test_has_model_false_for_never_saved_module(tmp_path: Path) -> None:
    """has_model returns False when no artifact exists (no exception)."""
    store = ModelStore(models_dir=str(tmp_path))
    assert store.has_model("mac_traffic") is False


def test_has_model_false_for_incomplete_version_without_legacy(tmp_path: Path) -> None:
    """A manifest pointing at an incomplete version (no legacy mirror) is absent."""
    store = ModelStore(models_dir=str(tmp_path))
    _save(store, "conn", 1, "dt")
    # Break the versioned pair AND remove the legacy flat mirror so the only
    # remaining artifact is the incomplete version directory.
    manifest = json.loads((tmp_path / "conn_classifier" / "current.json").read_text())
    version = manifest["version"]
    (tmp_path / "conn_classifier" / "versions" / version / "meta.json").unlink()
    (tmp_path / "conn_classifier.joblib").unlink()
    (tmp_path / "conn_classifier_meta.json").unlink()
    assert store.has_model("conn") is False


def test_has_model_true_for_legacy_flat_without_manifest(tmp_path: Path) -> None:
    """has_model recognises a legacy flat model with no versioned layout."""
    import joblib

    joblib.dump({"model": {"x": 9}, "scaler": {"s": 10}}, tmp_path / "conn_classifier.joblib")
    (tmp_path / "conn_classifier_meta.json").write_text(json.dumps({"algo": "legacy"}))

    store = ModelStore(models_dir=str(tmp_path))
    assert store.has_model("conn") is True


def test_has_model_does_not_migrate_legacy_flat(tmp_path: Path) -> None:
    """has_model is a pure probe: it never creates a manifest for legacy files."""
    import joblib

    joblib.dump({"model": {"x": 9}, "scaler": {"s": 10}}, tmp_path / "conn_classifier.joblib")
    (tmp_path / "conn_classifier_meta.json").write_text(json.dumps({"algo": "legacy"}))

    store = ModelStore(models_dir=str(tmp_path))
    assert store.has_model("conn") is True
    # Unlike load(), the probe must NOT seed a versioned layout/manifest.
    assert not (tmp_path / "conn_classifier" / "current.json").exists()


def test_in_process_swap_updates_bundle(tmp_path: Path) -> None:
    """A published model swaps into a bundle as one coherent InferenceModel."""
    from otalon_clas.runtime.module_bundle import InferenceModel

    store = ModelStore(models_dir=str(tmp_path))
    _save(store, "mod", 7, "rf")
    model, scaler, meta = store.load("mod")

    # Simulate the supervisor swap: build the immutable model, publish it.
    class _Bundle:
        def __init__(self) -> None:
            self._m: InferenceModel | None = None
            import threading

            self._lock = threading.RLock()
            self.label_map: dict = {}

            class _Pipe:
                backend = None
                scaler = None

            self.ml_pipeline = _Pipe()

        def set_inference_model(self, m: InferenceModel) -> None:
            with self._lock:
                self._m = m
                self.ml_pipeline.backend = m.backend
                self.ml_pipeline.scaler = m.scaler
                self.label_map = dict(m.label_map)

        def model_snapshot(self) -> InferenceModel | None:
            with self._lock:
                return self._m

    bundle = _Bundle()
    label_map = {int(k): v for k, v in meta["label_map"].items()}
    bundle.set_inference_model(InferenceModel(backend=model, scaler=scaler, label_map=label_map, protocol_map=None))

    snap = bundle.model_snapshot()
    assert snap is not None
    # Coherent tuple: backend, scaler and label_map all from the same model.
    assert snap.backend == {"x": 7}
    assert snap.scaler == {"s": 8}
    assert snap.label_map == {0: "benign", 1: "attack"}
