"""Backward-compatibility shim for the legacy package name ``cyberclas_ics``.

The package was renamed ``cyberclas_ics`` -> ``cyberclas_ics_next`` ->
``otalon_clas`` across two successive renames. Pickled ML models
persisted before the FIRST rename reference classes via
``cyberclas_ics.ml.backends.random_forest.RandomForestBackend`` (and
similar) — the oldest module path, one generation further back than the
``cyberclas_ics_next`` shim already covers. This single-file shim
registers ``cyberclas_ics`` and all of its submodules as aliases of the
current ``otalon_clas`` package in :data:`sys.modules`, so that
``joblib.load`` / ``pickle.load`` calls against those oldest artifacts
succeed without re-training.

Remove this shim once every production ML model has been re-trained or
re-saved under the new module path (same condition as the sibling
``cyberclas_ics_next`` shim).
"""

from __future__ import annotations

import importlib
import sys

_NEW_PKG = "otalon_clas"
_OLD_PKG = "cyberclas_ics"


def _install_aliases() -> None:
    new_root = importlib.import_module(_NEW_PKG)

    # Build a list of every importable submodule under otalon_clas by
    # walking its filesystem layout (the package is installed editable, so
    # __path__ points to the source tree).
    submodules: list[str] = []
    pkg_path = getattr(new_root, "__path__", None)
    if pkg_path is None:
        return

    import pkgutil

    for module_info in pkgutil.walk_packages(pkg_path, prefix=f"{_NEW_PKG}."):
        submodules.append(module_info.name)

    for full_name in submodules:
        try:
            mod = importlib.import_module(full_name)
        except ImportError:
            continue
        alias_name = _OLD_PKG + full_name[len(_NEW_PKG) :]
        sys.modules[alias_name] = mod

    # Register the alias for the root package itself.
    sys.modules[_OLD_PKG] = new_root


_install_aliases()

# Re-export the new package as the current module so ``import cyberclas_ics``
# behaves exactly like ``import otalon_clas``.
sys.modules[__name__] = sys.modules[_NEW_PKG]
