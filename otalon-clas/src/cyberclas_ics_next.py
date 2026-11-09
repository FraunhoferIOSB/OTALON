"""Backward-compatibility shim for the legacy package name ``cyberclas_ics_next``.

The package was renamed to ``otalon_clas`` in 2026-08 after the legacy
``cyberclas-ics`` service was decommissioned. Pickled ML models from before
the rename reference classes via ``cyberclas_ics_next.ml.backends.decision_tree.
DecisionTreeBackend`` (and similar). This single-file shim registers
``cyberclas_ics_next`` and all of its submodules as aliases of the new
``otalon_clas`` package in :data:`sys.modules`, so that ``joblib.load`` and
``pickle.load`` calls succeed without re-training.

Remove this shim once every production ML model has been re-trained or
re-saved under the new module path.
"""

from __future__ import annotations

import importlib
import sys

_NEW_PKG = "otalon_clas"
_OLD_PKG = "cyberclas_ics_next"


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

# Re-export the new package as the current module so ``import cyberclas_ics_next``
# behaves exactly like ``import otalon_clas``.
sys.modules[__name__] = sys.modules[_NEW_PKG]
