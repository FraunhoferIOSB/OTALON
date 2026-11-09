"""MITRE ICS ATT&CK helper functions for MCP tools.

This module loads a STIX bundle, builds in-memory indexes, and exposes
query/update helpers for tactics and techniques.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests
from loguru import logger

_LOADED: bool = False
_STIX_PATH: Optional[str] = None
_RAW_OBJECTS: List[Dict[str, Any]] = []
_TECHNIQUES: List[Dict[str, Any]] = []
_BY_EXT_ID: Dict[str, Dict[str, Any]] = {}
_TACTIC_MAP: Dict[str, List[Dict[str, Any]]] = {}

LATEST_RELEASE_URL = "https://api.github.com/repos/mitre-attack/attack-stix-data/releases/latest"
RAW_URL_TEMPLATE = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/{tag}/ics-attack/ics-attack.json"


def init(stix_path: str) -> None:
    """Initialize MITRE helpers with a configurable STIX bundle path."""
    global _STIX_PATH, _LOADED
    _STIX_PATH = stix_path
    _LOADED = False
    logger.debug("tools.mitre.init: stix_path={stix_path}", stix_path=stix_path)
    ensure_loaded()


def _read_json_bundle(path: str) -> List[Dict[str, Any]]:
    bundle_path = Path(path)
    if not bundle_path.exists():
        raise FileNotFoundError(f"STIX bundle not found: {bundle_path}")
    with bundle_path.open("r", encoding="utf-8") as file_handle:
        data = json.load(file_handle)
    objects = data.get("objects") if isinstance(data, dict) else None
    if isinstance(objects, list):
        return objects
    if isinstance(data, list):
        return data
    raise ValueError("Invalid STIX bundle format: missing 'objects'.")


def _get_external_id(stix_obj: Dict[str, Any]) -> Optional[str]:
    references = stix_obj.get("external_references") or []
    for reference in references:
        external_id = reference.get("external_id")
        if isinstance(external_id, str) and external_id.startswith("T"):
            return external_id
    return None


def _get_mitre_url(stix_obj: Dict[str, Any]) -> Optional[str]:
    references = stix_obj.get("external_references") or []
    for reference in references:
        if reference.get("source_name") == "mitre-attack" and reference.get("url"):
            return str(reference.get("url"))
    return None


def _normalize_technique(stix_obj: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if stix_obj.get("type") != "attack-pattern":
        return None
    domains = stix_obj.get("x_mitre_domains") or []
    if domains and "ics-attack" not in domains:
        return None
    external_id = _get_external_id(stix_obj)
    if not external_id:
        return None
    phases = stix_obj.get("kill_chain_phases") or []
    tactics = [phase.get("phase_name") for phase in phases if phase.get("phase_name")]
    return {
        "stix_id": stix_obj.get("id"),
        "external_id": external_id,
        "name": stix_obj.get("name"),
        "description": stix_obj.get("description"),
        "tactics": tactics,
        "url": _get_mitre_url(stix_obj),
        "is_subtechnique": bool(stix_obj.get("x_mitre_is_subtechnique", False)),
        "platforms": stix_obj.get("x_mitre_platforms") or [],
        "domains": domains,
        "revoked": bool(stix_obj.get("revoked", False)),
        "deprecated": bool(stix_obj.get("x_mitre_deprecated", False)),
        "detection": stix_obj.get("x_mitre_detection"),
        "created": stix_obj.get("created"),
        "modified": stix_obj.get("modified"),
        "raw": stix_obj,
    }


def _index_data() -> None:
    global _LOADED, _RAW_OBJECTS, _TECHNIQUES, _BY_EXT_ID, _TACTIC_MAP
    if not _STIX_PATH:
        raise ValueError("MITRE STIX path is not configured. Call init(stix_path=...) first.")

    objects = _read_json_bundle(_STIX_PATH)
    techniques: List[Dict[str, Any]] = []
    by_ext_id: Dict[str, Dict[str, Any]] = {}
    tactic_map: Dict[str, List[Dict[str, Any]]] = {}

    for stix_obj in objects:
        if stix_obj.get("type") != "attack-pattern":
            continue
        if stix_obj.get("revoked", False) or stix_obj.get("x_mitre_deprecated", False):
            continue
        normalized = _normalize_technique(stix_obj)
        if not normalized:
            continue
        techniques.append(normalized)
        external_id = normalized["external_id"]
        by_ext_id[external_id] = normalized
        for tactic in normalized.get("tactics", []):
            tactic_map.setdefault(tactic, []).append(normalized)

    _RAW_OBJECTS = objects
    _TECHNIQUES = techniques
    _BY_EXT_ID = by_ext_id
    _TACTIC_MAP = tactic_map
    _LOADED = True
    logger.info("tools.mitre._index_data loaded techniques={count}", count=len(_TECHNIQUES))


def ensure_loaded() -> None:
    """Load and index MITRE data if not loaded yet."""
    if not _LOADED:
        _index_data()


def list_tactics() -> List[Dict[str, Any]]:
    """Return all ICS ATT&CK tactics with associated technique counts."""
    ensure_loaded()
    return [{"tactic": tactic, "technique_count": len(_TACTIC_MAP[tactic])} for tactic in sorted(_TACTIC_MAP.keys())]


def list_techniques(tactic: Optional[str] = None, limit: Optional[int] = None) -> List[Dict[str, Any]]:
    """Return techniques, optionally filtered by tactic and limited by count."""
    ensure_loaded()
    rows = _TECHNIQUES
    if tactic:
        tactic_name = tactic.strip().lower()
        rows = [
            technique
            for technique in rows
            if any((phase or "").lower() == tactic_name for phase in technique.get("tactics", []))
        ]
    if limit is not None and limit > 0:
        rows = rows[: int(limit)]
    return [
        {
            "external_id": technique["external_id"],
            "name": technique["name"],
            "tactics": technique["tactics"],
            "url": technique["url"],
            "is_subtechnique": technique["is_subtechnique"],
        }
        for technique in rows
    ]


def get_technique_by_external_id(external_id: str) -> Dict[str, Any]:
    """Return detailed information for a technique by MITRE external ID."""
    ensure_loaded()
    key = external_id.strip()
    hit = _BY_EXT_ID.get(key) or _BY_EXT_ID.get(key.upper())
    if not hit:
        return {"ok": False, "error": f"No technique found with ID '{external_id}'."}
    flattened = {entry_key: entry_value for entry_key, entry_value in hit.items() if entry_key != "raw"}
    return {"ok": True, **flattened}


def get_techniques_by_tactic(tactic: str, limit: Optional[int] = None) -> Dict[str, Any]:
    """Return techniques that belong to a given tactic."""
    rows = list_techniques(tactic=tactic, limit=None)
    if limit is not None and limit > 0:
        rows = rows[: int(limit)]
    return {"ok": True, "tactic": tactic, "count": len(rows), "techniques": rows}


def search_techniques(query: str, limit: int = 10) -> Dict[str, Any]:
    """Search techniques by case-insensitive match in name and description."""
    ensure_loaded()
    normalized_query = query.strip().lower()
    hits: List[Dict[str, Any]] = []
    for technique in _TECHNIQUES:
        name = str(technique.get("name") or "").lower()
        description = str(technique.get("description") or "").lower()
        if normalized_query in name or normalized_query in description:
            hits.append(
                {
                    "external_id": technique["external_id"],
                    "name": technique["name"],
                    "tactics": technique["tactics"],
                    "url": technique["url"],
                }
            )
        if limit > 0 and len(hits) >= limit:
            break
    return {"ok": True, "query": query, "count": len(hits), "techniques": hits}


def get_subtechniques(parent_external_id: str) -> Dict[str, Any]:
    """Return sub-techniques for a parent technique external ID."""
    ensure_loaded()
    prefix = parent_external_id.strip().upper()
    subtechniques: List[Dict[str, Any]] = []
    for technique in _TECHNIQUES:
        external_id = str(technique.get("external_id") or "")
        if not external_id or not technique.get("is_subtechnique"):
            continue
        if external_id.upper().startswith(f"{prefix}."):
            subtechniques.append(
                {
                    "external_id": technique["external_id"],
                    "name": technique["name"],
                    "tactics": technique["tactics"],
                    "url": technique["url"],
                }
            )
    return {
        "ok": True,
        "parent": parent_external_id,
        "count": len(subtechniques),
        "subtechniques": subtechniques,
    }


def _version_file_path() -> Path:
    if not _STIX_PATH:
        raise ValueError("MITRE STIX path is not configured. Call init(stix_path=...) first.")
    return Path(_STIX_PATH).parent / "mitre_version.json"


def _load_version_info() -> Optional[Dict[str, Any]]:
    version_path = _version_file_path()
    if not version_path.exists():
        return None
    with version_path.open("r", encoding="utf-8") as file_handle:
        return json.load(file_handle)


def stats() -> Dict[str, Any]:
    """Return dataset statistics and MITRE version metadata."""
    ensure_loaded()
    tactics = list_tactics()
    return {
        "ok": True,
        "total_techniques": len(_TECHNIQUES),
        "total_subtechniques": sum(1 for technique in _TECHNIQUES if technique.get("is_subtechnique")),
        "tactic_count": len(tactics),
        "tactics": tactics,
        "version": _load_version_info(),
        "source": {"path": _STIX_PATH},
    }


def ping() -> str:
    """Return a simple liveness response."""
    return "pong"


def update_stix_data() -> Dict[str, Any]:
    """Download and replace MITRE ICS STIX data and refresh in-memory indexes."""
    if not _STIX_PATH:
        return {
            "ok": False,
            "error": "MITRE STIX path is not configured. Call init(stix_path=...) first.",
        }

    try:
        ensure_loaded()
        previous_count = len(_TECHNIQUES)

        release_response = requests.get(LATEST_RELEASE_URL, timeout=30)
        release_response.raise_for_status()
        tag = release_response.json().get("tag_name")
        if not isinstance(tag, str) or not tag.strip():
            raise ValueError("Missing tag_name in GitHub release response.")

        source_url = RAW_URL_TEMPLATE.format(tag=tag)
        bundle_response = requests.get(source_url, timeout=60)
        bundle_response.raise_for_status()
        bundle_data = bundle_response.json()
        objects = bundle_data.get("objects") if isinstance(bundle_data, dict) else None
        if not isinstance(objects, list):
            raise ValueError("Downloaded STIX bundle is invalid: 'objects' key is missing.")
        attack_patterns = [obj for obj in objects if isinstance(obj, dict) and obj.get("type") == "attack-pattern"]
        if not attack_patterns:
            raise ValueError("Downloaded STIX bundle does not contain any attack-pattern objects.")

        stix_path = Path(_STIX_PATH)
        stix_path.parent.mkdir(parents=True, exist_ok=True)
        backup_path = stix_path.with_suffix(f"{stix_path.suffix}.bak")
        if stix_path.exists():
            stix_path.replace(backup_path)
        with stix_path.open("w", encoding="utf-8") as file_handle:
            json.dump(bundle_data, file_handle, ensure_ascii=False, indent=2)

        global _LOADED
        _LOADED = False
        _index_data()

        downloaded_at = datetime.now(timezone.utc).isoformat()
        version_payload = {
            "tag": tag,
            "downloaded_at": downloaded_at,
            "technique_count": len(_TECHNIQUES),
            "source_url": source_url,
        }
        version_path = _version_file_path()
        with version_path.open("w", encoding="utf-8") as file_handle:
            json.dump(version_payload, file_handle, ensure_ascii=False, indent=2)

        result = {
            "ok": True,
            "tag": tag,
            "source_url": source_url,
            "previous_count": previous_count,
            "new_count": len(_TECHNIQUES),
            "backup_path": str(backup_path),
            "version_file": str(version_path),
        }
        logger.info(
            "tools.mitre.update_stix_data success tag={tag} count={count}",
            tag=tag,
            count=len(_TECHNIQUES),
        )
        return result
    except (
        requests.RequestException,
        ValueError,
        json.JSONDecodeError,
        OSError,
    ) as exc:
        logger.exception("tools.mitre.update_stix_data failed: {exc}", exc=exc)
        return {"ok": False, "error": str(exc)}
