"""CLI utility to download and update MITRE ICS ATT&CK STIX data."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

import requests
from loguru import logger

LATEST_RELEASE_URL = (
    "https://api.github.com/repos/mitre-attack/attack-stix-data/releases/latest"
)
RAW_URL_TEMPLATE = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/{tag}/ics-attack/ics-attack.json"


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Update MITRE ICS ATT&CK STIX bundle")
    parser.add_argument(
        "--output",
        default="data/ics-attack.json",
        help="Output path for downloaded STIX bundle",
    )
    return parser.parse_args()


def _validate_bundle(bundle_data: Any) -> int:
    objects = bundle_data.get("objects") if isinstance(bundle_data, dict) else None
    if not isinstance(objects, list):
        raise ValueError("Downloaded STIX bundle is invalid: 'objects' key is missing.")
    attack_pattern_count = sum(
        1
        for obj in objects
        if isinstance(obj, dict) and obj.get("type") == "attack-pattern"
    )
    if attack_pattern_count < 1:
        raise ValueError(
            "Downloaded STIX bundle does not contain any attack-pattern objects."
        )
    return attack_pattern_count


def update_stix_data(output_path: str) -> Dict[str, Any]:
    """Download latest MITRE ICS STIX bundle and update output files."""
    output = Path(output_path)
    logger.info("Fetching latest MITRE ATT&CK release metadata")
    release_response = requests.get(LATEST_RELEASE_URL, timeout=30)
    release_response.raise_for_status()
    tag = release_response.json().get("tag_name")
    if not isinstance(tag, str) or not tag.strip():
        raise ValueError("Missing tag_name in GitHub release response.")

    source_url = RAW_URL_TEMPLATE.format(tag=tag)
    logger.info("Downloading ICS STIX bundle from tag={tag}", tag=tag)
    bundle_response = requests.get(source_url, timeout=60)
    bundle_response.raise_for_status()
    bundle_data = bundle_response.json()
    attack_pattern_count = _validate_bundle(bundle_data)

    output.parent.mkdir(parents=True, exist_ok=True)
    backup_path = output.with_suffix(f"{output.suffix}.bak")
    previous_exists = output.exists()
    if previous_exists:
        output.replace(backup_path)

    with output.open("w", encoding="utf-8") as file_handle:
        json.dump(bundle_data, file_handle, ensure_ascii=False, indent=2)

    version_payload = {
        "tag": tag,
        "downloaded_at": datetime.now(timezone.utc).isoformat(),
        "technique_count": attack_pattern_count,
        "source_url": source_url,
    }
    version_path = output.parent / "mitre_version.json"
    with version_path.open("w", encoding="utf-8") as file_handle:
        json.dump(version_payload, file_handle, ensure_ascii=False, indent=2)

    result = {
        "ok": True,
        "tag": tag,
        "output": str(output),
        "version_file": str(version_path),
        "backup": str(backup_path) if previous_exists else None,
        "technique_count": attack_pattern_count,
        "source_url": source_url,
    }
    logger.info("MITRE STIX update finished: {result}", result=result)
    return result


def main() -> int:
    """Run CLI updater."""
    args = parse_args()
    try:
        update_stix_data(args.output)
        return 0
    except (
        requests.RequestException,
        ValueError,
        json.JSONDecodeError,
        OSError,
    ) as exc:
        logger.exception("Failed to update MITRE STIX data: {exc}", exc=exc)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
