"""Comprehensive unit tests for the MITRE ICS ATT&CK tools module.

Tests use the real STIX bundle at ``data/ics-attack.json`` for all query
functions. HTTP calls in ``update_stix_data`` are mocked so tests remain
deterministic and offline.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict
from unittest.mock import MagicMock, patch

import pytest

from otalon_mcp.tools import mitre as mitre_tools

ROOT = os.path.dirname(os.path.dirname(__file__))


@pytest.fixture(scope="module")
def stix_path() -> str:
    """Resolve the path to the real STIX bundle shipped with the project."""
    path = os.path.join(ROOT, "data", "ics-attack.json")
    assert os.path.isfile(path), f"STIX bundle not found at {path}"
    return path


@pytest.fixture(scope="module")
def loaded_mitre(stix_path: str) -> None:
    """Initialize the MITRE module once for all tests in this module."""
    mitre_tools.init(stix_path=stix_path)


def _reset_module_state() -> None:
    """Reset internal module-level state so init can be called again."""
    mitre_tools._LOADED = False
    mitre_tools._STIX_PATH = None
    mitre_tools._RAW_OBJECTS = []
    mitre_tools._TECHNIQUES = []
    mitre_tools._BY_EXT_ID = {}
    mitre_tools._TACTIC_MAP = {}


# ---------------------------------------------------------------------------
# Loading & Initialization Tests
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestInitialization:
    """Tests for init, ensure_loaded, and bundle loading."""

    def test_init_loads_stix_bundle(self, loaded_mitre: None) -> None:
        """Calling init with a valid STIX path populates internal indexes."""
        assert mitre_tools._LOADED is True
        assert len(mitre_tools._TECHNIQUES) > 0

    def test_init_invalid_path_raises(self) -> None:
        """Calling init with a non-existent path raises FileNotFoundError."""
        saved_state = (
            mitre_tools._LOADED,
            mitre_tools._STIX_PATH,
            list(mitre_tools._TECHNIQUES),
            dict(mitre_tools._BY_EXT_ID),
            dict(mitre_tools._TACTIC_MAP),
        )
        try:
            with pytest.raises(FileNotFoundError):
                mitre_tools.init(stix_path="/nonexistent/path/ics-attack.json")
        finally:
            mitre_tools._LOADED = saved_state[0]
            mitre_tools._STIX_PATH = saved_state[1]
            mitre_tools._TECHNIQUES = saved_state[2]
            mitre_tools._BY_EXT_ID = saved_state[3]
            mitre_tools._TACTIC_MAP = saved_state[4]

    def test_ensure_loaded_idempotent(self, loaded_mitre: None) -> None:
        """Calling ensure_loaded multiple times does not raise or reload."""
        count_before = len(mitre_tools._TECHNIQUES)
        mitre_tools.ensure_loaded()
        mitre_tools.ensure_loaded()
        assert len(mitre_tools._TECHNIQUES) == count_before


# ---------------------------------------------------------------------------
# list_tactics Tests
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestListTactics:
    """Tests for the list_tactics function."""

    def test_list_tactics_returns_list(self, loaded_mitre: None) -> None:
        """list_tactics returns a non-empty list of dicts with expected keys."""
        result = mitre_tools.list_tactics()
        assert isinstance(result, list)
        assert len(result) > 0
        for item in result:
            assert "tactic" in item
            assert "technique_count" in item

    def test_list_tactics_known_tactics(self, loaded_mitre: None) -> None:
        """Well-known ICS tactics are present in the results."""
        result = mitre_tools.list_tactics()
        tactic_names = {item["tactic"] for item in result}
        for expected_tactic in ("initial-access", "execution", "persistence"):
            assert expected_tactic in tactic_names, f"Expected tactic '{expected_tactic}' not found"

    def test_list_tactics_technique_counts_positive(self, loaded_mitre: None) -> None:
        """Every tactic has at least one technique associated."""
        result = mitre_tools.list_tactics()
        for item in result:
            assert item["technique_count"] > 0, f"Tactic '{item['tactic']}' has 0 techniques"


# ---------------------------------------------------------------------------
# list_techniques Tests
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestListTechniques:
    """Tests for the list_techniques function."""

    def test_list_techniques_all(self, loaded_mitre: None) -> None:
        """Unfiltered list_techniques returns a non-empty list with expected keys."""
        result = mitre_tools.list_techniques()
        assert isinstance(result, list)
        assert len(result) > 0
        for item in result:
            assert "external_id" in item
            assert "name" in item
            assert "tactics" in item

    def test_list_techniques_with_tactic_filter(self, loaded_mitre: None) -> None:
        """Filtering by tactic returns only techniques belonging to that tactic."""
        result = mitre_tools.list_techniques(tactic="initial-access")
        assert len(result) > 0
        for item in result:
            lowered = [t.lower() for t in item["tactics"]]
            assert "initial-access" in lowered

    def test_list_techniques_with_limit(self, loaded_mitre: None) -> None:
        """Setting limit=3 returns exactly 3 techniques."""
        result = mitre_tools.list_techniques(limit=3)
        assert len(result) == 3

    def test_list_techniques_unknown_tactic(self, loaded_mitre: None) -> None:
        """Filtering by a non-existent tactic returns an empty list."""
        result = mitre_tools.list_techniques(tactic="nonexistent")
        assert result == []


# ---------------------------------------------------------------------------
# get_technique_by_external_id Tests
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestGetTechniqueByExternalId:
    """Tests for the get_technique_by_external_id function."""

    def test_get_technique_known_id(self, loaded_mitre: None) -> None:
        """T0829 (Loss of View) returns ok=True with expected fields."""
        result = mitre_tools.get_technique_by_external_id("T0829")
        assert result["ok"] is True
        assert "name" in result
        assert "description" in result
        assert "tactics" in result
        assert "url" in result
        assert result["name"] == "Loss of View"

    def test_get_technique_case_insensitive(self, loaded_mitre: None) -> None:
        """Lowercase external ID t0829 returns the same technique."""
        upper_result = mitre_tools.get_technique_by_external_id("T0829")
        lower_result = mitre_tools.get_technique_by_external_id("t0829")
        assert lower_result["ok"] is True
        assert lower_result["name"] == upper_result["name"]

    def test_get_technique_unknown_id(self, loaded_mitre: None) -> None:
        """A non-existent external ID returns ok=False."""
        result = mitre_tools.get_technique_by_external_id("T9999")
        assert result["ok"] is False
        assert "error" in result

    def test_get_technique_subtechnique_id(self, loaded_mitre: None) -> None:
        """Looking up a subtechnique ID that does not exist returns ok=False.

        The ICS ATT&CK v18.1 dataset has no subtechniques, so this verifies
        graceful handling of a dotted ID that is not present.
        """
        result = mitre_tools.get_technique_by_external_id("T0829.001")
        assert result["ok"] is False


# ---------------------------------------------------------------------------
# get_techniques_by_tactic Tests
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestGetTechniquesByTactic:
    """Tests for the get_techniques_by_tactic function."""

    def test_get_by_tactic_valid(self, loaded_mitre: None) -> None:
        """Execution tactic returns ok=True with a positive count."""
        result = mitre_tools.get_techniques_by_tactic(tactic="execution")
        assert result["ok"] is True
        assert result["count"] > 0
        assert len(result["techniques"]) == result["count"]

    def test_get_by_tactic_with_limit(self, loaded_mitre: None) -> None:
        """Limit parameter caps the number of returned techniques."""
        result = mitre_tools.get_techniques_by_tactic(tactic="execution", limit=2)
        assert result["ok"] is True
        assert len(result["techniques"]) <= 2

    def test_get_by_tactic_invalid(self, loaded_mitre: None) -> None:
        """A non-existent tactic returns ok=True with count=0."""
        result = mitre_tools.get_techniques_by_tactic(tactic="nonexistent")
        assert result["ok"] is True
        assert result["count"] == 0


# ---------------------------------------------------------------------------
# search_techniques Tests
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestSearchTechniques:
    """Tests for the search_techniques function."""

    def test_search_by_name(self, loaded_mitre: None) -> None:
        """Searching for 'spearphishing' matches at least one technique."""
        result = mitre_tools.search_techniques(query="spearphishing")
        assert result["ok"] is True
        assert result["count"] >= 1

    def test_search_by_description(self, loaded_mitre: None) -> None:
        """Searching for 'firmware' returns at least one technique."""
        result = mitre_tools.search_techniques(query="firmware")
        assert result["ok"] is True
        assert result["count"] >= 1

    def test_search_with_limit(self, loaded_mitre: None) -> None:
        """Limit parameter caps the number of search results."""
        result = mitre_tools.search_techniques(query="remote", limit=3)
        assert result["ok"] is True
        assert len(result["techniques"]) <= 3

    def test_search_no_results(self, loaded_mitre: None) -> None:
        """A nonsense query returns ok=True with count=0."""
        result = mitre_tools.search_techniques(query="xyznonexistent123")
        assert result["ok"] is True
        assert result["count"] == 0

    def test_search_case_insensitive(self, loaded_mitre: None) -> None:
        """Uppercase and lowercase queries return the same results."""
        upper_result = mitre_tools.search_techniques(query="REMOTE", limit=50)
        lower_result = mitre_tools.search_techniques(query="remote", limit=50)
        upper_ids = {t["external_id"] for t in upper_result["techniques"]}
        lower_ids = {t["external_id"] for t in lower_result["techniques"]}
        assert upper_ids == lower_ids


# ---------------------------------------------------------------------------
# get_subtechniques Tests
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestGetSubtechniques:
    """Tests for the get_subtechniques function."""

    def test_subtechniques_valid_parent(self, loaded_mitre: None) -> None:
        """A known parent ID returns ok=True (count may be 0 for ICS dataset v18.1)."""
        result = mitre_tools.get_subtechniques("T0829")
        assert result["ok"] is True
        assert isinstance(result["count"], int)
        assert isinstance(result["subtechniques"], list)

    def test_subtechniques_no_children(self, loaded_mitre: None) -> None:
        """A parent without subtechniques returns count=0."""
        result = mitre_tools.get_subtechniques("T0800")
        assert result["ok"] is True
        assert result["count"] == 0

    def test_subtechniques_invalid_parent(self, loaded_mitre: None) -> None:
        """A non-existent parent ID returns ok=True with count=0."""
        result = mitre_tools.get_subtechniques("T9999")
        assert result["ok"] is True
        assert result["count"] == 0


# ---------------------------------------------------------------------------
# stats Tests
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestStats:
    """Tests for the stats function."""

    def test_stats_structure(self, loaded_mitre: None) -> None:
        """Stats returns ok=True with positive technique and tactic counts."""
        result = mitre_tools.stats()
        assert result["ok"] is True
        assert result["total_techniques"] > 0
        assert result["tactic_count"] > 0

    def test_stats_source_info(self, loaded_mitre: None) -> None:
        """Stats includes source metadata with the path to the STIX bundle."""
        result = mitre_tools.stats()
        assert "source" in result
        assert "path" in result["source"]

    def test_stats_includes_version_info(self, loaded_mitre: None) -> None:
        """Stats includes version info when mitre_version.json exists.

        The real data directory ships with mitre_version.json, so the version
        field should be a dict (not None).
        """
        result = mitre_tools.stats()
        version_path = Path(mitre_tools._STIX_PATH).parent / "mitre_version.json"
        if version_path.exists():
            assert result["version"] is not None
            assert isinstance(result["version"], dict)
        else:
            assert result["version"] is None


# ---------------------------------------------------------------------------
# ping Test
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestPing:
    """Test for the ping function."""

    def test_mitre_ping(self) -> None:
        """ping returns the literal string 'pong'."""
        assert mitre_tools.ping() == "pong"


# ---------------------------------------------------------------------------
# update_stix_data Tests (all HTTP mocked)
# ---------------------------------------------------------------------------


def _make_valid_stix_bundle(technique_count: int = 2) -> Dict[str, Any]:
    """Build a minimal but valid STIX bundle for testing update_stix_data."""
    objects = []
    for idx in range(technique_count):
        objects.append(
            {
                "type": "attack-pattern",
                "id": f"attack-pattern--fake-{idx}",
                "name": f"Fake Technique {idx}",
                "description": f"Description for fake technique {idx}.",
                "x_mitre_domains": ["ics-attack"],
                "x_mitre_is_subtechnique": False,
                "kill_chain_phases": [{"kill_chain_name": "mitre-ics-attack", "phase_name": "execution"}],
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": f"T{9900 + idx}",
                        "url": f"https://attack.mitre.org/techniques/T{9900 + idx}",
                    }
                ],
            }
        )
    return {"type": "bundle", "id": "bundle--fake", "objects": objects}


@pytest.mark.unit
class TestUpdateStixData:
    """Tests for update_stix_data with mocked HTTP requests."""

    def _setup_for_update(self, tmp_path: Path, stix_path: str) -> str:
        """Copy current STIX data to a temp directory and re-init.

        Returns the temporary STIX path.
        """
        data_dir = tmp_path / "data"
        data_dir.mkdir()
        tmp_stix = data_dir / "ics-attack.json"

        with open(stix_path, "r", encoding="utf-8") as src:
            original_data = json.load(src)
        with tmp_stix.open("w", encoding="utf-8") as dst:
            json.dump(original_data, dst)

        mitre_tools.init(stix_path=str(tmp_stix))
        return str(tmp_stix)

    def test_update_stix_data_success(self, tmp_path: Path, stix_path: str) -> None:
        """A successful update writes the new bundle and version file."""
        tmp_stix = self._setup_for_update(tmp_path, stix_path)
        bundle = _make_valid_stix_bundle(technique_count=3)

        mock_release = MagicMock()
        mock_release.status_code = 200
        mock_release.json.return_value = {"tag_name": "v99.0"}
        mock_release.raise_for_status = MagicMock()

        mock_download = MagicMock()
        mock_download.status_code = 200
        mock_download.json.return_value = bundle
        mock_download.raise_for_status = MagicMock()

        with patch("otalon_mcp.tools.mitre.requests.get", side_effect=[mock_release, mock_download]):
            result = mitre_tools.update_stix_data()

        assert result["ok"] is True
        assert result["tag"] == "v99.0"

        with open(tmp_stix, "r", encoding="utf-8") as fh:
            written_data = json.load(fh)
        assert written_data["id"] == "bundle--fake"

        version_path = Path(tmp_stix).parent / "mitre_version.json"
        assert version_path.exists()
        with version_path.open("r", encoding="utf-8") as fh:
            version_data = json.load(fh)
        assert version_data["tag"] == "v99.0"

    def test_update_stix_data_network_error(self, tmp_path: Path, stix_path: str) -> None:
        """A network error returns ok=False and leaves the existing file intact."""
        tmp_stix = self._setup_for_update(tmp_path, stix_path)

        with open(tmp_stix, "r", encoding="utf-8") as fh:
            original_data = json.load(fh)

        import requests as req_lib

        with patch(
            "otalon_mcp.tools.mitre.requests.get",
            side_effect=req_lib.ConnectionError("network down"),
        ):
            result = mitre_tools.update_stix_data()

        assert result["ok"] is False
        assert "error" in result

        with open(tmp_stix, "r", encoding="utf-8") as fh:
            after_data = json.load(fh)
        assert after_data == original_data

    def test_update_stix_data_invalid_json(self, tmp_path: Path, stix_path: str) -> None:
        """An invalid JSON response returns ok=False and leaves the file unchanged."""
        tmp_stix = self._setup_for_update(tmp_path, stix_path)

        with open(tmp_stix, "r", encoding="utf-8") as fh:
            original_data = json.load(fh)

        mock_release = MagicMock()
        mock_release.status_code = 200
        mock_release.json.return_value = {"tag_name": "v99.0"}
        mock_release.raise_for_status = MagicMock()

        mock_download = MagicMock()
        mock_download.status_code = 200
        mock_download.json.return_value = {"not_a_bundle": True}
        mock_download.raise_for_status = MagicMock()

        with patch("otalon_mcp.tools.mitre.requests.get", side_effect=[mock_release, mock_download]):
            result = mitre_tools.update_stix_data()

        assert result["ok"] is False

        with open(tmp_stix, "r", encoding="utf-8") as fh:
            after_data = json.load(fh)

        assert "objects" in after_data or after_data == original_data

    def test_update_stix_data_backup_created(self, tmp_path: Path, stix_path: str) -> None:
        """A successful update creates a .bak backup of the original file."""
        tmp_stix = self._setup_for_update(tmp_path, stix_path)
        bundle = _make_valid_stix_bundle(technique_count=2)

        mock_release = MagicMock()
        mock_release.status_code = 200
        mock_release.json.return_value = {"tag_name": "v99.0"}
        mock_release.raise_for_status = MagicMock()

        mock_download = MagicMock()
        mock_download.status_code = 200
        mock_download.json.return_value = bundle
        mock_download.raise_for_status = MagicMock()

        with patch("otalon_mcp.tools.mitre.requests.get", side_effect=[mock_release, mock_download]):
            result = mitre_tools.update_stix_data()

        assert result["ok"] is True
        backup_path = Path(tmp_stix).with_suffix(".json.bak")
        assert backup_path.exists(), f"Backup file not found at {backup_path}"

    def test_update_stix_data_reloads_index(self, tmp_path: Path, stix_path: str) -> None:
        """After a successful update the in-memory index reflects the new data."""
        self._setup_for_update(tmp_path, stix_path)

        bundle = _make_valid_stix_bundle(technique_count=5)

        mock_release = MagicMock()
        mock_release.status_code = 200
        mock_release.json.return_value = {"tag_name": "v99.0"}
        mock_release.raise_for_status = MagicMock()

        mock_download = MagicMock()
        mock_download.status_code = 200
        mock_download.json.return_value = bundle
        mock_download.raise_for_status = MagicMock()

        with patch("otalon_mcp.tools.mitre.requests.get", side_effect=[mock_release, mock_download]):
            result = mitre_tools.update_stix_data()

        assert result["ok"] is True
        assert len(mitre_tools._TECHNIQUES) == 5
        assert mitre_tools._TECHNIQUES[0]["external_id"] == "T9900"
