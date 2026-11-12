"""A failed Windows process query does not prove the old capture owner is gone."""

from types import SimpleNamespace
from unittest.mock import patch

import pytest
from windows_collector import collector


def test_owner_absence_is_not_assumed_after_failed_tasklist():
    assert hasattr(collector, "previous_owner_alive"), "collector owner query is not fail-closed"
    with patch.object(collector.subprocess, "run", return_value=SimpleNamespace(returncode=1, stdout="")):
        with pytest.raises(RuntimeError, match="owner"):
            collector.previous_owner_alive(123)
    with patch.object(
        collector.subprocess,
        "run",
        return_value=SimpleNamespace(returncode=0, stdout='"dumpcap.exe","123","Console","1","10 K"'),
    ):
        assert collector.previous_owner_alive(123)
    with patch.object(
        collector.subprocess,
        "run",
        return_value=SimpleNamespace(
            returncode=0, stdout="INFO: No tasks are running which match the specified criteria."
        ),
    ):
        assert not collector.previous_owner_alive(123)
