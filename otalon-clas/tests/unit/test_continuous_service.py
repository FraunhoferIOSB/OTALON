"""Recovery automatically discovers committed receiver batches, never manual jobs."""

import importlib.util
from types import SimpleNamespace
from unittest.mock import Mock

import pytest


def test_registration_survives_restart_without_skipping_module_work(tmp_path):
    assert importlib.util.find_spec("otalon_clas.recovery.service"), "automatic source recovery service missing"
    from otalon_clas.recovery.progress import LocalProgress
    from otalon_clas.recovery.service import CaptureRecovery

    service = CaptureRecovery.__new__(CaptureRecovery)
    service.progress = LocalProgress(tmp_path)
    service.bundles = [
        SimpleNamespace(config=SimpleNamespace(name="conn")),
        SimpleNamespace(config=SimpleNamespace(name="mac")),
    ]
    calls = []

    class Client:
        def get_batches(self, after):
            calls.append(after)
            return [{"id": 2, "chunk": "source-only", "payload": []}] if after == 0 else []

    service.client = Client()
    assert service.discover() == 1
    assert service.discover() == 0
    service.progress.close()
    service.progress = LocalProgress(tmp_path)
    assert service.progress.cursor() == 2
    assert service.progress.next_work("conn")["id"] == 2
    assert service.progress.next_work("mac")["id"] == 2
    assert calls == [0, 2]


@pytest.mark.parametrize(
    "discovery,work,delay",
    [(0, True, 0.1), (1, False, 0.1), (1, True, 0.1), (0, False, 1)],
)
def test_active_recovery_does_not_use_idle_delay(monkeypatch, discovery, work, delay):
    from otalon_clas.recovery import service as module

    service = module.CaptureRecovery.__new__(module.CaptureRecovery)
    service.thread = None
    service.stop_event = Mock()
    service.stop_event.is_set.side_effect = [False, True]
    service.discover = Mock(return_value=discovery)
    service.worker = SimpleNamespace(process_one=Mock(return_value=work))
    monkeypatch.setattr(module.threading, "Thread", lambda *, target, **kwargs: SimpleNamespace(start=target))

    service.start()

    service.discover.assert_called_once_with()
    service.worker.process_one.assert_called_once_with()
    service.stop_event.wait.assert_called_once_with(delay)


@pytest.mark.parametrize("stage", ["discovery", "work"])
def test_recovery_failure_keeps_bounded_retry_delay(monkeypatch, stage):
    from otalon_clas.recovery import service as module

    service = module.CaptureRecovery.__new__(module.CaptureRecovery)
    service.thread = None
    service.stop_event = Mock()
    service.stop_event.is_set.side_effect = [False, True]
    service.discover = Mock(return_value=1)
    service.worker = SimpleNamespace(process_one=Mock(return_value=True))
    failing = service.discover if stage == "discovery" else service.worker.process_one
    failing.side_effect = OSError("unit-only unavailable")
    monkeypatch.setattr(module.threading, "Thread", lambda *, target, **kwargs: SimpleNamespace(start=target))

    service.start()

    service.stop_event.wait.assert_called_once_with(1)
    if stage == "discovery":
        service.worker.process_one.assert_not_called()
