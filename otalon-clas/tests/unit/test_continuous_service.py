"""Recovery automatically discovers committed receiver batches, never manual jobs."""

import importlib.util
from types import SimpleNamespace


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
