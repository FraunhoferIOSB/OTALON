"""A busy first module cannot starve other historical modules forever."""

from types import SimpleNamespace

from otalon_clas.recovery.worker import RecoveryWorker


def test_recovery_rotates_modules_after_each_completed_work():
    class Progress:
        def __init__(self):
            self.order = []

        def next_work(self, module):
            self.order.append(module)
            return {"hash": "h", "batch": {"id": 1, "payload": []}}

        def outcome(self, ident):
            return None

        def put_outcome(self, *args):
            pass

        def complete(self, *args):
            pass

        def ack_outcome(self, *args):
            pass

    class Repository:
        source_id = "fixture"

        def persist(self, payload):
            return []

    class Bundle:
        def __init__(self, name):
            self.config = SimpleNamespace(name=name, measurement=name)
            self.freq_monitor = None
            self.preprocessor = None

        def model_snapshot(self):
            return None

    progress = Progress()
    worker = RecoveryWorker([Bundle("conn"), Bundle("mac"), Bundle("proto")], progress, Repository(), None)
    from unittest.mock import patch

    with (
        patch("otalon_clas.recovery.worker.isolated_frequency", return_value=None),
        patch("otalon_clas.recovery.worker.isolated_preprocessor", return_value=None),
    ):
        for _ in range(3):
            assert worker.process_one()
    assert progress.order == ["conn", "mac", "proto"], "continuous conn backlog starved downstream modules"
