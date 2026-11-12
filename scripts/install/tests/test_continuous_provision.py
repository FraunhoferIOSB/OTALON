"""Source key provision precedes startup; certificate export follows TLS startup."""

from test_continuous_package import tool


def test_source_only_prepare_does_not_require_certificate_or_windows_export(tmp_path):
    module = tool()
    assert module.prepare(tmp_path, None, None) == 0
    key = tmp_path / "shared/continuous-source.key"
    before = key.read_bytes()
    assert len(before.strip()) == 64
    assert module.prepare(tmp_path, None, None) == 0
    assert key.read_bytes() == before
