"""Fault the installed Client3 body, not an atomic top-level constructor fake."""

from types import SimpleNamespace
from unittest.mock import Mock

import influxdb_client_3 as dependency
import pytest
from influxdb_client_3.query import query_api

from desktop_ingest.pipeline import ContinuousPipeline
from otalon_capture import influxdb_writer as module
from otalon_capture.settings import InfluxConfig, WriteOptionsConfig


class OwnerAbort(BaseException):
    pass


def config():
    return InfluxConfig(
        host="http://owner.invalid",
        token="synthetic-only",
        database="owner_test",
        measurement_name="network",
        tags=["uci"],
        fields={"packet_count": "packet_count"},
    )


@pytest.fixture
def components(monkeypatch):
    resources = []
    stages = []
    fault = {"stage": None, "error": OwnerAbort("construction aborted"), "close_failure": None}
    forbidden = Mock(side_effect=AssertionError("cleanup must not write or flush"))

    def factory(name):
        def construct(*args, **kwargs):
            stages.append(name)
            if fault["stage"] == name:
                raise fault["error"]
            resource = SimpleNamespace(close=Mock(), write=forbidden, flush=forbidden, query=forbidden)
            if fault["close_failure"] == name:
                resource.close.side_effect = OwnerAbort("synthetic release failure")
            resources.append((name, resource))
            return resource

        return construct

    # Client3.__init__ itself is unpatched. Only its constructed dependencies are controlled.
    monkeypatch.setattr(dependency, "_InfluxDBClient", factory("http"))
    monkeypatch.setattr(dependency, "_WriteApi", factory("write"))
    monkeypatch.setattr(query_api, "FlightClient", factory("flight"))
    try:
        yield SimpleNamespace(resources=resources, stages=stages, fault=fault, forbidden=forbidden)
    finally:
        fault["error"].__traceback__ = None
        for _, resource in resources:
            resource.close.side_effect = None
        resources.clear()
        fault.clear()


@pytest.mark.parametrize("stage", ["http", "write", "query_options", "flight", "deadline"])
@pytest.mark.parametrize("error_type", [RuntimeError, OwnerAbort])
@pytest.mark.parametrize("close_failure", [None, "http", "write"])
def test_real_client3_partial_construction_releases_assigned_components(
    monkeypatch, components, stage, error_type, close_failure
):
    error = error_type("construction aborted")
    components.fault.update(stage=stage, error=error, close_failure=close_failure)
    partial_clients = []

    class ObservedClient(module.InfluxDBClient3):
        def __new__(cls, *args, **kwargs):
            client = object.__new__(cls)
            partial_clients.append(client)
            return client

    # Retain the otherwise unreturned object without replacing either initializer body.
    monkeypatch.setattr(module, "InfluxDBClient3", ObservedClient)
    if stage == "query_options":
        monkeypatch.setattr(dependency.QueryApiOptionsBuilder, "build", Mock(side_effect=error))
    if stage == "deadline":
        monkeypatch.setattr(module.InfluxDBWriter, "_compute_next_deadline", Mock(side_effect=error))
    writer = module.InfluxDBWriter.__new__(module.InfluxDBWriter)
    options = WriteOptionsConfig(batch_size=10, flush_interval=1000, jitter_interval=0, precision="ms")
    try:
        with pytest.raises(error_type) as caught:
            writer.__init__(config(), options, 375)
        assert caught.value is error
        expected = {
            "http": ["http"],
            "write": ["http", "write"],
            "query_options": ["http", "write"],
            "flight": ["http", "write", "flight"],
            "deadline": ["http", "write", "flight"],
        }
        assert components.stages == expected[stage]
        for _, resource in components.resources:
            resource.close.assert_called_once_with()
        assert len(partial_clients) == 1
        client = partial_clients[0]
        failures = client.release_failures
        for _ in range(2):
            if failures:
                with pytest.raises(module.ClientReleaseError):
                    client.close()
            else:
                client.close()
        assert all(getattr(client, slot, None) is None for slot in ("_client", "_write_api", "_query_api"))
        # A second owner release also covers the writer whose client never returned.
        with writer._lock:
            writer._release_client_locked()
            writer._release_client_locked()
        for _, resource in components.resources:
            resource.close.assert_called_once_with()
        components.forbidden.assert_not_called()
    finally:
        error.__traceback__ = None
        partial_clients.clear()


@pytest.mark.parametrize("close_failure", [None, "write", "flight", "http"])
def test_continuous_close_independently_releases_real_query_flight_and_http(components, close_failure):
    components.fault["close_failure"] = close_failure
    options = WriteOptionsConfig(batch_size=10, flush_interval=1000, jitter_interval=0, precision="ms")
    writer = module.InfluxDBWriter(config(), options, 375)
    assert isinstance(writer.client, dependency.InfluxDBClient3)
    assert isinstance(writer.client._query_api, query_api.QueryApi)
    assert writer.client._query_api._flight_client is components.resources[2][1]
    point = writer._build_point({"time": 4123, "uci": "synthetic", "packet_count": 3})
    writer._buffer.append(point)
    buffer = writer._buffer
    owner = ContinuousPipeline.__new__(ContinuousPipeline)
    owner.writers = {"network": writer}
    owner.native = owner.sparse = owner.mac = owner.proto = None
    try:
        if close_failure:
            with pytest.raises(module.ClientReleaseError) as caught:
                owner.close()
            assert str(caught.value) == "InfluxDB client release failed."
            assert caught.value.__cause__ is None
            assert caught.value.__context__ is None
        else:
            owner.close()
        for _, resource in components.resources:
            resource.close.assert_called_once_with()
        assert writer._buffer is buffer and writer._buffer == [point]
        assert writer._terminal_status is None
        assert writer._closed is False
        assert writer._released is True
        for _ in range(2):
            with writer._lock:
                writer._release_client_locked()
            if close_failure:
                with pytest.raises(module.ClientReleaseError):
                    owner.close()
            else:
                owner.close()
        for _, resource in components.resources:
            resource.close.assert_called_once_with()
        names = {"write": "write_api", "flight": "query_api", "http": "http_client"}
        assert writer.release_failures == (() if close_failure is None else (names[close_failure],))
        assert owner.release_failures == (() if close_failure is None else ("network." + names[close_failure],))
        components.forbidden.assert_not_called()
    finally:
        for _, resource in components.resources:
            resource.close.side_effect = None
        with writer._lock:
            writer._release_client_locked()
