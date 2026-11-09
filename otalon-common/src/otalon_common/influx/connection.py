"""Standardized InfluxDB v3 client creation."""

from urllib.parse import urlparse

from influxdb_client_3 import InfluxDBClient3


def create_influx_client(url: str, token: str, database: str) -> InfluxDBClient3:
    """Create an InfluxDBClient3 instance from a full URL.

    Parses the URL to extract host and port, then constructs the client
    with the correct parameters. This avoids requiring callers to manually
    split URLs into host/port components.

    Args:
        url: Full InfluxDB URL (e.g., ``"http://localhost:8181"``).
        token: Authentication token.
        database: Default database name.

    Returns:
        A configured InfluxDBClient3 instance.

    Raises:
        ValueError: When *url* is not an absolute ``http``/``https`` URL
            with a host. A scheme-less value such as ``"influxdb:8181"``
            parses with ``scheme='influxdb'`` and ``hostname=None``, which
            used to build the nonsense host ``"influxdb://None"`` and fail
            later as an opaque connection error far from the real cause
            (audit QUA-C7).
    """
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError(
            f"invalid InfluxDB URL {url!r}: expected an absolute URL such as "
            f"'http://influxdb3:8181' (got scheme={parsed.scheme!r}, "
            f"host={parsed.hostname!r})"
        )

    host = f"{parsed.scheme}://{parsed.hostname}"
    if parsed.port:
        host = f"{host}:{parsed.port}"

    return InfluxDBClient3(host=host, token=token, database=database, org="")
