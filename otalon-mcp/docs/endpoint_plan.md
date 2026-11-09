# OTALON-MCP Endpoint Plan

> Historical design document, retained for provenance. Its configuration and
> transport examples are not current deployment instructions. Use the root
> INSTALL.md and tool_reference.md, together with the shipped server/settings
> and config/config.json, for the active contract.

## Overview

The OTALON-MCP server exposes Model Context Protocol (MCP) tools that allow AI agents to inspect telemetry stored in OTALON data stores (InfluxDB v3 and PostgreSQL) and to manage anomaly life-cycle actions. The server shares configuration with the WebUI, reusing repository logic to avoid duplication.

## Configuration Sources

1. Environment variables (optionally loaded via `.env`)
2. `OTALON_CONFIG` override (absolute path)
3. Default fallback `../otalon-ui/config/config.json`

Required variables resolved from configuration or the environment:

- `POSTGRES_DSN`
- `INFLUX_URL`
- `INFLUX_TOKEN`

Optional overrides:

- `OTALON_INFLUX_DB`
- `OTALON_INFLUX_TOKEN`
- `OTALON_INFLUX_HOST`

## Transport

- Default MCP transport: stdio (FastMCP)
- Optional `--http` flag enables FastMCP HTTP transport

## Tool Portfolio

### Core & Health

| Tool name | Purpose | Response schema |
|-----------|---------|-----------------|
| `core.ping` | Connectivity check | `{ "ok": true, "message": "pong" }` |
| `core.capabilities` | Lists tool groups and environment metadata | `{ "ok": true, "groups": [...] }` |
| `core.health_check` | Validates InfluxDB and PostgreSQL connections | `{ "ok": bool, "postgres": {...}, "influx": {...} }` |

### PostgreSQL Data Access

| Tool | Parameters | Description |
|------|------------|-------------|
| `postgres.list_tables` | – | Returns public table names |
| `postgres.list_columns` | `table: str` | Returns ordered column names |
| `postgres.fetch_rows` | `table: str`, `columns: list[str] \| None`, `filters: list[FilterSpec] \| None`, `limit: int \| None`, `order_by: list[OrderSpec] \| None` | Parameterised read access; filters support `=`, `!=`, `<`, `<=`, `>`, `>=`, `in`, `like`, `ilike` |
| `postgres.bounds` | `module: str`, `series_id: str \| None`, `features: list[str] \| None` | Structured bounds output with expanded lower/upper limits |
| `postgres.anomalies` | `module: str`, `series_id: str \| None`, `metric: str \| None`, `start: str \| None`, `stop: str \| None`, `limit: int \| None` | Windowed anomaly queries |
| `postgres.anomaly_groups` | `module: str \| None`, `type: str \| None`, `confirmed: bool \| None`, `start: str \| None`, `stop: str \| None`, `limit: int \| None` | Aggregated alarm groups |
| `postgres.anomaly_group_details` | `alarm_id: str` | Single alarm record lookup |
| `postgres.set_anomaly_group_confirmed` | `alarm_id: str`, `confirmed: bool` | Updates confirmation status |
| `postgres.whitelisted_tables` | `allow_list: list[str] \| None` | Exposes repository whitelist helper for admin scenarios |

### InfluxDB Data Access

| Tool | Parameters | Description |
|------|------------|-------------|
| `influx.list_ids_recent` | `measurement: str`, `id_tag: str`, `minutes: int = 10` | Wrapper around `InfluxRepo.list_ids` |
| `influx.list_ids_between` | `measurement: str`, `id_tag: str`, `start: str`, `stop: str`, `nonzero: bool = false`, `fields: list[str] \| None`, `threshold: float \| None` | Historical ID discovery with optional non-zero check |
| `influx.query_timeseries` | `measurement: str`, `id_tag: str`, `fields: list[str]`, `start: str`, `stop: str`, `tags: dict[str, str \| int \| float \| bool] \| None`, `limit: int \| None`, `aggregate: str \| dict[str, str] \| None`, `sample_max_points: int \| None`, `preserve_extrema: bool = True` | Time-series query with aggregation support |
| `influx.query_timeseries_multi` | `measurement: str`, `id_tag: str`, `fields: list[str]`, `start: str`, `stop: str`, `ids: list[str]`, `limit: int \| None`, `initial_chunk_size: int = 5000` | Chunked multi-ID time-series query |

## Data Shapes

- Timestamps are returned as ISO-8601 strings.
- Data frames are converted to `{ "columns": [...], "rows": [[...]] }`.
- Numeric values remain native Python types.

## Validation & Safety

- Each tool group defines Pydantic models for input validation.
- Filters are translated into bound SQLAlchemy expressions; raw SQL fragments are rejected.
- Updates such as `set_anomaly_group_confirmed` enforce allow-lists and return affected row counts.

## Performance & Streaming

- Tools are synchronous; heavy queries should leverage limits or aggregation.
- Future work may introduce streaming once MCP transports support it.

## Observability

- Logging uses `loguru` with optional integration into the existing `log_perf_event` helper.
- Every tool invocation logs latency, row counts, and failures.
