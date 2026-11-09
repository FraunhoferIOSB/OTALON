# OTALON MCP Tool Reference

This document describes the MCP tools currently exposed by the unified OTALON MCP server. All tools return a result object that contains an `ok` flag plus a data payload. Tool parameters have meaningful defaults to reduce call verbosity.

Core Tools

- `core.ping()`
  - Reachability probe.
  - Returns: `{ "ok": true, "message": "pong" }`.

- `core.capabilities()`
  - Enumerates available tool groups and the active default configuration values used by other tools.
  - Returns:
    - `groups`: list of capability descriptors
    - `defaults`: `{ measurement, id_tag, fields }` used by Influx tools and sensible defaults for Postgres tools.

- `core.web_search_duckduckgo(query, max_results=6?)`
  - Performs a DuckDuckGo HTML search (no API key required).
  - Parameters:
    - `query`: Search term (string).
    - `max_results?` (int, default: 6, practical range: 1–25).
  - Returns: `{ "ok": true, "query": str, "results": [{ "title": str, "url": str, "snippet": str }, ...] }`.

PostgreSQL Tools

All PostgreSQL tools operate on the configured database and return either records or a record object. Defaults assume the `netcap` module when reasonable.

- `postgres.read_bounds(module="netcap", series_id?, features?)`
  - Retrieves trained bounds for the specified `module` and optional `series_id`. Expands stored lower/upper bounds into flat columns (`lb_*`, `ub_*`) plus metadata.
  - Parameters:
    - `module` (str, default: `"netcap"`)
    - `series_id?` (str)
    - `features?` (list[str], default: server defaults if omitted)
  - Returns: `{ "ok": true, "records": [...] }`.

- `postgres.read_anomalies(module="netcap", series_id?, metric?, start?, stop?, limit=100, default_window_minutes=1440)`
  - Reads anomalies filtered by `module`, optional `series_id`, optional `metric`, and optional time range.
  - Parameters:
    - `module` (str, default: `"netcap"`)
    - `series_id?` (str)
    - `metric?` (str)
    - `start?, stop?` (ISO-8601 UTC w/ trailing `Z`; if omitted, defaults to last 24h)
    - `limit` (int, default: `100`)
    - `default_window_minutes` (int, default: `1440`)
  - Returns: `{ "ok": true, "records": [...], "count": int }`.

- `postgres.read_alarms(module?, type_?, confirmed?, start?, stop?, limit=200, default_window_minutes=1440)`
  - Fetches aggregated alarm ("anomaly groups") records with optional filters and time range.
  - Parameters:
    - `module?` (str)
    - `type_?` (str)
    - `confirmed?` (bool)
    - `start?, stop?` (ISO-8601 UTC, defaults to last 24h if omitted)
    - `limit` (int, default: `200`)
    - `default_window_minutes` (int, default: `1440`)
  - Returns: `{ "ok": true, "records": [...], "count": int }`.

- `postgres.read_alarm_details(id)`
  - Reads details for a single alarm/group by ID.
  - Parameters:
    - `id` (str, required)
  - Returns: `{ "ok": true, "record": {...} }` or `{ "ok": false, "error": str }`.

- `postgres.read_recent_alarms(minutes=120, limit=50)`
  - Reads alarms from the last `minutes`.
  - Parameters:
    - `minutes` (int, default: `120`)
    - `limit` (int, default: `50`)
  - Returns: `{ "ok": true, "records": [...], "count": int }`.

- `postgres.get_top_alarm_counts(k=10, group_by="type", minutes=1440)`
  - Computes top-`k` alarm values and their counts over the last `minutes`.
  - Parameters:
    - `k` (int, default: `10`)
    - `group_by` (str, default: `"type"`)
    - `minutes` (int, default: `1440`)
  - Returns: `{ "ok": true, "rows": [(value, count), ...], "k": int, "total": int }`.

- `postgres.get_most_common_alarm(group_by="type", minutes=1440)`
  - Returns the most common alarm value over the last `minutes` plus top-5 counts.
  - Parameters:
    - `group_by` (str, default: `"type"`)
    - `minutes` (int, default: `1440`)
  - Returns:
    ```
    {
      "ok": true,
      "most_common": str,
      "count": int,
      "total": int,
      "top5": [(value, count), ...]
    }
    ```

InfluxDB Tools

All Influx tools use sensible defaults sourced from the server configuration (`measurement`, `id_tag`, `fields`). Timestamps use ISO-8601 UTC strings ending in `Z`.

- `influx.list_recent_time_series_ids(measurement?, id_tag?, minutes=10)`
  - Lists distinct series IDs observed in the last `minutes`.
  - Parameters:
    - `measurement?` (str, default: server default, e.g., `"network_metrics"`)
    - `id_tag?` (str, default: server default, e.g., `"uci"`)
    - `minutes` (int, default: `10`, range: `1..1440`)
  - Returns: `{ "ok": true, "ids": [...], "count": int }`.

- `influx.list_time_series(start?, stop?, measurement?, id_tag?, nonzero=false, fields?, threshold=0.0, default_window_minutes=60)`
  - Lists series IDs observed between `start` and `stop`. If `nonzero=true`, only IDs with aggregate sum of `fields` greater than `threshold` are returned.
  - Parameters:
    - `start?, stop?` (ISO-8601 UTC, defaults to last `default_window_minutes` if omitted)
    - `measurement?` (str, default: server default)
    - `id_tag?` (str, default: server default)
    - `nonzero` (bool, default: `false`)
    - `fields?` (list[str], default: server defaults if omitted)
    - `threshold` (float, default: `0.0`)
    - `default_window_minutes` (int, default: `60`)
  - Returns: `{ "ok": true, "ids": [...], "count": int, "start": str, "stop": str }`.

- `influx.read_single_time_series(series_id, fields?, start?, stop?, measurement?, id_tag?, tags?, limit?, aggregate="avg"?, sample_max_points=1000?, preserve_extrema=true?, default_window_minutes=60)`
  - Reads a single time series for the given `series_id`. Ensures `id_tag` filter matches `series_id` when not provided via `tags`.
  - Parameters:
    - `series_id` (str, required)
    - `fields?` (list[str], default: server defaults)
    - `start?, stop?` (ISO-8601 UTC, defaults to last `default_window_minutes`)
    - `measurement?` (str, default: server default)
    - `id_tag?` (str, default: server default)
    - `tags?` (dict, optional additional tag filters)
    - `limit?` (int)
    - `aggregate?` (str or dict, default: `"avg"`)
    - `sample_max_points?` (int, default: `1000`)
    - `preserve_extrema?` (bool, default: `true`)
    - `default_window_minutes` (int, default: `60`)
  - Returns: `{ "ok": true, "series_id": str, "data": { "columns": [...], "rows": [...], "rowcount": int } }`.

- `influx.read_multiple_time_series(ids?, fields?, start?, stop?, measurement?, id_tag?, limit?, initial_chunk_size=5000, default_recent_minutes=10, default_window_minutes=60, fallback_k=5)`
  - Reads multiple time series for `ids`. If `ids` omitted, uses top-`k` recent IDs as fallback.
  - Parameters:
    - `ids?` (list[str], default: fallback recent IDs)
    - `fields?` (list[str], default: server defaults)
    - `start?, stop?` (ISO-8601 UTC, defaults to last `default_window_minutes`)
    - `measurement?` (str, default: server default)
    - `id_tag?` (str, default: server default)
    - `limit?` (int)
    - `initial_chunk_size` (int, default: `5000`)
    - `default_recent_minutes` (int, default: `10`)
    - `default_window_minutes` (int, default: `60`)
    - `fallback_k` (int, default: `5`)
  - Returns: `{ "ok": true, "ids": [...], "data": { "columns": [...], "rows": [...], "rowcount": int } }`.

MITRE ICS ATT&CK Tools

The `mitre.*` tools provide access to the MITRE ICS ATT&CK knowledge base. Data is loaded from a STIX 2.1 bundle sourced from the [mitre-attack/attack-stix-data](https://github.com/mitre-attack/attack-stix-data) repository. The bundle path is configured via `mitre.stix_bundle_path` in `config/config.json` (default: `data/ics-attack.json`). The dataset can be updated at runtime using `mitre.update_stix_data` or offline via `scripts/update_mitre_stix.py`.

- `mitre.list_tactics()`
  - Lists all ICS ATT&CK tactics with associated technique counts.
  - Returns: `[{ "tactic": str, "technique_count": int }, ...]`.

- `mitre.list_techniques(tactic?, limit?)`
  - Lists techniques, optionally filtered by tactic name and limited by count.
  - Parameters:
    - `tactic?` (str, case-insensitive tactic name, e.g., `"initial-access"`)
    - `limit?` (int, max results)
  - Returns: `[{ "external_id": str, "name": str, "tactics": [...], "url": str, "is_subtechnique": bool }, ...]`.

- `mitre.get_technique_by_id(external_id)`
  - Retrieves full details for a technique by its MITRE external ID.
  - Parameters:
    - `external_id` (str, required, e.g., `"T0829"`)
  - Returns: `{ "ok": true, "external_id": str, "name": str, "description": str, "tactics": [...], "url": str, ... }` or `{ "ok": false, "error": str }`.

- `mitre.get_techniques_by_tactic(tactic, limit?)`
  - Returns all techniques mapped to a given tactic.
  - Parameters:
    - `tactic` (str, required, e.g., `"lateral-movement"`)
    - `limit?` (int, max results)
  - Returns: `{ "ok": true, "tactic": str, "count": int, "techniques": [...] }`.

- `mitre.search_techniques(query, limit=10)`
  - Full-text search across technique names and descriptions (case-insensitive).
  - Parameters:
    - `query` (str, required)
    - `limit` (int, default: `10`)
  - Returns: `{ "ok": true, "query": str, "count": int, "techniques": [...] }`.

- `mitre.get_subtechniques(parent_external_id)`
  - Lists sub-techniques of a parent technique.
  - Parameters:
    - `parent_external_id` (str, required, e.g., `"T0803"`)
  - Returns: `{ "ok": true, "parent": str, "count": int, "subtechniques": [...] }`.

- `mitre.stats()`
  - Returns dataset statistics including technique/tactic counts and MITRE version metadata.
  - Returns: `{ "ok": true, "total_techniques": int, "total_subtechniques": int, "tactic_count": int, "tactics": [...], "version": {...}, "source": {...} }`.

- `mitre.ping()`
  - Health check for the MITRE ICS tools.
  - Returns: `"pong"`.

- `mitre.update_stix_data()`
  - Downloads the latest ICS ATT&CK STIX bundle from GitHub (`mitre-attack/attack-stix-data`) and reloads the in-memory index. Creates a backup of the previous bundle and writes version metadata to `data/mitre_version.json`.
  - Returns: `{ "ok": true, "tag": str, "source_url": str, "previous_count": int, "new_count": int, "backup_path": str, "version_file": str }` or `{ "ok": false, "error": str }`.

Baseline Tools

The baseline tools expose a curated "quiet traffic" reference window. They are used by the `otalon-agent` subagent worker to ground its classifications against known-good behaviour. Baselines are managed via the `otalon-api` baselines endpoints; see `documentation/baselines.md` for the full lifecycle. All five tools resolve the active baseline when `baseline_id` is omitted.

- `influx.list_baseline_time_series(baseline_id?, start?, stop?)`
  - Lists distinct UCIs (`series_ids`) observed in the baseline window. Optional `start`/`stop` clamp to a sub-range; if omitted, the baseline's full `[start_ts, end_ts]` is used.
  - Returns: `{ "ok": true, "baseline_id": str, "start": iso8601, "stop": iso8601, "series_ids": [str, ...], "count": int }`.

- `influx.get_baseline_single_time_series(series_id, baseline_id?, chunk_filename?, fields?, aggregation?)`
  - Reads one UCI for a single 30 s baseline PCAP-chunk window. If `chunk_filename` is omitted, a random chunk is picked. The 30 s window is derived from the chunk's filename (`YYYYMMDD_HHMMSS.pcap`).
  - Returns: `{ "ok": true, "baseline_id": str, "chunk_filename": str, "start": iso8601, "stop": iso8601, "series_id": str, "table": { columns, rows, rowcount } }`.

- `influx.get_baseline_multiple_time_series(series_ids, baseline_id?, chunk_filename?, fields?, aggregation?)`
  - Reads multiple UCIs for one baseline PCAP-chunk window (otherwise same as the single-series variant).
  - Returns: `{ "ok": true, "baseline_id": str, "chunk_filename": str, "start": iso8601, "stop": iso8601, "tables": { "<series_id>": { columns, rows, rowcount }, ... } }`.

- `pcap.list_baseline_chunks(baseline_id?, start_ts?, end_ts?, last_minutes?, last_hours?, last_chunks?, limit=200)`
  - Lists baseline PCAP chunks with optional filters. Relative filters (`last_minutes`, `last_hours`, `last_chunks`) anchor to the baseline's `end_ts`, not wall-clock now.
  - Returns: `{ "ok": true, "baseline_id": str, "chunks": [{ filename, start_ts, size_bytes, is_anomaly, labels }, ...], "count": int }`.

- `pcap.get_baseline_chunks(baseline_id?, limit=5)`
  - Returns up to `limit` randomly sampled baseline chunks. Useful when the LLM wants representative PCAP samples without a specific time anchor.
  - Returns: `{ "ok": true, "baseline_id": str, "chunks": [...], "count": int }`.

Agent Proxy Tools

The agent-proxy tools allow chat agents to trigger and observe
`otalon-ai` subagent classifications without blocking the chat
loop. All three forward HTTP calls to `otalon-ai` (`AI_URL`, default
`http://otalon-ai:9100`; falls back to the legacy `AGENT_URL` env
during the transition). Since Phase 9 of
`replace-n8n-chat-orchestration` the jobs surface of `otalon-ai`
is backed exclusively by the LiteLLM proxy.

- `agent.classify_alert(alarm_id, prompt_variant="expert", llm_provider?, llm_model?, baseline_id?, timeout_seconds=600)`
  - Triggers an independent zero-shot LLM classification of the given alarm. **Returns immediately** with a `job_id`; the heavy lifting happens asynchronously inside `otalon-ai`. The chat agent should embed `[subagent-job:<uuid>]` in its reply so the UI's chat overlay renders the inline live trace card.
  - Parameters:
    - `alarm_id` (str): live `alarms.id` (typically from `ui_context.alarm.id`).
    - `prompt_variant` (str, default: `"expert"`): `"expert"` (paper Prompt E, 89% S2-Eff) or `"open"` (Prompt C).
    - `llm_provider?` (str): **Legacy/optional.** Forwarded verbatim on the request body for payload backward-compat with older callers. Since Phase 9 of `replace-n8n-chat-orchestration` the service no longer dispatches between Azure / OpenAI-compat / LiteLLM on this value — every job runs through the LiteLLM proxy regardless. New callers should leave this unset.
    - `llm_model?` (str): a **LiteLLM model identifier** (e.g. `litellm/gpt-5.4`, `litellm/claude-opus-4-7`, `litellm/gpt-5.5-2`). Default: `otalon-ai` config (`JOBS_LLM_MODEL` env).
    - `baseline_id?` (uuid): use a specific baseline; default: active baseline.
    - `timeout_seconds` (int, default: `600`): per-job worker timeout.
  - Returns (success): `{ "ok": true, "job_id": str, "status": "pending", "eta_seconds": int, "events_url": str, "hint": "Embed [subagent-job:<uuid>] in your reply ..." }`.
  - Returns (failure, agent unreachable): `{ "ok": false, "error": str, "detail": str }`.

- `agent.get_classification_status(job_id)`
  - Fetches the current status and (if available) partial or final results of a subagent job.
  - Returns: full job record incl. `status, prompt_variant, llm_provider, llm_model, baseline_id, started_at, finished_at, duration_seconds, step1_technical, step2_classification, tool_trace, tokens_prompt, tokens_completion, error_message`. If `tool_trace` exceeds 30 entries, it is truncated to the last 10 with `tool_trace_truncated: true` and `tool_trace_total: int` to protect chat context. The full trace is always available via the UI.

- `agent.list_classifications_for_alert(alarm_id, limit=10)`
  - Returns a summary list of recent subagent jobs for one alarm. Useful when the user asks "what did the subagent say about this alarm previously".
  - Returns: `{ "ok": true, "jobs": [{ job_id, status, prompt_variant, started_at, finished_at, duration_seconds, step2_classification_summary }, ...], "count": int }`.

## Defaults & Configuration

- Defaults used by tools:
  - `measurement`: `"network_metrics"` (override via `OTALON_INFLUX_MEASUREMENT`)
  - `id_tag`: `"uci"` (override via `OTALON_INFLUX_ID_TAG`)
  - `fields`: default list of core netcap metrics (override via `OTALON_INFLUX_FIELDS`, JSON array or CSV)

- Server configuration is loaded from:
  - `otalon-mcp/config/config.json`
    ```
    {
      "server": {
"name": "otalon-mcp",
        "host": "0.0.0.0",
        "port": 9000,
        "transport": "streamable-http"   // or "stdio"
      },
      "postgres": {
        "dsn": "$POSTGRES_DSN"
      },
      "influx": {
        "url": "$INFLUX_URL",
        "token": "$INFLUX_TOKEN"
      },
      "logging": {
        "level": "DEBUG",
        "file": "$OTALON_UI_LOG_FILE"
      },
      "mitre": {
        "stix_bundle_path": "data/ics-attack.json"
      }
    }
    ```
  - Environment variables referenced in config (prefixed with `$`) must be set prior to server start.

- Influx database resolution:
  - Uses `OTALON_INFLUX_DB` or `INFLUX_DATABASE`, defaulting to `netcap`.

## Transport

- Default transport: `"streamable-http"`
- Alternative: `"stdio"`
- Controlled via `server.transport` in `config.json`.

## Return Formats

- Table payloads:
  ```
  {
    "columns": [...],
    "rows": [...],
    "rowcount": int
  }
  ```
- Record lists:
  ```
  {
    "ok": true,
    "records": [ { ... }, ... ],
    "count": int // when applicable
  }
  ```
- Error payloads:
  ```
  { "ok": false, "error": "message" }
  ```

## Quick Notes

- Timestamps must be ISO-8601 UTC strings with trailing `Z` (e.g., `"2025-01-01T10:00:00Z"`).
- When `start` and `stop` are omitted, tools use sensible default windows (60 minutes for Influx reads, 1440 minutes for Postgres anomaly/alarms).
- Aggregation options for `influx.read_single_time_series`:
  - `"avg"`, `"min"`, `"max"`, `"sum"`, etc., or a per-field mapping `{ "fieldA": "avg", "fieldB": "sum" }`.
- The server applies log rotation (10 MB) and logs to both file and stdout as configured.
