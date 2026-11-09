/**
 * TypeScript type definitions for OTALON API responses.
 *
 * These interfaces mirror the backend Pydantic schemas exactly,
 * preserving snake_case field names and nullable semantics.
 * Use these types for all API integration; UI components should
 * map to the golden-data types where presentation differs.
 */

// =============================================================================
// Generic API Envelope
// =============================================================================

/**
 * Generic envelope for paginated list responses returned by the backend.
 * Most list endpoints wrap their payload in this structure.
 *
 * @typeParam T - The type of each item in the `data` array.
 */
export interface ApiEnvelope<T> {
  data: T[]
  row_count: number
  parameters: Record<string, unknown>
}

// =============================================================================
// Dashboard KPIs
// =============================================================================

/**
 * Single entry in the top connections ranking.
 * Mirrors `TopConnectionItem` Pydantic model on the backend.
 */
export interface TopConnectionItem {
  uci: string
  packet_count: number
  byte_count: number
  is_anomaly: boolean
  sparkline?: number[]
}

/**
 * Single KPI snapshot matching `DashboardKpisData` on the backend.
 * Provides the traffic-light signal color and aggregate counts.
 */
export interface DashboardKpisData {
  signal_color: string
  anomaly_count: number
  classified_count: number
  device_count: number
  protocol_count: number
  connection_count: number
  top_connections: TopConnectionItem[]
}

/**
 * Response wrapper for the dashboard KPIs endpoint.
 * Mirrors `DashboardKpisResponse` Pydantic model.
 */
export type DashboardKpisResponse = ApiEnvelope<DashboardKpisData>

/**
 * Dashboard vulnerability summary data.
 * Mirrors `VulnerabilitySummaryData` Pydantic model on the backend.
 */
export interface VulnerabilitySummaryData {
  affected_device_count: number
  total_cve_count: number
  severity_breakdown: Record<string, number>
  top_cves: Array<{
    vuln_id: string
    severity: string
    count: number
  }>
}

/**
 * Single entry in the top assets (MAC) ranking.
 * Mirrors `TopAssetItem` Pydantic model on the backend.
 */
export interface TopAssetItem {
  id: string
  packet_count: number
  byte_count: number
  is_anomaly: boolean
  sparkline?: number[]
}

/**
 * Response from `GET /api/v1/dashboard/top-assets`.
 * Returns ranked MAC addresses with traffic metrics and sparklines.
 */
export type TopAssetsResponse = ApiEnvelope<TopAssetItem>

/**
 * Single entry in the top protocols ranking.
 * Mirrors `TopProtocolItem` Pydantic model on the backend.
 */
export interface TopProtocolItem {
  id: string
  protocol: string
  packet_count: number
  byte_count: number
  is_anomaly: boolean
  sparkline?: number[]
}

/**
 * Response from `GET /api/v1/dashboard/top-protocols`.
 * Returns ranked protocol stacks with traffic metrics and sparklines.
 */
export type TopProtocolsResponse = ApiEnvelope<TopProtocolItem>

// =============================================================================
// Anomaly Groups
// =============================================================================

/**
 * Normalization reference values used when computing anomaly scores.
 * Mirrors `NormRefs` Pydantic model.
 */
export interface NormRefs {
  packet_rate_ref: number
  byte_rate_ref: number
  coverage_ref: number
  count_ref: number
}

/**
 * Weight parameters for the anomaly scoring formula.
 * Mirrors `Weights` Pydantic model.
 */
export interface Weights {
  w_rate: number
  w_cov: number
  w_persist: number
  w_pr: number
  w_br: number
  gamma: number
}

/**
 * Detailed statistics for a single anomaly type within a group.
 * Mirrors `AnomalyTypeStatDetail` Pydantic model.
 */
export interface AnomalyTypeStatDetail {
  interval_count: number
  count: number
  confidence_sum: number | null
  confidence_max: number | null
  confidence_min: number | null
  confidence_mean: number
  packet_rate_sum: number | null
  byte_rate_sum: number | null
  rate_count: number | null
  protocol_penalty_sum: number | null
  protocol_penalty_count: number | null
  severity_mean_sum: number | null
  severity_max_sum: number | null
  severity_count: number | null
  packet_rate_mean: number | null
  byte_rate_mean: number | null
  type_series_count: number | null
  severity_mean: number | null
  severity_max: number | null
  protocol_penalty_mean: number | null
  traffic_n: number | null
  coverage_n: number | null
  count_n: number | null
  conf_factor: number | null
  score_raw: number | null
  score: number | null
  norm_refs: NormRefs | null
  weights: Weights | null
  score_norm: number
}

/**
 * A single anomaly group as returned by the backend.
 * Mirrors `AnomalyGroupItem` Pydantic model.
 *
 * Note: `primary_type` is always `string` from the API.
 * The golden-data `RealAlarmGroup` uses `string | string[]`
 * for UI flexibility; mapping should happen at the adapter layer.
 */
export interface AnomalyGroupItem {
  id: string
  module: string
  start_timestamp: string
  end_timestamp: string
  primary_type: string | string[]
  multi_type: boolean
  confirmed: boolean
  is_active: boolean
  series_ids: string[]
  /** Index-parallel with series_ids; null marks non-protocol entries. */
  protocols?: (string | null)[] | null
  anomaly_type_stats: Record<string, AnomalyTypeStatDetail>
  enrichment?: Record<string, unknown> | null
  /** Features reported by anomaly records or bound review for this group. */
  affected_features?: string[]
  affected_feature_state?: 'BoundViolation' | 'NoBounds'
}

/**
 * Response wrapper for the anomaly groups endpoint.
 * Mirrors `AnomalyGroupsResponse` Pydantic model.
 */
export type AnomalyGroupsResponse = ApiEnvelope<AnomalyGroupItem>

// =============================================================================
// Health Checks
// =============================================================================

/**
 * Status of a single monitored service.
 * Mirrors `HealthCheckItem` Pydantic model.
 */
export interface HealthCheckItem {
  name: string
  running: boolean
  in_budget?: boolean
  detail: string
  timestamp: number
  classification?: 'core' | 'optional'
  /**
   * Explicit service status distinct from `running`. `not-configured` and
   * `disabled` are truthful non-failure states for optional components and
   * MUST NOT be rendered as `failed`.
   */
  status?: 'healthy' | 'failed' | 'not-configured' | 'disabled'
}

/**
 * Aggregate health response for all monitored services.
 * Mirrors `HealthResponse` Pydantic model.
 */
export interface HealthResponse {
  services: HealthCheckItem[]
  overall_status: string
  caches?: Record<string, Record<string, unknown>>
  active_incidents?: HealthIncidentSummary[]
  recent_incidents?: HealthIncidentSummary[]
  unacknowledged_incidents?: HealthIncidentSummary[]
}

export type HealthIncidentStatus = 'active' | 'recovered'

export interface HealthIncidentSample {
  service: string
  owning_service?: string
  probe_target?: string
  running: boolean
  category: string
  cause: string
  latency_ms: number
  latency_budget_ms: number
  timestamp: string | number | null
  detail: string
}

export interface HealthIncidentSummary {
  id: string
  service: string
  owning_service?: string
  probe_target?: string
  system_service_id?: string | null
  category: string
  cause: string
  status: HealthIncidentStatus
  first_seen: string
  last_seen: string
  recovered_at: string | null
  sample_count: number
  failure_count: number
  latency_budget_ms: number
  worst_latency_ms: number
  acknowledged?: boolean
  acknowledged_at?: string | null
  acknowledged_by?: string | null
  evidence_type: 'operational_health'
  samples?: HealthIncidentSample[]
}

export interface HealthIncidentListResponse {
  items: HealthIncidentSummary[]
  retention: { max_incidents: number; max_days: number }
}

export interface DetectionReadinessItem {
  module: string
  state: string
  detection_mode: string
  bounds_series_count: number
  no_bounds_count: number
  no_bounds_event_count?: number
  no_bounds_series_count?: number
  frequency_profile_count: number
  last_training: string | null
  schema_version: string
  schema_compatible: boolean
  classification_state?: string
  bounds_state?: string
  frequency_state?: string
}

export interface DetectionReadinessResponse {
  modules: DetectionReadinessItem[]
  live_poll_interval_seconds?: number
}

export interface OperationsStorageResponse {
  host: {
    unit: string
    mounts: Record<string, { total_gb: number; used_gb: number; free_gb: number; used_pct: number; fs: string }>
  }
  ringbuffer: {
    size_gb: number
    cap_gb: number
    files: number
    file_cap: number
    state: string
  }
  contributors: Array<{
    name: string
    size_gb: number
    oldest: string | null
    newest: string | null
    note: string
  }>
  unattributed_gb: number
}

// =============================================================================
// Operations (UI-075)
// =============================================================================

/**
 * Pipeline freshness state for a single source.
 * Mirrors `PipelineSource` Pydantic model.
 */
export interface PipelineSource {
  name: 'conn' | 'mac' | 'proto'
  last_record: string | null
  age_seconds: number | null
  state: 'current' | 'stale' | 'no-data'
  records_per_hour: number
  expected_interval_seconds: number
}

/**
 * Aggregate InfluxDB write freshness.
 * Mirrors `PipelineInflux` Pydantic model.
 */
export interface PipelineInflux {
  last_write: string | null
  age_seconds: number | null
}

/**
 * Detection-cycle freshness metadata.
 * Mirrors `PipelineDetection` Pydantic model.
 */
export interface PipelineDetection {
  last_cycle: string | null
  age_seconds: number | null
  duration_seconds: number | null
  series_evaluated: number | null
}

/**
 * Response from `GET /api/v1/operations/pipeline`.
 * Mirrors `PipelineResponse` Pydantic model.
 */
export interface PipelineResponse {
  sources: PipelineSource[]
  influx: PipelineInflux
  detection: PipelineDetection
  backlog: number | null
}

/**
 * Navigation target for an attention finding.
 * Mirrors `AttentionFindingLink` Pydantic model.
 */
export interface AttentionFindingLink {
  label: string
  route: string
}

/**
 * Single ranked operational attention finding.
 * Mirrors `AttentionFinding` Pydantic model.
 */
export interface AttentionFinding {
  priority: 'High' | 'Medium' | 'Low'
  kind: string
  title: string
  link: AttentionFindingLink
}

/**
 * Response from `GET /api/v1/operations/attention`.
 * Mirrors `AttentionResponse` Pydantic model.
 */
export interface AttentionResponse {
  findings: AttentionFinding[]
}

/**
 * Response from `GET /api/v1/operations/capture-status`.
 * Mirrors `CaptureStatus` Pydantic model.
 */
export interface CaptureStatus {
  interface: string | null
  link_up: boolean | null
  recording: boolean | null
  drops_24h_pct: number | null
  overflows: number | null
}

/**
 * Response from `GET /api/v1/operations/passive-discovery`.
 * Mirrors the `PassiveDiscoveryStatus` Pydantic model.
 *
 * Read-only producer truth derived from persisted `network_interfaces`
 * rows tagged `source='passive'`. `runtime_control_enabled` reports whether
 * the runtime control plane is reachable; the controls themselves live on
 * Operations → Configuration → Runtime.
 */
export interface PassiveDiscoveryStatus {
  observed_asset_count: number
  observed_interface_count: number
  latest_seen_at: string | null
  first_seen_at: string | null
  age_seconds: number | null
  freshness: 'current' | 'stale' | 'no-data'
  runtime_control_enabled: boolean
}

// =============================================================================
// Runtime configuration & passive-seeder status (UI-015)
// =============================================================================

/**
 * Declared value type of a runtime configuration key.
 *
 * Mirrors the `type` field of the `RuntimeConfigItem` Pydantic model, which
 * is sourced from the shared runtime-key registry. `list` keys (e.g. the
 * CLAS-071 series blacklist) transport the value as the canonical JSON
 * serialization of a string array.
 */
export type RuntimeConfigValueType = 'bool' | 'int' | 'float' | 'str' | 'list'

/**
 * One runtime configuration key as returned by
 * `GET /api/v1/operations/configuration/runtime`.
 *
 * Mirrors the `RuntimeConfigItem` Pydantic model. The response is
 * manifest-complete: keys without a persisted `runtime_config` row are still
 * listed, carrying their boot-derived value with `updated_at` / `updated_by`
 * / `value_prev` all `null`.
 *
 * `value` is always transported as a string regardless of `type`; callers
 * coerce using `type`. `domain` is a human-readable interval such as
 * `"[10, 3600]"` and is a display hint only — the server validates
 * authoritatively.
 */
export interface RuntimeConfigItem {
  service: string
  key: string
  value: string
  value_prev: string | null
  updated_at: string | null
  updated_by: string | null
  type: RuntimeConfigValueType
  domain: string | null
  description: string
}

/**
 * Response from `GET /api/v1/operations/configuration/runtime`.
 */
export interface RuntimeConfigResponse {
  items: RuntimeConfigItem[]
}

/**
 * Request body for `PUT /api/v1/operations/configuration/runtime`.
 *
 * Writes exactly one key. `reason` is optional and, when present, is
 * recorded verbatim on the audit row.
 */
export interface RuntimeConfigWrite {
  service: string
  key: string
  value: string
  reason?: string
}

/**
 * Response from `PUT /api/v1/operations/configuration/runtime`.
 *
 * Mirrors the `RuntimeConfigApplyResponse` Pydantic model: the refreshed
 * manifest-complete collection plus write metadata. `restart_required` is
 * always `false` for runtime keys — they are picked up within one poll
 * cycle of the owning service, which is the entire point of this surface
 * versus the boot-configuration tab.
 */
export interface RuntimeConfigApplyResponse extends RuntimeConfigResponse {
  changed_keys: string[]
  restart_required: boolean
}

/**
 * Operational state of the passive seeder.
 *
 * - `running` — the seeder is enabled and completing cycles.
 * - `disabled` — the seeder is up but idling because `enabled` is false.
 * - `error` — the last cycle failed; see `last_error`.
 * - `unknown` — no status row exists yet (the seeder has never reported).
 */
export type PassiveSeederState = 'running' | 'disabled' | 'error' | 'unknown'

/**
 * Response from `GET /api/v1/operations/passive-seeder/status`.
 *
 * Mirrors the `PassiveSeederStatusResponse` Pydantic model.
 *
 * Field semantics that are easy to get wrong:
 * - `rows_seeded` counts the rows written by the **last** cycle only. It is
 *   not a cumulative total.
 * - `last_error` is reset to `null` by the next clean cycle, so its absence
 *   means the most recent cycle was clean — not that no error ever occurred.
 * - state `unknown` means no row exists yet; it must not be presented as
 *   `disabled`.
 */
export interface PassiveSeederStatus {
  service: string
  state: PassiveSeederState
  last_cycle_at: string | null
  last_error: string | null
  rows_seeded: number
  poll_interval_s: number | null
  updated_at: string | null
}

// =============================================================================
// Operations Jobs & Change Audit (UI-075 Wave B)
// =============================================================================

/**
 * Canonical operations job lifecycle state.
 */
export type OperationsJobState = 'queued' | 'running' | 'cancelling' | 'completed' | 'failed' | 'cancelled'

/**
 * Canonical operations job type.
 */
export type OperationsJobType = 'training' | 'ingest' | 'backup' | 'service' | 'maintenance'

/**
 * Single operations job returned by `GET /api/v1/operations/jobs/{id}`.
 */
export interface OperationsJob {
  id: number
  display_id: string
  type: OperationsJobType
  title: string
  state: OperationsJobState
  trigger: string
  actor: string | null
  started_at: string
  ended_at: string | null
  phase_current: number | null
  phase_total: number | null
  phase_label: string | null
  latest_event: string | null
  params: Record<string, unknown>
  log: unknown[]
  error: string | null
  result: string | null
  can_cancel: boolean
  can_retry: boolean
  retried_as_id: number | null
}

/**
 * Compact job row from `GET /api/v1/operations/jobs`.
 */
export interface OperationsJobSummary {
  id: number
  display_id: string
  type: OperationsJobType
  title: string
  state: OperationsJobState
  trigger: string
  actor: string | null
  started_at: string
  ended_at: string | null
  latest_event: string | null
  can_cancel: boolean
  can_retry: boolean
}

/**
 * Response from `GET /api/v1/operations/jobs`.
 */
export interface OperationsJobsResponse {
  items: OperationsJobSummary[]
  total: number
}

/**
 * Response from `POST /api/v1/operations/jobs/{id}/cancel` or `/retry`.
 */
export interface OperationsJobActionResponse {
  success: boolean
  job: OperationsJob | null
  message: string | null
}

/**
 * Change Audit category.
 */
export type OperationsAuditCategory = 'config' | 'bounds' | 'reset' | 'service' | 'job' | 'access'

/**
 * Single Change Audit row.
 */
export interface OperationsAuditEntry {
  id: number
  at: string
  category: OperationsAuditCategory
  actor: string
  action: string
  target: string
  reason: string | null
  detail: string | null
}

/**
 * Response from `GET /api/v1/operations/audit`.
 */
export interface OperationsAuditResponse {
  items: OperationsAuditEntry[]
  total: number
}

// =============================================================================
// Group Entities (Detail Panel)
// =============================================================================

/**
 * Network entity associated with an anomaly group.
 * Mirrors `NetcapEntityItem` Pydantic model.
 */
interface _NetcapEntityItem {
  source_mac: string
  destination_mac: string
  source_ip: string
  destination_ip: string
  source_port: string
  destination_port: string
  vlan: string
  ip_proto: string
  protocols: string
  uci: string
}

/**
 * Response wrapper for the group entities endpoint.
 * Mirrors `GroupEntitiesResponse` Pydantic model.
 *
 * Note: The backend returns `list[dict[str, Any]]` for `data`,
 * so items are typed as `Record<string, unknown>`. Consumers
 * that know the shape can cast to `NetcapEntityItem`.
 */
type _GroupEntitiesResponse = ApiEnvelope<Record<string, unknown>>

// =============================================================================
// Request Types
// =============================================================================

/**
 * Request body for PATCH /groups/:id to update group confirmation.
 * Mirrors `UpdateGroupRequest` Pydantic model.
 */
export interface UpdateGroupRequest {
  confirmed: boolean
}

/**
 * Client-side filter parameters for querying alarm groups.
 */
export interface AlarmFilter {
  module?: string
  status?: 'active' | 'confirmed' | 'all'
  limit?: number
}

// =============================================================================
// SSE Event Types
// =============================================================================

/**
 * Server-Sent Event payload for real-time KPI updates.
 */
export interface SseKpiEvent {
  event: 'kpi'
  data: DashboardKpisData
}

/**
 * Server-Sent Event payload for real-time anomaly group updates.
 */
export interface SseAnomalyEvent {
  event: 'anomaly'
  data: AnomalyGroupItem
}

/**
 * Server-Sent Event payload for real-time health status updates.
 */
export interface SseHealthEvent {
  event: 'health'
  data: HealthResponse
}

/**
 * Union of all possible SSE event types for discriminated matching.
 */
type _SseEvent = SseKpiEvent | SseAnomalyEvent | SseHealthEvent

// =============================================================================
// Convenience Type Aliases
// =============================================================================

/** Alias for `AnomalyGroupItem` used in alarm-related UI code. */
type _ApiAlarmGroup = AnomalyGroupItem

/** Alias for `AnomalyTypeStatDetail` used in alarm-related UI code. */
type _ApiAnomalyTypeStat = AnomalyTypeStatDetail

/** Alias for `HealthCheckItem` used in health-related UI code. */
type _ApiHealthService = HealthCheckItem

/** Alias for `DashboardKpisData` used in dashboard UI code. */
type _ApiKpiData = DashboardKpisData

// =============================================================================
// Dashboard Throughput
// =============================================================================

/**
 * Single data point in the network throughput time series.
 * Mirrors `ThroughputDataPoint` Pydantic model on the backend.
 */
export interface ThroughputDataPoint {
  timestamp: string
  total_bytes: number
  total_packets: number
}

/**
 * Response from `GET /api/v1/dashboard/throughput`.
 * Returns aggregated network throughput bucketed over time.
 */
export interface ThroughputResponse {
  data: ThroughputDataPoint[]
  bucket_seconds: number
  parameters: Record<string, unknown>
}

// =============================================================================
// Timeseries API
// =============================================================================

/**
 * Response from `GET /api/v1/timeseries/data` and `GET /api/v1/timeseries/plot`.
 * Returns time-series rows for a single UCI within the requested time window.
 */
interface _TimeseriesResponse {
  uci: string
  start: string
  stop: string
  features: string[]
  bucket_seconds: number | null
  row_count: number
  data: Record<string, unknown>[]
}

/**
 * Single item in the IDs response.
 * When `group_wildcards=true` is requested, `is_wildcard` and
 * `member_count` indicate whether the UCI is a wildcard group.
 */
export interface IdsResponseItem {
  uci: string
  is_wildcard: boolean
  member_count: number
  collapsed_port_count?: number | null
  rule_trained?: boolean
  profiled?: boolean
}

/**
 * Response from `GET /api/v1/timeseries/ids`.
 * Lists available UCI identifiers with optional nonzero filtering
 * and optional wildcard grouping.
 */
export interface IdsResponse {
  start: string
  stop: string
  nonzero: boolean
  count: number
  data: IdsResponseItem[]
}

/**
 * Response from `GET /api/v1/timeseries/features`.
 * Returns the list of available feature column names.
 */
export interface FeaturesResponse {
  features: string[]
}

/**
 * A base-key sibling UCI that has non-zero data in the queried window.
 * Shares all 7 base-key fields with the selected UCI but differs in port.
 */
export interface SiblingItem {
  uci: string
  src_port: string
  dst_port: string
}

/**
 * Response from `GET /api/v1/timeseries/siblings`.
 *
 * Used by the connections page empty-metrics branch to distinguish a
 * rotating-port connection (`has_active_sibling=true`) from a genuinely
 * inactive one.
 */
export interface SiblingsResponse {
  uci: string
  start: string
  stop: string
  has_active_sibling: boolean
  count: number
  siblings: SiblingItem[]
}

// =============================================================================
// Source-specific Timeseries API (MAC / Proto)
// =============================================================================

/**
 * Single entry in a source-specific IDs response (MAC or Proto).
 */
export interface SourceIdsResponseItem {
  id: string
  protocol?: string | null
}

/**
 * Response from `GET /api/v1/timeseries/mac/ids` or `/proto/ids`.
 */
export interface SourceIdsResponse {
  start: string
  stop: string
  nonzero: boolean
  count: number
  data: SourceIdsResponseItem[]
}

/**
 * Response from `GET /api/v1/timeseries/mac/data` or `/proto/data`.
 */
export interface SourceTimeseriesResponse {
  series_id: string
  start: string
  stop: string
  features: string[]
  bucket_seconds: number | null
  row_count: number
  data: Record<string, unknown>[]
}

// =============================================================================
// Timeseries with Bounds (Anomaly Overlay)
// =============================================================================

/**
 * Single data point in a merged timeseries + bounds response.
 * Each row pairs a measured value with its trained boundary and
 * flags whether the value violates the lower or upper bound.
 */
export interface TimeseriesWithBoundsItem {
  time: string
  value: number | null
  value_min: number | null
  value_max: number | null
  lower_bound: number | null
  upper_bound: number | null
  violation_low: boolean
  violation_high: boolean
}

/**
 * Response from `GET /api/v1/anomalies/bounds`.
 * Returns timeseries values merged with trained boundary data
 * and violation flags for anomaly visualization.
 */
export interface TimeseriesWithBoundsResponse {
  data: TimeseriesWithBoundsItem[]
  row_count: number
  parameters: Record<string, unknown> & {
    sample_max_points?: number
    bucket_seconds?: number | null
  }
}

// =============================================================================
// Alarm Intervals
// =============================================================================

/**
 * Single alarm interval representing a contiguous anomaly period.
 * Maps to the `AlarmIntervalItem` Pydantic model on the backend.
 */
export interface AlarmIntervalItem {
  start_timestamp: string
  end_timestamp: string
  alarm_group_id: string
  anomaly_type: string | null
}

/**
 * Response from `GET /api/v1/anomalies/intervals`.
 * Returns alarm intervals for overlay on timeseries charts.
 */
export interface AlarmIntervalsResponse {
  data: AlarmIntervalItem[]
  row_count: number
  parameters: Record<string, unknown>
}

// =============================================================================
// Topology API
// =============================================================================

/**
 * Metadata for a resolved topology node.
 * Mirrors `NodeMeta` Pydantic model on the backend.
 */
export interface TopologyNodeMeta {
  name: string
  alias: string | null
  device_type_name: string
  device_role: string | null
  mac: string
  ip4: string[]
}

/**
 * Single node in the topology graph response.
 * Mirrors `TopologyNode` Pydantic model.
 *
 * Note: The backend serializes `is_anomaly` as `isAnomaly` (camelCase)
 * in the JSON response via custom serialization helpers.
 */
export interface TopologyNodeItem {
  id: string
  label: string
  type: string
  isAnomaly: boolean
  meta: TopologyNodeMeta | Record<string, unknown>
}

/**
 * Metadata for a topology edge (connection between nodes).
 * Mirrors `EdgeMeta` Pydantic model.
 */
export interface TopologyEdgeMeta {
  ucis: string[]
  protocols: string[]
  src_ports: string[]
  dst_ports: string[]
  wildcard: string
}

/**
 * Single edge in the topology graph response.
 * Mirrors `TopologyEdge` Pydantic model.
 *
 * Note: `isAnomaly` is camelCase in JSON (see TopologyNodeItem note).
 */
export interface TopologyEdgeItem {
  id: string
  source: string
  target: string
  label: string
  isAnomaly: boolean
  size: number
  meta: TopologyEdgeMeta
}

/**
 * Graph-level metadata in the topology response.
 * Mirrors `TopologyGraphMeta` Pydantic model.
 */
export interface TopologyGraphMeta {
  node_count: number
  edge_count: number
  truncated: boolean
}

/**
 * Response from `GET /api/v1/topology/graph`.
 * Returns the full topology graph with nodes, edges, and metadata.
 */
export interface TopologyGraphResponse {
  nodes: TopologyNodeItem[]
  edges: TopologyEdgeItem[]
  meta: TopologyGraphMeta
}

/**
 * Single open-port entry inside the `open_ports_summary` JSON column.
 */
export interface OpenPortSummaryItem {
  port: number
  protocol: string
  service?: string | null
}

/**
 * One network interface attached to a device, returned by the API as part
 * of `DeviceItem.interfaces`.
 */
export interface NetworkInterfaceItem {
  id: number
  mac_address: string | null
  ipv4_address: string | null
  ipv6_address: string | null
  subnet: string | null
  open_ports_summary: OpenPortSummaryItem[] | null
  last_scan_at: string | null
  notes: string | null
  /**
   * Producer provenance of the interface record (e.g. `passive` from the
   * passive seeder). Nullable when the producer does not attribute a source;
   * carries no traffic-presence or freshness claim on its own.
   */
  source: string | null
}

/**
 * Single CVE / vulnerability record stored in the `vulnerabilities` JSONB column.
 *
 * Fields emitted by ``device_topology_view`` (active vulns only).
 * ``status_changed_by`` is **not** present in the view and is tracked
 * client-side after a successful PATCH (Welle D / 4.3).
 */
export interface DeviceVulnerabilityItem {
  /**
   * Observation primary key (``vulnerability_observations.id``), exposed
   * by ``device_topology_view`` as the JSONB key ``id`` since migration
   * 0008. Numeric. ``observation_id`` is kept as a legacy alias for any
   * older payload shape.
   */
  id?: number
  observation_id?: number
  /** Canonical CVE identifier (``vuln_id`` in the view; ``cve`` is a legacy alias). */
  vuln_id?: string
  cve?: string
  /** Direct link to the NVD detail page for this CVE. */
  url?: string
  severity?: 'low' | 'medium' | 'high' | 'critical' | 'none' | string
  /** Short human-readable summary derived from the description. */
  summary?: string
  /** Full description from NVD (used in the detail panel). */
  description?: string
  /** Numeric CVSS base score. */
  cvss_score?: number
  /** CVSS vector string (e.g. ``CVSS:3.1/AV:N/AC:L/...``). */
  vector?: string
  /** Lowest version known to contain the fix (``versionEndExcluding``). */
  fixed_in?: string
  /** ISO timestamp from NVD when the CVE was first published. */
  published?: string
  /** Up to a few related links (vendor advisories, exploits). */
  references?: string[]
  /** Lifecycle status (``active`` from the view). */
  status?: string
  /** Source module tag (``nvd``, ``cert_vde``, …). */
  source_module?: string
  /** First time this CVE was seen for the asset. */
  detected_at?: string
  /** Last time the auto-loop refreshed this observation. */
  last_seen_at?: string
  /** Client-side mirror of ``status_changed_by`` from PATCH response. */
  _status_changed_by?: string | null
  [key: string]: unknown
}

// =============================================================================
// Vulnerability Lookup (Welle D)
// =============================================================================

/**
 * Request body for ``POST /api/v1/vulnerabilities/lookup``.
 * Mirrors ``VulnerabilityLookupRequest`` in otalon-scan.
 */
export interface VulnerabilityLookupRequest {
  device_ids?: number[]
  all?: boolean
}

/**
 * Response from ``POST /api/v1/vulnerabilities/lookup`` (async job, 202).
 * Mirrors ``VulnerabilityLookupResponse`` in otalon-scan.
 */
export interface VulnerabilityLookupResponse {
  job_id: string
  status: string
  eligible_assets: number
}

/**
 * Single CVE-lookup job-header row (``GET /vulnerabilities/lookups``).
 * Mirrors ``CveLookupItem`` in otalon-scan.
 */
export interface CveLookupItem {
  job_id: string
  scope: string
  device_id: number | null
  source: string
  api_key_used: boolean
  status: string
  summary: Record<string, unknown> | null
  error: string | null
  started_at: string | null
  finished_at: string | null
}

/**
 * Envelope for ``GET /vulnerabilities/lookups``.
 * Mirrors ``CveLookupsListResponse`` in otalon-scan.
 */
export interface CveLookupsListResponse {
  lookups: CveLookupItem[]
}

/**
 * Per-asset progress event emitted on the CVE-lookup SSE stream.
 */
export interface CveLookupProgressEvent {
  job_id: string
  device_id: number
  cve_count: number
  index: number
  total: number
}

/**
 * Terminal ``done`` event emitted on the CVE-lookup SSE stream.
 */
export interface CveLookupDoneEvent {
  job_id: string
  status: string
  cves_found: number
  critical: number
}

/**
 * Terminal ``failed`` event emitted on the CVE-lookup SSE stream.
 */
export interface CveLookupFailedEvent {
  job_id: string
  status: string
  error: string
}

/**
 * Terminal ``aborted`` event emitted on the CVE-lookup SSE stream when an
 * operator stops an in-flight lookup (R-02). Carries the ``aborted``
 * status so the dialog can settle the running state and stop its timer.
 */
export interface CveLookupAbortedEvent {
  job_id: string
  status: string
}

/**
 * Request body for ``PATCH /api/v1/vulnerabilities/{vuln_id}``.
 * Mirrors ``VulnerabilityPatchRequest`` in otalon-scan.
 */
export interface VulnerabilityPatchRequest {
  status?: string
  severity?: string
  summary?: string
  status_changed_by?: string
}

/**
 * Single vulnerability observation returned by ``PATCH``.
 * Mirrors ``VulnerabilityItem`` in otalon-scan.
 */
export interface VulnerabilityItem {
  id: number
  scan_id: string
  device_id: number | null
  interface_id: number | null
  source_module: string | null
  vuln_id: string | null
  severity: string | null
  summary: string | null
  status: string
  status_changed_at: string | null
  status_changed_by: string | null
  detected_at: string | null
  last_seen_at: string | null
}

/**
 * Single device record from the topology devices endpoint.
 * Mirrors `DeviceItem` Pydantic model.
 */
export interface DeviceItem {
  id: number
  hostname: string | null
  vendor: string | null
  device_family: string | null
  device_type: string | null
  hostname: string | null
  description: string | null
  article_number: string | null
  device_role: string | null
  firmware_version: string | null
  product_name: string | null
  hw_version: string | null
  sw_version: string | null
  serial_number: string | null
  /**
   * SCAN-023: identity-field names the operator has manually set and
   * locked against scan-overwrite (e.g. `["vendor", "firmware_version"]`).
   * Drives the per-field "manual" marker in the device detail panel.
   * Optional so topology payloads that predate the column still parse.
   */
  manual_identity_fields?: string[] | null
  vulnerabilities: DeviceVulnerabilityItem[] | null
  update_available: boolean
  last_scan_at: string | null
  notes: string | null
  created_at: string
  updated_at: string | null
  interfaces: NetworkInterfaceItem[]
  /**
   * UI-only marker: the device was not seen within the selected time
   * window. Set by the devices page so such rows can be dimmed and labelled
   * "Not in window" instead of being dropped from the inventory
   * (audit UI-04). Never sent by the API.
   */
  _outsideTimeWindow?: boolean
}

/**
 * Partial identity body for `PATCH /api/v1/devices/{id}` (SCAN-023).
 * Only supplied fields are written AND locked against scan-overwrite.
 */
export interface DeviceIdentityPatch {
  vendor?: string | null
  device_family?: string | null
  device_type?: DeviceType | null
  article_number?: string | null
  firmware_version?: string | null
  product_name?: string | null
  hw_version?: string | null
  sw_version?: string | null
}

export type DeviceType =
  | 'Application Server'
  | 'Control Server'
  | 'Data Gateway'
  | 'Data Historian'
  | 'DCS Controller'
  | 'Field I/O'
  | 'Firewall'
  | 'HMI'
  | 'IED'
  | 'Jump Host'
  | 'PAC'
  | 'PLC'
  | 'RTU'
  | 'Routers'
  | 'Safety Controller'
  | 'Switch'
  | 'VPN Server'
  | 'Workstation'
  | 'Other'

/**
 * Response from `PATCH /api/v1/devices/{id}` (SCAN-023). Flat identity
 * projection returned by the otalon-scan `DeviceItem` wire model.
 */
export interface DeviceIdentityPatchResponse {
  id: number
  primary_mac: string | null
  vendor: string | null
  device_family: string | null
  device_type: string | null
  article_number: string | null
  firmware_version: string | null
  product_name: string | null
  hw_version: string | null
  sw_version: string | null
  manual_identity_fields: string[]
  last_scan_at: string | null
}

/**
 * Single service observation returned by `GET /api/v1/devices/{id}/observations`.
 * Mirrors the `ServiceObservationItem` Pydantic model in otalon-scan.
 */
export interface ServiceObservationItem {
  id: number
  scan_id: string
  interface_id: number
  ip_address: string | null
  mac_address: string | null
  port: number | null
  transport: string | null
  protocol: string | null
  service_name: string | null
  product: string | null
  version: string | null
  cpe: string | null
  extra_info: string | null
  first_seen_at: string
  last_seen_at: string
}

/**
 * Response from `GET /api/v1/devices/{id}/observations`.
 */
export interface DeviceObservationsResponse {
  observations: ServiceObservationItem[]
}

/**
 * Response from `GET /api/v1/topology/devices`.
 * Returns a paginated list of network devices.
 */
export interface DevicesResponse {
  devices: DeviceItem[]
  total: number
}

/**
 * Request body for `PUT /api/v1/topology/devices/{id}/type`.
 * Overrides the automatically detected device type.
 */
interface _DeviceTypeOverrideRequest {
  device_type: string
}

/**
 * Response from `PUT /api/v1/topology/devices/{id}/type`.
 * Confirms the device type override with before/after information.
 */
export interface DeviceTypeOverrideResponse {
  device_id: number
  device_type: string
  previous_type: string
  message: string
}

// =============================================================================
// Admin API (Docker / Compose / ENV / DB)
// =============================================================================

/**
 * Status information for a single Docker container.
 * Mirrors `ContainerInfoResponse` Pydantic model.
 */
export interface ContainerInfo {
  name: string
  status: string
  image: string
  created: string
  ports: Record<string, string>
  health: string
}

/**
 * Response containing a list of container statuses.
 * Mirrors `ContainerListResponse` Pydantic model.
 */
export interface ContainerListResponse {
  containers: ContainerInfo[]
}

/**
 * Response containing container log output.
 * Mirrors `ContainerLogsResponse` Pydantic model.
 */
export interface ContainerLogsResponse {
  name: string
  lines: number
  logs: string
}

/**
 * Request to execute a Docker Compose action on a service.
 */
interface _ComposeActionRequest {
  service: string
  action: 'up' | 'stop' | 'restart' | 'recreate'
}

/**
 * Response for a Docker Compose action.
 * Mirrors `ComposeActionResponse` Pydantic model.
 */
export interface ComposeActionResponse {
  service: string
  action: string
  exit_code: number
  output: string
  success: boolean
}

/**
 * Response containing masked environment variables and the list of editable keys.
 * Mirrors `EnvResponse` Pydantic model.
 */
export interface EnvResponse {
  env: Record<string, string>
  editable_keys: string[]
}

/**
 * Request to update environment variables.
 * Mirrors `EnvUpdateRequest` Pydantic model.
 */
interface _EnvUpdateRequest {
  updates: Record<string, string>
}

/**
 * Response after updating environment variables.
 * Mirrors `EnvUpdateResponse` Pydantic model.
 */
export interface EnvUpdateResponse {
  env: Record<string, string>
  changed_keys: string[]
  backup_path: string | null
}

/**
 * Request to truncate a database table.
 */
interface _DbTruncateRequest {
  table: string
}

/**
 * Response for a database truncate operation.
 * Mirrors `DbTruncateResponse` Pydantic model.
 */
export interface DbTruncateResponse {
  table: string
  success: boolean
  message: string
}

// =============================================================================
// Subagent Classification (otalon-agent)
// =============================================================================

/**
 * Step-1 attack-method identification produced by the LLM subagent.
 * Mirrors the paper's `step1_technical` JSON shape.
 */
export interface SubagentStep1Technical {
  technical_method: string
  observed_activity: string
  evidence: string[]
}

export interface SubagentVerdict {
  outcome: 'attack' | 'benign' | 'inconclusive' | 'false_positive'
  reasoning: string
  fp_reason?: string
}

/**
 * One MITRE classification candidate.
 */
export interface SubagentClassification {
  technique_id: string
  technique_name?: string
  confidence: number
  reasoning?: string
  variant?: string
}

/**
 * Step-2 MITRE-mapping result (sorted by confidence descending).
 */
export interface SubagentStep2Classification {
  classifications: SubagentClassification[]
}

/**
 * One tool call performed during the worker loop.
 */
export interface SubagentTraceEntry {
  round: number
  tool: string
  args: Record<string, unknown>
  result_chars: number
  result_preview?: string | null
  duration_ms: number
  error: string | null
  ts?: string | null
}

export type SubagentJobStatus = 'pending' | 'running' | 'completed' | 'failed' | 'timeout' | 'cancelled'

export interface SubagentJob {
  id: string
  alarm_id: string
  status: SubagentJobStatus
  prompt_variant: 'open' | 'expert' | 'forensic'
  prompt_hash: string
  llm_provider: string
  llm_model: string
  llm_endpoint?: string | null
  reasoning_effort?: string | null
  baseline_id?: string | null
  timeout_seconds: number
  trigger_source: string
  started_at?: string | null
  finished_at?: string | null
  duration_seconds?: number | null
  step1_technical: SubagentStep1Technical | null
  step2_classification: SubagentStep2Classification | null
  verdict: SubagentVerdict | null
  tool_trace: SubagentTraceEntry[]
  tokens_prompt: number
  tokens_completion: number
  error_message?: string | null
  created_at: string
}

export interface SubagentJobSummary {
  id: string
  alarm_id: string
  status: SubagentJobStatus
  prompt_variant: string
  llm_provider: string
  llm_model: string
  started_at?: string | null
  finished_at?: string | null
  duration_seconds?: number | null
  tool_trace_count: number
  tokens_total: number
  top_step2: SubagentClassification | null
  step1_method: string | null
  verdict_outcome: SubagentVerdict['outcome'] | null
  created_at: string
}

export interface SubagentJobListResponse {
  items: (SubagentJob | SubagentJobSummary)[]
  total: number
  limit: number
  offset: number
}

export interface CreateSubagentJobRequest {
  prompt_variant?: 'open' | 'expert' | 'forensic'
  llm_provider?: 'azure_openai' | 'openai_compat'
  llm_model?: string
  llm_endpoint?: string | null
  reasoning_effort?: 'low' | 'medium' | 'high'
  baseline_id?: string | null
  timeout_seconds?: number
}

export interface CreateSubagentJobResponse {
  job_id: string
  status: SubagentJobStatus
  eta_seconds: number
  events_url: string
}

// =============================================================================
// Baselines (curated quiet-traffic windows)
// =============================================================================

export interface Baseline {
  id: string
  name: string
  description: string | null
  start_ts: string
  end_ts: string
  is_active: boolean
  pcap_chunk_count: number | null
  uci_count: number | null
  size_bytes: number | null
  audit_log: Array<Record<string, unknown>>
  archived_at: string | null
  created_at: string
  created_by: string | null
}

export interface BaselinePreview {
  start_ts: string
  end_ts: string
  pcap_chunk_count: number
  uci_count: number
  anomaly_count: number
  size_bytes: number
  thresholds: { min_uci_count: number; min_pcap_chunks: number }
  meets_thresholds: boolean
}

export interface CreateBaselineRequest {
  name: string
  description?: string
  start_ts: string
  end_ts: string
}

// =============================================================================
// Frequency Profiles / Rhythm
// =============================================================================

/**
 * Detector state for one series, from `GET /api/v1/frequency/profile`.
 *
 * `no_profile` is a normal state, not an error: the frequency monitor
 * has never trained a cadence for this connection, so there is no rhythm
 * to show.
 */
export type RhythmState = 'no_profile' | 'no_last_seen' | 'normal' | 'frequency_anomaly' | 'absence_active'

/**
 * An effective detector factor together with its provenance, so the UI
 * can name whether a threshold is operator-tuned or the shipped default.
 */
export interface EffectiveFactor {
  value: number
  source: 'override' | 'global_default'
  override: number | null
  global_default: number
}

/**
 * Frequency profile and derived rhythm state for one series.
 *
 * All instants are ISO 8601 UTC. `now` is the server instant the derived
 * fields were computed against; deriving durations from it rather than
 * from the browser clock keeps displayed times self-consistent.
 */
export interface FrequencyProfileResponse {
  module: string
  series_id: string
  series_display?: string | null
  state: RhythmState
  has_profile: boolean
  mean_interval_seconds: number | null
  std_interval_seconds: number | null
  tolerance_factor: EffectiveFactor | null
  absence_factor: EffectiveFactor | null
  last_seen: string | null
  trained_at: string | null
  now: string
  absence_deadline: string | null
  absence_timeout_seconds: number | null
  seconds_until_deadline: number | null
  seconds_since_last_seen: number | null
  active_anomaly_type: string | null
  active_anomaly_since: string | null
  recent_absence_count?: number
  recent_frequency_anomaly_count?: number
}

/**
 * Envelope of `GET /api/v1/frequency/profiles`.
 *
 * Independent of any traffic window, so it also lists connections that
 * carry a learned cadence but are currently silent.
 */
export interface FrequencyProfileListResponse {
  module: string
  count: number
  data: FrequencyProfileResponse[]
}

// =============================================================================
// Frequency Profile Corrections (UI-101 Rhythm Review)
// =============================================================================

/**
 * Canonical before-state of the two editable override columns.
 *
 * Preview returns it; Apply must send it back byte-identical. The API
 * compares it against the locked profile row and answers HTTP 409 when a
 * concurrent writer changed either override in the meantime, so a stale
 * correction can never overwrite newer state.
 */
export interface FrequencyOverrideSnapshot {
  tolerance_factor_override: number | null
  absence_factor_override: number | null
}

/**
 * Before/after view of one editable factor including its provenance.
 *
 * `field` carries the persisted semantic name
 * (`tolerance_factor.override` / `absence_factor.override`); the request
 * payload uses the flat `*_override` spelling.
 */
export interface FrequencyFactorDiff {
  field: string
  old_override: number | null
  new_override: number | null
  old_effective: number
  new_effective: number
  old_source: 'override' | 'global_default'
  new_source: 'override' | 'global_default'
  changed: boolean
}

/**
 * Detector-threshold impact of a proposed tolerance change.
 *
 * The detector applies `max(tolerance x std, relative_floor_factor x mean)`.
 * When `floor_dominates` is true, changing the tolerance factor does not
 * move the threshold at all; `crossover_tolerance_factor` names the value
 * at which it would start to.
 */
export interface FrequencyThresholdImpact {
  mean_interval_seconds: number | null
  std_interval_seconds: number | null
  relative_floor_factor: number
  floor_seconds: number | null
  old_threshold_seconds: number | null
  new_threshold_seconds: number | null
  floor_dominates: boolean
  crossover_tolerance_factor: number | null
  absence_timeout_seconds: number | null
}

/**
 * Provenance for a server-generated rhythm suggestion.
 */
export interface FrequencySuggestionEvidence {
  observations: number
  window_days: number
  method: string
}

/**
 * Advisory factor proposal. Never auto-applied: the operator still has to
 * preview, supply an audited reason, and confirm.
 */
export interface FrequencyOverrideSuggestion {
  module: string
  series_id: string
  tolerance_factor_suggested: number | null
  absence_factor_suggested: number | null
  evidence: FrequencySuggestionEvidence
}

/**
 * Response of `POST /api/v1/frequency/{series_id}/override/preview`.
 */
export interface FrequencyOverridePreviewResponse {
  module: string
  series_id: string
  diff: FrequencyFactorDiff[]
  before_snapshot: FrequencyOverrideSnapshot
  impact: FrequencyThresholdImpact
  suggestion: FrequencyOverrideSuggestion | null
}

/**
 * Response of `POST /api/v1/frequency/{series_id}/override/apply`.
 */
export interface FrequencyOverrideApplyResponse {
  history_id: string
  module: string
  series_id: string
  diff: FrequencyFactorDiff[]
  profile: FrequencyProfileResponse
  notified: boolean
}

/**
 * One chronological correction-audit record for a series.
 */
export interface FrequencyHistoryRecord {
  actor: string
  old_tolerance: number | null
  new_tolerance: number | null
  old_absence: number | null
  new_absence: number | null
  reason: string
  changed_at: string
}

/**
 * Envelope of `GET /api/v1/frequency/{series_id}/history`.
 */
export interface FrequencyHistoryResponse {
  module: string
  series_id: string
  count: number
  data: FrequencyHistoryRecord[]
}

/**
 * One persisted rhythm anomaly episode for a series.
 *
 * Detector evidence, not an operator correction: the same `anomalies`
 * row the rhythm state derives from, narrowed to the two rhythm types.
 * `duration_seconds` stays `null` when the persisted interval has no end
 * instant rather than inventing a length.
 */
export interface FrequencyEventRecord {
  anomaly_type: string
  start_ts: string
  end_ts: string | null
  duration_seconds: number | null
  confidence: number | null
}

/**
 * Envelope of `GET /api/v1/frequency/{series_id}/events`.
 *
 * `truncated` reports that more episodes matched the window than the
 * requested limit returned, so the timeline can say so instead of
 * implying it is complete.
 */
export interface FrequencyEventsResponse {
  module: string
  series_id: string
  count: number
  truncated: boolean
  data: FrequencyEventRecord[]
}

/**
 * Requested override values for Preview and Apply.
 *
 * A field that is absent means "leave as is"; an explicit `null` clears
 * the override and restores the global default. Learned cadence is not
 * part of this payload and is rejected by the API.
 */
export interface FrequencyOverridePayload {
  tolerance_factor_override?: number | null
  absence_factor_override?: number | null
}
