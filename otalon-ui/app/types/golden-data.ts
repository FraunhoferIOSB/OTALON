/**
 * TypeScript type definitions for Golden Data structures.
 *
 * These interfaces mirror the JSON structures extracted from the
 * otalon-api golden data files used as static mockup data.
 */

// =============================================================================
// Dashboard KPIs (gd09)
// =============================================================================

export type SignalColor = 'danger' | 'warning' | 'success' | 'info'

export interface KpiData {
  signal_color: SignalColor
  anomaly_count: number
  classified_count: number
  device_count: number
  connection_count: number
}

// =============================================================================
// Timeseries (gd05)
// =============================================================================

export interface TimeseriesPoint {
  time: string
  value: number | null
  value_min: number | null
  value_max: number | null
  lower_bound: number | null
  upper_bound: number | null
  violation_low: boolean
  violation_high: boolean
}

// =============================================================================
// Connection Data (gd01)
// =============================================================================

export type ConnectionState = 'normal' | 'anomaly'

/**
 * Whether a connection is currently sending or only known from a profile.
 *
 * `live` — the connection appears in the traffic window returned by
 * `GET /api/v1/timeseries/ids`.
 * `silent` — the connection has a learned frequency profile but no
 * traffic in the current window. Exactly the case the absence detector
 * exists for, so it must stay selectable rather than vanish from the list.
 */
export type ConnectionPresence = 'live' | 'silent'

export interface Connection {
  uci: string
  source: string
  destination: string
  sourceIp: string | null
  sourceMac: string | null
  destIp: string | null
  destMac: string | null
  protocol: string
  port: string | null
  state: ConnectionState
  isWildcard: boolean
  memberCount: number
  collapsed_port_count?: number | null
  ruleTrained: boolean
  profiled?: boolean
  presence?: ConnectionPresence
}

/** @deprecated Legacy flat timeseries shape from gd01 — replaced by Connection list. */
export interface ConnectionPoint {
  time: string
  packet_count: number
  total_volume: number
  mean_packet_size: number
}

// =============================================================================
// Feature Timeseries
// =============================================================================

export type FeatureName =
  | 'packet_count'
  | 'total_volume'
  | 'mean_packet_size'
  | 'min_packet_size'
  | 'max_packet_size'
  | 'mean_interarrival_time'
  | 'min_interarrival_time'
  | 'max_interarrival_time'
  | 'std_packet_size'
  | 'std_interarrival_time'

export interface FeatureTimeseriesPoint {
  time: string
  value: number
  upper_bound: number | null
  lower_bound: number | null
  value_min?: number | null
  value_max?: number | null
  violation_low?: boolean
  violation_high?: boolean
}

export type EnvelopeMode = 'auto' | 'on' | 'off'

export interface FeatureTimeseries {
  feature: FeatureName
  points: FeatureTimeseriesPoint[]
}

export interface AnomalyInterval {
  start: string
  end: string
  label?: string
}

// =============================================================================
// Alarm Groups (gd08)
// =============================================================================

export interface AlarmTypeStat {
  type: string
  count: number
}

export interface AlarmEntityDetail {
  mac: string
  ip: string
  port: number
  protocols: string[]
  uci: string
}

export interface AlarmGroup {
  group_id: number
  module: string
  primary_type: string
  start_time: string
  end_time: string | null
  is_active: boolean
  is_confirmed: boolean
  anomaly_count: number
  entity_count: number
  type_stats: AlarmTypeStat[]
  entities: AlarmEntityDetail[]
}

export interface AlarmGroupData {
  groups: AlarmGroup[]
}

/** @deprecated Legacy flat entity shape — kept for backward compatibility. */
export interface AlarmEntity {
  'Source MAC': string
  'Destination MAC': string
  'Source IP': string
  'Destination IP': string
  'Source Port': string
  'Destination Port': string
  VLAN: string
  'IP Proto': string
  Protocols: string
  UCI: string
}

// =============================================================================
// Real Alarm Groups (gd-alarm-groups-real)
// =============================================================================

export interface AnomalyTypeStat {
  interval_count: number
  count: number
  confidence_mean: number
  score_norm: number
  packet_rate_mean: number
  byte_rate_mean: number
}

export interface RealAlarmGroup {
  id: string
  module: string
  start_timestamp: string
  end_timestamp: string
  primary_type: string | string[]
  multi_type: boolean
  confirmed: boolean
  is_active: boolean
  series_ids: string[]
  anomaly_type_stats: Record<string, AnomalyTypeStat>
}

// =============================================================================
// Topology Graph (gd10)
// =============================================================================

export type NodeType = 'PLC' | 'IPC' | 'IO' | 'Other'

export interface TopologyNodeMeta {
  name: string
  alias: string
  device_type_name: string
  device_role: string
  mac: string
  ip4: string[]
}

export interface TopologyNode {
  id: string
  label: string
  type: NodeType
  isAnomaly: boolean
  meta: TopologyNodeMeta
}

export interface TopologyEdgeMeta {
  ucis: string[]
  protocols: string[]
  src_ports: string[]
  dst_ports: string[]
  wildcard: string
}

export interface TopologyEdge {
  id: string
  source: string
  target: string
  label: string
  isAnomaly: boolean
  size: number
  meta: TopologyEdgeMeta
}

export interface TopologyGraph {
  nodes: TopologyNode[]
  edges: TopologyEdge[]
}

// =============================================================================
// Health (gd12a)
// =============================================================================

export interface HealthService {
  name: string
  running: boolean
  detail: string
  timestamp: number
}

// =============================================================================
// Devices (gd13)
// =============================================================================

export interface Device {
  id: number
  vendor: string | null
  device_family: string | null
  device_type: string
  description: string
  article_number: string | null
  device_role: string | null
  firmware_version: string | null
  vulnerabilities: string | null
  update_available: boolean
  last_scan_at: string
  notes: string
  created_at: string
  updated_at: string | null
}
