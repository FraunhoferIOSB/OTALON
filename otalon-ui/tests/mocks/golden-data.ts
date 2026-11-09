/**
 * Golden mock data constants for Phase 4 tests.
 *
 * These values match the golden data JSON files and are used by
 * both MSW handlers (response bodies) and test assertions (expected values).
 */
import type {
  AlarmIntervalItem,
  AnomalyGroupItem,
  AnomalyTypeStatDetail,
  AttentionResponse,
  CaptureStatus,
  ContainerInfo,
  ContainerListResponse,
  DashboardKpisData,
  DeviceItem,
  EnvResponse,
  HealthCheckItem,
  HealthIncidentListResponse,
  HealthIncidentSummary,
  HealthResponse,
  NetworkInterfaceItem,
  NormRefs,
  PassiveDiscoveryStatus,
  PassiveSeederStatus,
  PipelineResponse,
  TimeseriesWithBoundsItem,
  TopAssetItem,
  TopConnectionItem,
  TopProtocolItem,
  TopologyEdgeItem,
  TopologyGraphMeta,
  TopologyGraphResponse,
  TopologyNodeItem,
  Weights,
} from '~/types/api'

const DEFAULT_NORM_REFS: NormRefs = {
  packet_rate_ref: 1.0,
  byte_rate_ref: 1.0,
  coverage_ref: 1.0,
  count_ref: 1.0,
}

const DEFAULT_WEIGHTS: Weights = {
  w_rate: 0.3,
  w_cov: 0.2,
  w_persist: 0.2,
  w_pr: 0.5,
  w_br: 0.5,
  gamma: 1.0,
}

function makeStatDetail(overrides: Partial<AnomalyTypeStatDetail> = {}): AnomalyTypeStatDetail {
  return {
    interval_count: 4,
    count: 12,
    confidence_sum: 9.6,
    confidence_max: 0.95,
    confidence_min: 0.7,
    confidence_mean: 0.8,
    packet_rate_sum: 1200.0,
    byte_rate_sum: 96000.0,
    rate_count: 4,
    protocol_penalty_sum: 0.8,
    protocol_penalty_count: 4,
    severity_mean_sum: 3.2,
    severity_max_sum: 3.8,
    severity_count: 4,
    packet_rate_mean: 300.0,
    byte_rate_mean: 24000.0,
    type_series_count: 2,
    severity_mean: 0.8,
    severity_max: 0.95,
    protocol_penalty_mean: 0.2,
    traffic_n: 0.5,
    coverage_n: 0.4,
    count_n: 0.6,
    conf_factor: 0.85,
    score_raw: 0.72,
    score: 0.61,
    norm_refs: DEFAULT_NORM_REFS,
    weights: DEFAULT_WEIGHTS,
    score_norm: 0.61,
    ...overrides,
  }
}

export const GOLDEN_TOP_CONNECTIONS: TopConnectionItem[] = [
  {
    uci: '00:1B:1B:F8:3A:02/00:1B:1B:F8:3A:03///////Ethernet:PROFINET_RT',
    packet_count: 48200,
    byte_count: 5_800_000,
    is_anomaly: false,
    sparkline: [10, 12, 15, 14, 18, 22, 20, 19, 25, 23, 21, 24],
  },
  {
    uci: 'a8:74:1d:02:99:8d/00:1B:1B:F8:3A:05//6/192.168.1.10/192.168.1.20//502/Ethernet:IPv4:TCP:Modbus',
    packet_count: 31500,
    byte_count: 2_400_000,
    is_anomaly: true,
    sparkline: [5, 8, 6, 30, 45, 50, 48, 42, 38, 35, 40, 44],
  },
  {
    uci: '00:1B:1B:F8:3A:03/FF:FF:FF:FF:FF:FF///////Ethernet:ARP',
    packet_count: 12000,
    byte_count: 720_000,
    is_anomaly: false,
    sparkline: [],
  },
]

export const GOLDEN_KPI: DashboardKpisData = {
  signal_color: 'danger',
  anomaly_count: 200,
  classified_count: 200,
  device_count: 0,
  connection_count: 0,
  top_connections: GOLDEN_TOP_CONNECTIONS,
}

export const GOLDEN_HEALTH_SERVICES: HealthCheckItem[] = [
  { name: 'Postgres', running: true, detail: 'ok in 0 ms', timestamp: 1774352114.33 },
  { name: 'InfluxDB', running: true, detail: 'ok in 0 ms', timestamp: 1774352114.33 },
]

export const GOLDEN_HEALTH: HealthResponse = {
  services: GOLDEN_HEALTH_SERVICES,
  overall_status: 'healthy',
}

export const GOLDEN_ACTIVE_INCIDENT: HealthIncidentSummary = {
  id: '11111111-1111-1111-1111-111111111111',
  service: 'Network Traffic Recorder',
  owning_service: 'otalon-capture',
  probe_target: 'Network Traffic Recorder',
  system_service_id: 'otalon-capture',
  category: 'probe_timeout',
  cause: 'health probe timeout',
  status: 'active',
  first_seen: '2026-07-23T10:00:00Z',
  last_seen: '2026-07-23T10:05:00Z',
  recovered_at: null,
  sample_count: 6,
  failure_count: 5,
  latency_budget_ms: 3000,
  worst_latency_ms: 5010,
  evidence_type: 'operational_health',
  samples: [
    {
      service: 'Network Traffic Recorder',
      running: false,
      category: 'probe_timeout',
      cause: 'health probe timeout',
      latency_ms: 5010,
      latency_budget_ms: 3000,
      timestamp: '2026-07-23T10:05:00Z',
      detail: 'probe timeout after 5010 ms',
    },
  ],
}

export const GOLDEN_RECOVERED_INCIDENT: HealthIncidentSummary = {
  ...GOLDEN_ACTIVE_INCIDENT,
  id: '22222222-2222-2222-2222-222222222222',
  status: 'recovered',
  recovered_at: '2026-07-23T10:10:00Z',
  last_seen: '2026-07-23T10:10:00Z',
}

export const GOLDEN_HEALTH_INCIDENTS: HealthIncidentListResponse = {
  items: [GOLDEN_ACTIVE_INCIDENT, GOLDEN_RECOVERED_INCIDENT],
  retention: { max_incidents: 50, max_days: 7 },
}

export const GOLDEN_PIPELINE: PipelineResponse = {
  sources: [
    {
      name: 'conn',
      last_record: '2026-07-17T10:00:00Z',
      age_seconds: 30,
      state: 'current',
      records_per_hour: 120,
      expected_interval_seconds: 5,
    },
    {
      name: 'mac',
      last_record: '2026-07-17T10:00:00Z',
      age_seconds: 35,
      state: 'current',
      records_per_hour: 90,
      expected_interval_seconds: 5,
    },
    {
      name: 'proto',
      last_record: '2026-07-17T09:30:00Z',
      age_seconds: 1830,
      state: 'stale',
      records_per_hour: 10,
      expected_interval_seconds: 5,
    },
  ],
  influx: {
    last_write: '2026-07-17T10:00:00Z',
    age_seconds: 30,
  },
  detection: {
    last_cycle: '2026-07-17T09:59:00Z',
    age_seconds: 90,
    duration_seconds: 3.4,
    series_evaluated: 1812,
  },
  backlog: null,
}

export const GOLDEN_ATTENTION: AttentionResponse = {
  findings: [
    {
      priority: 'High',
      kind: 'warn',
      title: 'Protocols source stale — 30 min since last record',
      link: { label: 'Data Sources', route: '/operations/data-sources' },
    },
  ],
}

export const GOLDEN_CAPTURE_STATUS: CaptureStatus = {
  interface: 'enp5s0',
  link_up: true,
  recording: true,
  drops_24h_pct: null,
  overflows: null,
}

export const GOLDEN_PASSIVE_DISCOVERY: PassiveDiscoveryStatus = {
  observed_asset_count: 10,
  observed_interface_count: 10,
  latest_seen_at: '2026-07-21T07:14:43.750Z',
  first_seen_at: '2026-07-02T09:29:12.637Z',
  age_seconds: 42,
  freshness: 'current',
  runtime_control_enabled: false,
}

/**
 * Passive-seeder status as returned by the live stack after UI-015 Stage 1.
 *
 * `rows_seeded` is the last cycle's count, not a cumulative total, and
 * `last_error` is null because the most recent cycle was clean.
 */
export const GOLDEN_PASSIVE_SEEDER_STATUS: PassiveSeederStatus = {
  service: 'otalon-scan',
  state: 'running',
  last_cycle_at: '2026-07-29T12:44:48.600Z',
  last_error: null,
  rows_seeded: 15,
  poll_interval_s: 120,
  updated_at: '2026-07-29T12:44:48.600Z',
}

export const GOLDEN_ALARM_GROUPS: AnomalyGroupItem[] = [
  {
    id: 'def17204-239c-4568-bdb2-cc7368d2cec2',
    module: 'netcap',
    start_timestamp: '2025-06-01T10:00:00Z',
    end_timestamp: '2025-06-01T10:15:00Z',
    primary_type: 'T0802/opcua_enum',
    multi_type: true,
    confirmed: false,
    is_active: false,
    series_ids: [
      'series-001',
      'series-002',
      'series-003',
      'series-004',
      'series-005',
      'series-006',
      'series-007',
      'series-008',
    ],
    anomaly_type_stats: {
      'T0802/opcua_enum': makeStatDetail({ count: 20, confidence_mean: 0.92 }),
      'T0846/pn_discovery': makeStatDetail({ count: 8, confidence_mean: 0.78 }),
      'T0803/opcua_write': makeStatDetail({ count: 5, confidence_mean: 0.85 }),
      'T0836/modbus_write': makeStatDetail({ count: 3, confidence_mean: 0.65 }),
      'T0855/s7comm': makeStatDetail({ count: 2, confidence_mean: 0.55 }),
    },
  },
  {
    id: 'afc13141-676b-4b9c-9ef3-401931ebe305',
    module: 'netcap',
    start_timestamp: '2025-06-01T09:30:00Z',
    end_timestamp: '2025-06-01T09:45:00Z',
    primary_type: 'T0846/pn_discovery',
    multi_type: false,
    confirmed: false,
    is_active: false,
    series_ids: ['series-010', 'series-011', 'series-012'],
    anomaly_type_stats: {
      'T0846/pn_discovery': makeStatDetail({ count: 15, confidence_mean: 0.88 }),
    },
  },
  {
    id: 'b3a42f91-8e2d-4c19-a5f7-9d1234abcdef',
    module: 'netcap',
    start_timestamp: '2025-06-01T08:00:00Z',
    end_timestamp: '2025-06-01T08:20:00Z',
    primary_type: 'T0836/modbus_write',
    multi_type: false,
    confirmed: true,
    is_active: true,
    series_ids: ['series-020', 'series-021'],
    anomaly_type_stats: {
      'T0836/modbus_write': makeStatDetail({ count: 30, confidence_mean: 0.95 }),
    },
  },
]

// =============================================================================
// Timeseries Golden Data (Phase 5a)
// =============================================================================

export const GOLDEN_UCI_LIST = [
  {
    uci: '00:1B:1B:F8:3A:02/00:1B:1B:F8:3A:03///////Ethernet:PROFINET_RT:PROFINET_RT_IO',
    is_wildcard: false,
    member_count: 1,
  },
  {
    uci: '00:1B:1B:F8:3A:04/01:00:5E:00:00:FB///192.168.1.20/224.0.0.251//5353/Ethernet:IPv4:UDP:mDNS',
    is_wildcard: false,
    member_count: 1,
  },
  { uci: '00:1B:1B:F8:3A:03/FF:FF:FF:FF:FF:FF///////Ethernet:ARP', is_wildcard: false, member_count: 1 },
  {
    uci: 'a8:74:1d:02:99:8d/00:1B:1B:F8:3A:05//6/192.168.1.10/192.168.1.20//502/Ethernet:IPv4:TCP:Modbus',
    is_wildcard: false,
    member_count: 1,
  },
  {
    uci: 'a8:74:1d:02:99:8d/00:1B:1B:F8:3A:06//6/192.168.1.30/192.168.1.40//4840/Ethernet:IPv4:TCP:OPC_UA',
    is_wildcard: false,
    member_count: 1,
  },
  {
    uci: '00:1B:1B:F8:3A:07/33:33:00:00:00:FB//17/fe80::1b:1bff:fef8:3a07/ff02::fb//5353/Ethernet:IPv6:UDP:mDNS',
    is_wildcard: false,
    member_count: 1,
  },
  {
    uci: 'a8:74:1d:02:99:8e/00:1B:1B:F8:3A:08//6/2001:db8::1/2001:db8::2//443/Ethernet:IPv6:TCP:TLS',
    is_wildcard: false,
    member_count: 1,
  },
  {
    uci: '00:1B:1B:F8:3A:09/33:33:FF:F8:3A:07///fe80::1b:1bff:fef8:3a09///0/Ethernet:IPv6:ICMPv6',
    is_wildcard: false,
    member_count: 1,
  },
  {
    uci: 'aa:bb:cc:dd:ee:01/aa:bb:cc:dd:ee:02/0//192.168.1.1//*/*/Ethernet:IPv4:TCP',
    is_wildcard: true,
    member_count: 1,
    collapsed_port_count: 7,
  },
  {
    uci: 'aa:bb:cc:dd:ee:03/aa:bb:cc:dd:ee:04/0//10.0.0.1//*/*/Ethernet:IPv4:TCP',
    is_wildcard: true,
    member_count: 3,
    collapsed_port_count: null,
  },
]

export const GOLDEN_FEATURES = [
  'packet_count',
  'total_volume',
  'mean_packet_size',
  'min_packet_size',
  'max_packet_size',
  'mean_interarrival_time',
  'min_interarrival_time',
  'max_interarrival_time',
  'std_packet_size',
  'std_interarrival_time',
]

function makeTimeseriesPoint(timeOffset: number, base: number, index: number): TimeseriesWithBoundsItem {
  const baseTime = new Date('2026-03-07T00:00:00Z')
  const time = new Date(baseTime.getTime() + timeOffset * 1000)
  const noise = Math.sin(index * 0.5) * base * 0.1
  const value = base + noise
  return {
    time: time.toISOString(),
    value,
    value_min: value * 0.95,
    value_max: value * 1.05,
    lower_bound: base * 0.7,
    upper_bound: base * 1.3,
    violation_low: value < base * 0.7,
    violation_high: value > base * 1.3,
  }
}

export const GOLDEN_BOUNDS_DATA: TimeseriesWithBoundsItem[] = Array.from({ length: 20 }, (_, i) =>
  makeTimeseriesPoint(i * 10, 125, i),
)

export const GOLDEN_SINGLE_POINT_DATA: TimeseriesWithBoundsItem[] = [makeTimeseriesPoint(100, 42, 0)]

export const GOLDEN_ALARM_INTERVALS: AlarmIntervalItem[] = [
  {
    start_timestamp: '2026-03-07T02:00:00Z',
    end_timestamp: '2026-03-07T05:00:00Z',
    alarm_group_id: 'group-001',
    anomaly_type: 'T0802',
  },
  {
    start_timestamp: '2026-03-07T14:00:00Z',
    end_timestamp: '2026-03-07T16:30:00Z',
    alarm_group_id: 'group-002',
    anomaly_type: 'T0830',
  },
]

// =============================================================================
// Topology Golden Data (Phase 5b)
// =============================================================================

export const GOLDEN_TOPOLOGY_NODES: TopologyNodeItem[] = [
  {
    id: '1',
    label: '',
    type: 'Other',
    isAnomaly: false,
    meta: { name: '', alias: '', device_type_name: '', device_role: '', mac: '', ip4: [] },
  },
  {
    id: '2',
    label: '',
    type: 'PLC',
    isAnomaly: false,
    meta: { name: '', alias: '', device_type_name: '', device_role: '', mac: '', ip4: [] },
  },
  {
    id: '3',
    label: '',
    type: 'PLC',
    isAnomaly: false,
    meta: { name: '', alias: '', device_type_name: '', device_role: '', mac: '', ip4: [] },
  },
  {
    id: 'unresolved:00:01:05:00:00:01',
    label: '00:01:05:00:00:01',
    type: 'IPC',
    isAnomaly: false,
    meta: { mac: '00:01:05:00:00:01', ip: '' },
  },
  {
    id: 'unresolved:cc:82:7f:a1:8a:36',
    label: 'cc:82:7f:a1:8a:36',
    type: 'Other',
    isAnomaly: true,
    meta: { mac: 'cc:82:7f:a1:8a:36', ip: '' },
  },
]

export const GOLDEN_TOPOLOGY_EDGES: TopologyEdgeItem[] = [
  {
    id: '1-2',
    source: '1',
    target: '2',
    label: '',
    isAnomaly: false,
    size: 10,
    meta: {
      ucis: ['00:01:05:00:00:01/a8:74:1d:02:99:8d///////Ethernet:PROFINET_RT'],
      protocols: ['Ethernet:PROFINET_RT'],
      src_ports: [],
      dst_ports: [],
      wildcard: '00:01:05:00:00:01/a8:74:1d:02:99:8d/////*/*/Ethernet:PROFINET_RT',
    },
  },
  {
    id: '2-3',
    source: '2',
    target: '3',
    label: '',
    isAnomaly: true,
    size: 4,
    meta: {
      ucis: ['cc:82:7f:a1:8a:36/00:01:05:93:50:9b///////Ethernet:ARP'],
      protocols: ['Ethernet:ARP'],
      src_ports: [],
      dst_ports: [],
      wildcard: 'cc:82:7f:a1:8a:36/00:01:05:93:50:9b/////*/*/Ethernet:ARP',
    },
  },
  {
    id: 'unresolved:cc:82:7f:a1:8a:36-3',
    source: 'unresolved:cc:82:7f:a1:8a:36',
    target: '3',
    label: '',
    isAnomaly: true,
    size: 4,
    meta: {
      ucis: ['cc:82:7f:a1:8a:36/a8:74:1d:18:c6:96///////Ethernet:ARP'],
      protocols: ['Ethernet:ARP'],
      src_ports: [],
      dst_ports: [],
      wildcard: 'cc:82:7f:a1:8a:36/a8:74:1d:18:c6:96/////*/*/Ethernet:ARP',
    },
  },
]

export const GOLDEN_TOPOLOGY_META: TopologyGraphMeta = {
  node_count: 5,
  edge_count: 3,
  truncated: false,
}

export const GOLDEN_TOPOLOGY_GRAPH: TopologyGraphResponse = {
  nodes: GOLDEN_TOPOLOGY_NODES,
  edges: GOLDEN_TOPOLOGY_EDGES,
  meta: GOLDEN_TOPOLOGY_META,
}

const DEFAULT_INTERFACE: NetworkInterfaceItem = {
  id: 1,
  mac_address: null,
  ipv4_address: null,
  ipv6_address: null,
  subnet: null,
  open_ports_summary: null,
  last_scan_at: null,
  notes: null,
  source: null,
}

export const GOLDEN_DEVICES: DeviceItem[] = [
  {
    id: 1,
    vendor: 'Siemens',
    product_name: 'SIMATIC S7-1500',
    device_family: null,
    device_type: "LocalizedText(Locale=None, Text='SIMATIC.S7-1500.OPC-UA.Application:PLC_1')",
    description: 'OPC UA application 0',
    article_number: null,
    device_role: null,
    firmware_version: null,
    vulnerabilities: null,
    update_available: false,
    last_scan_at: '2026-02-26T10:01:49Z',
    notes: 'opcua_type=0;product_uri=https://www.siemens.com/s7-1500',
    created_at: '2026-02-26T09:01:49Z',
    updated_at: null,
    interfaces: [{ ...DEFAULT_INTERFACE, id: 1, mac_address: '00:1b:1b:f8:3a:02', ipv4_address: '192.168.1.10' }],
  },
  {
    id: 2,
    vendor: null,
    device_family: null,
    device_type: "LocalizedText(Locale=None, Text='SIMATIC.S7-1500.OPC-UA.Application:PLC_1')",
    description: 'OPC UA application 0',
    article_number: null,
    device_role: null,
    firmware_version: null,
    vulnerabilities: null,
    update_available: false,
    last_scan_at: '2026-02-26T10:01:49Z',
    notes: 'opcua_type=0;product_uri=https://www.siemens.com/s7-1500',
    created_at: '2026-02-26T09:01:49Z',
    updated_at: null,
    interfaces: [],
  },
  {
    id: 3,
    vendor: null,
    device_family: null,
    device_type: "LocalizedText(Locale=None, Text='SIMATIC.S7-1500.OPC-UA.Application:PLC_1')",
    description: 'OPC UA application 0',
    article_number: null,
    device_role: null,
    firmware_version: null,
    vulnerabilities: null,
    update_available: false,
    last_scan_at: '2026-02-26T10:01:49Z',
    notes: 'opcua_type=0;product_uri=https://www.siemens.com/s7-1500',
    created_at: '2026-02-26T09:01:49Z',
    updated_at: null,
    interfaces: [],
  },
  {
    id: 4,
    vendor: null,
    device_family: null,
    device_type: "LocalizedText(Locale=None, Text='SIMATIC.S7-1500.OPC-UA.Application:PLC_1')",
    description: 'OPC UA application 0',
    article_number: null,
    device_role: null,
    firmware_version: null,
    vulnerabilities: null,
    update_available: false,
    last_scan_at: '2026-02-26T10:01:49Z',
    notes: 'opcua_type=0;product_uri=https://www.siemens.com/s7-1500',
    created_at: '2026-02-26T09:01:49Z',
    updated_at: null,
    interfaces: [],
  },
]

// =============================================================================
// Admin Golden Data (Phase 6 — Management)
// =============================================================================

export const GOLDEN_CONTAINERS: ContainerInfo[] = [
  {
    name: 'postgres',
    status: 'running',
    image: 'postgres:15',
    created: '2026-03-20T10:00:00Z',
    ports: { '5432/tcp': '0.0.0.0:5432' },
    health: 'healthy',
  },
  {
    name: 'influxdb3',
    status: 'running',
    image: 'quay.io/influxdb/influxdb3-enterprise:latest',
    created: '2026-03-20T10:00:00Z',
    ports: { '8181/tcp': '0.0.0.0:8181' },
    health: 'healthy',
  },
  {
    name: 'otalon-scan',
    status: 'running',
    image: 'otalon-scan:latest',
    created: '2026-03-20T10:01:00Z',
    ports: { '8091/tcp': '0.0.0.0:8091' },
    health: '',
  },
  {
    name: 'otalon-api',
    status: 'running',
    image: 'otalon-api:latest',
    created: '2026-03-20T10:01:00Z',
    ports: { '8090/tcp': '0.0.0.0:8090' },
    health: 'healthy',
  },
]

export const GOLDEN_CONTAINER_LIST: ContainerListResponse = {
  containers: GOLDEN_CONTAINERS,
}

export const GOLDEN_ENV: EnvResponse = {
  env: {
    INFLUX_URL: 'http://influxdb3:8181',
    INFLUX_TOKEN: '***',
    POSTGRES_PASSWORD: '***',
    POSTGRES_DSN: 'postgresql://admin:***@postgres:5432/otalon',
    TZ: 'Europe/Berlin',
    API_KEY: '***',
    LOG_LEVEL: 'INFO',
  },
  editable_keys: ['INFLUX_URL', 'INFLUX_TOKEN', 'POSTGRES_PASSWORD', 'POSTGRES_DSN', 'TZ'],
}

// =============================================================================
// MAC Timeseries Golden Data
// =============================================================================

export const GOLDEN_MAC_FEATURES = [
  'out_conn_count',
  'out_total_packets',
  'out_total_volume',
  'out_unique_dst_count',
  'out_unique_proto_count',
  'in_conn_count',
  'in_total_packets',
  'in_total_volume',
  'in_unique_src_count',
  'ratio_in_out_packets',
  'ratio_in_out_volume',
  'total_unique_peers',
  'total_conn_count',
]

export const GOLDEN_MAC_LIST = [{ id: '00:1b:1b:f8:3a:02' }, { id: 'a8:74:1d:02:99:8d' }, { id: '00:1b:1b:f8:3a:03' }]

export const GOLDEN_PROTO_LIST = [
  { id: '1435473285', protocol: 'Ethernet:IPv4:TCP' },
  { id: '9876543210', protocol: 'Ethernet:IPv4:UDP' },
  { id: '1111111111', protocol: 'Ethernet:ARP' },
]

export const GOLDEN_TOP_ASSETS: TopAssetItem[] = [
  {
    id: '00:1b:1b:f8:3a:02',
    packet_count: 125000,
    byte_count: 16_200_000,
    is_anomaly: false,
    sparkline: [12, 14, 13, 15, 18, 20, 19, 22, 21, 23, 25, 24],
  },
  {
    id: 'a8:74:1d:02:99:8d',
    packet_count: 84000,
    byte_count: 9_800_000,
    is_anomaly: true,
    sparkline: [8, 9, 7, 35, 50, 55, 52, 48, 42, 38, 44, 46],
  },
  {
    id: '00:1b:1b:f8:3a:03',
    packet_count: 32000,
    byte_count: 3_100_000,
    is_anomaly: false,
    sparkline: [],
  },
]

export const GOLDEN_TOP_PROTOCOLS: TopProtocolItem[] = [
  {
    id: '1435473285',
    protocol: 'Ethernet:IPv4:TCP',
    packet_count: 210000,
    byte_count: 28_500_000,
    is_anomaly: false,
    sparkline: [20, 22, 21, 24, 26, 25, 28, 27, 29, 30, 31, 32],
  },
  {
    id: '9876543210',
    protocol: 'Ethernet:IPv4:UDP',
    packet_count: 95000,
    byte_count: 11_200_000,
    is_anomaly: true,
    sparkline: [10, 12, 11, 13, 15, 14, 16, 18, 17, 19, 20, 21],
  },
  {
    id: '1111111111',
    protocol: 'Ethernet:ARP',
    packet_count: 45000,
    byte_count: 2_700_000,
    is_anomaly: false,
    sparkline: [5, 6, 5, 7, 6, 8, 7, 6, 5, 6, 7, 6],
  },
]

export const GOLDEN_MAC_BOUNDS_DATA: TimeseriesWithBoundsItem[] = Array.from({ length: 20 }, (_, i) =>
  makeTimeseriesPoint(i * 10, 80, i),
)

export const GOLDEN_MAC_ALARM_INTERVALS: AlarmIntervalItem[] = [
  {
    start_timestamp: '2026-03-07T03:00:00Z',
    end_timestamp: '2026-03-07T04:00:00Z',
    alarm_group_id: 'group-mac-001',
    anomaly_type: 'BoundViolation',
  },
]
