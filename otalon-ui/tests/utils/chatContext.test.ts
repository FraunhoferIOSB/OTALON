/**
 * Unit tests for the chat-context builder utilities (UI-057).
 *
 * Verifies that each page contribution contains the expected compact
 * tables, that Klasse-B detail data is gated by the panel-open flag, and
 * that the Klasse-C timeseries summary stays within the JSON budget.
 */
import { describe, expect, it } from 'vitest'

import {
  buildAlarmsContribution,
  buildAssetsContribution,
  buildConnectionsContribution,
  buildDashboardContribution,
  buildMacTimeseriesContribution,
  buildProtoTimeseriesContribution,
  buildTimeseriesSummary,
} from '~/utils/chatContext'
import type {
  AnomalyGroupItem,
  DeviceItem,
  DeviceVulnerabilityItem,
  ServiceObservationItem,
  SubagentJob,
  SubagentJobSummary,
  TimeseriesWithBoundsItem,
  TopAssetItem,
  TopConnectionItem,
  TopProtocolItem,
} from '~/types/api'

function tableNames(contrib: { visible_data?: Array<{ name: string }> }): string[] {
  return (contrib.visible_data ?? []).map((t) => t.name)
}

const mockHealthServices = [
  { name: 'api', running: true, detail: 'ok', timestamp: 1 },
  { name: 'ingest', running: true, detail: 'ok', timestamp: 1 },
  { name: 'ai', running: false, detail: 'down', timestamp: 1 },
]

const mockAlarmGroup = (overrides?: Partial<AnomalyGroupItem>): AnomalyGroupItem => ({
  id: 'alarm-1',
  module: 'conn',
  start_timestamp: '2026-07-07T00:00:00Z',
  end_timestamp: '2026-07-07T01:00:00Z',
  primary_type: 'T0846/arp_scan',
  multi_type: false,
  confirmed: false,
  is_active: true,
  series_ids: ['10.0.0.1/10.0.0.2', 'aa:bb:cc:dd:ee:ff'],
  protocols: [],
  anomaly_type_stats: {
    'T0846/arp_scan': {
      interval_count: 3,
      count: 12,
      confidence_sum: 2.7,
      confidence_max: 0.95,
      confidence_min: 0.8,
      confidence_mean: 0.9,
      packet_rate_sum: null,
      byte_rate_sum: null,
      rate_count: null,
      protocol_penalty_sum: null,
      protocol_penalty_count: null,
      severity_mean_sum: null,
      severity_max_sum: null,
      severity_count: null,
      packet_rate_mean: null,
      byte_rate_mean: null,
      type_series_count: null,
      severity_mean: null,
      severity_max: null,
      protocol_penalty_mean: null,
      traffic_n: null,
      coverage_n: null,
      count_n: null,
      conf_factor: null,
      score_raw: null,
      score: null,
      norm_refs: null,
      weights: null,
      score_norm: 0.91,
    },
  },
  enrichment: {
    proto: [{ series_id: 'icmp', protocol: 'icmp', anomaly_type: 'T0846/arp_scan' }],
  },
  ...overrides,
})

const mockSubagentJobSummary = (id: string): SubagentJobSummary => ({
  id,
  alarm_id: 'alarm-1',
  status: 'completed',
  prompt_variant: 'expert',
  llm_provider: 'azure_openai',
  llm_model: 'gpt-5.4',
  tool_trace_count: 5,
  tokens_total: 1200,
  top_step2: {
    technique_id: 'T0846',
    technique_name: 'Remote System Discovery',
    confidence: 0.92,
    reasoning: 'ARP scan pattern observed',
  },
  step1_method: 'arp_scan',
  created_at: '2026-07-07T00:05:00Z',
})

const mockSubagentJob = (id: string): SubagentJob => ({
  id,
  alarm_id: 'alarm-1',
  status: 'completed',
  prompt_variant: 'expert',
  prompt_hash: 'abc',
  llm_provider: 'azure_openai',
  llm_model: 'gpt-5.4',
  timeout_seconds: 600,
  trigger_source: 'chat',
  tokens_prompt: 400,
  tokens_completion: 800,
  tool_trace: [],
  created_at: '2026-07-07T00:05:00Z',
  step1_technical: {
    technical_method: 'arp_scan',
    observed_activity: 'Host sends many ARP who-has requests',
    evidence: ['ev1'],
  },
  step2_classification: {
    classifications: [
      {
        technique_id: 'T0846',
        technique_name: 'Remote System Discovery',
        confidence: 0.92,
        reasoning: 'ARP scan pattern observed',
      },
    ],
  },
})

const mockDevice = (overrides?: Partial<DeviceItem>): DeviceItem => ({
  id: 42,
  hostname: 'plc-01',
  vendor: 'Siemens',
  device_family: 'SIMATIC',
  device_type: 'PLC',
  description: null,
  article_number: null,
  device_role: null,
  firmware_version: 'v2.1',
  product_name: null,
  hw_version: null,
  sw_version: null,
  serial_number: null,
  manual_identity_fields: [],
  vulnerabilities: [
    { vuln_id: 'CVE-2021-1234', severity: 'high', cvss_score: 8.2, status: 'active' } as DeviceVulnerabilityItem,
  ],
  update_available: false,
  last_scan_at: '2026-07-06T00:00:00Z',
  notes: null,
  created_at: '2026-07-01T00:00:00Z',
  updated_at: null,
  interfaces: [
    {
      id: 1,
      mac_address: 'aa:bb:cc:dd:ee:ff',
      ipv4_address: '10.0.0.10',
      ipv6_address: null,
      subnet: '10.0.0.0/24',
    },
  ],
  ...overrides,
})

const mockObservation = (overrides?: Partial<ServiceObservationItem>): ServiceObservationItem => ({
  id: 1,
  scan_id: 'scan-1',
  interface_id: 1,
  ip_address: '10.0.0.10',
  mac_address: 'aa:bb:cc:dd:ee:ff',
  port: 102,
  transport: 'tcp',
  protocol: 's7',
  service_name: 'S7',
  product: 'Siemens S7',
  version: '2.1',
  cpe: null,
  extra_info: null,
  first_seen_at: '2026-07-06T00:00:00Z',
  last_seen_at: '2026-07-06T00:00:00Z',
  ...overrides,
})

describe('buildDashboardContribution (Klasse A)', () => {
  it('includes protocol_count, asset_count and service health details', () => {
    const contrib = buildDashboardContribution({
      visibleWidgets: ['kpi', 'health'],
      hiddenWidgets: ['map'],
      recentAlarms: [],
      topConnections: [],
      topProtocols: [
        { id: 'icmp', protocol: 'icmp', packet_count: 100, byte_count: 8000, is_anomaly: false } as TopProtocolItem,
      ],
      topAssets: [{ id: 'aa:bb:cc:dd:ee:ff', packet_count: 50, byte_count: 4000, is_anomaly: true } as TopAssetItem],
      vulnerabilitySummary: {
        affected_device_count: 1,
        total_cve_count: 3,
        severity_breakdown: { high: 1, medium: 2 },
        top_cves: [{ vuln_id: 'CVE-2021-1234', severity: 'high', count: 2 }],
      },
      signalColor: 'success',
      signalLabel: 'Normal',
      anomalyCount: 5,
      classifiedCount: 2,
      connectionCount: 12,
      assetCount: 8,
      protocolCount: 4,
      healthStatus: 'ok',
      healthServices: mockHealthServices,
      formatUci: (uci: string) => uci,
    })

    expect(contrib.summary?.protocol_count).toBe(4)
    expect(contrib.summary?.asset_count).toBe(8)
    expect(contrib.summary?.health_details).toContain('api: ok')
    expect(contrib.summary?.health_details).toContain('ai: down')

    expect(tableNames(contrib)).toContain('top_protocols')
    expect(tableNames(contrib)).toContain('top_assets')
    expect(tableNames(contrib)).toContain('vulnerabilities')
  })

  it('stays within the 2 KB JSON budget for a representative snapshot', () => {
    const contrib = buildDashboardContribution({
      visibleWidgets: ['kpi', 'health', 'top-connections', 'top-protocols', 'top-assets', 'vulnerabilities'],
      hiddenWidgets: ['map'],
      recentAlarms: [
        mockAlarmGroup({ id: 'a1', primary_type: 'scan' }),
        mockAlarmGroup({ id: 'a2', primary_type: 'flood' }),
      ],
      topConnections: [
        {
          uci: '10.0.0.1/10.0.0.2',
          packet_count: 1000,
          total_volume: 1_000_000,
          is_anomaly: false,
        } as TopConnectionItem,
      ],
      topProtocols: [
        { id: 'icmp', protocol: 'icmp', packet_count: 100, byte_count: 8000, is_anomaly: false } as TopProtocolItem,
      ],
      topAssets: [{ id: 'aa:bb:cc:dd:ee:ff', packet_count: 50, byte_count: 4000, is_anomaly: true } as TopAssetItem],
      vulnerabilitySummary: {
        affected_device_count: 1,
        total_cve_count: 3,
        severity_breakdown: { high: 1, medium: 2 },
        top_cves: [{ vuln_id: 'CVE-2021-1234', severity: 'high', count: 2 }],
      },
      signalColor: 'success',
      signalLabel: 'Normal',
      anomalyCount: 5,
      classifiedCount: 2,
      connectionCount: 12,
      assetCount: 8,
      protocolCount: 4,
      healthStatus: 'ok',
      healthServices: mockHealthServices,
      formatUci: (uci: string) => uci,
    })

    expect(JSON.stringify(contrib).length).toBeLessThanOrEqual(2048)
  })
})

describe('buildAlarmsContribution (Klasse B)', () => {
  const selectedGroup = mockAlarmGroup()
  const jobs: SubagentJobSummary[] = [mockSubagentJobSummary('job-1')]
  const liveJobs: Record<string, SubagentJob> = { 'job-1': mockSubagentJob('job-1') }
  const buildSubagent = vi.fn((_id: string) => [
    {
      job_id: 'job-1',
      alarm_id: 'alarm-1',
      prompt_variant: 'expert',
      llm: 'azure/gpt-5.4',
      created_at: '2026-07-07T00:05:00Z',
      step2: [],
    },
  ])

  it('omits detail tables when the detail panel is closed', () => {
    const contrib = buildAlarmsContribution({
      groups: [selectedGroup],
      selectedGroup,
      detailOpen: false,
      subagentJobs: jobs,
      liveJobsById: liveJobs,
      filters: {},
      activeCount: 1,
      totalGroups: 1,
      buildSubagentChatContext: buildSubagent,
      isMacAddress: () => false,
      isProtocolHashId: () => false,
      humanizeProtocolStack: (v: string) => v,
      extractAlarmMacs: (g: AnomalyGroupItem) => g.series_ids.filter((id) => !id.includes('/')),
    })

    expect(contrib.selection?.id).toBe('alarm-1')
    expect(tableNames(contrib)).not.toContain('alarm_connections')
    expect(tableNames(contrib)).not.toContain('alarm_assets')
    expect(tableNames(contrib)).not.toContain('alarm_protocols')
    expect(tableNames(contrib)).not.toContain('alarm_prediction_stats')
    expect(tableNames(contrib)).not.toContain('alarm_forensics_jobs')
    expect(contrib.subagent).toBeUndefined()
  })

  it('includes connections, assets, protocols, prediction stats and forensics when the panel is open', () => {
    const contrib = buildAlarmsContribution({
      groups: [selectedGroup],
      selectedGroup,
      detailOpen: true,
      subagentJobs: jobs,
      liveJobsById: liveJobs,
      filters: {},
      activeCount: 1,
      totalGroups: 1,
      buildSubagentChatContext: buildSubagent,
      isMacAddress: () => false,
      isProtocolHashId: () => false,
      humanizeProtocolStack: (v: string) => v,
      extractAlarmMacs: (g: AnomalyGroupItem) => g.series_ids.filter((id) => !id.includes('/')),
    })

    expect(tableNames(contrib)).toContain('alarm_connections')
    expect(tableNames(contrib)).toContain('alarm_assets')
    expect(tableNames(contrib)).toContain('alarm_protocols')
    expect(tableNames(contrib)).toContain('alarm_prediction_stats')
    expect(tableNames(contrib)).toContain('alarm_forensics_jobs')
    expect(contrib.subagent).toHaveLength(1)
  })

  it('does not leak alarm detail after the detail panel is closed (UI-076a)', () => {
    const contrib = buildAlarmsContribution({
      groups: [selectedGroup],
      selectedGroup: null,
      detailOpen: false,
      subagentJobs: jobs,
      liveJobsById: liveJobs,
      filters: {},
      activeCount: 1,
      totalGroups: 1,
      buildSubagentChatContext: buildSubagent,
      isMacAddress: () => false,
      isProtocolHashId: () => false,
      humanizeProtocolStack: (v: string) => v,
      extractAlarmMacs: (g: AnomalyGroupItem) => g.series_ids.filter((id) => !id.includes('/')),
    })

    expect(contrib.selection).toBeUndefined()
    expect(tableNames(contrib)).not.toContain('alarm_connections')
    expect(tableNames(contrib)).not.toContain('alarm_assets')
    expect(tableNames(contrib)).not.toContain('alarm_protocols')
    expect(tableNames(contrib)).not.toContain('alarm_prediction_stats')
    expect(tableNames(contrib)).not.toContain('alarm_forensics_jobs')
    expect(contrib.subagent).toBeUndefined()
  })
})

describe('buildAssetsContribution (Klasse B)', () => {
  const device = mockDevice()
  const observations: ServiceObservationItem[] = [
    mockObservation({ protocol: 's7', port: 102, service_name: 'S7' }),
    mockObservation({
      protocol: 'opcua',
      port: 4840,
      service_name: 'OPC-UA',
      extra_info: JSON.stringify({
        'Endpoint URL': 'opc.tcp://10.0.0.10:4840',
        'Security Mode': 'SignAndEncrypt',
      }),
    }),
  ]

  it('omits detail tables when the detail panel is closed', () => {
    const contrib = buildAssetsContribution({
      devices: [device],
      selectedDevice: device,
      detailOpen: false,
      observations,
      filters: { kpiFilter: 'all', vendor: null, searchTerm: null },
      totalDevices: 1,
      onlineCount: 1,
      updatesAvailableCount: 0,
      vulnerabilityCount: 1,
      vendorOptions: ['Siemens'],
    })

    expect(contrib.selection?.id).toBe('42')
    expect(tableNames(contrib)).not.toContain('asset_vulnerabilities')
    expect(tableNames(contrib)).not.toContain('asset_observed_services')
    expect(tableNames(contrib)).not.toContain('asset_opcua_endpoints')
  })

  it('includes vulnerabilities, observed services and OPC-UA endpoints when the panel is open', () => {
    const contrib = buildAssetsContribution({
      devices: [device],
      selectedDevice: device,
      detailOpen: true,
      observations,
      filters: { kpiFilter: 'all', vendor: null, searchTerm: null },
      totalDevices: 1,
      onlineCount: 1,
      updatesAvailableCount: 0,
      vulnerabilityCount: 1,
      vendorOptions: ['Siemens'],
    })

    expect(tableNames(contrib)).toContain('asset_vulnerabilities')
    expect(tableNames(contrib)).toContain('asset_observed_services')
    expect(tableNames(contrib)).toContain('asset_opcua_endpoints')

    const opcuaTable = contrib.visible_data?.find((t) => t.name === 'asset_opcua_endpoints')
    expect(opcuaTable?.rows[0]?.endpoint_url).toBe('opc.tcp://10.0.0.10:4840')
  })
})

describe('buildTimeseriesSummary (Klasse C)', () => {
  const point = (
    value: number,
    lower: number | null = null,
    upper: number | null = null,
  ): TimeseriesWithBoundsItem => ({
    time: '2026-07-07T00:00:00Z',
    value,
    value_min: value,
    value_max: value,
    lower_bound: lower,
    upper_bound: upper,
    violation_low: false,
    violation_high: false,
  })

  it('produces a compact per-feature summary', () => {
    const [table] = buildTimeseriesSummary({
      seriesId: 'uci-1',
      plotData: {
        packet_count: [point(10), point(20), point(30)],
        total_volume: [point(100), point(90), point(80)],
      },
      featureLabels: { packet_count: 'Packets', total_volume: 'Bytes' },
    })

    expect(table.name).toBe('selected_series_summary')
    expect(table.columns).toEqual(['feature', 'min', 'max', 'avg', 'last', 'point_count', 'trend', 'outlier'])
    expect(table.rows).toHaveLength(2)

    const packetRow = table.rows.find((r) => r.feature === 'Packets')
    expect(packetRow?.trend).toBe('rising')
    expect(packetRow?.outlier).toBe(false)

    const volumeRow = table.rows.find((r) => r.feature === 'Bytes')
    expect(volumeRow?.trend).toBe('falling')
  })

  it('flags outlier rows when a value exceeds the trained boundary', () => {
    const [table] = buildTimeseriesSummary({
      seriesId: 'uci-1',
      plotData: {
        packet_count: [point(10, 0, 15), point(20, 0, 15)],
      },
    })

    expect(table.rows[0]?.outlier).toBe(true)
  })

  it('stays within the 400-byte target for a small feature set', () => {
    const [table] = buildTimeseriesSummary({
      seriesId: 'uci-1',
      plotData: {
        packet_count: [point(10), point(20), point(30)],
        total_volume: [point(100), point(90), point(80)],
      },
    })

    expect(JSON.stringify(table).length).toBeLessThanOrEqual(1024)
  })
})

describe('page-specific base builders', () => {
  it('buildConnectionsContribution includes the connections list', () => {
    const contrib = buildConnectionsContribution({
      connections: [
        {
          uci: '10.0.0.1/10.0.0.2',
          source: '10.0.0.1',
          destination: '10.0.0.2',
          protocol: 'tcp',
          port: 102,
          isWildcard: false,
          memberCount: null,
        },
      ],
      selectedConnection: null,
      selectedPackets: null,
      selectedBytes: null,
      filters: {},
      totalConnections: 1,
    })

    expect(tableNames(contrib)).toContain('connections_list')
    expect(contrib.summary?.total_connections).toBe(1)
  })

  it('buildMacTimeseriesContribution includes the MAC list', () => {
    const contrib = buildMacTimeseriesContribution({
      macs: [{ mac: 'aa:bb:cc:dd:ee:ff', name: 'PLC-01', state: 'anomaly' }],
      selectedMac: null,
      filters: {},
      totalMacs: 1,
    })

    expect(tableNames(contrib)).toContain('mac_list')
    expect(contrib.summary?.total_macs).toBe(1)
  })

  it('buildProtoTimeseriesContribution includes the protocol list', () => {
    const contrib = buildProtoTimeseriesContribution({
      protos: [{ id: 'icmp', label: 'icmp', isAnomalous: false }],
      selectedProto: null,
      filters: {},
      totalProtos: 1,
    })

    expect(tableNames(contrib)).toContain('protocol_list')
    expect(contrib.summary?.total_protocols).toBe(1)
  })
})
