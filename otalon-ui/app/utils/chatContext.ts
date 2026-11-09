/**
 * Pure builder functions for per-page chat-context contributions.
 *
 * These helpers keep page providers short and make the snapshot logic
 * independently unit-testable. All functions return
 * :class:`ChatContextContribution` shapes and stay inside the compact
 * ≤ ~2 KB JSON budget by using truncation and small row caps.
 */

import type { ChatContextContribution, ChatSubagentClassification } from '#shared/uiContext'
import { makeVisibleTable } from '~/composables/useChatContext'
import type {
  AnomalyGroupItem,
  DeviceItem,
  DeviceVulnerabilityItem,
  HealthCheckItem,
  ServiceObservationItem,
  SubagentJob,
  SubagentJobSummary,
  TimeseriesWithBoundsItem,
  TopAssetItem,
  TopConnectionItem,
  TopProtocolItem,
  VulnerabilitySummaryData,
} from '~/types/api'
import { extractEndpointsFromJsonString } from '~/utils/opcua'
import { buildProtocolItems, classifySeriesIdentifier, humanizeProtocolStack, isProtocolHashId } from '~/utils/protocol'

interface DashboardContextInput {
  visibleWidgets: string[]
  hiddenWidgets: string[]
  recentAlarms: AnomalyGroupItem[]
  topConnections: TopConnectionItem[]
  topProtocols: TopProtocolItem[]
  topAssets: TopAssetItem[]
  vulnerabilitySummary: VulnerabilitySummaryData | null
  signalColor: string
  signalLabel: string
  anomalyCount: number
  classifiedCount: number
  connectionCount: number
  assetCount: number
  protocolCount: number
  healthStatus: string
  healthServices: HealthCheckItem[]
  formatUci: (uci: string) => string
}

interface AlarmContextInput {
  groups: AnomalyGroupItem[]
  selectedGroup: AnomalyGroupItem | null
  detailOpen: boolean
  subagentJobs: SubagentJobSummary[]
  liveJobsById: Record<string, SubagentJob | undefined>
  filters: { status?: string | null; module?: string | null; limit?: number | null }
  activeCount: number
  totalGroups: number
  buildSubagentChatContext: (alarmId: string) => ChatSubagentClassification[]
  isMacAddress: (value: string) => boolean
  isProtocolHashId: (value: string) => boolean
  humanizeProtocolStack: (value: string) => string
  extractAlarmMacs: (group: AnomalyGroupItem) => string[]
}

interface AssetContextInput {
  devices: DeviceItem[]
  selectedDevice: DeviceItem | null
  detailOpen: boolean
  observations: ServiceObservationItem[]
  filters: { kpiFilter: string; vendor: string | null; searchTerm: string | null }
  totalDevices: number
  onlineCount: number
  updatesAvailableCount: number
  vulnerabilityCount: number
  vendorOptions: string[]
}

interface TimeseriesContextInput {
  seriesId: string | null
  plotData: Record<string, TimeseriesWithBoundsItem[]>
  featureLabels?: Record<string, string>
}

interface ConnectionContextInput {
  connections: {
    uci: string
    source: string
    destination: string
    protocol: string
    port: number | null
    isWildcard: boolean
    memberCount?: number | null
  }[]
  selectedConnection: {
    uci: string
    source: string
    destination: string
    protocol: string
    port: number | null
    isWildcard: boolean
    memberCount?: number | null
  } | null
  selectedPackets: number | null
  selectedBytes: number | null
  filters: Record<string, unknown>
  totalConnections: number
}

interface MacContextInput {
  macs: { mac: string; name?: string | null; state?: string | null }[]
  selectedMac: { mac: string; name?: string | null; ip?: string | null; state?: string | null } | null
  filters: Record<string, unknown>
  totalMacs: number
}

interface ProtoContextInput {
  protos: { id: string; label: string; isAnomalous: boolean }[]
  selectedProto: { id: string; label: string } | null
  filters: Record<string, unknown>
  totalProtos: number
}

function primaryTypeLabel(primaryType: string | string[] | null | undefined): string {
  if (Array.isArray(primaryType)) return primaryType.join(',')
  return primaryType ?? ''
}

function compactNumber(value: number | null | undefined): number | null {
  if (value == null || Number.isNaN(value)) return null
  return Number(value.toFixed(1))
}

function nonNullNumbers(values: (number | null | undefined)[]): number[] {
  return values.filter((v): v is number => v != null && !Number.isNaN(v))
}

/**
 * Build the chat-context contribution for the Dashboard page (Klasse A).
 */
export function buildDashboardContribution(input: DashboardContextInput): ChatContextContribution {
  const recentAlarmsRows = input.recentAlarms.map((g) => ({
    id: g.id,
    is_active: g.is_active,
    confirmed: g.confirmed,
    primary_type: primaryTypeLabel(g.primary_type),
    start_timestamp: g.start_timestamp,
    series_count: g.series_ids?.length ?? 0,
  }))

  const topConnectionRows = input.topConnections.map((c) => ({
    uci: input.formatUci(c.uci),
    packet_count: c.packet_count ?? null,
    total_volume_bytes: c.byte_count ?? null,
  }))

  const topProtocolRows = input.topProtocols.map((p) => ({
    id: p.id,
    protocol: p.protocol,
    packet_count: p.packet_count ?? null,
    byte_count: p.byte_count ?? null,
    is_anomaly: p.is_anomaly,
  }))

  const topAssetRows = input.topAssets.map((a) => ({
    id: a.id,
    packet_count: a.packet_count ?? null,
    byte_count: a.byte_count ?? null,
    is_anomaly: a.is_anomaly,
  }))

  const vulnSummary = input.vulnerabilitySummary
  const vulnRows = vulnSummary
    ? vulnSummary.top_cves.map((c) => ({
        vuln_id: c.vuln_id,
        severity: c.severity,
        count: c.count,
      }))
    : []

  const healthDetails = input.healthServices
    .map((s) => (s.running ? `${s.name}: ok` : `${s.name}: ${s.detail || 'unavailable'}`))
    .join('; ')

  const summary: Record<string, string | number | boolean | null> = {
    signal: input.signalColor,
    signal_label: input.signalLabel,
    anomaly_count: input.anomalyCount,
    classified_count: input.classifiedCount,
    connection_count: input.connectionCount,
    asset_count: input.assetCount,
    protocol_count: input.protocolCount,
    health_status: input.healthStatus,
    ...(healthDetails ? { health_details: healthDetails } : {}),
  }

  if (vulnSummary) {
    summary.vulnerability_device_count = vulnSummary.affected_device_count
    summary.vulnerability_total_count = vulnSummary.total_cve_count
    summary.vulnerability_severity_breakdown = Object.entries(vulnSummary.severity_breakdown)
      .map(([k, v]) => `${k}:${v}`)
      .join(',')
  }

  return {
    widgets: { visible: input.visibleWidgets, hidden: input.hiddenWidgets },
    summary,
    visible_data: [
      makeVisibleTable(
        'recent_alarms',
        ['id', 'is_active', 'confirmed', 'primary_type', 'start_timestamp', 'series_count'],
        recentAlarmsRows,
      ),
      makeVisibleTable('top_connections', ['uci', 'packet_count', 'total_volume_bytes'], topConnectionRows),
      makeVisibleTable(
        'top_protocols',
        ['id', 'protocol', 'packet_count', 'byte_count', 'is_anomaly'],
        topProtocolRows,
      ),
      makeVisibleTable('top_assets', ['id', 'packet_count', 'byte_count', 'is_anomaly'], topAssetRows),
      makeVisibleTable('vulnerabilities', ['vuln_id', 'severity', 'count'], vulnRows),
    ],
  }
}

function buildTypeStatsContribution(selectedGroup: AnomalyGroupItem): ChatContextContribution['visible_data'] {
  const rows = Object.entries(selectedGroup.anomaly_type_stats)
    .map(([type, stat]) => ({
      type,
      score_norm: compactNumber(stat.score_norm),
      confidence_mean: stat.confidence_mean != null ? Math.round(stat.confidence_mean * 100) : null,
      interval_count: stat.interval_count,
      count: stat.count,
    }))
    .sort((a, b) => (b.score_norm ?? 0) - (a.score_norm ?? 0))

  return [
    makeVisibleTable(
      'alarm_prediction_stats',
      ['type', 'score_norm', 'confidence_mean', 'interval_count', 'count'],
      rows,
    ),
  ]
}

function buildConnectionAlarmIds(group: AnomalyGroupItem): string[] {
  const mod = group.module ?? ''
  const isConnectionAlarm = mod === 'conn' || mod === 'netcap'
  return isConnectionAlarm ? group.series_ids.filter((id) => id.includes('/')) : []
}

function parseEnrichmentBucket(
  group: AnomalyGroupItem,
  bucket: 'mac' | 'proto',
): Array<{ series_id: string; protocol: string | null; anomaly_type: string | null }> {
  const enr = group.enrichment as Record<string, unknown> | null | undefined
  const value = enr?.[bucket]
  if (!Array.isArray(value)) return []
  return value
    .filter((item): item is Record<string, unknown> => item != null && typeof item === 'object')
    .map((item) => ({
      series_id: String(item.series_id ?? '—'),
      protocol: item.protocol != null ? String(item.protocol) : null,
      anomaly_type: item.anomaly_type != null ? String(item.anomaly_type) : null,
    }))
}

function buildProtoItems(
  group: AnomalyGroupItem,
): { id: string; label: string }[] {
  if (group.module === 'proto_traffic') {
    return buildProtocolItems(group.series_ids, group.protocols ?? [])
  }
  const map = new Map<string, { id: string; label: string }>()
  for (const id of group.series_ids) {
    if (classifySeriesIdentifier(id) !== 'protocol') continue
    map.set(id, { id, label: humanizeProtocolStack(id) })
  }
  for (const e of parseEnrichmentBucket(group, 'proto')) {
    if (isProtocolHashId(e.series_id)) continue
    map.set(e.series_id, { id: e.series_id, label: humanizeProtocolStack(e.protocol ?? e.series_id) })
  }
  return Array.from(map.values())
}

function buildForensicsJobRows(
  jobs: SubagentJobSummary[],
  liveJobsById: Record<string, SubagentJob | undefined>,
): Array<Record<string, string | number | boolean | null>> {
  return jobs.map((job) => {
    const full = liveJobsById[job.id]
    const top = job.top_step2
    const preview =
      full?.step1_technical?.observed_activity ?? full?.step1_technical?.technical_method ?? top?.reasoning ?? null
    return {
      job_id: job.id,
      status: job.status,
      step1_method: job.step1_method ?? full?.step1_technical?.technical_method ?? null,
      top_technique: top?.technique_id ?? null,
      confidence: top?.confidence ?? null,
      verdict: full?.verdict ?? (job.verdict_outcome ? { outcome: job.verdict_outcome } : null),
      output_preview: preview,
    }
  })
}

/**
 * Build the chat-context contribution for the Alarms page (Klasse B).
 */
export function buildAlarmsContribution(input: AlarmContextInput): ChatContextContribution {
  const visibleGroups = input.groups
  const visibleRows = visibleGroups.map((g) => ({
    id: g.id,
    is_active: g.is_active,
    confirmed: g.confirmed,
    primary_type: primaryTypeLabel(g.primary_type),
    module: g.module ?? null,
    start_timestamp: g.start_timestamp,
    series_count: g.series_ids?.length ?? 0,
  }))

  const sel = input.selectedGroup
  const selection = sel
    ? {
        kind: 'alarm' as const,
        id: sel.id,
        label: primaryTypeLabel(sel.primary_type),
        fields: {
          is_active: sel.is_active,
          confirmed: sel.confirmed,
          start_timestamp: sel.start_timestamp,
          end_timestamp: sel.end_timestamp,
          series_count: sel.series_ids?.length ?? 0,
          multi_type: sel.multi_type,
        },
      }
    : undefined

  const visibleData: ChatContextContribution['visible_data'] = [
    makeVisibleTable(
      'alarms_list',
      ['id', 'is_active', 'confirmed', 'primary_type', 'module', 'start_timestamp', 'series_count'],
      visibleRows,
    ),
  ]

  let subagent: ChatSubagentClassification[] | undefined

  if (sel && input.detailOpen) {
    const connectionIds = buildConnectionAlarmIds(sel)
    const macIds = input.extractAlarmMacs(sel)
    const protoItems = buildProtoItems(sel)

    visibleData.push(
      makeVisibleTable(
        'alarm_connections',
        ['uci'],
        connectionIds.map((id) => ({ uci: id })),
      ),
      makeVisibleTable(
        'alarm_assets',
        ['mac'],
        macIds.map((mac) => ({ mac })),
      ),
      makeVisibleTable(
        'alarm_protocols',
        ['id', 'label'],
        protoItems.map((p) => ({ id: p.id, label: p.label })),
      ),
      ...buildTypeStatsContribution(sel),
    )

    const completedJobs = input.subagentJobs.filter((j) => j.status === 'completed')
    if (completedJobs.length > 0) {
      visibleData.push(
        makeVisibleTable(
          'alarm_forensics_jobs',
          ['job_id', 'status', 'step1_method', 'top_technique', 'output_preview'],
          buildForensicsJobRows(completedJobs, input.liveJobsById),
        ),
      )
    }

    subagent = input.buildSubagentChatContext(sel.id)
  }

  return {
    selection,
    filters: {
      status: input.filters.status ?? null,
      module: input.filters.module ?? null,
      limit: input.filters.limit ?? null,
    },
    summary: {
      total_groups: input.totalGroups,
      active_count: input.activeCount,
      filtered_count: visibleGroups.length,
    },
    visible_data: visibleData,
    ...(subagent && subagent.length > 0 ? { subagent } : {}),
  }
}

function buildVulnerabilityRows(vulns: DeviceVulnerabilityItem[]): Array<Record<string, unknown>> {
  return vulns.map((v) => ({
    vuln_id: v.vuln_id ?? v.cve ?? v.id ?? '?',
    severity: v.severity ?? null,
    cvss_score: v.cvss_score ?? null,
    status: v.status ?? null,
  }))
}

function buildServiceRows(observations: ServiceObservationItem[]): Array<Record<string, unknown>> {
  return observations
    .filter((o) => o.protocol !== 'opcua')
    .map((o) => ({
      port_transport: o.port != null && o.transport ? `${o.port}/${o.transport}` : null,
      service_name: o.service_name ?? null,
      product: [o.product, o.version].filter(Boolean).join(' ') || null,
      ip_address: o.ip_address ?? null,
    }))
}

function buildOpcUaRows(observations: ServiceObservationItem[]): Array<Record<string, unknown>> {
  const rows: Array<Record<string, unknown>> = []
  for (const obs of observations.filter((o) => o.protocol === 'opcua')) {
    const endpoints = extractEndpointsFromJsonString(obs.extra_info)
    if (endpoints.length === 0) {
      rows.push({
        port_transport: obs.port != null && obs.transport ? `${obs.port}/${obs.transport}` : null,
        service_name: obs.service_name ?? null,
        endpoint_url: null,
        security_mode: null,
      })
      continue
    }
    for (const ep of endpoints) {
      rows.push({
        port_transport: obs.port != null && obs.transport ? `${obs.port}/${obs.transport}` : null,
        service_name: obs.service_name ?? null,
        endpoint_url: ep.url,
        security_mode: ep.securityMode,
      })
    }
  }
  return rows
}

/**
 * Build the chat-context contribution for the Asset List page (Klasse B).
 */
export function buildAssetsContribution(input: AssetContextInput): ChatContextContribution {
  const rows = input.devices.map((d) => {
    const firstIface = d.interfaces[0] ?? null
    const vulnCount = Array.isArray(d.vulnerabilities) ? d.vulnerabilities.length : 0
    return {
      id: d.id,
      vendor: d.vendor,
      device_family: d.device_family,
      device_type: d.device_type,
      hostname: d.hostname,
      device_role: d.device_role,
      firmware_version: d.firmware_version,
      ip: firstIface?.ipv4_address ?? firstIface?.ipv6_address ?? null,
      mac: firstIface?.mac_address ?? null,
      update_available: d.update_available,
      vulnerability_count: vulnCount,
    }
  })

  const sel = input.selectedDevice
  const selection = sel
    ? {
        kind: 'asset' as const,
        id: String(sel.id),
        label: sel.device_family || sel.device_type || sel.vendor || `Device ${sel.id}`,
        fields: {
          vendor: sel.vendor,
          device_family: sel.device_family,
          device_type: sel.device_type,
          hostname: sel.hostname,
          device_role: sel.device_role,
          firmware_version: sel.firmware_version,
          update_available: sel.update_available,
          interface_count: sel.interfaces.length,
          primary_ip: sel.interfaces[0]?.ipv4_address ?? sel.interfaces[0]?.ipv6_address ?? null,
          primary_mac: sel.interfaces[0]?.mac_address ?? null,
          vulnerability_count: Array.isArray(sel.vulnerabilities) ? sel.vulnerabilities.length : 0,
          last_scan_at: sel.last_scan_at,
        },
      }
    : undefined

  const visibleData: ChatContextContribution['visible_data'] = [
    makeVisibleTable(
      'assets_list',
      [
        'id',
        'vendor',
        'device_family',
        'device_type',
        'firmware_version',
        'ip',
        'mac',
        'update_available',
        'vulnerability_count',
      ],
      rows,
    ),
  ]

  if (sel && input.detailOpen) {
    const vulns = Array.isArray(sel.vulnerabilities) ? sel.vulnerabilities : []
    visibleData.push(
      makeVisibleTable(
        'asset_vulnerabilities',
        ['vuln_id', 'severity', 'cvss_score', 'status'],
        buildVulnerabilityRows(vulns),
      ),
      makeVisibleTable(
        'asset_observed_services',
        ['port_transport', 'service_name', 'product', 'ip_address'],
        buildServiceRows(input.observations),
      ),
      makeVisibleTable(
        'asset_opcua_endpoints',
        ['port_transport', 'service_name', 'endpoint_url', 'security_mode'],
        buildOpcUaRows(input.observations),
      ),
    )
  }

  return {
    selection,
    filters: {
      kpi_filter: input.filters.kpiFilter,
      vendor: input.filters.vendor,
      search_term: input.filters.searchTerm,
    },
    summary: {
      total_devices: input.totalDevices,
      filtered_count: input.devices.length,
      online_count: input.onlineCount,
      updates_available_count: input.updatesAvailableCount,
      vulnerability_count: input.vulnerabilityCount,
      vendors_loaded: input.vendorOptions.length,
    },
    visible_data: visibleData,
  }
}

/**
 * Compute a compact statistical summary of the currently selected
 * timeseries (Klasse C). One row per visible feature with min/max/avg/last,
 * point count, coarse trend and an outlier flag.
 */
export function buildTimeseriesSummary(input: TimeseriesContextInput): ChatContextContribution['visible_data'] {
  if (!input.seriesId) return []

  const rows: Array<Record<string, unknown>> = []
  for (const [feature, points] of Object.entries(input.plotData)) {
    const values = nonNullNumbers(points.map((p) => p.value))
    if (values.length === 0) {
      rows.push({
        feature: input.featureLabels?.[feature] ?? feature,
        min: null,
        max: null,
        avg: null,
        last: null,
        point_count: 0,
        trend: 'flat',
        outlier: false,
      })
      continue
    }

    const first = values[0]
    const last = values[values.length - 1]
    const min = Math.min(...values)
    const max = Math.max(...values)
    const avg = values.reduce((a, b) => a + b, 0) / values.length

    let trend: 'rising' | 'falling' | 'flat' = 'flat'
    if (first !== 0 && last != null) {
      if (last > first * 1.05) trend = 'rising'
      else if (last < first * 0.95) trend = 'falling'
    } else if (first === 0 && last != null && last > 0) {
      trend = 'rising'
    }

    const outlier = points.some(
      (p) =>
        p.violation_low ||
        p.violation_high ||
        (p.value != null && p.lower_bound != null && p.value < p.lower_bound) ||
        (p.value != null && p.upper_bound != null && p.value > p.upper_bound),
    )

    rows.push({
      feature: input.featureLabels?.[feature] ?? feature,
      min: compactNumber(min),
      max: compactNumber(max),
      avg: compactNumber(avg),
      last: compactNumber(last),
      point_count: points.length,
      trend,
      outlier,
    })
  }

  return [
    makeVisibleTable(
      'selected_series_summary',
      ['feature', 'min', 'max', 'avg', 'last', 'point_count', 'trend', 'outlier'],
      rows,
    ),
  ]
}

/**
 * Build the chat-context contribution for the Connections page.
 */
export function buildConnectionsContribution(input: ConnectionContextInput): ChatContextContribution {
  const rows = input.connections.map((c) => ({
    uci: c.uci,
    source: c.source,
    destination: c.destination,
    protocol: c.protocol,
    port: c.port,
    is_wildcard: c.isWildcard,
    member_count: c.memberCount ?? null,
  }))

  const sel = input.selectedConnection
  const selection = sel
    ? {
        kind: 'connection' as const,
        id: sel.uci,
        label: `${sel.source} → ${sel.destination} (${sel.protocol})`,
        fields: {
          source: sel.source,
          destination: sel.destination,
          protocol: sel.protocol,
          port: sel.port,
          is_wildcard: sel.isWildcard,
          member_count: sel.memberCount ?? null,
        },
      }
    : undefined

  const summary: Record<string, unknown> = {
    total_connections: input.totalConnections,
    filtered_connections: input.connections.length,
  }
  if (input.selectedPackets != null) summary.selected_conn_packets = input.selectedPackets
  if (input.selectedBytes != null) summary.selected_conn_bytes = input.selectedBytes

  return {
    selection,
    filters: input.filters,
    summary,
    visible_data: [
      makeVisibleTable('connections_list', ['uci', 'source', 'destination', 'protocol', 'port', 'is_wildcard'], rows),
    ],
  }
}

/**
 * Build the chat-context contribution for the MAC Timeseries page.
 */
export function buildMacTimeseriesContribution(input: MacContextInput): ChatContextContribution {
  const selection = input.selectedMac
    ? {
        kind: 'mac' as const,
        id: input.selectedMac.mac,
        label: input.selectedMac.name || input.selectedMac.mac,
        fields: {
          ip: input.selectedMac.ip ?? null,
          state: input.selectedMac.state ?? null,
        },
      }
    : undefined

  const rows = input.macs.map((m) => ({
    mac: m.mac,
    label: m.name ?? m.mac,
    is_anomalous: m.state === 'anomaly',
  }))

  return {
    selection,
    filters: input.filters,
    summary: {
      total_macs: input.totalMacs,
      filtered_macs: input.macs.length,
    },
    visible_data: [makeVisibleTable('mac_list', ['mac', 'label', 'is_anomalous'], rows)],
  }
}

/**
 * Build the chat-context contribution for the Protocol Timeseries page.
 */
export function buildProtoTimeseriesContribution(input: ProtoContextInput): ChatContextContribution {
  const selection = input.selectedProto
    ? {
        kind: 'protocol' as const,
        id: input.selectedProto.id,
        label: input.selectedProto.label,
        fields: {},
      }
    : undefined

  const rows = input.protos.map((p) => ({
    id: p.id,
    label: p.label,
    is_anomalous: p.isAnomalous,
  }))

  return {
    selection,
    filters: input.filters,
    summary: {
      total_protocols: input.totalProtos,
      filtered_protocols: input.protos.length,
    },
    visible_data: [makeVisibleTable('protocol_list', ['id', 'label', 'is_anomalous'], rows)],
  }
}
