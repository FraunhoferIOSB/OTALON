/**
 * MSW v2 request handlers for Phase 4 + Phase 5a API endpoints.
 *
 * Provides default happy-path handlers using golden data, plus
 * named error handlers that individual tests can activate via
 * `server.use(errorHandlers.kpi500)`.
 */
import { http, HttpResponse, delay } from 'msw'

import {
  GOLDEN_ALARM_GROUPS,
  GOLDEN_ALARM_INTERVALS,
  GOLDEN_ATTENTION,
  GOLDEN_BOUNDS_DATA,
  GOLDEN_CAPTURE_STATUS,
  GOLDEN_CONTAINER_LIST,
  GOLDEN_DEVICES,
  GOLDEN_ENV,
  GOLDEN_FEATURES,
  GOLDEN_HEALTH,
  GOLDEN_HEALTH_INCIDENTS,
  GOLDEN_KPI,
  GOLDEN_MAC_ALARM_INTERVALS,
  GOLDEN_MAC_BOUNDS_DATA,
  GOLDEN_MAC_FEATURES,
  GOLDEN_MAC_LIST,
  GOLDEN_PASSIVE_DISCOVERY,
  GOLDEN_PASSIVE_SEEDER_STATUS,
  GOLDEN_PIPELINE,
  GOLDEN_PROTO_LIST,
  GOLDEN_SINGLE_POINT_DATA,
  GOLDEN_TOP_ASSETS,
  GOLDEN_TOPOLOGY_GRAPH,
  GOLDEN_TOP_PROTOCOLS,
  GOLDEN_UCI_LIST,
} from './golden-data'

export const handlers = [
  http.get('*/api/v1/dashboard/kpis', () => {
    return HttpResponse.json({
      data: [GOLDEN_KPI],
      row_count: 1,
      parameters: {},
    })
  }),

  http.get('*/api/v1/dashboard/top-assets', () => {
    return HttpResponse.json({
      data: GOLDEN_TOP_ASSETS,
      row_count: GOLDEN_TOP_ASSETS.length,
      parameters: {},
    })
  }),

  http.get('*/api/v1/dashboard/top-protocols', () => {
    return HttpResponse.json({
      data: GOLDEN_TOP_PROTOCOLS,
      row_count: GOLDEN_TOP_PROTOCOLS.length,
      parameters: {},
    })
  }),

  http.get('*/api/v1/dashboard/layout', () => {
    return HttpResponse.json({ detail: 'No dashboard layout saved' }, { status: 404 })
  }),

  http.put('*/api/v1/dashboard/layout', async ({ request }) => {
    const body = (await request.json()) as { version: number; layout: unknown[]; hidden: string[] }
    return HttpResponse.json(body)
  }),

  // Default tour state: not completed. Tests that need a completed
  // account override this with server.use(http.get(...)).
  http.get('*/api/v1/dashboard/tour', () => {
    return HttpResponse.json({ completed: false })
  }),

  http.put('*/api/v1/dashboard/tour', async ({ request }) => {
    const body = (await request.json()) as { completed: boolean }
    return HttpResponse.json({ completed: body.completed })
  }),

  http.get('*/api/v1/anomalies/groups', ({ request }) => {
    const url = new URL(request.url)
    const limit = Number(url.searchParams.get('limit') ?? '100')
    const module = url.searchParams.get('module')
    const sort = url.searchParams.get('sort')

    let groups = [...GOLDEN_ALARM_GROUPS]

    if (module) {
      groups = groups.filter((g) => g.module === module)
    }

    groups = groups.slice(0, limit)

    return HttpResponse.json({
      data: groups,
      row_count: groups.length,
      parameters: { limit, ...(module && { module }), ...(sort && { sort }) },
    })
  }),

  http.patch('*/api/v1/anomalies/groups/:groupId', async ({ request, params }) => {
    const body = (await request.json()) as { confirmed: boolean }
    const groupId = params.groupId as string

    return HttpResponse.json({
      result: { group_id: groupId, confirmed: body.confirmed, rows_affected: 1 },
      parameters: { group_id: groupId },
    })
  }),

  // alarmsStore.loadAffectedFeatures (alarmsStore.ts:224) queries this
  // endpoint. Without a handler the request escaped MSW and opened a real
  // TCP connection to localhost:3000, surfacing as an unhandled
  // ECONNREFUSED rejection during the store tests (SUITE-034).
  http.get('*/api/v1/anomalies/series', () => {
    return HttpResponse.json({ data: [], row_count: 0 })
  }),

  // alarmsStore.loadAffectedFeatures also resolves bound thresholds here.
  // Missing handler => real network request (SUITE-034).
  http.get('*/api/v1/operations/bounds', () => {
    return HttpResponse.json({ data: [], row_count: 0 })
  }),

  http.get('*/api/v1/status/health', () => {
    return HttpResponse.json(GOLDEN_HEALTH)
  }),

  http.get('*/api/v1/operations/health-incidents/:id', ({ params }) => {
    const match = GOLDEN_HEALTH_INCIDENTS.items.find((incident) => incident.id === params.id)
    if (!match) return HttpResponse.json({ detail: 'Health incident not found' }, { status: 404 })
    return HttpResponse.json(match)
  }),

  http.get('*/api/v1/operations/health-incidents', ({ request }) => {
    const status = new URL(request.url).searchParams.get('status')
    const items = status
      ? GOLDEN_HEALTH_INCIDENTS.items.filter((incident) => incident.status === status)
      : GOLDEN_HEALTH_INCIDENTS.items
    return HttpResponse.json({ items, retention: GOLDEN_HEALTH_INCIDENTS.retention })
  }),

  http.get('*/api/v1/operations/pipeline', () => {
    return HttpResponse.json(GOLDEN_PIPELINE)
  }),

  http.get('*/api/v1/operations/attention', () => {
    return HttpResponse.json(GOLDEN_ATTENTION)
  }),

  http.get('*/api/v1/operations/detection/readiness', () => {
    return HttpResponse.json({
      modules: [
        { module: 'conn', state: 'ready' },
        { module: 'mac_traffic', state: 'ready' },
        { module: 'proto_traffic', state: 'untrained' },
      ],
    })
  }),

  http.get('*/api/v1/operations/storage', () => {
    return HttpResponse.json({
      host: {
        total_gib: 100,
        used_gib: 62.5,
        free_gib: 37.5,
        used_pct: 62.5,
        mount: '/',
        fs: 'ext4',
      },
      ringbuffer: { size_gib: 1, cap_gib: 48.8, files: 2, file_cap: 2000, state: 'rotating' },
      contributors: [],
      unattributed_gib: 62.5,
    })
  }),

  http.get('*/api/v1/operations/capture-status', () => {
    return HttpResponse.json(GOLDEN_CAPTURE_STATUS)
  }),

  http.get('*/api/v1/operations/passive-discovery', () => {
    return HttpResponse.json(GOLDEN_PASSIVE_DISCOVERY)
  }),

  http.get('*/api/v1/operations/passive-seeder/status', () => {
    return HttpResponse.json(GOLDEN_PASSIVE_SEEDER_STATUS)
  }),

  // PCAP import (UI-078 Wave D). The default listing is empty so the
  // honest empty state is what a page test sees unless it overrides.
  http.get('*/api/v1/operations/pcap-import', () => {
    return HttpResponse.json({ items: [], total: 0 })
  }),

  http.get('*/api/v1/timeseries/ids', ({ request }) => {
    const url = new URL(request.url)
    const start = url.searchParams.get('start') ?? ''
    const stop = url.searchParams.get('stop') ?? ''
    const nonzero = url.searchParams.get('nonzero') === 'true'

    return HttpResponse.json({
      start,
      stop,
      nonzero,
      count: GOLDEN_UCI_LIST.length,
      data: GOLDEN_UCI_LIST,
    })
  }),

  http.get('*/api/v1/timeseries/features', () => {
    return HttpResponse.json({
      features: GOLDEN_FEATURES,
    })
  }),

  http.get('*/api/v1/anomalies/bounds', ({ request }) => {
    const url = new URL(request.url)
    const uci = url.searchParams.get('uci') ?? ''
    const metric = url.searchParams.get('metric') ?? ''
    const start = url.searchParams.get('start') ?? ''
    const stop = url.searchParams.get('stop') ?? ''

    return HttpResponse.json({
      data: GOLDEN_BOUNDS_DATA,
      row_count: GOLDEN_BOUNDS_DATA.length,
      parameters: { uci, metric, module: 'netcap', start, stop },
    })
  }),

  http.get('*/api/v1/anomalies/intervals', ({ request }) => {
    const url = new URL(request.url)
    const uci = url.searchParams.get('uci') ?? ''
    const start = url.searchParams.get('start') ?? ''
    const stop = url.searchParams.get('stop') ?? ''

    return HttpResponse.json({
      data: GOLDEN_ALARM_INTERVALS,
      row_count: GOLDEN_ALARM_INTERVALS.length,
      parameters: { uci, module: 'netcap', start, stop },
    })
  }),

  // Proto timeseries endpoints
  http.get('*/api/v1/timeseries/proto/ids', ({ request }) => {
    const url = new URL(request.url)
    const start = url.searchParams.get('start') ?? ''
    const stop = url.searchParams.get('stop') ?? ''
    const nonzero = url.searchParams.get('nonzero') === 'true'

    return HttpResponse.json({
      start,
      stop,
      nonzero,
      count: GOLDEN_PROTO_LIST.length,
      data: GOLDEN_PROTO_LIST,
    })
  }),

  http.get('*/api/v1/timeseries/proto/features', () => {
    return HttpResponse.json({
      features: ['proto_total_packets', 'proto_total_volume', 'proto_conn_count'],
    })
  }),

  // MAC timeseries endpoints
  http.get('*/api/v1/timeseries/mac/ids', ({ request }) => {
    const url = new URL(request.url)
    const start = url.searchParams.get('start') ?? ''
    const stop = url.searchParams.get('stop') ?? ''
    const nonzero = url.searchParams.get('nonzero') === 'true'

    return HttpResponse.json({
      start,
      stop,
      nonzero,
      count: GOLDEN_MAC_LIST.length,
      data: GOLDEN_MAC_LIST,
    })
  }),

  http.get('*/api/v1/timeseries/mac/features', () => {
    return HttpResponse.json({
      features: GOLDEN_MAC_FEATURES,
    })
  }),

  http.get('*/api/v1/anomalies/mac/bounds', ({ request }) => {
    const url = new URL(request.url)
    const seriesId = url.searchParams.get('series_id') ?? ''
    const metric = url.searchParams.get('metric') ?? ''
    const start = url.searchParams.get('start') ?? ''
    const stop = url.searchParams.get('stop') ?? ''

    return HttpResponse.json({
      data: GOLDEN_MAC_BOUNDS_DATA,
      row_count: GOLDEN_MAC_BOUNDS_DATA.length,
      parameters: { series_id: seriesId, metric, module: 'mac_traffic', start, stop },
    })
  }),

  http.get('*/api/v1/anomalies/mac/intervals', ({ request }) => {
    const url = new URL(request.url)
    const seriesId = url.searchParams.get('series_id') ?? ''
    const start = url.searchParams.get('start') ?? ''
    const stop = url.searchParams.get('stop') ?? ''

    return HttpResponse.json({
      data: GOLDEN_MAC_ALARM_INTERVALS,
      row_count: GOLDEN_MAC_ALARM_INTERVALS.length,
      parameters: { series_id: seriesId, module: 'mac_traffic', start, stop },
    })
  }),

  http.get('*/api/v1/topology/graph', ({ request }) => {
    // start/stop accepted for URL-shape parity but ignored — the golden
    // fixture is a single snapshot, so any time window returns it.
    const url = new URL(request.url)
    const _start = url.searchParams.get('start') ?? ''
    const _stop = url.searchParams.get('stop') ?? ''

    return HttpResponse.json(GOLDEN_TOPOLOGY_GRAPH)
  }),

  http.get('*/api/v1/topology/devices', ({ request }) => {
    const url = new URL(request.url)
    const limit = Number(url.searchParams.get('limit') ?? '100')
    const offset = Number(url.searchParams.get('offset') ?? '0')

    const sliced = GOLDEN_DEVICES.slice(offset, offset + limit)

    return HttpResponse.json({
      devices: sliced,
      total: GOLDEN_DEVICES.length,
    })
  }),

  http.put('*/api/v1/topology/devices/:deviceId/type', async ({ request, params }) => {
    const body = (await request.json()) as { device_type: string }
    const deviceId = Number(params.deviceId)

    return HttpResponse.json({
      device_id: deviceId,
      device_type: body.device_type,
      previous_type: 'Other',
      message: 'Device type updated',
    })
  }),

  // =========================================================================
  // Admin Endpoints (Phase 6 — Management)
  // =========================================================================

  http.get('*/api/v1/admin/containers', () => {
    return HttpResponse.json(GOLDEN_CONTAINER_LIST)
  }),

  http.get('*/api/v1/admin/containers/:name/logs', ({ params }) => {
    const name = params.name as string
    return HttpResponse.json({
      name,
      lines: 50,
      logs: `2026-03-26 10:00:00 LOG: ${name} service started\n2026-03-26 10:00:01 LOG: Listening on configured port\n2026-03-26 10:00:02 LOG: Ready to accept connections`,
    })
  }),

  http.post('*/api/v1/admin/compose/action', async ({ request }) => {
    const body = (await request.json()) as { service: string; action: string }
    return HttpResponse.json({
      service: body.service,
      action: body.action,
      exit_code: 0,
      output: `${body.action} ${body.service} ... done`,
      success: true,
    })
  }),

  http.get('*/api/v1/admin/env', () => {
    return HttpResponse.json(GOLDEN_ENV)
  }),

  http.put('*/api/v1/admin/env/:key', async ({ params, request }) => {
    const key = params.key as string
    const body = (await request.json()) as { value: string }
    const updatedEnv = { ...GOLDEN_ENV.env, [key]: body.value }
    return HttpResponse.json({
      env: updatedEnv,
      changed_keys: [key],
      backup_path: '/workspace/.env.compose.bak.20260326_183000',
    })
  }),

  http.post('*/api/v1/admin/db/truncate', async ({ request }) => {
    const body = (await request.json()) as { table: string }
    return HttpResponse.json({
      table: body.table,
      success: true,
      message: `Table ${body.table} truncated successfully`,
    })
  }),
]

export const errorHandlers = {
  kpi500: http.get('*/api/v1/dashboard/kpis', () => {
    return HttpResponse.json({ detail: 'Internal server error' }, { status: 500 })
  }),

  groups404: http.get('*/api/v1/anomalies/groups', () => {
    return HttpResponse.json({ detail: 'Not found' }, { status: 404 })
  }),

  patchTimeout: http.patch('*/api/v1/anomalies/groups/:groupId', async () => {
    await delay(10_000)
    return HttpResponse.json({ detail: 'Gateway timeout' }, { status: 504 })
  }),

  health503: http.get('*/api/v1/status/health', () => {
    return HttpResponse.json({ detail: 'Service unavailable' }, { status: 503 })
  }),

  ids500: http.get('*/api/v1/timeseries/ids', () => {
    return HttpResponse.json({ detail: 'Internal server error' }, { status: 500 })
  }),

  features500: http.get('*/api/v1/timeseries/features', () => {
    return HttpResponse.json({ detail: 'Internal server error' }, { status: 500 })
  }),

  bounds500: http.get('*/api/v1/anomalies/bounds', () => {
    return HttpResponse.json({ detail: 'Internal server error' }, { status: 500 })
  }),

  intervals500: http.get('*/api/v1/anomalies/intervals', () => {
    return HttpResponse.json({ detail: 'Internal server error' }, { status: 500 })
  }),

  topologyGraph500: http.get('*/api/v1/topology/graph', () => {
    return HttpResponse.json({ detail: 'Internal server error' }, { status: 500 })
  }),

  devices500: http.get('*/api/v1/topology/devices', () => {
    return HttpResponse.json({ detail: 'Internal server error' }, { status: 500 })
  }),

  deviceTypePut500: http.put('*/api/v1/topology/devices/:deviceId/type', () => {
    return HttpResponse.json({ detail: 'Internal server error' }, { status: 500 })
  }),

  containers401: http.get('*/api/v1/admin/containers', () => {
    return HttpResponse.json({ detail: 'Invalid or missing API key' }, { status: 401 })
  }),

  containers500: http.get('*/api/v1/admin/containers', () => {
    return HttpResponse.json({ detail: 'Internal server error' }, { status: 500 })
  }),

  env401: http.get('*/api/v1/admin/env', () => {
    return HttpResponse.json({ detail: 'Invalid or missing API key' }, { status: 401 })
  }),

  env500: http.get('*/api/v1/admin/env', () => {
    return HttpResponse.json({ detail: 'Internal server error' }, { status: 500 })
  }),

  envUpdate500: http.put('*/api/v1/admin/env/:key', () => {
    return HttpResponse.json({ detail: 'Internal server error' }, { status: 500 })
  }),

  truncate500: http.post('*/api/v1/admin/db/truncate', () => {
    return HttpResponse.json({ detail: 'Internal server error' }, { status: 500 })
  }),

  pipeline500: http.get('*/api/v1/operations/pipeline', () => {
    return HttpResponse.json({ detail: 'Internal server error' }, { status: 500 })
  }),

  operations401: http.get('*/api/v1/operations/pipeline', () => {
    return HttpResponse.json({ detail: 'Invalid or missing API key' }, { status: 401 })
  }),

  captureStatus500: http.get('*/api/v1/operations/capture-status', () => {
    return HttpResponse.json({ detail: 'Internal server error' }, { status: 500 })
  }),

  captureStatus401: http.get('*/api/v1/operations/capture-status', () => {
    return HttpResponse.json({ detail: 'Invalid or missing API key' }, { status: 401 })
  }),

  passiveDiscovery500: http.get('*/api/v1/operations/passive-discovery', () => {
    return HttpResponse.json({ detail: 'Internal server error' }, { status: 500 })
  }),

  passiveSeederStatus500: http.get('*/api/v1/operations/passive-seeder/status', () => {
    return HttpResponse.json({ detail: 'Internal server error' }, { status: 500 })
  }),

  pcapImportList500: http.get('*/api/v1/operations/pcap-import', () => {
    return HttpResponse.json({ detail: 'Internal server error' }, { status: 500 })
  }),

  // No status row persisted yet: the API answers an explicit `unknown`
  // rather than inventing a disabled state.
  passiveSeederStatusUnknown: http.get('*/api/v1/operations/passive-seeder/status', () => {
    return HttpResponse.json({
      service: 'otalon-scan',
      state: 'unknown',
      last_cycle_at: null,
      last_error: null,
      rows_seeded: 0,
      poll_interval_s: null,
      updated_at: null,
    })
  }),

  passiveSeederStatusError: http.get('*/api/v1/operations/passive-seeder/status', () => {
    return HttpResponse.json({
      service: 'otalon-scan',
      state: 'error',
      last_cycle_at: '2026-07-29T12:44:48.600Z',
      last_error: 'influx query failed: connection refused',
      rows_seeded: 0,
      poll_interval_s: 120,
      updated_at: '2026-07-29T12:44:48.600Z',
    })
  }),

  passiveDiscoveryNoData: http.get('*/api/v1/operations/passive-discovery', () => {
    return HttpResponse.json({
      observed_asset_count: 0,
      observed_interface_count: 0,
      latest_seen_at: null,
      first_seen_at: null,
      age_seconds: null,
      freshness: 'no-data',
      runtime_control_enabled: false,
    })
  }),

  passiveDiscoveryStale: http.get('*/api/v1/operations/passive-discovery', () => {
    return HttpResponse.json({
      observed_asset_count: 12,
      observed_interface_count: 14,
      latest_seen_at: '2026-07-21T06:30:00.000Z',
      first_seen_at: '2026-07-02T09:29:12.637Z',
      age_seconds: 2680,
      freshness: 'stale',
      runtime_control_enabled: false,
    })
  }),

  composeFail: http.post('*/api/v1/admin/compose/action', () => {
    return HttpResponse.json({
      service: 'unknown',
      action: 'restart',
      exit_code: 1,
      output: 'Error: service not found',
      success: false,
    })
  }),

  composeAction500: http.post('*/api/v1/admin/compose/action', () => {
    return HttpResponse.json({ detail: 'Internal server error' }, { status: 500 })
  }),

  boundsEmpty: http.get('*/api/v1/anomalies/bounds', ({ request }) => {
    const url = new URL(request.url)
    return HttpResponse.json({
      data: [],
      row_count: 0,
      parameters: {
        uci: url.searchParams.get('uci') ?? '',
        metric: url.searchParams.get('metric') ?? '',
        module: 'netcap',
        start: url.searchParams.get('start') ?? '',
        stop: url.searchParams.get('stop') ?? '',
      },
    })
  }),

  boundsSinglePoint: http.get('*/api/v1/anomalies/bounds', ({ request }) => {
    const url = new URL(request.url)
    return HttpResponse.json({
      data: GOLDEN_SINGLE_POINT_DATA,
      row_count: 1,
      parameters: {
        uci: url.searchParams.get('uci') ?? '',
        metric: url.searchParams.get('metric') ?? '',
        module: 'netcap',
        start: url.searchParams.get('start') ?? '',
        stop: url.searchParams.get('stop') ?? '',
      },
    })
  }),

  protoIds500: http.get('*/api/v1/timeseries/proto/ids', () => {
    return HttpResponse.json({ detail: 'Internal server error' }, { status: 500 })
  }),

  macIds500: http.get('*/api/v1/timeseries/mac/ids', () => {
    return HttpResponse.json({ detail: 'Internal server error' }, { status: 500 })
  }),

  topAssets500: http.get('*/api/v1/dashboard/top-assets', () => {
    return HttpResponse.json({ detail: 'Internal server error' }, { status: 500 })
  }),

  topProtocols500: http.get('*/api/v1/dashboard/top-protocols', () => {
    return HttpResponse.json({ detail: 'Internal server error' }, { status: 500 })
  }),

  layoutGet500: http.get('*/api/v1/dashboard/layout', () => {
    return HttpResponse.json({ detail: 'Internal server error' }, { status: 500 })
  }),

  layoutPut500: http.put('*/api/v1/dashboard/layout', () => {
    return HttpResponse.json({ detail: 'Internal server error' }, { status: 500 })
  }),

  macFeatures500: http.get('*/api/v1/timeseries/mac/features', () => {
    return HttpResponse.json({ detail: 'Internal server error' }, { status: 500 })
  }),

  macBounds500: http.get('*/api/v1/anomalies/mac/bounds', () => {
    return HttpResponse.json({ detail: 'Internal server error' }, { status: 500 })
  }),

  macIntervals500: http.get('*/api/v1/anomalies/mac/intervals', () => {
    return HttpResponse.json({ detail: 'Internal server error' }, { status: 500 })
  }),

  featuresNoDefaults: http.get('*/api/v1/timeseries/features', () => {
    return HttpResponse.json({
      features: ['mean_packet_size', 'std_packet_size'],
    })
  }),

  protoFeatures500: http.get('*/api/v1/timeseries/proto/features', () => {
    return HttpResponse.json({ detail: 'Internal server error' }, { status: 500 })
  }),
}
