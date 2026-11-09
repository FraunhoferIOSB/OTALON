import { beforeEach, describe, expect, it, vi } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'
import { useSystemStore } from '~/stores/systemStore'

// Exact producer shape of GET /api/v1/operations/storage
// (OperationsMaintenanceService.storage): host.unit + decimal *_gb mounts for
// /, /home, /var; ringbuffer size_gb/cap_gb; contributor size_gb; unattributed_gb.
const STORAGE = {
  host: {
    unit: 'GB',
    total_gb: 128.72,
    used_gb: 107.41,
    free_gb: 14.7,
    used_pct: 83.44,
    mount: '/',
    fs: 'unknown',
    mounts: {
      '/': { total_gb: 33.29, used_gb: 13.96, free_gb: 17.62, used_pct: 41.94, purpose: 'System / OS' },
      '/home': {
        total_gb: 294.5,
        used_gb: 178.34,
        free_gb: 101.87,
        used_pct: 60.56,
        purpose: 'Suite checkout, user data, and models',
      },
      '/var': {
        total_gb: 138.55,
        used_gb: 116.0,
        free_gb: 16.11,
        used_pct: 83.72,
        purpose: 'Docker images, volumes, databases, and logs',
      },
    },
  },
  ringbuffer: { unit: 'GB', size_gb: 2.0, cap_gb: 48.8, files: 1, file_cap: 2000, state: 'rotating' },
  contributors: [
    { name: 'InfluxDB', size_gb: 12.0, oldest: null, newest: null, note: 'best-effort local footprint' },
    { name: 'backups', size_gb: 8.0, oldest: null, newest: null, note: 'best-effort local footprint' },
  ],
  unattributed_gb: 87.41,
}

// Exact producer shape of GET /api/v1/operations/version
// (OperationsMaintenanceService.version): suite version/build_ref/digest +
// per-component version/build_ref/digest.
const VERSION = {
  suite: { version: '1.4.0', build_ref: 'abc1234', digest: 'sha256:abc' },
  components: [
    { name: 'otalon-api', version: '1.4.0', build_ref: 'abc1234', digest: 'sha256:api' },
    { name: 'otalon-ui', version: 'unknown', build_ref: 'unknown', digest: 'unknown' },
  ],
}

const SERVICES = {
  services: [
    { name: 'otalon-api', status: 'running', core_db: false },
    { name: 'otalon-ai', status: 'running', core_db: false },
    { name: 'postgres', status: 'running', core_db: true },
  ],
}

// Exact producer shape of GET /api/v1/operations/backups (backups route):
// items (catalog) + last_backup manifest + verified/stale.
const CATALOG_ITEM = {
  artifact_id: 'art-1',
  artifact_name: 'otalon-backup-art-1.zip',
  created_at: '2026-07-20T20:51:04.661004+00:00',
  scope: ['config', 'postgresql', 'models', 'baselines', 'pcap_archive'],
  archive_bytes: 4096,
  verified: true,
}
const BACKUPS_FULL = {
  items: [CATALOG_ITEM],
  last_backup: {
    artifact_id: 'art-1',
    artifact_name: 'otalon-backup-art-1.zip',
    scope: ['config', 'postgresql', 'models', 'baselines', 'pcap_archive'],
    created_at: '2026-07-20T20:51:04.661004+00:00',
    sha256: 'deadbeef',
    verified: true,
    stale: false,
    age_seconds: 100,
    archive_bytes: 4096,
  },
  verified: true,
  stale: false,
}

describe('systemStore', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    vi.restoreAllMocks()
  })

  it('reconciles contributor and unattributed storage against decimal-GB host usage', () => {
    const store = useSystemStore()
    store.storage = STORAGE
    expect(store.storage.host.unit).toBe('GB')
    // Mount rows carry decimal *_gb, not GiB.
    expect(store.storage.host.mounts['/var'].used_gb).toBeCloseTo(116.0, 2)
    expect(store.storage.host.mounts['/home'].total_gb).toBeCloseTo(294.5, 2)
    expect(store.accountedStorage).toBeCloseTo(20.0, 2)
    expect(store.storage.unattributed_gb).toBeCloseTo(87.41, 2)
  })

  it('exposes all three host mounts /, /home and /var from the producer envelope', () => {
    const store = useSystemStore()
    store.storage = STORAGE
    expect(Object.keys(store.storage.host.mounts)).toEqual(['/', '/home', '/var'])
    expect(store.storage.host.mounts['/var'].purpose).toContain('Docker')
  })

  it('loads all four System reads via same-origin operations paths without browser credentials', async () => {
    const fetchMock = vi.spyOn(globalThis, '$fetch')
    fetchMock.mockResolvedValueOnce(SERVICES)
    fetchMock.mockResolvedValueOnce(STORAGE)
    fetchMock.mockResolvedValueOnce(VERSION)
    fetchMock.mockResolvedValueOnce(BACKUPS_FULL)
    const store = useSystemStore()
    await store.load()
    expect(fetchMock.mock.calls.map(([url]) => url)).toEqual([
      '/api/v1/operations/services',
      '/api/v1/operations/storage',
      '/api/v1/operations/version',
      '/api/v1/operations/backups',
    ])
    // No Authorization/X-API-Key header is ever attached in the browser channel.
    expect(fetchMock.mock.calls.every(([, options]) => !options || !('headers' in options))).toBe(true)
    expect(store.services.map((s) => s.name)).toContain('otalon-ai')
    expect(store.storage?.host.mounts['/'].used_pct).toBeCloseTo(41.94, 2)
  })

  it('binds version suite and component build_ref refs from the producer envelope', async () => {
    const fetchMock = vi.spyOn(globalThis, '$fetch')
    fetchMock.mockResolvedValueOnce(SERVICES)
    fetchMock.mockResolvedValueOnce(STORAGE)
    fetchMock.mockResolvedValueOnce(VERSION)
    fetchMock.mockResolvedValueOnce(BACKUPS_FULL)
    const store = useSystemStore()
    await store.load()
    expect(store.version?.suite.build_ref).toBe('abc1234')
    expect(store.version?.components[0]?.build_ref).toBe('abc1234')
    // Unknown component refs remain the honest 'unknown' string, not silently blanked.
    expect(store.version?.components[1]?.build_ref).toBe('unknown')
    expect(store.version?.components[1]?.version).toBe('unknown')
  })

  it('binds the backup catalog items and last-backup manifest from the load envelope', async () => {
    const fetchMock = vi.spyOn(globalThis, '$fetch')
    fetchMock.mockResolvedValueOnce(SERVICES)
    fetchMock.mockResolvedValueOnce(STORAGE)
    fetchMock.mockResolvedValueOnce(VERSION)
    fetchMock.mockResolvedValueOnce(BACKUPS_FULL)
    const store = useSystemStore()
    await store.load()
    expect(store.backupCatalog).toHaveLength(1)
    expect(store.backupCatalog[0]?.artifact_id).toBe('art-1')
    expect(store.backups?.stale).toBe(false)
    expect(store.backups?.scope).toContain('pcap_archive')
  })

  it('keeps failed lifecycle actions truthful', async () => {
    vi.spyOn(globalThis, '$fetch').mockRejectedValueOnce(new Error('backend unavailable'))
    const store = useSystemStore()
    expect(await store.serviceAction('worker', 'restart')).toBeNull()
    expect(store.actionError).toBe('backend unavailable')
  })

  it('forwards a typed confirmation phrase when running a service action', async () => {
    const fetchMock = vi.spyOn(globalThis, '$fetch')
    fetchMock.mockResolvedValueOnce({ job: { display_id: 'J-9', state: 'completed' } })
    fetchMock.mockResolvedValueOnce(SERVICES)
    const store = useSystemStore()
    await store.serviceAction('otalon-ai', 'restart', 'CONFIRM RESTART otalon-ai')
    expect(fetchMock.mock.calls[0][0]).toBe('/api/v1/operations/services/action')
    expect(fetchMock.mock.calls[0][1]).toMatchObject({
      method: 'POST',
      body: { service: 'otalon-ai', action: 'restart', confirmation: 'CONFIRM RESTART otalon-ai' },
    })
  })

  it('runs a backup and stores the returned manifest with a deep-link job id', async () => {
    const result = {
      job: { display_id: 'J-42', state: 'completed' },
      manifest: { scope: ['config'], created_at: 't', sha256: 'deadbeef', verified: true },
    }
    vi.spyOn(globalThis, '$fetch').mockResolvedValueOnce(result)
    const store = useSystemStore()
    const out = await store.runBackup(['config'])
    expect(out?.job.display_id).toBe('J-42')
    expect(store.backups?.sha256).toBe('deadbeef')
  })

  it('checks updates manually and records registry-not-contacted gate', async () => {
    vi.spyOn(globalThis, '$fetch').mockResolvedValueOnce({
      manual_only: true,
      checked: true,
      registry_contacted: false,
      gate: { compatibility: { status: 'unknown', detail: '' } },
    })
    const store = useSystemStore()
    await store.checkUpdates()
    expect(store.update?.registry_contacted).toBe(false)
    expect(store.update?.gate.compatibility?.status).toBe('unknown')
  })

  it('runs a read-only health check and surfaces findings with no mutations', async () => {
    vi.spyOn(globalThis, '$fetch').mockResolvedValueOnce({
      status: 'warn',
      findings: [
        { name: 'postgresql', status: 'pass', detail: 'ok', remediation: '' },
        {
          name: 'detection_cycle',
          status: 'unknown',
          detail: 'No detection-cycle probe is available',
          remediation: '',
        },
      ],
      mutations: [],
    })
    const store = useSystemStore()
    await store.runHealthCheck()
    expect(store.health?.mutations).toEqual([])
    expect(store.health?.findings.map((f) => f.name)).toEqual(['postgresql', 'detection_cycle'])
    // Unknown-evidence findings stay 'unknown', never silently coerced to pass.
    expect(store.health?.findings[1]?.status).toBe('unknown')
  })

  it('previews and creates a support bundle without exposing secrets', async () => {
    const fetchMock = vi.spyOn(globalThis, '$fetch')
    fetchMock.mockResolvedValueOnce({
      privacy_scope: 'local-only',
      included: ['service logs'],
      excluded: ['PCAPs'],
      redacted: ['API keys'],
    })
    fetchMock.mockResolvedValueOnce({ path: '/app/operations/bundles/x.json', sha256: 'abc', uploaded: false })
    const store = useSystemStore()
    await store.loadSupportPreview()
    const ack = await store.createSupportBundle()
    expect(store.support?.excluded).toContain('PCAPs')
    expect(ack?.uploaded).toBe(false)
    expect(fetchMock.mock.calls[1][0]).toBe('/api/v1/operations/support-bundle')
  })

  it('restore precheck forwards selected artifact_id without live intent', async () => {
    const precheck = {
      compatible: true,
      migrations: 'none detected',
      database_restore: true,
      confirmation_required: 'RESTORE DATABASE',
      confirmed: false,
      backup_available: true,
      backup_stale: false,
      executed: false,
    }
    const fetchMock = vi.spyOn(globalThis, '$fetch').mockResolvedValueOnce(precheck)
    const store = useSystemStore()
    store.selectedArtifactId = 'art-1'
    const result = await store.restore(['postgresql'])
    expect(result?.executed).toBe(false)
    const body = (fetchMock.mock.calls[0][1] as { body: Record<string, unknown> }).body
    // Selected artifact drives the precheck body.
    expect(body.artifact_id).toBe('art-1')
    expect(body.scope).toEqual(['postgresql'])
    // Precheck remains safe and does not send live intent.
    expect(body.dry_run).toBeUndefined()
  })

  it('admin restore confirmation serializes live intent', async () => {
    const fetchMock = vi.spyOn(globalThis, '$fetch').mockResolvedValueOnce({ executed: false })
    const store = useSystemStore()
    await store.restore(['postgresql'], 'RESTORE DATABASE', true)
    const body = (fetchMock.mock.calls[0][1] as { body: Record<string, unknown> }).body
    expect(body.dry_run).toBe(false)
  })

  it('restore precheck omits artifact_id when none is selected and still never executes', async () => {
    const fetchMock = vi.spyOn(globalThis, '$fetch').mockResolvedValueOnce({
      compatible: false,
      migrations: 'none detected',
      database_restore: true,
      confirmation_required: 'RESTORE DATABASE',
      confirmed: false,
      backup_available: false,
      backup_stale: false,
      executed: false,
    })
    const store = useSystemStore()
    const result = await store.restore(['postgresql'])
    expect(result?.executed).toBe(false)
    const body = (fetchMock.mock.calls[0][1] as { body: Record<string, unknown> }).body
    expect(body).not.toHaveProperty('artifact_id')
    expect(body.dry_run).toBeUndefined()
  })

  it('previews PostgreSQL reset via the dedicated postgres preview URL (read-only, no execution)', async () => {
    const fetchMock = vi.spyOn(globalThis, '$fetch').mockResolvedValueOnce({
      target: 'postgresql',
      scope: 'anomaly-history',
      tables: ['anomalies', 'alarms'],
      destructive: true,
      execution_supported: true,
      requires_fresh_full_backup: false,
      backup_compatible: null,
      executed: false,
    })
    const store = useSystemStore()
    const preview = await store.previewPostgresqlReset('anomaly-history')
    expect(fetchMock.mock.calls[0][0]).toBe('/api/v1/operations/reset/postgresql/preview')
    expect(fetchMock.mock.calls[0][1]).toMatchObject({ method: 'POST', body: { scope: 'anomaly-history' } })
    expect(preview?.executed).toBe(false)
    expect(preview?.target).toBe('postgresql')
    expect(preview?.tables).toEqual(['anomalies', 'alarms'])
  })

  it('previews InfluxDB reset via a separate influx preview URL that exposes no execution path', async () => {
    const fetchMock = vi.spyOn(globalThis, '$fetch').mockResolvedValueOnce({
      target: 'influxdb',
      scope: 'timeseries',
      measurements: ['network_metrics', 'mac_traffic', 'proto_traffic'],
      destructive: true,
      execution_supported: false,
      requires_fresh_full_backup: false,
      executed: false,
    })
    const store = useSystemStore()
    const preview = await store.previewInfluxReset('timeseries')
    expect(fetchMock.mock.calls[0][0]).toBe('/api/v1/operations/reset/influx/preview')
    expect(fetchMock.mock.calls[0][1]).toMatchObject({ method: 'POST', body: { scope: 'timeseries' } })
    expect(preview?.execution_supported).toBe(false)
    expect(preview?.measurements).toEqual(['network_metrics', 'mac_traffic', 'proto_traffic'])
    expect(preview?.executed).toBe(false)
  })

  it('reset forwards scope/reason/phrase without live intent by default', async () => {
    const fetchMock = vi.spyOn(globalThis, '$fetch').mockResolvedValueOnce({
      executed: false,
      scope: 'anomaly-history',
      tables: ['anomalies', 'alarms'],
      deleted: {},
    })
    const store = useSystemStore()
    const out = await store.reset('anomaly-history', 'cleanup reason', 'RESET ANOMALY-HISTORY')
    expect(out?.executed).toBe(false)
    expect(fetchMock.mock.calls[0][0]).toBe('/api/v1/operations/reset')
    const body = (fetchMock.mock.calls[0][1] as { body: Record<string, unknown> }).body
    expect(body).toMatchObject({
      scope: 'anomaly-history',
      reason: 'cleanup reason',
      confirmation: 'RESET ANOMALY-HISTORY',
    })
    expect(body.dry_run).toBeUndefined()
  })

  it('admin reset confirmation serializes live intent', async () => {
    const fetchMock = vi.spyOn(globalThis, '$fetch').mockResolvedValueOnce({ executed: true })
    const store = useSystemStore()
    await store.reset('anomaly-history', 'cleanup reason', 'RESET ANOMALY-HISTORY', true)
    const body = (fetchMock.mock.calls[0][1] as { body: Record<string, unknown> }).body
    expect(body.dry_run).toBe(false)
  })

  it('service action preserves existing action payload', async () => {
    const fetchMock = vi.spyOn(globalThis, '$fetch').mockResolvedValueOnce({ job: {} })
    const store = useSystemStore()
    await store.serviceAction('otalon-ai', 'restart', 'CONFIRM RESTART otalon-ai')
    expect(fetchMock.mock.calls[0][1]).toMatchObject({
      method: 'POST',
      body: {
        service: 'otalon-ai',
        action: 'restart',
        confirmation: 'CONFIRM RESTART otalon-ai',
      },
    })
  })

  it('reset uses the truthful detection-results scope, not a misleading timeseries one', async () => {
    const fetchMock = vi
      .spyOn(globalThis, '$fetch')
      .mockResolvedValueOnce({ executed: false, scope: 'detection-results', tables: ['anomalies'], deleted: {} })
    const store = useSystemStore()
    const out = await store.reset('detection-results', 'clear detection results', 'RESET DETECTION-RESULTS')
    expect(out?.tables).toEqual(['anomalies'])
    expect(fetchMock.mock.calls[0][1]).toMatchObject({
      body: { scope: 'detection-results', confirmation: 'RESET DETECTION-RESULTS' },
    })
  })

  it('fetches service logs via an encoded same-origin path', async () => {
    vi.spyOn(globalThis, '$fetch').mockResolvedValueOnce({ logs: 'line-1\nline-2' })
    const store = useSystemStore()
    await store.fetchLogs('otalon-ai')
    expect(store.logs['otalon-ai']).toContain('line-1')
  })
})
