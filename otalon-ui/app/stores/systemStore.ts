import { defineStore } from 'pinia'
import { operationErrorMessage } from '~/utils/permissions'

export interface SystemService {
  name: string
  status: string
  image?: string
  ports?: string
  core_db?: boolean
  coreDb?: boolean
}

export interface StorageContributor {
  name: string
  size_gb?: number
  size_gib?: number
  oldest: string | null
  newest: string | null
  note: string
}

export interface StorageSummary {
  host: {
    unit: string
    mounts: Record<
      string,
      { total_gb: number; used_gb: number; free_gb: number; used_pct: number; fs: string; purpose?: string }
    >
  }
  ringbuffer: { size_gb: number; cap_gb: number; files: number; file_cap: number; state: string }
  contributors: StorageContributor[]
  unattributed_gb: number
  unattributed_gib?: number
}

export interface SystemFinding {
  name: string
  status: 'pass' | 'warn' | 'fail' | 'unknown'
  detail: string
  remediation: string
}

export interface HealthCheck {
  status: string
  findings: SystemFinding[]
  mutations: string[]
}
export interface BackupManifest {
  artifact_id?: string
  artifact_name?: string
  scope: string[]
  created_at: string
  sha256: string
  verified: boolean
  age_seconds?: number
  stale?: boolean
  archive?: string
  archive_bytes?: number
}
export interface BackupCatalogItem extends BackupManifest {
  artifact_id: string
  artifact_name: string
  archive_bytes: number
}
export interface VersionInfo {
  suite: { version: string; build_ref: string; digest: string | null }
  components: Array<{ name: string; version: string; build_ref: string; digest: string | null }>
}
export interface UpdateCheck {
  manual_only: boolean
  checked: boolean
  registry_contacted: boolean
  gate: Record<string, { status: 'pass' | 'warn' | 'fail' | 'unknown'; detail: string }>
}
export interface SupportPreview {
  privacy_scope: string
  included: string[]
  excluded: string[]
  redacted: string[]
}
export interface SupportBundle {
  path: string
  sha256: string
  uploaded: false
}

export interface BackupResult {
  job: { display_id: string; state: string }
  manifest: BackupManifest
}

export interface RestorePrecheck {
  compatible: boolean
  migrations: string
  database_restore: boolean
  confirmation_required: string
  confirmed: boolean
  backup_available: boolean
  backup_stale: boolean
  executed: boolean
}

export interface ResetResult {
  executed: boolean
  scope: ResetScope
  tables: string[]
  deleted: Record<string, number>
}

export type ServiceAction = 'up' | 'stop' | 'restart' | 'recreate'
export type ResetScope = 'anomaly-history' | 'trained-bounds' | 'detection-results' | 'factory'

export interface SystemState {
  services: SystemService[]
  logs: Record<string, string>
  storage: StorageSummary | null
  version: VersionInfo | null
  backups: BackupManifest | null
  backupCatalog: BackupCatalogItem[]
  selectedArtifactId: string | null
  health: HealthCheck | null
  update: UpdateCheck | null
  support: SupportPreview | null
  isLoading: boolean
  error: string | null
  actionError: string | null
}

function message(error: unknown): string {
  const operationMessage = operationErrorMessage(error, '')
  if (operationMessage) return operationMessage
  if (error instanceof Error && error.message) return error.message
  if (typeof error === 'object' && error !== null && 'statusMessage' in error) return String(error.statusMessage)
  return 'Operation failed. Check the API connection and try again.'
}

export const useSystemStore = defineStore('system', {
  state: (): SystemState => ({
    services: [],
    logs: {},
    storage: null,
    version: null,
    backups: null,
    backupCatalog: [],
    selectedArtifactId: null,
    health: null,
    update: null,
    support: null,
    isLoading: false,
    error: null,
    actionError: null,
  }),
  getters: {
    accountedStorage: (state): number =>
      (state.storage?.contributors ?? []).reduce((sum, item) => sum + (item.size_gb ?? item.size_gib ?? 0), 0),
  },
  actions: {
    async load(): Promise<void> {
      this.isLoading = true
      this.error = null
      try {
        const [services, storage, version, backups] = await Promise.all([
          $fetch<{ services: SystemService[] }>('/api/v1/operations/services'),
          $fetch<StorageSummary>('/api/v1/operations/storage'),
          $fetch<VersionInfo>('/api/v1/operations/version'),
          $fetch<{ items: BackupCatalogItem[]; last_backup: BackupManifest | null }>('/api/v1/operations/backups'),
        ])
        this.services = services.services
        this.storage = storage
        this.version = version
        this.backups = backups.last_backup
        this.backupCatalog = backups.items
      } catch (error: unknown) {
        this.error = message(error)
      } finally {
        this.isLoading = false
      }
    },
    async fetchLogs(name: string): Promise<void> {
      this.actionError = null
      try {
        const response = await $fetch<{ logs: string }>(`/api/v1/operations/services/${encodeURIComponent(name)}/logs`)
        this.logs = { ...this.logs, [name]: response.logs }
      } catch (error: unknown) {
        this.actionError = message(error)
      }
    },
    async serviceAction(service: string, action: ServiceAction, confirmation?: string): Promise<unknown> {
      this.actionError = null
      try {
        const result = await $fetch('/api/v1/operations/services/action', {
          method: 'POST',
          body: { service, action, confirmation },
        })
        await this.loadServices()
        return result
      } catch (error: unknown) {
        this.actionError = message(error)
        return null
      }
    },
    async loadServices(): Promise<void> {
      try {
        this.services = (await $fetch<{ services: SystemService[] }>('/api/v1/operations/services')).services
      } catch (error: unknown) {
        this.actionError = message(error)
      }
    },
    async runHealthCheck(): Promise<void> {
      this.actionError = null
      try {
        this.health = await $fetch<HealthCheck>('/api/v1/operations/health-check', { method: 'POST' })
      } catch (error: unknown) {
        this.actionError = message(error)
      }
    },
    async loadSupportPreview(): Promise<void> {
      try {
        this.support = await $fetch<SupportPreview>('/api/v1/operations/support-bundle/preview')
      } catch (error: unknown) {
        this.actionError = message(error)
      }
    },
    async createSupportBundle(): Promise<SupportBundle | null> {
      try {
        return await $fetch<SupportBundle>('/api/v1/operations/support-bundle', {
          method: 'POST',
          body: { output_dir: 'bundles' },
        })
      } catch (error: unknown) {
        this.actionError = message(error)
        return null
      }
    },
    async checkUpdates(): Promise<void> {
      try {
        this.update = await $fetch<UpdateCheck>('/api/v1/operations/update/check', { method: 'POST' })
      } catch (error: unknown) {
        this.actionError = message(error)
      }
    },
    async runBackup(scope: string[]): Promise<BackupResult | null> {
      try {
        const result = await $fetch<BackupResult>('/api/v1/operations/backup', { method: 'POST', body: { scope } })
        this.backups = result.manifest
        return result
      } catch (error: unknown) {
        this.actionError = message(error)
        return null
      }
    },
    async restore(scope: string[], confirmation?: string, live = false): Promise<RestorePrecheck | null> {
      try {
        return await $fetch<RestorePrecheck>('/api/v1/operations/restore', {
          method: 'POST',
          body: {
            scope,
            confirmation,
            ...(this.selectedArtifactId ? { artifact_id: this.selectedArtifactId } : {}),
            ...(live ? { dry_run: false } : {}),
          },
        })
      } catch (error: unknown) {
        this.actionError = message(error)
        return null
      }
    },
    async reset(scope: ResetScope, reason: string, confirmation: string, live = false): Promise<ResetResult | null> {
      try {
        return await $fetch<ResetResult>('/api/v1/operations/reset', {
          method: 'POST',
          body: { scope, reason, confirmation, ...(live ? { dry_run: false } : {}) },
        })
      } catch (error: unknown) {
        this.actionError = message(error)
        return null
      }
    },
    async previewPostgresqlReset(scope: ResetScope): Promise<Record<string, unknown> | null> {
      try {
        return await $fetch('/api/v1/operations/reset/postgresql/preview', { method: 'POST', body: { scope } })
      } catch (error: unknown) {
        this.actionError = message(error)
        return null
      }
    },
    async previewInfluxReset(scope: 'timeseries' | 'factory'): Promise<Record<string, unknown> | null> {
      try {
        return await $fetch('/api/v1/operations/reset/influx/preview', { method: 'POST', body: { scope } })
      } catch (error: unknown) {
        this.actionError = message(error)
        return null
      }
    },
  },
})
