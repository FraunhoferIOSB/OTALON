import { defineStore } from 'pinia'
import { useApi, type ApiError } from '~/composables/useApi'
import { formatApiErrorDetail } from '~/utils/apiError'
import type {
  RuntimeConfigApplyResponse,
  RuntimeConfigItem,
  RuntimeConfigResponse,
  RuntimeConfigWrite,
} from '~/types/api'
import { isAuthorizationError, operationErrorMessage } from '~/utils/permissions'

export type ConnectionState = 'not-configured' | 'ready' | 'failed' | 'testing'

/**
 * Extract the server's own error text from a failed request.
 *
 * The runtime-configuration endpoint answers an invalid write with HTTP 400
 * and a precise `detail` string produced by the shared runtime-key registry
 * (for example `expected an integer in [10, 3600], got 1`, or the rejection
 * of a secret key). That message is the contract and must reach the operator
 * verbatim rather than being flattened into a generic "invalid input".
 *
 * `useApi` rejects with a structured {@link ApiError} object literal, not an
 * `Error` instance, so an `instanceof Error` check would silently discard it.
 *
 * @param error - The value thrown by `useApi`.
 * @param fallback - Message used when no server text is available.
 * @returns The server's message when present, else `fallback`.
 * @internal
 */
function serverMessage(error: unknown, fallback: string): string {
  if (isAuthorizationError(error)) return operationErrorMessage(error, fallback)
  if (error && typeof error === 'object' && 'status' in error) {
    const apiError = error as ApiError
    const detail = formatApiErrorDetail(apiError.detail as Parameters<typeof formatApiErrorDetail>[0])
    if (detail !== null) return detail
    if (apiError.message) return apiError.message
  }
  if (error instanceof Error && error.message) return error.message
  return fallback
}

/** Masked boot configuration and per-key service impact. */
export interface BootConfig {
  env: Record<string, string>
  editable_keys: string[]
  sensitive_keys: string[]
  readonly_keys: string[]
  affected_services: Record<string, string[]>
}

/** Non-secret AI connection metadata (never carries the key value). */
export interface AIConnection {
  provider: string
  endpoint: string
  chat_model: string
  job_model: string
  state: ConnectionState
  key_configured: boolean
  /** AI-046: maximum chat context window in tokens (runtime_config, default 128000). */
  context_window: number
}

/**
 * Active models reported by otalon-ai versus the persisted ones (AI-045).
 *
 * ``active_*_model`` is ``null`` when the running otalon-ai could not be
 * reached; ``drift`` is then ``false`` — an unreachable runtime is never
 * presented as "in sync".
 */
export interface AIDrift {
  provider: string
  endpoint: string
  chat_model: string
  job_model: string
  state: ConnectionState
  key_configured: boolean
  active_chat_model: string | null
  active_job_model: string | null
  drift: boolean
  context_window: number
}

/**
 * Result of an AI connection save: metadata plus the live-push outcome.
 *
 * ``live_applied`` states whether the pushed configuration reached the
 * running otalon-ai; ``live_detail`` names the failed step otherwise.
 */
export interface AISaveResult extends AIConnection {
  live_applied: boolean
  live_detail: string
}

/**
 * Operator-facing post-save notice derived from {@link AISaveResult}.
 *
 * ``applied`` selects the applied-state versus recreate-fallback wording
 * (ui--ai-connection spec: the recreate hint SHALL NOT appear when the
 * live update applied).
 */
export interface AISaveNotice {
  applied: boolean
  message: string
}

/** Model identifiers offered by the proxy (identifiers only, never keys). */
export interface AIModelList {
  models: string[]
}

/** Safe configuration audit row with explicit rollback eligibility. */
export interface ConfigHistoryItem {
  id: number
  at: string
  actor: string
  action: string
  target: string
  reason?: string
  rollback_eligible: boolean
}

export interface BootApplyRequest {
  key: string
  value: string
  reason: string
}

export interface AIUpdateRequest {
  provider: string
  endpoint: string
  chat_model: string
  job_model: string
  reason: string
  allow_unlisted_model?: boolean
  /** AI-046: optional; omitted keeps the saved value. */
  context_window?: number
}

export interface AITestResult {
  success: boolean
  state: ConnectionState
}

/** Outcome of one accepted runtime write, used to confirm live application. */
export interface RuntimeApplyResult {
  changed_keys: string[]
  restart_required: boolean
}

interface ConfigurationState {
  boot: BootConfig | null
  ai: AIConnection | null
  aiDrift: AIDrift | null
  aiModels: string[]
  aiModelsError: string
  lastAISave: AISaveNotice | null
  history: ConfigHistoryItem[]
  runtime: RuntimeConfigItem[]
  runtimeError: string
  runtimeSavingKey: string | null
  lastRuntimeApply: RuntimeApplyResult | null
  loading: boolean
  saving: boolean
  error: string
}

/**
 * Pinia store for the Operations Configuration page.
 *
 * Fetches the read-only Boot / AI-drift / History surfaces and drives the
 * audited mutation actions (boot apply, AI update, write-only key replace,
 * connection test, rollback). All mutations travel through the server-side
 * operator-key proxy via {@link useApi}; the store never holds a secret.
 *
 * The AI GET surface is a drift report (AI-045): the persisted connection
 * metadata (`ai`) arrives with the save response and is kept across saves,
 * while `aiDrift` reflects the active models reported by the running
 * otalon-ai versus the persisted ones.
 *
 * @example
 * ```ts
 * const store = useConfigurationStore()
 * await store.fetchAll()
 * await store.fetchAIModels()
 * await store.saveBoot({ key: 'TZ', value: 'UTC', reason: 'dst change' })
 * const notice = await store.updateAI({ provider: 'litellm', endpoint: 'https://x', chat_model: 'gpt-5.4', job_model: 'gpt-5.4', reason: 'switch model' })
 * notice.applied // true → live, no recreate needed
 * ```
 */
export const useConfigurationStore = defineStore('configuration', {
  state: (): ConfigurationState => ({
    boot: null,
    ai: null,
    aiDrift: null,
    aiModels: [],
    aiModelsError: '',
    lastAISave: null,
    history: [],
    runtime: [],
    runtimeError: '',
    runtimeSavingKey: null,
    lastRuntimeApply: null,
    loading: false,
    saving: false,
    error: '',
  }),
  getters: {
    /** True when AI is not configured (distinct from a failed connection). */
    aiNotConfigured: (state): boolean => state.ai?.state === 'not-configured',
    /** True only when both an endpoint and a configured key are present. */
    aiTestable: (state): boolean => Boolean(state.ai?.endpoint && state.ai?.key_configured),
    /** Editable (non-sensitive) boot keys the operator may set a value for. */
    editableBootKeys: (state): string[] => {
      if (!state.boot) return []
      return state.boot.editable_keys
    },
    /**
     * Runtime keys grouped by owning service, preserving manifest order.
     *
     * Keys without a persisted row are included with their boot-derived
     * value — the backend response is manifest-complete and the UI must
     * never omit a key just because it has never been written.
     */
    runtimeByService: (state): { service: string; items: RuntimeConfigItem[] }[] => {
      const groups: { service: string; items: RuntimeConfigItem[] }[] = []
      for (const item of state.runtime) {
        const existing = groups.find((group) => group.service === item.service)
        if (existing) existing.items.push(item)
        else groups.push({ service: item.service, items: [item] })
      }
      return groups
    },
  },
  actions: {
    /** Return true when a boot key holds a sensitive (write-only) value. */
    isSensitiveKey(key: string): boolean {
      return Boolean(this.boot?.sensitive_keys.includes(key))
    },
    async fetchAll(): Promise<void> {
      this.loading = true
      this.error = ''
      try {
        const api = useApi()
        const [boot, drift, history] = await Promise.all([
          api.get<BootConfig>('/api/v1/operations/configuration/boot'),
          api.get<AIDrift>('/api/v1/operations/ai-connection'),
          api.get<ConfigHistoryItem[]>('/api/v1/operations/configuration/history'),
        ])
        this.boot = boot
        this.aiDrift = drift
        // The GET now carries the persisted connection too (AI-045 Task 2.5 regression
        // fix). Store it so the AI form pre-fills from the server, not from stale state.
        this.ai = {
          provider: drift.provider,
          endpoint: drift.endpoint,
          chat_model: drift.chat_model,
          job_model: drift.job_model,
          // AI-046: the saved chat context window must reach the form, not the default.
          context_window: drift.context_window,
          state: drift.state,
          key_configured: drift.key_configured,
        }
        this.history = history
      } catch (error: unknown) {
        this.error = error instanceof Error ? error.message : 'Configuration could not be loaded'
      } finally {
        this.loading = false
      }
      await this.fetchRuntime()
    },
    /**
     * Load every runtime key from the live control plane.
     *
     * Failures are kept in `runtimeError`, separate from the page-level
     * `error`, so a runtime read failure never blanks the Boot / AI tabs.
     */
    async fetchRuntime(): Promise<void> {
      this.runtimeError = ''
      try {
        const response = await useApi().get<RuntimeConfigResponse>('/api/v1/operations/configuration/runtime')
        this.runtime = response.items
      } catch (error: unknown) {
        this.runtimeError = serverMessage(error, 'Runtime configuration could not be loaded')
      }
    },
    async fetchRuntimeStrict(): Promise<void> {
      this.runtimeError = ''
      const response = await useApi().get<RuntimeConfigResponse>('/api/v1/operations/configuration/runtime')
      this.runtime = response.items
    },
    /**
     * Load the model identifiers the proxy offers (AI-045 D5).
     *
     * The list populates the chat/job model selects; failures are kept in
     * `aiModelsError`, separate from `error`, so a catalog outage degrades
     * to the explicit free-text fallback instead of blanking the tab.
     *
     * @returns The validated identifiers, empty when the proxy is unavailable.
     *
     * @example
     * ```ts
     * await store.fetchAIModels()
     * store.aiModels // ['gpt-5.4', 'claude-opus-5-5', ...]
     * ```
     */
    async fetchAIModels(): Promise<string[]> {
      this.aiModelsError = ''
      try {
        const response = await useApi().post<AIModelList>('/api/v1/operations/ai-connection/models', {})
        this.aiModels = response.models
      } catch (error: unknown) {
        this.aiModels = []
        this.aiModelsError = serverMessage(error, 'Model list unavailable')
      }
      return this.aiModels
    },
    /**
     * Write exactly one runtime key, then re-read the server's own view.
     *
     * The refreshed collection from the write response is applied and then
     * confirmed by a full re-fetch, so the table always shows persisted
     * server state rather than optimistic local state.
     *
     * On rejection the server's message (HTTP 400 from the shared key
     * registry) is stored verbatim in `runtimeError` and re-thrown so the
     * caller can keep the editor open.
     *
     * @param request - The single-key write, with an optional audited reason.
     * @returns The `changed_keys` / `restart_required` metadata of the write.
     * @throws The original {@link ApiError} when the server rejects the write.
     *
     * @example
     * ```ts
     * await store.saveRuntime({
     *   service: 'otalon-scan',
     *   key: 'poll_interval_s',
     *   value: '120',
     *   reason: 'reduce influx load',
     * })
     * ```
     */
    async saveRuntime(request: RuntimeConfigWrite): Promise<RuntimeApplyResult> {
      this.runtimeError = ''
      this.runtimeSavingKey = `${request.service}:${request.key}`
      try {
        const response = await useApi().put<RuntimeConfigApplyResponse>(
          '/api/v1/operations/configuration/runtime',
          request,
        )
        this.runtime = response.items
        const result: RuntimeApplyResult = {
          changed_keys: response.changed_keys,
          restart_required: response.restart_required,
        }
        this.lastRuntimeApply = result
        await this.fetchRuntime()
        return result
      } catch (error: unknown) {
        this.runtimeError = serverMessage(error, 'Runtime value could not be applied')
        throw error
      } finally {
        this.runtimeSavingKey = null
      }
    },
    async saveRuntimeJob(requests: RuntimeConfigWrite[]): Promise<unknown> {
      return useApi().post('/api/v1/operations/configuration/runtime/job', { updates: requests })
    },
    async saveBoot(request: BootApplyRequest): Promise<void> {
      this.error = ''
      this.saving = true
      try {
        this.boot = await useApi().put<BootConfig>('/api/v1/operations/configuration/boot', request)
        await this.fetchAll()
      } catch (error: unknown) {
        this.error = error instanceof Error ? error.message : 'Boot configuration could not be applied'
        throw error
      } finally {
        this.saving = false
      }
    },
    /**
     * Save the non-secret AI connection fields and record the live outcome.
     *
     * The response carries `live_applied`/`live_detail` (AI-045 D4): the
     * notice is stored in `lastAISave`, and a failed push keeps the
     * persisted metadata in `ai` while never rolling the file back.
     *
     * @param request - The non-secret fields, audited reason and the
     *   explicit `allow_unlisted_model` fallback flag.
     * @returns The operator-facing applied/recreate notice.
     * @throws The original {@link ApiError} when the server rejects the save.
     */
    async updateAI(request: AIUpdateRequest): Promise<AISaveNotice> {
      this.error = ''
      this.saving = true
      try {
        const response = await useApi().put<AISaveResult>('/api/v1/operations/ai-connection', request)
        this.ai = {
          provider: response.provider,
          endpoint: response.endpoint,
          chat_model: response.chat_model,
          job_model: response.job_model,
          // AI-046: keep the persisted window the server returned, never the default.
          context_window: response.context_window,
          state: response.state,
          key_configured: response.key_configured,
        }
        this.aiDrift = {
          active_chat_model: response.chat_model,
          active_job_model: response.job_model,
          drift: false,
          context_window: response.context_window,
        }
        const notice: AISaveNotice = response.live_applied
          ? { applied: true, message: 'AI connection saved — the running otalon-ai uses the new configuration.' }
          : {
              applied: false,
              message: `AI connection saved, but the live update did not apply (${response.live_detail}). Recreate otalon-ai to apply the saved configuration.`,
            }
        this.lastAISave = notice
        // AI-045 operator feedback: the success note must not stay forever. A failed live push
        // stays visible until the next save, so it cannot be overlooked.
        if (notice.applied) {
          // Pinia stores a reactive proxy, so the stored object is not the same reference
          // as `notice`. Compare the message instead: only clear the note this save created.
          const message = notice.message
          setTimeout(() => {
            if (this.lastAISave?.applied && this.lastAISave.message === message) this.lastAISave = null
          }, 6000)
        }
        return notice
      } catch (error: unknown) {
        this.error = error instanceof Error ? error.message : 'AI connection could not be updated'
        throw error
      } finally {
        this.saving = false
      }
    },
    async replaceAIKey(key: string, reason: string): Promise<void> {
      this.error = ''
      this.saving = true
      try {
        this.ai = await useApi().post<AIConnection>('/api/v1/operations/ai-connection/key', { key, reason })
      } catch (error: unknown) {
        this.error = error instanceof Error ? error.message : 'AI key could not be replaced'
        throw error
      } finally {
        this.saving = false
      }
    },
    async testAI(): Promise<AITestResult> {
      this.error = ''
      const result = await useApi().post<AITestResult>('/api/v1/operations/ai-connection/test', {})
      if (this.ai) this.ai.state = result.state
      else
        this.ai = {
          provider: '',
          endpoint: '',
          chat_model: '',
          job_model: '',
          // AI-046: nothing was saved yet; 128000 is the documented default, not a saved value.
          context_window: 128000,
          state: result.state,
          key_configured: false,
        }
      return result
    },
    async rollback(entryId: number, reason: string): Promise<void> {
      this.error = ''
      this.saving = true
      try {
        await useApi().post(`/api/v1/operations/configuration/history/${entryId}/rollback`, {
          reason,
          confirmed: true,
        })
        await this.fetchAll()
      } catch (error: unknown) {
        this.error = error instanceof Error ? error.message : 'Rollback failed'
        throw error
      } finally {
        this.saving = false
      }
    },
  },
})
