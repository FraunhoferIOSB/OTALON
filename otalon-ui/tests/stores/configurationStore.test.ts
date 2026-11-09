import { beforeEach, describe, expect, it, vi } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'

const get = vi.fn()
const put = vi.fn()
const post = vi.fn()
vi.mock('~/composables/useApi', () => ({ useApi: () => ({ get, put, post }) }))

// Exact producer shape of GET /api/v1/operations/configuration/boot
// (operations_config._boot_response): env with sensitive fully masked,
// editable_keys, derived readonly_keys (e.g. POSTGRES_DSN), sensitive_keys,
// and per-key affected_services.
const BOOT = {
  env: {
    INFLUX_URL: 'http://x:8181',
    INFLUX_TOKEN: '••••••••',
    TZ: 'UTC',
    POSTGRES_DSN: 'postgresql://postgres:••••••••@postgres:5432/otalon',
  },
  editable_keys: ['INFLUX_URL', 'INFLUX_TOKEN', 'TZ'],
  readonly_keys: ['POSTGRES_DSN'],
  sensitive_keys: ['INFLUX_TOKEN'],
  affected_services: {
    TZ: ['postgres', 'otalon-api'],
    INFLUX_URL: ['influxdb3'],
    POSTGRES_DSN: ['postgres', 'otalon-api'],
  },
}

const AI_READY = {
  provider: 'litellm',
  endpoint: 'https://llm.example.com',
  chat_model: 'gpt',
  job_model: 'gpt',
  state: 'ready',
  key_configured: true,
}

/**
 * Producer shape of GET /api/v1/operations/ai-connection after AI-045
 * (AIConnectionDriftResponse): the active models reported by the running
 * otalon-ai plus the persisted-vs-active drift flag. `null` actives with
 * `drift=false` mean the runtime could not be reached and must never be
 * presented as "in sync".
 */
// Fixed: the GET also carries the persisted connection (provider, endpoint, models,
// state, key_configured) so the form pre-fills. The earlier fake omitted these and
// hid the regression where the AI form loaded empty.
const PERSISTED = {
  provider: 'litellm',
  endpoint: 'http://host.docker.internal:4000/v1',
  chat_model: 'gpt',
  job_model: 'gpt',
  // AI-046: a non-default value, so a fall-back to the 128000 default is visible in the test.
  context_window: 256000,
  state: 'ready',
  key_configured: true,
}
const AI_DRIFT_SYNCED = { ...PERSISTED, active_chat_model: 'gpt', active_job_model: 'gpt', drift: false }
const AI_DRIFT_OFF = { ...PERSISTED, active_chat_model: 'old-model', active_job_model: 'gpt', drift: true }

/**
 * Producer shape of PUT /api/v1/operations/ai-connection after AI-045
 * (AIConnectionSaveResult): persisted metadata plus the live-push outcome.
 */
const AI_SAVE_LIVE = {
  provider: 'litellm',
  endpoint: 'https://llm.example.com',
  chat_model: 'gpt-5.4',
  job_model: 'gpt-5.4',
  // AI-046: non-default saved window, as the PUT response now returns it.
  context_window: 320000,
  state: 'ready',
  key_configured: true,
  live_applied: true,
  live_detail: 'llm-config applied',
}

const AI_SAVE_NO_LIVE = {
  ...AI_SAVE_LIVE,
  live_applied: false,
  live_detail: 'live push failed: ConnectError',
}

const HISTORY = [
  { id: 2, at: '2026-07-18T01:00:00Z', actor: 'operator', action: 'update', target: 'TZ', rollback_eligible: true },
  {
    id: 1,
    at: '2026-07-18T00:00:00Z',
    actor: 'operator',
    action: 'replace-ai-key',
    target: 'LITELLM_API_KEY',
    rollback_eligible: false,
  },
]

// Exact producer shape of GET /api/v1/operations/configuration/runtime
// (operations_config._runtime_items): manifest-complete, so a key with no
// persisted row still appears carrying its boot-derived value with null
// audit fields.
const RUNTIME_ITEMS = [
  {
    service: 'otalon-scan',
    key: 'poll_interval_s',
    value: '120',
    value_prev: '60',
    updated_at: '2026-07-29T11:46:02.763014+02:00',
    updated_by: 'operator',
    type: 'int',
    domain: '[10, 3600]',
    description: 'Seconds the passive seeder waits between poll cycles.',
  },
  {
    service: 'otalon-clas',
    key: 'training.retrain_paused',
    value: 'false',
    value_prev: null,
    updated_at: null,
    updated_by: null,
    type: 'bool',
    domain: null,
    description: 'Whether retrain jobs are paused without stopping the supervisor.',
  },
]

function mockFetchAll(aiDrift: Record<string, unknown> = AI_DRIFT_SYNCED): void {
  get.mockImplementation(async (path: string) => {
    if (path.endsWith('/boot')) return BOOT
    if (path.endsWith('/ai-connection')) return aiDrift
    if (path.endsWith('/history')) return HISTORY
    if (path.endsWith('/runtime')) return { items: RUNTIME_ITEMS }
    return []
  })
}

async function freshStore() {
  const { useConfigurationStore } = await import('~/stores/configurationStore')
  return useConfigurationStore()
}

describe('configurationStore', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    get.mockReset()
    put.mockReset()
    post.mockReset()
  })

  it('fills the persisted AI connection from the GET so the form pre-fills (AI-045 regression)', async () => {
    mockFetchAll()
    const store = await freshStore()
    await store.fetchAll()
    expect(store.ai).not.toBeNull()
    expect(store.ai?.provider).toBe('litellm')
    expect(store.ai?.endpoint).toBe('http://host.docker.internal:4000/v1')
    expect(store.ai?.chat_model).toBe('gpt')
    expect(store.ai?.key_configured).toBe(true)
  })

  it('carries the saved context window from the GET into the store, not the 128000 default (AI-046)', async () => {
    mockFetchAll()
    const store = await freshStore()
    await store.fetchAll()
    // Gegenprobe: the old store code dropped this field, so the value fell back to undefined/default.
    expect(store.ai?.context_window).toBe(256000)
  })

  it('maps not-configured separately from failed and never models a key value', async () => {
    mockFetchAll()
    put.mockResolvedValue({ ...AI_READY, state: 'not-configured', key_configured: false, live_applied: false, live_detail: 'x' })
    const store = await freshStore()
    await store.fetchAll()
    await store.updateAI({
      provider: 'litellm',
      endpoint: '',
      chat_model: 'gpt',
      job_model: 'gpt',
      reason: 'r',
    })
    expect(store.aiNotConfigured).toBe(true)
    expect(store.aiTestable).toBe(false)
    expect(JSON.stringify(store.ai)).not.toContain('key":')
    expect(JSON.stringify(store.ai)).not.toContain('LITELLM_API_KEY')
  })

  it('exposes only editable boot keys for writes and flags sensitive ones', async () => {
    mockFetchAll()
    const store = await freshStore()
    await store.fetchAll()
    expect(store.editableBootKeys).toEqual(['INFLUX_URL', 'INFLUX_TOKEN', 'TZ'])
    expect(store.isSensitiveKey('INFLUX_TOKEN')).toBe(true)
    expect(store.isSensitiveKey('TZ')).toBe(false)
  })

  it('binds derived readonly_keys and never offers them as writable boot keys', async () => {
    mockFetchAll()
    const store = await freshStore()
    await store.fetchAll()
    // Derived DSN is surfaced as read-only, distinct from editable and sensitive.
    expect(store.boot?.readonly_keys).toEqual(['POSTGRES_DSN'])
    expect(store.editableBootKeys).not.toContain('POSTGRES_DSN')
    // A derived value can never be selected for a write.
    expect(store.editableBootKeys.includes('POSTGRES_DSN')).toBe(false)
    // The masked DSN carries no clear secret and the store never models a raw value for writes.
    expect(store.boot?.env.POSTGRES_DSN).not.toContain('postgres:postgres')
  })

  it('keeps sensitive values masked in the boot env and never preloads a clear secret', async () => {
    mockFetchAll()
    put.mockResolvedValue({ ...AI_READY, live_applied: true, live_detail: 'llm-config applied' })
    const store = await freshStore()
    await store.fetchAll()
    await store.updateAI({
      provider: 'litellm',
      endpoint: 'https://llm.example.com',
      chat_model: 'gpt',
      job_model: 'gpt',
      reason: 'r',
    })
    // Sensitive value arrives fully masked from the producer and is flagged write-only.
    expect(store.boot?.env.INFLUX_TOKEN).toBe('••••••••')
    expect(store.isSensitiveKey('INFLUX_TOKEN')).toBe(true)
    // AI key value is never present on any AI surface (drift GET, save result).
    expect(JSON.stringify(store.ai)).not.toContain('LITELLM_API_KEY')
    expect(JSON.stringify(store.ai)).not.toContain('sk-new-secret')
    expect(JSON.stringify(store.aiDrift)).not.toContain('key')
  })

  it('aiTestable requires both endpoint and configured key', async () => {
    mockFetchAll()
    put.mockResolvedValue({ ...AI_READY, key_configured: false, live_applied: true, live_detail: 'x' })
    const store = await freshStore()
    await store.updateAI({
      provider: 'litellm',
      endpoint: 'https://llm.example.com',
      chat_model: 'gpt',
      job_model: 'gpt',
      reason: 'r',
    })
    expect(store.aiTestable).toBe(false)
  })

  it('saveBoot PUTs the explicit key/value/reason then refetches', async () => {
    mockFetchAll()
    put.mockResolvedValue(BOOT)
    const store = await freshStore()
    await store.saveBoot({ key: 'TZ', value: 'Europe/Berlin', reason: 'dst change' })
    expect(put).toHaveBeenCalledWith('/api/v1/operations/configuration/boot', {
      key: 'TZ',
      value: 'Europe/Berlin',
      reason: 'dst change',
    })
    expect(get).toHaveBeenCalled()
    expect(store.saving).toBe(false)
  })

  it('surfaces an error and rethrows when saveBoot fails', async () => {
    put.mockRejectedValue(new Error('boom'))
    const store = await freshStore()
    await expect(store.saveBoot({ key: 'TZ', value: 'x', reason: 'because' })).rejects.toThrow('boom')
    expect(store.error).toBe('boom')
    expect(store.saving).toBe(false)
  })

  it('replaceAIKey posts the key + reason to the key endpoint', async () => {
    post.mockResolvedValue(AI_READY)
    const store = await freshStore()
    await store.replaceAIKey('sk-new-secret', 'rotate key')
    expect(post).toHaveBeenCalledWith('/api/v1/operations/ai-connection/key', {
      key: 'sk-new-secret',
      reason: 'rotate key',
    })
  })

  it('updateAI puts the non-secret fields and never a key value', async () => {
    put.mockResolvedValue(AI_SAVE_LIVE)
    const store = await freshStore()
    await store.updateAI({
      provider: 'litellm',
      endpoint: 'https://x',
      chat_model: 'a',
      job_model: 'b',
      reason: 'r',
      allow_unlisted_model: true,
    })
    expect(put).toHaveBeenCalledWith(
      '/api/v1/operations/ai-connection',
      expect.objectContaining({ provider: 'litellm', reason: 'r', allow_unlisted_model: true }),
    )
    const body = put.mock.calls[0][1] as Record<string, unknown>
    const serialized = JSON.stringify(body)
    expect(serialized).not.toContain('sk-new-secret')
    expect(serialized).not.toContain('LITELLM_API_KEY')
  })

  it('testAI updates the connection state from the result', async () => {
    mockFetchAll()
    post.mockResolvedValue({ success: false, state: 'failed' })
    const store = await freshStore()
    await store.fetchAll()
    const result = await store.testAI()
    expect(result.state).toBe('failed')
    expect(store.ai?.state).toBe('failed')
  })

  it('testAI seeds the connection object when none was saved yet', async () => {
    // "None saved yet" = the GET reports not-configured with empty fields, so the
    // store has nothing to pre-fill and testAI must seed the object itself.
    mockFetchAll({
      ...PERSISTED,
      provider: 'litellm',
      endpoint: '',
      chat_model: '',
      job_model: '',
      state: 'not-configured',
      key_configured: false,
    })
    post.mockResolvedValue({ success: false, state: 'failed' })
    const store = await freshStore()
    await store.fetchAll()
    expect(store.ai?.state).toBe('not-configured')
    await store.testAI()
    expect(store.ai?.state).toBe('failed')
    expect(store.ai?.key_configured).toBe(false)
  })

  it('testAI empty-state seed uses the documented 128000 default for the window (AI-046)', async () => {
    post.mockResolvedValue({ success: true, state: 'ready' })
    const store = await freshStore()
    expect(store.ai).toBeNull()
    await store.testAI()
    expect(store.ai?.context_window).toBe(128000)
  })

  it('rollback posts confirmed=true and refetches', async () => {
    mockFetchAll()
    post.mockResolvedValue({ success: true })
    const store = await freshStore()
    await store.rollback(2, 'undo change')
    expect(post).toHaveBeenCalledWith('/api/v1/operations/configuration/history/2/rollback', {
      reason: 'undo change',
      confirmed: true,
    })
    expect(get).toHaveBeenCalled()
  })

  it('captures a load error into store.error', async () => {
    get.mockRejectedValue(new Error('network down'))
    const store = await freshStore()
    await store.fetchAll()
    expect(store.error).toBe('network down')
    expect(store.loading).toBe(false)
  })
})

describe('configurationStore — AI-045 model catalog (fetchAIModels)', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    get.mockReset()
    put.mockReset()
    post.mockReset()
  })

  it('POSTs the models endpoint and stores the identifiers', async () => {
    post.mockResolvedValue({ models: ['gpt-5.4', 'claude-opus-5-5'] })
    const store = await freshStore()
    const models = await store.fetchAIModels()
    expect(post).toHaveBeenCalledWith('/api/v1/operations/ai-connection/models', {})
    expect(models).toEqual(['gpt-5.4', 'claude-opus-5-5'])
    expect(store.aiModels).toEqual(['gpt-5.4', 'claude-opus-5-5'])
    expect(store.aiModelsError).toBe('')
  })

  it('degrades a catalog 502 to an empty list plus aiModelsError, never a raise', async () => {
    post.mockRejectedValue({ status: 502, message: 'Bad Gateway', detail: 'model list unavailable' })
    const store = await freshStore()
    const models = await store.fetchAIModels()
    expect(models).toEqual([])
    expect(store.aiModels).toEqual([])
    expect(store.aiModelsError).toBe('model list unavailable')
    expect(store.error).toBe('')
  })
})

describe('configurationStore — AI-045 save outcome (live_applied / live_detail)', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    get.mockReset()
    put.mockReset()
    post.mockReset()
  })

  it('a live-applied save reports the applied state and never the recreate hint', async () => {
    put.mockResolvedValue(AI_SAVE_LIVE)
    const store = await freshStore()
    const notice = await store.updateAI({
      provider: 'litellm',
      endpoint: 'https://x',
      chat_model: 'gpt-5.4',
      job_model: 'gpt-5.4',
      reason: 'switch model',
    })
    expect(notice.applied).toBe(true)
    expect(notice.message).not.toContain('recreate')
    expect(store.lastAISave).toEqual(notice)
    expect(store.ai?.chat_model).toBe('gpt-5.4')
  })

  it('success note clears after 6 seconds (AI-045 operator feedback)', async () => {
    vi.useFakeTimers()
    try {
      put.mockResolvedValue(AI_SAVE_LIVE)
      const store = await freshStore()
      await store.updateAI({ provider: 'litellm', endpoint: 'https://x', chat_model: 'a', job_model: 'b', reason: '' })
      expect(store.lastAISave?.applied).toBe(true)
      vi.advanceTimersByTime(5000)
      expect(store.lastAISave).not.toBeNull()
      vi.advanceTimersByTime(2000)
      // Gegenprobe: without the timer the success note would still be there.
      expect(store.lastAISave).toBeNull()
    } finally {
      vi.useRealTimers()
    }
  })

  it('a failed live push note stays visible after the timeout (never auto-cleared)', async () => {
    vi.useFakeTimers()
    try {
      put.mockResolvedValue(AI_SAVE_NO_LIVE)
      const store = await freshStore()
      await store.updateAI({ provider: 'litellm', endpoint: 'https://x', chat_model: 'a', job_model: 'b', reason: '' })
      expect(store.lastAISave?.applied).toBe(false)
      vi.advanceTimersByTime(60000)
      expect(store.lastAISave?.applied).toBe(false)
      expect(store.lastAISave).not.toBeNull()
    } finally {
      vi.useRealTimers()
    }
  })

  it('a failed live save names the failed step and the recreate fallback', async () => {
    put.mockResolvedValue(AI_SAVE_NO_LIVE)
    const store = await freshStore()
    const notice = await store.updateAI({
      provider: 'litellm',
      endpoint: 'https://x',
      chat_model: 'gpt-5.4',
      job_model: 'gpt-5.4',
      reason: 'switch model',
    })
    expect(notice.applied).toBe(false)
    expect(notice.message).toContain('live push failed: ConnectError')
    expect(notice.message).toContain('Recreate otalon-ai')
    expect(store.ai?.chat_model).toBe('gpt-5.4')
  })

  it('keeps the saved context window from the PUT response in ai and aiDrift (AI-046)', async () => {
    mockFetchAll(AI_DRIFT_SYNCED)
    put.mockResolvedValue(AI_SAVE_LIVE)
    const store = await freshStore()
    await store.fetchAll()
    expect(store.ai?.context_window).toBe(256000)
    await store.updateAI({ provider: 'litellm', endpoint: 'https://x', chat_model: 'a', job_model: 'b', reason: '' })
    expect(store.ai?.context_window).toBe(320000)
    expect(store.aiDrift?.context_window).toBe(320000)
  })

  it('a live-applied save clears drift (active now equals the saved models)', async () => {
    mockFetchAll(AI_DRIFT_OFF)
    put.mockResolvedValue(AI_SAVE_LIVE)
    const store = await freshStore()
    await store.fetchAll()
    expect(store.aiDrift?.drift).toBe(true)
    await store.updateAI({
      provider: 'litellm',
      endpoint: 'https://x',
      chat_model: 'gpt',
      job_model: 'gpt',
      reason: 'r',
    })
    expect(store.aiDrift?.drift).toBe(false)
    expect(store.aiDrift?.active_chat_model).toBe('gpt-5.4')
  })
})

describe('configurationStore — AI-045 drift surface (GET)', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    get.mockReset()
    put.mockReset()
    post.mockReset()
  })

  it('loads active models and drift from the GET surface', async () => {
    mockFetchAll(AI_DRIFT_SYNCED)
    const store = await freshStore()
    await store.fetchAll()
    expect(store.aiDrift).toEqual(AI_DRIFT_SYNCED)
  })

  it('reports drift=true when the active chat model differs from the saved one', async () => {
    mockFetchAll(AI_DRIFT_OFF)
    const store = await freshStore()
    await store.fetchAll()
    expect(store.aiDrift?.drift).toBe(true)
    expect(store.aiDrift?.active_chat_model).toBe('old-model')
  })

  it('never fabricates drift when otalon-ai is unreachable (null actives)', async () => {
    mockFetchAll({ active_chat_model: null, active_job_model: null, drift: false })
    const store = await freshStore()
    await store.fetchAll()
    expect(store.aiDrift?.drift).toBe(false)
    expect(store.aiDrift?.active_chat_model).toBeNull()
  })
})

describe('configurationStore — runtime control plane', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    get.mockReset()
    put.mockReset()
    post.mockReset()
  })

  it('loads every manifest key, including keys never written', async () => {
    mockFetchAll()
    const store = await freshStore()
    await store.fetchRuntime()
    expect(get).toHaveBeenCalledWith('/api/v1/operations/configuration/runtime')
    expect(store.runtime).toHaveLength(2)
    const unwritten = store.runtime.find((i) => i.key === 'training.retrain_paused')
    expect(unwritten?.value).toBe('false')
    expect(unwritten?.updated_at).toBeNull()
  })

  it('groups runtime keys by owning service in manifest order', async () => {
    mockFetchAll()
    const store = await freshStore()
    await store.fetchRuntime()
    expect(store.runtimeByService.map((g) => g.service)).toEqual(['otalon-scan', 'otalon-clas'])
  })

  it('writes exactly one key and re-reads server state afterwards', async () => {
    mockFetchAll()
    put.mockResolvedValue({ items: RUNTIME_ITEMS, changed_keys: ['poll_interval_s'], restart_required: false })
    const store = await freshStore()
    const result = await store.saveRuntime({
      service: 'otalon-scan',
      key: 'poll_interval_s',
      value: '300',
      reason: 'reduce load',
    })
    expect(put).toHaveBeenCalledWith('/api/v1/operations/configuration/runtime', {
      service: 'otalon-scan',
      key: 'poll_interval_s',
      value: '300',
      reason: 'reduce load',
    })
    expect(result).toEqual({ changed_keys: ['poll_interval_s'], restart_required: false })
    // Local state is never trusted: a fresh GET confirms the write.
    expect(get).toHaveBeenCalledWith('/api/v1/operations/configuration/runtime')
  })

  it('reports restart_required=false so the no-restart guarantee is surfaced', async () => {
    mockFetchAll()
    put.mockResolvedValue({ items: RUNTIME_ITEMS, changed_keys: ['enabled'], restart_required: false })
    const store = await freshStore()
    await store.saveRuntime({ service: 'otalon-scan', key: 'enabled', value: 'true' })
    expect(store.lastRuntimeApply).toEqual({ changed_keys: ['enabled'], restart_required: false })
  })

  it('keeps the server 400 message verbatim instead of a generic one', async () => {
    mockFetchAll()
    // useApi rejects with a structured ApiError object literal, not an Error
    // instance — an `instanceof Error` check would discard the contract text.
    const detail = 'expected an integer in [10, 3600], got 1'
    put.mockRejectedValue({ status: 400, message: 'Bad Request', detail })
    const store = await freshStore()
    await expect(
      store.saveRuntime({ service: 'otalon-scan', key: 'poll_interval_s', value: '1' }),
    ).rejects.toBeDefined()
    expect(store.runtimeError).toBe(detail)
    expect(store.runtimeSavingKey).toBeNull()
  })

  it('keeps a secret-key rejection message verbatim', async () => {
    mockFetchAll()
    const detail = 'key influx_token is a secret and cannot be set through this surface'
    put.mockRejectedValue({ status: 400, message: 'Bad Request', detail })
    const store = await freshStore()
    await expect(store.saveRuntime({ service: 'otalon-scan', key: 'influx_token', value: 'x' })).rejects.toBeDefined()
    expect(store.runtimeError).toBe(detail)
  })

  it('isolates a runtime read failure from the Boot and AI surfaces', async () => {
    get.mockImplementation(async (path: string) => {
      if (path.endsWith('/boot')) return BOOT
      if (path.endsWith('/ai-connection')) return AI_READY
      if (path.endsWith('/history')) return HISTORY
      throw { status: 503, message: 'Service Unavailable', detail: 'runtime repo unavailable' }
    })
    const store = await freshStore()
    await store.fetchAll()
    expect(store.runtimeError).toBe('runtime repo unavailable')
    expect(store.error).toBe('')
    expect(store.boot).not.toBeNull()
  })
})
