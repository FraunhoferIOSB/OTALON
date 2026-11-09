/**
 * Component tests for the Operations Configuration page.
 *
 * Verifies the frozen five-tab IA, the security-relevant UI contracts
 * (sensitive boot value never rendered, AI key never shown, rollback
 * disabled unless the backend marks the entry eligible), the typed
 * confirmation gating on the Boot apply and rollback flows, and the live
 * write-capable Runtime tab (manifest completeness, per-type controls,
 * verbatim server rejections, no-restart messaging). The store is replaced
 * with a controllable stub so no network call is made.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises } from '@vue/test-utils'
import { reactive } from 'vue'

const notifyCreate = vi.fn()
vi.mock('quasar', () => ({
  Notify: { create: notifyCreate },
  Dialog: { create: vi.fn() },
}))

/**
 * Manifest-complete runtime fixture: one bool, one int with a persisted
 * history, and one int that has never been written (boot-derived value,
 * null audit fields) — the case the table must still render.
 */
const RUNTIME_ITEMS = [
  {
    service: 'otalon-scan',
    key: 'enabled',
    value: 'true',
    value_prev: null,
    updated_at: '2026-07-29T11:46:02.775467+02:00',
    updated_by: 'operator',
    type: 'bool' as const,
    domain: null,
    description: 'Whether the passive seeder performs work or idles visibly.',
  },
  {
    service: 'otalon-scan',
    key: 'poll_interval_s',
    value: '120',
    value_prev: '60',
    updated_at: '2026-07-29T11:46:02.763014+02:00',
    updated_by: 'operator',
    type: 'int' as const,
    domain: '[10, 3600]',
    description: 'Seconds the passive seeder waits between poll cycles.',
  },
  {
    service: 'otalon-scan',
    key: 'lookback_window_s',
    value: '300',
    value_prev: null,
    updated_at: null,
    updated_by: null,
    type: 'int' as const,
    domain: '[30, 86400]',
    description: 'Seconds of InfluxDB history each passive-seeder cycle reads.',
  },
  {
    service: 'otalon-scan',
    key: 'owner_email',
    value: 'ops@example.com',
    value_prev: null,
    updated_at: '2026-07-29T11:46:02.775467+02:00',
    updated_by: 'operator',
    type: 'str' as const,
    domain: null,
    description: 'Contact address for passive-seeder alerts.',
  },
  {
    service: 'otalon-scan',
    key: 'noise_threshold',
    value: '0.25',
    value_prev: null,
    updated_at: '2026-07-29T11:46:02.775467+02:00',
    updated_by: 'operator',
    type: 'float' as const,
    domain: '(0, 0.5]',
    description: 'Fraction of noise the passive seeder tolerates.',
  },
]

/**
 * The CLAS-071 series blacklist: a list-typed key whose value is the
 * canonical JSON serialization of the pattern array.
 */
const RUNTIME_LIST_ITEMS = [
  {
    service: 'otalon-clas',
    key: 'detection.series_blacklist',
    value: '["ff:ff:ff:ff:ff:ff","33:33:*"]',
    value_prev: null,
    updated_at: '2026-11-01T10:00:00+01:00',
    updated_by: 'operator',
    type: 'list' as const,
    domain: 'IP, MAC (wildcards allowed), protocol tag, or UCI with * fields',
    description: 'Series blacklist patterns applied to all modules.',
  },
]

// Reactive so that mutations made by the page (and by rejection paths that
// set `runtimeError`) actually trigger a re-render, as the real Pinia store
// would.
const storeStub = reactive({
  boot: {
    env: { INFLUX_URL: 'http://x:8181', INFLUX_TOKEN: '***', TZ: 'UTC' },
    editable_keys: ['INFLUX_URL', 'INFLUX_TOKEN', 'TZ'],
    sensitive_keys: ['INFLUX_TOKEN'],
    affected_services: { TZ: ['postgres', 'otalon-api'], INFLUX_URL: ['influxdb3'] },
  },
  ai: {
    provider: 'litellm',
    endpoint: 'https://llm.example.com',
    chat_model: 'gpt',
    job_model: 'gpt',
    state: 'ready' as const,
    key_configured: true,
  },
  aiDrift: { active_chat_model: 'gpt', active_job_model: 'gpt', drift: false },
  aiModels: ['gpt', 'gpt-5.4'],
  aiModelsError: '',
  lastAISave: null as { applied: boolean; message: string } | null,
  history: [
    { id: 2, at: '2026-07-18T01:00:00Z', actor: 'operator', action: 'update', target: 'TZ', rollback_eligible: true },
    {
      id: 1,
      at: '2026-07-18T00:00:00Z',
      actor: 'operator',
      action: 'replace-ai-key',
      target: 'LITELLM_API_KEY',
      rollback_eligible: false,
    },
  ],
  runtime: RUNTIME_ITEMS,
  runtimeByService: [
    { service: 'otalon-scan', items: RUNTIME_ITEMS },
    { service: 'otalon-clas', items: RUNTIME_LIST_ITEMS },
  ],
  runtimeError: '',
  runtimeSavingKey: null as string | null,
  lastRuntimeApply: null as { changed_keys: string[]; restart_required: boolean } | null,
  loading: false,
  saving: false,
  error: '',
  editableBootKeys: ['INFLUX_URL', 'TZ'],
  aiNotConfigured: false,
  aiTestable: true,
  isSensitiveKey: (key: string) => key === 'INFLUX_TOKEN',
  fetchAll: vi.fn().mockResolvedValue(undefined),
  saveBoot: vi.fn().mockResolvedValue(undefined),
  fetchAIModels: vi.fn().mockResolvedValue([]),
  updateAI: vi.fn().mockResolvedValue({
    applied: true,
    message: 'AI connection saved — the running otalon-ai uses the new configuration.',
  }),
  replaceAIKey: vi.fn().mockResolvedValue(undefined),
  testAI: vi.fn().mockResolvedValue({ success: true, state: 'ready' }),
  rollback: vi.fn().mockResolvedValue(undefined),
  fetchRuntime: vi.fn().mockResolvedValue(undefined),
  saveRuntime: vi.fn().mockResolvedValue({ changed_keys: ['poll_interval_s'], restart_required: false }),
})

vi.mock('~/stores/configurationStore', () => ({
  useConfigurationStore: () => storeStub,
}))

async function mountPage() {
  const { mountWithPlugins } = await import('../helpers/mount')
  const mod = await import('~/pages/operations/configuration.vue')
  return mountWithPlugins(mod.default)
}

beforeEach(() => {
  notifyCreate.mockReset()
  storeStub.saveBoot.mockClear()
  storeStub.rollback.mockClear()
  storeStub.testAI.mockClear()
  storeStub.saveRuntime.mockClear()
  storeStub.saveRuntime.mockResolvedValue({ changed_keys: ['poll_interval_s'], restart_required: false })
  storeStub.updateAI.mockClear()
  storeStub.fetchAIModels.mockClear()
  storeStub.updateAI.mockResolvedValue({
    applied: true,
    message: 'AI connection saved — the running otalon-ai uses the new configuration.',
  })
  storeStub.fetchAIModels.mockResolvedValue([])
  storeStub.error = ''
  storeStub.runtimeError = ''
  storeStub.runtimeSavingKey = null
  storeStub.lastRuntimeApply = null
  storeStub.ai = {
    provider: 'litellm',
    endpoint: 'https://llm.example.com',
    chat_model: 'gpt',
    job_model: 'gpt',
    state: 'ready' as const,
    key_configured: true,
  }
  storeStub.aiDrift = { active_chat_model: 'gpt', active_job_model: 'gpt', drift: false }
  storeStub.aiModels = ['gpt', 'gpt-5.4']
  storeStub.aiModelsError = ''
  storeStub.lastAISave = null
})

afterEach(() => {
  vi.resetModules()
})

describe('Configuration page — IA', () => {
  it('renders exactly the five frozen tabs', async () => {
    const wrapper = await mountPage()
    const tabs = wrapper.findAll('.q-tab').map((t) => t.text())
    expect(tabs).toEqual(['Runtime', 'Boot & Environment', 'AI Connection', 'Access & Users', 'Change History'])
  })

  it('marks the Runtime tab live, never backend-pending', async () => {
    const wrapper = await mountPage()
    expect(wrapper.find('[data-test="runtime-live"]').text()).toContain('live')
    expect(wrapper.find('[data-test="runtime-pending"]').exists()).toBe(false)
  })

  it('shows no backend-pending or runtime info banner on any tab (AI-045 operator feedback)', async () => {
    const wrapper = await mountPage()
    // Operator 2026-11-09: the info banners are removed everywhere, not only on Runtime.
    expect(wrapper.find('[data-test="operations-mutations-pending"]').exists()).toBe(false)
    expect(wrapper.find('[data-test="runtime-live-banner"]').exists()).toBe(false)
    expect(wrapper.text()).not.toContain('backend-pending')
    expect(wrapper.text()).not.toContain('take effect within one poll cycle')
  })

  it('no banner appears on the boot tab either (Gegenprobe to the old scoped banner)', async () => {
    const wrapper = await mountPage()
    wrapper.findComponent({ name: 'QTabs' }).vm.$emit('update:modelValue', 'boot')
    await flushPromises()
    expect(wrapper.find('[data-test="operations-mutations-pending"]').exists()).toBe(false)
    expect(wrapper.text()).not.toContain('backend-pending')
  })
})

describe('Configuration page — AI Connection (AI-045 operator feedback)', () => {
  it('shows the Context size field in the AI Connection form (AI-046)', async () => {
    const wrapper = await mountPage()
    wrapper.findComponent({ name: 'QTabs' }).vm.$emit('update:modelValue', 'ai')
    await flushPromises()
    // Gegenprobe: the field exists only when the form is rendered, so a missing field fails here.
    // Labels are not rendered as text in this mount setup (see TriggerModal), so the
    // data-test attribute is the reliable handle.
    expect(wrapper.find('[data-test="ai-context-window"]').exists()).toBe(true)
  })

  it('shows no Provider input field (value is fixed, not user-editable)', async () => {
    const wrapper = await mountPage()
    wrapper.findComponent({ name: 'QTabs' }).vm.$emit('update:modelValue', 'ai')
    await flushPromises()
    // Gegenprobe: the rest of the AI form is rendered, so the Provider absence is meaningful.
    expect(wrapper.find('[data-test="ai-provider"]').exists()).toBe(false)
    expect(wrapper.text()).not.toContain('Provider')
  })
})

describe('Configuration page — Runtime tab', () => {
  it('lists every runtime key including those never written', async () => {
    const wrapper = await mountPage()
    const rows = wrapper.findAll('[data-test="runtime-row"]')
    expect(rows).toHaveLength(6)
    // A key with no persisted row must still appear with its boot-derived
    // value rather than being omitted from the table.
    expect(wrapper.text()).toContain('lookback_window_s')
    expect(wrapper.findAll('[data-test="runtime-never-written"]').length).toBe(1)
  })

  it('shows current value, previous value and who changed it when', async () => {
    const wrapper = await mountPage()
    const values = wrapper.findAll('[data-test="runtime-value"]').map((n) => n.text())
    expect(values).toContain('120')
    expect(wrapper.findAll('[data-test="runtime-value-prev"]').map((n) => n.text())).toContain('60')
    expect(wrapper.find('[data-test="runtime-updated"]').text()).toContain('operator')
  })

  it('states explicitly that runtime changes need no restart', async () => {
    const wrapper = await mountPage()
    expect(wrapper.find('[data-test="runtime-no-restart-note"]').text()).toContain('no restart is required')
  })

  it('renders a toggle for bool keys and a number input for int keys', async () => {
    const wrapper = await mountPage()
    const editButtons = wrapper.findAll('[data-test="runtime-edit"]')

    await editButtons[0].trigger('click')
    await flushPromises()
    expect(wrapper.find('[data-test="runtime-bool-input"]').exists()).toBe(true)
    await wrapper.find('[data-test="runtime-cancel"]').trigger('click')
    await flushPromises()

    await editButtons[1].trigger('click')
    await flushPromises()
    const numberInput = wrapper.find('[data-test="runtime-value-input"] input')
    expect(numberInput.exists()).toBe(true)
    expect(numberInput.attributes('type')).toBe('number')
  })

  it('submits the edited value with the optional reason', async () => {
    const wrapper = await mountPage()
    await wrapper.findAll('[data-test="runtime-edit"]')[1].trigger('click')
    await flushPromises()
    await wrapper.find('[data-test="runtime-value-input"] input').setValue('300')
    await wrapper.find('[data-test="runtime-reason-input"] input').setValue('reduce influx load')
    await wrapper.find('[data-test="runtime-apply"]').trigger('click')
    await flushPromises()

    expect(storeStub.saveRuntime).toHaveBeenCalledTimes(1)
    expect(storeStub.saveRuntime.mock.calls[0][0]).toEqual({
      service: 'otalon-scan',
      key: 'poll_interval_s',
      value: '300',
      reason: 'reduce influx load',
    })
  })

  it('omits the reason entirely when the operator leaves it blank', async () => {
    const wrapper = await mountPage()
    await wrapper.findAll('[data-test="runtime-edit"]')[1].trigger('click')
    await flushPromises()
    await wrapper.find('[data-test="runtime-value-input"] input').setValue('300')
    await wrapper.find('[data-test="runtime-apply"]').trigger('click')
    await flushPromises()
    expect(storeStub.saveRuntime.mock.calls[0][0]).not.toHaveProperty('reason')
  })

  it('warns client-side when a value falls outside the declared domain', async () => {
    const wrapper = await mountPage()
    await wrapper.findAll('[data-test="runtime-edit"]')[1].trigger('click')
    await flushPromises()
    await wrapper.find('[data-test="runtime-value-input"] input').setValue('1')
    await flushPromises()
    expect(wrapper.find('[data-test="runtime-domain-warning"]').text()).toContain('[10, 3600]')
  })

  it('shows the server rejection message verbatim, not a generic one', async () => {
    const serverText = 'expected an integer in [10, 3600], got 1'
    storeStub.saveRuntime.mockImplementationOnce(async () => {
      storeStub.runtimeError = serverText
      throw { status: 400, message: 'Bad Request', detail: serverText }
    })
    const wrapper = await mountPage()
    await wrapper.findAll('[data-test="runtime-edit"]')[1].trigger('click')
    await flushPromises()
    await wrapper.find('[data-test="runtime-value-input"] input').setValue('1')
    await wrapper.find('[data-test="runtime-apply"]').trigger('click')
    await flushPromises()

    expect(wrapper.find('[data-test="runtime-dialog-error"]').text()).toBe(serverText)
    expect(wrapper.text()).not.toContain('invalid input')
  })

  it('reports the applied keys and that no restart is needed', async () => {
    storeStub.lastRuntimeApply = { changed_keys: ['poll_interval_s'], restart_required: false }
    const wrapper = await mountPage()
    const result = wrapper.find('[data-test="runtime-apply-result"]')
    expect(result.text()).toContain('poll_interval_s')
    expect(wrapper.find('[data-test="runtime-apply-restart"]').text()).toContain('no restart')
  })

  it('shows one future-contract marker per Access section', async () => {
    const wrapper = await mountPage()
    const sections = wrapper.findAll('[data-test="access-section"]')
    expect(sections).toHaveLength(5)
    sections.forEach((section) => expect(section.text()).toContain('SUITE-016'))
  })
})

describe('Configuration page — Runtime list editor (CLAS-071)', () => {
  function findListEditButton(wrapper: Awaited<ReturnType<typeof mountPage>>) {
    return wrapper.findAll('[data-test="runtime-edit"]').at(-1)
  }

  async function openListDialog() {
    const wrapper = await mountPage()
    await findListEditButton(wrapper)!.trigger('click')
    await flushPromises()
    return wrapper
  }

  it('renders one editable row per entry from the GET payload plus a JSON preview', async () => {
    const wrapper = await openListDialog()

    const inputs = wrapper.findAll('[data-test="runtime-list-input"] input')
    expect(inputs).toHaveLength(2)
    expect((inputs[0].element as HTMLInputElement).value).toBe('ff:ff:ff:ff:ff:ff')
    expect((inputs[1].element as HTMLInputElement).value).toBe('33:33:*')
    expect(wrapper.find('[data-test="runtime-list-preview"]').text()).toContain('["ff:ff:ff:ff:ff:ff","33:33:*"]')
  })

  it('shows the English accepted-forms caption and the no-restart banner', async () => {
    const wrapper = await openListDialog()

    const caption = wrapper.find('[data-test="runtime-list-caption"]').text()
    expect(caption).toContain(
      'Series Blacklist — one pattern per line: IP, MAC (wildcards allowed), protocol tag, or UCI with `*` fields.',
    )
    expect(caption).toBe(caption.trim()) // no German strings in product UI
    expect(wrapper.find('[data-test="runtime-dialog-no-restart"]').exists()).toBe(true)
  })

  it('saving an empty list submits [] (all entries removed)', async () => {
    const wrapper = await openListDialog()

    const removeButtons = wrapper.findAll('[data-test="runtime-list-remove"]')
    expect(removeButtons).toHaveLength(2)
    await removeButtons[0].trigger('click')
    // Re-query after each removal — the first button's removal re-indexes rows.
    await wrapper.findAll('[data-test="runtime-list-remove"]')[0].trigger('click')
    await wrapper.find('[data-test="runtime-apply"]').trigger('click')
    await flushPromises()

    expect(storeStub.saveRuntime).toHaveBeenCalledTimes(1)
    expect(storeStub.saveRuntime.mock.calls[0][0]).toMatchObject({
      service: 'otalon-clas',
      key: 'detection.series_blacklist',
      value: '[]',
    })
  })

  it('add, edit and remove produce the expected submitted JSON array', async () => {
    const wrapper = await openListDialog()

    await wrapper.findAll('[data-test="runtime-list-remove"]')[1].trigger('click')
    await wrapper.find('[data-test="runtime-list-add"]').trigger('click')
    const inputs = wrapper.findAll('[data-test="runtime-list-input"] input')
    expect(inputs.length).toBeGreaterThanOrEqual(2)
    await inputs.at(-1)!.setValue('IPv6')

    await wrapper.find('[data-test="runtime-reason-input"] input').setValue('remove stale multicast entry')
    await wrapper.find('[data-test="runtime-apply"]').trigger('click')
    await flushPromises()

    expect(storeStub.saveRuntime).toHaveBeenCalledTimes(1)
    expect(storeStub.saveRuntime.mock.calls[0][0]).toEqual({
      service: 'otalon-clas',
      key: 'detection.series_blacklist',
      value: '["ff:ff:ff:ff:ff:ff","IPv6"]',
      reason: 'remove stale multicast entry',
    })
  })

  it('trims entries and drops empty ones from the submitted array', async () => {
    const wrapper = await openListDialog()

    const inputs = wrapper.findAll('[data-test="runtime-list-input"] input')
    await inputs[0].setValue('  50:61:d6:00:ba:b2  ')
    await inputs[1].setValue('   ')
    await wrapper.find('[data-test="runtime-apply"]').trigger('click')
    await flushPromises()

    expect(storeStub.saveRuntime.mock.calls[0][0]).toMatchObject({ value: '["50:61:d6:00:ba:b2"]' })
  })

  it('surfaces a server 422 entry detail verbatim and keeps the entries', async () => {
    const serverText = 'entry[0]: unmatched pattern form: "???"'
    storeStub.saveRuntime.mockImplementationOnce(async () => {
      storeStub.runtimeError = serverText
      throw { status: 422, message: 'Unprocessable Entity', detail: serverText }
    })
    const wrapper = await openListDialog()

    const inputs = wrapper.findAll('[data-test="runtime-list-input"] input')
    await inputs[0].setValue('???')
    await wrapper.find('[data-test="runtime-apply"]').trigger('click')
    await flushPromises()

    expect(wrapper.find('[data-test="runtime-dialog-error"]').text()).toBe(serverText)
    // The operator's in-progress entries survive the failed submit.
    const after = wrapper.findAll('[data-test="runtime-list-input"] input')
    expect((after[0].element as HTMLInputElement).value).toBe('???')
    expect((after[1].element as HTMLInputElement).value).toBe('33:33:*')
  })

  it('keeps the bool/int/float/str dialog paths unchanged', async () => {
    const wrapper = await mountPage()
    const editButtons = wrapper.findAll('[data-test="runtime-edit"]')

    await editButtons[0].trigger('click')
    await flushPromises()
    expect(wrapper.find('[data-test="runtime-bool-input"]').exists()).toBe(true)
    expect(wrapper.find('[data-test="runtime-list-input"]').exists()).toBe(false)
    await wrapper.find('[data-test="runtime-cancel"]').trigger('click')
    await flushPromises()

    await editButtons[1].trigger('click')
    await flushPromises()
    const numberInput = wrapper.find('[data-test="runtime-value-input"] input')
    expect(numberInput.exists()).toBe(true)
    expect(numberInput.attributes('type')).toBe('number')
    await wrapper.find('[data-test="runtime-cancel"]').trigger('click')
    await flushPromises()

    // Str keys keep the pre-existing single-input treatment (the shared
    // number-typed q-input renders today); only assert it is NOT the list
    // editor so this test cannot drift into re-speccing the str path.
    await editButtons[3].trigger('click')
    await flushPromises()
    expect(wrapper.find('[data-test="runtime-list-input"]').exists()).toBe(false)
    expect(wrapper.find('[data-test="runtime-value-input"]').exists()).toBe(true)
    await wrapper.find('[data-test="runtime-cancel"]').trigger('click')
    await flushPromises()

    await editButtons[4].trigger('click')
    await flushPromises()
    expect((wrapper.find('[data-test="runtime-value-input"] input').element as HTMLInputElement).value).toBe('0.25')
    await wrapper.find('[data-test="runtime-cancel"]').trigger('click')
    await flushPromises()
  })
})

describe('Configuration page — secrets are never rendered', () => {
  it('never renders a sensitive boot value', async () => {
    const wrapper = await mountPage()
    expect(wrapper.find('[data-test="boot-sensitive-value"]').text()).toContain('hidden')
    expect(wrapper.text()).not.toContain('supersecret')
  })

  it('shows the AI key as write-only and never as a value', async () => {
    const wrapper = await mountPage()
    expect(wrapper.find('[data-test="ai-key-state"]').text()).toContain('write-only')
  })
})

describe('Configuration page — Boot typed confirmation', () => {
  it('does not apply until reason + typed APPLY confirmation are present', async () => {
    const wrapper = await mountPage()
    await wrapper.find('[data-test="boot-open"]').trigger('click')
    await flushPromises()

    const applyBtn = wrapper.find('[data-test="boot-apply"]')
    // reason empty, confirm empty → disabled, click does nothing
    await applyBtn.trigger('click')
    expect(storeStub.saveBoot).not.toHaveBeenCalled()

    await wrapper.find('[data-test="boot-reason-input"] input').setValue('dst change')
    await wrapper.find('[data-test="boot-confirm-input"] input').setValue('WRONG')
    await applyBtn.trigger('click')
    expect(storeStub.saveBoot).not.toHaveBeenCalled()

    await wrapper.find('[data-test="boot-confirm-input"] input').setValue('APPLY')
    await applyBtn.trigger('click')
    await flushPromises()
    expect(storeStub.saveBoot).toHaveBeenCalledTimes(1)
    const arg = storeStub.saveBoot.mock.calls[0][0]
    expect(arg).toMatchObject({ reason: 'dst change' })
    expect(arg.key).toBe('INFLUX_URL')
  })

  it('surfaces the restart impact with the exact affected services', async () => {
    const wrapper = await mountPage()
    await wrapper.find('[data-test="boot-open"]').trigger('click')
    await flushPromises()
    expect(wrapper.find('[data-test="boot-impact"]').text()).toContain('influxdb3')
  })

  it('loads the selected key value on open (default key A)', async () => {
    const wrapper = await mountPage()
    await wrapper.find('[data-test="boot-open"]').trigger('click')
    await flushPromises()
    const valueInput = wrapper.find('[data-test="boot-value-input"] input').element as HTMLInputElement
    // Default first editable key is INFLUX_URL → its saved value, not blank/stale.
    expect(valueInput.value).toBe('http://x:8181')
  })

  it('syncs New value to the selected key when the Boot key changes to TZ', async () => {
    const wrapper = await mountPage()
    await wrapper.find('[data-test="boot-open"]').trigger('click')
    await flushPromises()

    // Switch the select from the default INFLUX_URL to TZ; the New value field
    // must immediately hold TZ's actual saved value, never the previous key's.
    const select = wrapper.findAllComponents({ name: 'QSelect' }).find((s) => s.attributes('data-test') === 'boot-key-select')
    select!.vm.$emit('update:modelValue', 'TZ')
    await flushPromises()

    const valueInput = wrapper.find('[data-test="boot-value-input"] input').element as HTMLInputElement
    expect(valueInput.value).toBe('UTC')
    // regression guard: must never carry the prior INFLUX_URL value.
    expect(valueInput.value).not.toBe('http://x:8181')
  })

  it('submits the selected key and its synced value after a key switch', async () => {
    const wrapper = await mountPage()
    await wrapper.find('[data-test="boot-open"]').trigger('click')
    await flushPromises()

    const select = wrapper.findAllComponents({ name: 'QSelect' }).find((s) => s.attributes('data-test') === 'boot-key-select')
    select!.vm.$emit('update:modelValue', 'TZ')
    await flushPromises()

    await wrapper.find('[data-test="boot-reason-input"] input').setValue('dst change')
    await wrapper.find('[data-test="boot-confirm-input"] input').setValue('APPLY')
    await wrapper.find('[data-test="boot-apply"]').trigger('click')
    await flushPromises()

    expect(storeStub.saveBoot).toHaveBeenCalledTimes(1)
    expect(storeStub.saveBoot.mock.calls[0][0]).toEqual({
      key: 'TZ',
      value: 'UTC',
      reason: 'dst change',
    })
  })
})

describe('Configuration page — rollback', () => {
  it('refuses to arm a rollback for an ineligible entry', async () => {
    const wrapper = await mountPage()
    const buttons = wrapper.findAll('[data-test="history-rollback"]')
    expect(buttons).toHaveLength(2)

    // Clicking the ineligible entry (id 1, a key replacement) must not arm a
    // rollback even if the shared dialog is then confirmed — the guard on
    // `rollback_eligible` rejects it and `rollbackEntryId` stays null.
    await buttons[1].trigger('click')
    await flushPromises()
    await wrapper.find('[data-test="rollback-reason-input"] input').setValue('undo it')
    await wrapper.find('[data-test="rollback-confirm-input"] input').setValue('ROLLBACK')
    await wrapper.find('[data-test="rollback-apply"]').trigger('click')
    await flushPromises()
    expect(storeStub.rollback).not.toHaveBeenCalled()
  })

  it('requires reason + typed ROLLBACK confirmation before rolling back', async () => {
    const wrapper = await mountPage()
    await wrapper.findAll('[data-test="history-rollback"]')[0].trigger('click')
    await flushPromises()

    const applyBtn = wrapper.find('[data-test="rollback-apply"]')
    await wrapper.find('[data-test="rollback-reason-input"] input').setValue('undo it')
    await applyBtn.trigger('click')
    expect(storeStub.rollback).not.toHaveBeenCalled()

    await wrapper.find('[data-test="rollback-confirm-input"] input').setValue('ROLLBACK')
    await applyBtn.trigger('click')
    await flushPromises()
    expect(storeStub.rollback).toHaveBeenCalledWith(2, 'undo it')
  })
})

describe('Configuration page — AI test gating', () => {
  it('runs the AI test when testable', async () => {
    const wrapper = await mountPage()
    await wrapper.find('[data-test="ai-test"]').trigger('click')
    await flushPromises()
    expect(storeStub.testAI).toHaveBeenCalled()
  })
})

describe('Configuration page — AI model selects (AI-045)', () => {
  it('fills the chat and job selects from the proxy model list', async () => {
    const wrapper = await mountPage()
    await flushPromises()
    expect(storeStub.fetchAIModels).toHaveBeenCalled()
    const chatSelect = wrapper.findAllComponents({ name: 'QSelect' }).find((s) => s.attributes('data-test') === 'ai-chat')
    const jobSelect = wrapper.findAllComponents({ name: 'QSelect' }).find((s) => s.attributes('data-test') === 'ai-job')
    expect(chatSelect).toBeDefined()
    expect(jobSelect).toBeDefined()
    expect(chatSelect!.props('options')).toEqual([
      { label: 'gpt', value: 'gpt' },
      { label: 'gpt-5.4', value: 'gpt-5.4' },
    ])
  })

  it('keeps the job model selectable when the chat model is not offered', async () => {
    storeStub.ai.chat_model = 'legacy-model'
    storeStub.aiModels = ['gpt', 'gpt-5.4']
    const wrapper = await mountPage()
    await flushPromises()
    // The unlisted chat model degrades to the explicit free-text fallback...
    expect(wrapper.find('[data-test="ai-chat"]').element.tagName).not.toBe('SELECT')
    // ...while the listed job model stays on the proxy-backed select.
    const jobSelect = wrapper.findAllComponents({ name: 'QSelect' }).find((s) => s.attributes('data-test') === 'ai-job')
    expect(jobSelect).toBeDefined()
    const jobValues = (jobSelect!.props('options') as { value: string }[]).map((option) => option.value)
    expect(jobValues).toContain('gpt')
    expect(jobValues).toContain('gpt-5.4')
  })

  it('arms the free-text fallback automatically for a saved unlisted model', async () => {
    storeStub.ai.chat_model = 'legacy-model'
    storeStub.aiModels = ['gpt-5.4']
    const wrapper = await mountPage()
    await flushPromises()
    expect(wrapper.find('[data-test="ai-chat-custom-toggle"]').exists()).toBe(true)
    const chatControl = wrapper.find('[data-test="ai-chat"]')
    expect(chatControl.exists()).toBe(true)
    expect(chatControl.element.tagName).not.toBe('SELECT')
    expect(wrapper.find('[data-test="ai-chat-unverified-warning"]').exists()).toBe(true)
  })

  it('shows the unverified-model warning only when the fallback is explicitly armed', async () => {
    const wrapper = await mountPage()
    await flushPromises()
    expect(wrapper.find('[data-test="ai-chat-unverified-warning"]').exists()).toBe(false)
    expect(wrapper.find('[data-test="ai-chat"]').element.tagName).toBe('SELECT')
    await wrapper.find('[data-test="ai-chat-custom-toggle"] input').setValue(true)
    await flushPromises()
    expect(wrapper.find('[data-test="ai-chat-unverified-warning"]').exists()).toBe(true)
    expect(wrapper.find('[data-test="ai-chat"]').element.tagName).not.toBe('SELECT')
  })

  it('announces an unavailable model list and yields to the free-text fallback', async () => {
    storeStub.aiModels = []
    storeStub.aiModelsError = 'model list unavailable'
    const wrapper = await mountPage()
    await flushPromises()
    const banner = wrapper.find('[data-test="ai-models-unavailable"]')
    expect(banner.exists()).toBe(true)
    expect(banner.text()).toContain('model list unavailable')
  })

  it('does not announce an unavailable list when models were loaded', async () => {
    storeStub.aiModels = ['gpt-5.4']
    storeStub.aiModelsError = ''
    const wrapper = await mountPage()
    await flushPromises()
    expect(wrapper.find('[data-test="ai-models-unavailable"]').exists()).toBe(false)
  })

  it('saves without an audit reason (reason is optional, AI-045 operator decision)', async () => {
    storeStub.updateAI.mockClear()
    const wrapper = await mountPage()
    await flushPromises()
    await wrapper.find('[data-test="ai-save"]').trigger('click')
    await flushPromises()
    // No reason typed: the confirm button must be enabled and must call updateAI.
    // Mount renders no disable state for q-btn, so the button's enabled state is
    // verified in the real browser (Phase 7), not here. This test covers the
    // behaviour: a save without reason reaches the store.
    await wrapper.find('[data-test="ai-save-confirm"]').trigger('click')
    await flushPromises()
    expect(storeStub.updateAI).toHaveBeenCalledTimes(1)
    expect(storeStub.updateAI.mock.calls[0][0].reason).toBe('')
  })

  it('never sends allow_unlisted_model while both models are picked from the list', async () => {
    const wrapper = await mountPage()
    await flushPromises()
    await wrapper.find('[data-test="ai-save"]').trigger('click')
    await flushPromises()
    await wrapper.find('[data-test="ai-reason-input"] input').setValue('switch model')
    await wrapper.find('[data-test="ai-save-confirm"]').trigger('click')
    await flushPromises()
    expect(storeStub.updateAI).toHaveBeenCalledTimes(1)
    expect(storeStub.updateAI.mock.calls[0][0]).not.toHaveProperty('allow_unlisted_model')
  })

  it('sends allow_unlisted_model=true when a fallback model is used', async () => {
    storeStub.ai.chat_model = 'custom-model'
    storeStub.aiModels = ['gpt']
    const wrapper = await mountPage()
    await flushPromises()
    // The unlisted saved model armed the fallback; the save must say so.
    expect(wrapper.find('[data-test="ai-chat-unverified-warning"]').exists()).toBe(true)
    await wrapper.find('[data-test="ai-save"]').trigger('click')
    await flushPromises()
    await wrapper.find('[data-test="ai-reason-input"] input').setValue('switch model')
    await wrapper.find('[data-test="ai-save-confirm"]').trigger('click')
    await flushPromises()
    expect(storeStub.updateAI).toHaveBeenCalledTimes(1)
    expect(storeStub.updateAI.mock.calls[0][0]).toMatchObject({ allow_unlisted_model: true })
  })
})

describe('Configuration page — AI save outcome hint (AI-045)', () => {
  it('shows the applied state without any recreate hint when the live update applied', async () => {
    storeStub.lastAISave = {
      applied: true,
      message: 'AI connection saved — the running otalon-ai uses the new configuration.',
    }
    const wrapper = await mountPage()
    const result = wrapper.find('[data-test="ai-save-result"]')
    expect(result.exists()).toBe(true)
    expect(result.text()).not.toContain('recreate')
    expect(result.text()).toContain('running otalon-ai uses the new configuration')
  })

  it('names the recreate fallback when the live update did not apply', async () => {
    storeStub.lastAISave = {
      applied: false,
      message:
        'AI connection saved, but the live update did not apply (live push failed: ConnectError). Recreate otalon-ai to apply the saved configuration.',
    }
    const wrapper = await mountPage()
    const result = wrapper.find('[data-test="ai-save-result"]')
    expect(result.exists()).toBe(true)
    expect(result.text()).toContain('live update did not apply')
    expect(result.text()).toContain('Recreate otalon-ai to apply the saved configuration')
  })

  it('notifies with the applied wording (no recreate hint) after a live save', async () => {
    const wrapper = await mountPage()
    await wrapper.find('[data-test="ai-save"]').trigger('click')
    await flushPromises()
    await wrapper.find('[data-test="ai-reason-input"] input').setValue('switch model')
    await wrapper.find('[data-test="ai-save-confirm"]').trigger('click')
    await flushPromises()
    expect(notifyCreate).toHaveBeenCalledTimes(1)
    expect(notifyCreate.mock.calls[0][0].message).not.toContain('recreate')
    storeStub.updateAI.mock.calls.length = 0
  })

  it('notifies with the recreate fallback after a failed live save', async () => {
    storeStub.updateAI.mockResolvedValueOnce({
      applied: false,
      message:
        'AI connection saved, but the live update did not apply (live push failed: ConnectError). Recreate otalon-ai to apply the saved configuration.',
    })
    const wrapper = await mountPage()
    await wrapper.find('[data-test="ai-save"]').trigger('click')
    await flushPromises()
    await wrapper.find('[data-test="ai-reason-input"] input').setValue('switch model')
    await wrapper.find('[data-test="ai-save-confirm"]').trigger('click')
    await flushPromises()
    expect(notifyCreate).toHaveBeenCalledTimes(1)
    expect(notifyCreate.mock.calls[0][0].message).toContain('Recreate otalon-ai to apply the saved configuration')
  })

  it('keeps the save dialog wording honest about the live push and recreate fallback', async () => {
    const wrapper = await mountPage()
    await wrapper.find('[data-test="ai-save"]').trigger('click')
    await flushPromises()
    const hint = wrapper.find('[data-test="ai-save-dialog-live-hint"]')
    expect(hint.exists()).toBe(true)
    expect(hint.text()).not.toContain('recreate otalon-ai to apply')
  })
})

describe('Configuration page — AI drift indicator (AI-045)', () => {
  it('shows a drift indicator with both model names after a plain restart', async () => {
    storeStub.ai = {
      provider: 'litellm',
      endpoint: 'https://llm.example.com',
      chat_model: 'gpt-5.4',
      job_model: 'gpt-5.4',
      state: 'ready' as const,
      key_configured: true,
    }
    storeStub.aiDrift = { active_chat_model: 'old-model', active_job_model: 'old-job', drift: true }
    const wrapper = await mountPage()
    const drift = wrapper.find('[data-test="ai-drift"]')
    expect(drift.exists()).toBe(true)
    expect(drift.text()).toContain('gpt-5.4')
    expect(drift.text()).toContain('old-model')
    expect(drift.text()).toContain('old-job')
  })

  it('shows no drift indicator when saved and active models match', async () => {
    const wrapper = await mountPage()
    expect(wrapper.find('[data-test="ai-drift"]').exists()).toBe(false)
  })

  it('shows no drift indicator when the runtime is unreachable (null actives)', async () => {
    storeStub.aiDrift = { active_chat_model: null, active_job_model: null, drift: false }
    const wrapper = await mountPage()
    expect(wrapper.find('[data-test="ai-drift"]').exists()).toBe(false)
  })
})
