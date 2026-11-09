/**
 * Component tests for the Passive Discovery card on the Operations /
 * Data Sources page.
 *
 * Verifies the card renders persisted producer truth (asset count, last
 * observed timestamp, active/stale/no-data badge) instead of a hard-coded
 * disabled/0 state, that the seeder's own reported status is surfaced with
 * correct semantics (last-cycle rows, unknown distinct from disabled,
 * verbatim last error), and that the page stays status-only with a deep
 * link to the runtime controls. The store is replaced with a controllable
 * stub so no network call is made.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises } from '@vue/test-utils'

import type { PassiveDiscoveryStatus, PassiveSeederState, PassiveSeederStatus } from '~/types/api'

// The page calls the auto-imported usePolling() at setup top-level; provide
// a no-op global so mounting does not start a real interval timer.
;(globalThis as Record<string, unknown>).usePolling = () => ({
  isActive: { value: true },
  pause: vi.fn(),
  resume: vi.fn(),
})

interface StoreStub {
  pipeline: null
  captureStatus: null
  passiveDiscovery: PassiveDiscoveryStatus | null
  passiveError: string | null
  seederStatus: PassiveSeederStatus | null
  seederError: string | null
  seederState: PassiveSeederState
  seederBadge: { label: string; kind: 'ok' | 'warn' | 'err' | 'muted' }
  isLoading: boolean
  pipelineError: null
  captureError: null
  sourceRows: never[]
  staleBanner: null
  passiveBadge: { label: string; kind: 'ok' | 'warn' | 'muted' }
  loadAll: () => Promise<void>
}

const SEEDER_STATUS: PassiveSeederStatus = {
  service: 'otalon-scan',
  state: 'running',
  last_cycle_at: '2026-07-29T12:44:48.600Z',
  last_error: null,
  rows_seeded: 15,
  poll_interval_s: 120,
  updated_at: '2026-07-29T12:44:48.600Z',
}

const CURRENT_STATUS: PassiveDiscoveryStatus = {
  observed_asset_count: 10,
  observed_interface_count: 10,
  latest_seen_at: '2026-07-21T07:14:43.750Z',
  first_seen_at: '2026-07-02T09:29:12.637Z',
  age_seconds: 42,
  freshness: 'current',
  runtime_control_enabled: false,
}

const storeStub: StoreStub = {
  pipeline: null,
  captureStatus: null,
  passiveDiscovery: CURRENT_STATUS,
  passiveError: null,
  seederStatus: SEEDER_STATUS,
  seederError: null,
  seederState: 'running',
  seederBadge: { label: 'running', kind: 'ok' },
  isLoading: false,
  pipelineError: null,
  captureError: null,
  sourceRows: [],
  staleBanner: null,
  passiveBadge: { label: 'active', kind: 'ok' },
  loadAll: vi.fn().mockResolvedValue(undefined),
}

vi.mock('~/stores/dataSourcesStore', () => ({
  DATA_SOURCE_LABELS: { conn: 'Connections', mac: 'Assets', proto: 'Protocols' },
  useDataSourcesStore: () => storeStub,
}))

async function mountPage() {
  const { mountWithPlugins } = await import('../helpers/mount')
  const mod = await import('~/pages/operations/data-sources.vue')
  return mountWithPlugins(mod.default)
}

beforeEach(() => {
  storeStub.passiveDiscovery = CURRENT_STATUS
  storeStub.passiveError = null
  storeStub.passiveBadge = { label: 'active', kind: 'ok' }
  storeStub.seederStatus = SEEDER_STATUS
  storeStub.seederError = null
  storeStub.seederState = 'running'
  storeStub.seederBadge = { label: 'running', kind: 'ok' }
})

afterEach(() => {
  vi.resetModules()
})

describe('Passive Discovery card — producer truth', () => {
  it('renders the persisted observed asset count, not a hard-coded 0', async () => {
    const wrapper = await mountPage()
    await flushPromises()
    expect(wrapper.find('[data-test="passive-assets"]').text()).toBe('10')
    expect(wrapper.find('[data-test="passive-assets"]').text()).not.toBe('0')
  })

  it('renders the latest observed timestamp, not an em-dash', async () => {
    const wrapper = await mountPage()
    await flushPromises()
    expect(wrapper.find('[data-test="passive-last-seen"]').text()).not.toBe('—')
  })

  it('shows an active badge when the producer is current', async () => {
    const wrapper = await mountPage()
    await flushPromises()
    expect(wrapper.find('[data-test="passive-badge"]').text()).toContain('active')
    expect(wrapper.text()).not.toContain('disabled')
  })

  it('shows a stale badge when the latest observation is aged', async () => {
    storeStub.passiveDiscovery = { ...CURRENT_STATUS, freshness: 'stale', age_seconds: 2680 }
    storeStub.passiveBadge = { label: 'stale', kind: 'warn' }
    const wrapper = await mountPage()
    await flushPromises()
    expect(wrapper.find('[data-test="passive-badge"]').text()).toContain('stale')
  })

  it('shows a no-data badge and em-dashes when no passive inventory exists', async () => {
    storeStub.passiveDiscovery = {
      observed_asset_count: 0,
      observed_interface_count: 0,
      latest_seen_at: null,
      first_seen_at: null,
      age_seconds: null,
      freshness: 'no-data',
      runtime_control_enabled: false,
    }
    storeStub.passiveBadge = { label: 'no data', kind: 'muted' }
    const wrapper = await mountPage()
    await flushPromises()
    expect(wrapper.find('[data-test="passive-badge"]').text()).toContain('no data')
    expect(wrapper.find('[data-test="passive-assets"]').text()).toBe('0')
    expect(wrapper.find('[data-test="passive-last-seen"]').text()).toBe('—')
  })
})

describe('Passive Discovery card — status only, controls elsewhere', () => {
  it('exposes no Apply control — this page never mutates the seeder', async () => {
    const wrapper = await mountPage()
    await flushPromises()
    const applyBtn = wrapper
      .findAllComponents({ name: 'QBtn' })
      .find((c) => c.attributes('data-test') === 'apply-discovery')
    expect(applyBtn).toBeUndefined()
  })

  it('points at Configuration → Runtime instead of claiming boot-managed', async () => {
    const wrapper = await mountPage()
    await flushPromises()
    const note = wrapper.find('[data-test="passive-controls-note"]').text()
    expect(note).toContain('Runtime')
    expect(note).not.toContain('boot-managed')
  })

  it('deep-links to the runtime configuration surface', async () => {
    const wrapper = await mountPage()
    await flushPromises()
    const link = wrapper.find('[data-test="seeder-runtime-link"]')
    expect(link.exists()).toBe(true)
    expect(link.attributes('to')).toBe('/operations/configuration')
  })

  it('carries no stale UI-015 marker anywhere on the page', async () => {
    const wrapper = await mountPage()
    await flushPromises()
    expect(wrapper.find('[data-test="marker-ui015"]').exists()).toBe(false)
    expect(wrapper.text()).not.toContain('UI-015')
  })
})

describe('Passive Discovery card — seeder status semantics', () => {
  it('renders the seeder state, last cycle, rows and poll interval', async () => {
    const wrapper = await mountPage()
    await flushPromises()
    expect(wrapper.find('[data-test="seeder-state"]').text()).toContain('running')
    expect(wrapper.find('[data-test="seeder-last-cycle"]').text()).not.toBe('—')
    expect(wrapper.find('[data-test="seeder-rows"]').text()).toBe('15')
    expect(wrapper.find('[data-test="seeder-poll-interval"]').text()).toBe('120 s')
  })

  it('labels rows as last-cycle work, never as a cumulative total', async () => {
    const wrapper = await mountPage()
    await flushPromises()
    const text = wrapper.text()
    expect(text).toContain('Rows last cycle')
    expect(text).not.toContain('Total rows')
    expect(text).not.toContain('rows seeded in total')
  })

  it('shows disabled as its own state, distinct from unknown', async () => {
    storeStub.seederStatus = { ...SEEDER_STATUS, state: 'disabled', rows_seeded: 0 }
    storeStub.seederState = 'disabled'
    storeStub.seederBadge = { label: 'disabled', kind: 'warn' }
    const wrapper = await mountPage()
    await flushPromises()
    expect(wrapper.find('[data-test="seeder-state"]').text()).toContain('disabled')
    expect(wrapper.find('[data-test="seeder-unknown"]').exists()).toBe(false)
  })

  it('states unknown honestly when no status row exists yet', async () => {
    storeStub.seederStatus = null
    storeStub.seederState = 'unknown'
    storeStub.seederBadge = { label: 'unknown', kind: 'muted' }
    const wrapper = await mountPage()
    await flushPromises()
    expect(wrapper.find('[data-test="seeder-state"]').text()).toContain('unknown')
    // "unknown" must never be presented as "disabled" — they are different
    // facts and conflating them fabricates a state the seeder never reported.
    expect(wrapper.find('[data-test="seeder-unknown"]').text()).toContain('not reported a status yet')
    expect(wrapper.find('[data-test="seeder-rows"]').text()).toBe('—')
  })

  it('surfaces the last error verbatim when the state is error', async () => {
    const message = 'influx query failed: connection refused'
    storeStub.seederStatus = { ...SEEDER_STATUS, state: 'error', last_error: message }
    storeStub.seederState = 'error'
    storeStub.seederBadge = { label: 'error', kind: 'err' }
    const wrapper = await mountPage()
    await flushPromises()
    expect(wrapper.find('[data-test="seeder-last-error"]').text()).toContain(message)
  })

  it('shows no error banner when the last cycle was clean', async () => {
    const wrapper = await mountPage()
    await flushPromises()
    // last_error is reset to null by the next clean cycle, so its absence
    // means "last cycle was clean" — nothing should be rendered for it.
    expect(wrapper.find('[data-test="seeder-last-error"]').exists()).toBe(false)
  })
})

describe('Passive Discovery card — no fabricated configuration truth', () => {
  it('shows only the poll interval the seeder itself reports', async () => {
    const wrapper = await mountPage()
    await flushPromises()
    const text = wrapper.text()
    // The poll interval is now real (reported by the seeder status row), but
    // the lookback window and MAC handling are still not carried by any
    // status contract and must not be invented here — they are edited on the
    // Runtime tab, which reads them from the runtime-key registry.
    expect(wrapper.find('[data-test="seeder-poll-interval"]').text()).toBe('120 s')
    expect(text).not.toContain('Lookback window')
    expect(text).not.toContain('Local MAC handling')
    expect(text).not.toContain('5 min')
    expect(text).not.toContain('60 min')
    expect(text).not.toContain('Ignore (recommended)')
  })

  it('renders an em-dash rather than a guess when the interval is unreported', async () => {
    storeStub.seederStatus = { ...SEEDER_STATUS, poll_interval_s: null }
    const wrapper = await mountPage()
    await flushPromises()
    expect(wrapper.find('[data-test="seeder-poll-interval"]').text()).toBe('—')
  })

  it('mounts no editable configuration widgets — controls live on Runtime', async () => {
    const wrapper = await mountPage()
    await flushPromises()
    expect(wrapper.findAllComponents({ name: 'QSelect' })).toHaveLength(0)
    expect(wrapper.findAllComponents({ name: 'QToggle' })).toHaveLength(0)
  })
})
