/**
 * Page-level wiring tests for the RHYTHM lane on the Assets and
 * Protocols timeseries pages.
 *
 * AbsenceAnomaly is produced for three detection modules, but the lane
 * originally existed only on the connections page — and the live 24h
 * counts (mac_traffic 6151, proto_traffic 3197, conn 354) put the bulk
 * of the absence alarms on exactly the two pages that could not show
 * them. These tests pin the wiring that closes that gap:
 *
 * - selecting a row fetches the profile for the page's OWN module;
 * - the Protocols page hashes its readable protocol stack first, because
 *   `frequency_profiles.series_id` is keyed by the hash and the
 *   frequency endpoint does no server-side translation;
 * - the shared singleton store never renders one page's state under
 *   another page's heading.
 *
 * The REAL frequency store is used throughout (only the network layer is
 * stubbed), so the module argument and the cross-page gate are genuinely
 * exercised rather than asserted against a self-fulfilling stub.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { flushPromises } from '@vue/test-utils'
import { createPinia, setActivePinia, type Pinia } from 'pinia'
import { nextTick } from 'vue'

import MacTimeseriesPage from '~/pages/mac-timeseries.vue'
import ProtoTimeseriesPage from '~/pages/proto-timeseries.vue'
import MacSelectorTable from '~/components/mac/MacSelectorTable.vue'
import ProtoSelectorTable from '~/components/proto/ProtoSelectorTable.vue'
import ConnectionRhythmLane from '~/components/connection/RhythmLane.vue'
import SharedPanelSubjectHeading from '~/components/shared/PanelSubjectHeading.vue'
import { useFrequencyStore } from '~/stores/frequencyStore'
import { useMacSourcesStore } from '~/stores/macSourcesStore'
import { useProtoSourcesStore } from '~/stores/protoSourcesStore'
import { protoSeriesHash } from '~/utils/protoHash'
import { mountWithPlugins } from '../helpers/mount'

/**
 * Components the pages reference through Nuxt's auto-import.
 *
 * Vitest does not run Nuxt's component resolver, so the selector tables
 * and the lane must be registered explicitly — otherwise the page
 * renders inert placeholders, no row is ever selected, and the wiring
 * under test would never execute.
 *
 * The selector tables and the lane are the REAL components: the
 * selection path (auto-select on mount → `select` event → store fetch)
 * and the lane's own render gate are exactly what is being verified.
 * Only the unrelated plot grid and toolbar are stubbed away.
 */
const PAGE_COMPONENTS = {
  MacSelectorTable,
  ProtoSelectorTable,
  ConnectionRhythmLane,
  SharedPanelSubjectHeading,
  MacFeaturePlotGrid: { template: '<div class="feature-plot-grid" />' },
  ProtoFeaturePlotGrid: { template: '<div class="feature-plot-grid" />' },
  SharedTimeToolbar: { template: '<div class="time-toolbar" />' },
  SharedErrorBanner: { template: '<div class="error-banner" />' },
  'q-splitter': { template: '<div class="q-splitter"><slot name="before" /><slot name="after" /></div>' },
  'q-virtual-scroll': { template: '<div class="q-virtual-scroll"><slot /></div>' },
}

/**
 * A UNICAST MAC that carries a live `mac_traffic` frequency profile.
 *
 * The Assets page deliberately hides broadcast/multicast addresses
 * (`isBroadcastOrMulticastMac`), so a multicast fixture such as
 * `01:80:c2:00:00:0e` would never reach the selector table and the
 * wiring under test would never run.
 */
const TEST_MAC = '38:4b:24:fa:b6:34'
const TEST_PROTOCOL = 'Ethernet:LLDP'
/** The persisted `frequency_profiles.series_id` for TEST_PROTOCOL. */
const TEST_PROTOCOL_HASH = '36545455'

interface FrequencyCall {
  uci: string
  module: string
}

const frequencyCalls: FrequencyCall[] = []

/**
 * Build a frequency profile payload for whichever series was asked for.
 */
function makeProfilePayload(uci: string, module: string): Record<string, unknown> {
  return {
    module,
    series_id: uci,
    state: 'absence_active',
    has_profile: true,
    mean_interval_seconds: 600,
    std_interval_seconds: 20,
    tolerance_factor: { value: 2, source: 'global_default', override: null, global_default: 2 },
    absence_factor: { value: 3, source: 'global_default', override: null, global_default: 3 },
    last_seen: '2026-07-26T09:45:00+00:00',
    trained_at: '2026-07-24T01:11:35+00:00',
    now: '2026-07-26T10:00:00+00:00',
    absence_deadline: '2026-07-26T09:50:00+00:00',
    absence_timeout_seconds: 1800,
    seconds_until_deadline: -600,
    seconds_since_last_seen: 900,
    active_anomaly_type: 'AbsenceAnomaly',
    active_anomaly_since: '2026-07-26T09:50:00+00:00',
  }
}

/**
 * Stub the network layer for both pages' initial loads.
 *
 * Every endpoint the pages touch answers with a minimal valid envelope;
 * only the frequency endpoint is recorded, since that is the wiring
 * under test.
 */
function installFetch(): void {
  const fetchMock = vi.fn((url: string, opts?: { params?: Record<string, unknown> }) => {
    if (url.includes('/frequency/profile')) {
      const uci = String(opts?.params?.uci ?? '')
      const module = String(opts?.params?.module ?? '')
      frequencyCalls.push({ uci, module })
      return Promise.resolve(makeProfilePayload(uci, module))
    }
    if (url.includes('/timeseries/mac/ids')) {
      return Promise.resolve({ count: 1, data: [{ id: TEST_MAC }] })
    }
    if (url.includes('/timeseries/proto/ids')) {
      return Promise.resolve({
        count: 1,
        data: [{ id: TEST_PROTOCOL, protocol: TEST_PROTOCOL }],
      })
    }
    if (url.includes('/features')) {
      return Promise.resolve({ features: ['out_total_packets', 'proto_total_packets'] })
    }
    if (url.includes('/bounds')) {
      return Promise.resolve({ data: [], row_count: 0, parameters: {} })
    }
    if (url.includes('/intervals')) {
      return Promise.resolve({ data: [], row_count: 0, parameters: {} })
    }
    if (url.includes('/anomalies/groups')) {
      return Promise.resolve({ data: [], row_count: 0 })
    }
    if (url.includes('/topology/devices')) {
      return Promise.resolve({ devices: [] })
    }
    return Promise.resolve({ data: [], row_count: 0 })
  })
  vi.stubGlobal('$fetch', fetchMock)
}

beforeEach(() => {
  frequencyCalls.length = 0
  installFetch()
  // `usePolling` is a Nuxt auto-import, so it resolves as a global at
  // runtime rather than through a module specifier. Live polling is not
  // under test here; the fetch paths it drives are covered directly.
  vi.stubGlobal('usePolling', vi.fn())
})

afterEach(() => {
  vi.unstubAllGlobals()
})

/**
 * Mount a page and let its initial loads settle.
 *
 * The selector tables auto-select their first row on mount, which is the
 * selection path these tests exercise.
 */
async function mountPage(component: typeof MacTimeseriesPage, pinia?: Pinia) {
  const wrapper = mountWithPlugins(component, {
    global: {
      stubs: PAGE_COMPONENTS,
      ...(pinia ? { plugins: [pinia] } : {}),
    },
  })
  await flushPromises()
  await nextTick()
  await flushPromises()
  return wrapper
}

describe('Assets page (mac_traffic) RHYTHM lane', () => {
  it('fetches the profile for the mac_traffic module on selection', async () => {
    await mountPage(MacTimeseriesPage)

    const call = frequencyCalls.find((c) => c.uci === TEST_MAC)
    expect(call, `expected a frequency fetch for ${TEST_MAC}`).toBeDefined()
    expect(call!.module).toBe('mac_traffic')
  })

  it('passes the MAC through unchanged, since it IS the profile key', async () => {
    await mountPage(MacTimeseriesPage)

    // mac_traffic profiles are keyed by the MAC address itself; any
    // translation here would break the lookup.
    expect(frequencyCalls.map((c) => c.uci)).toContain(TEST_MAC)
  })

  it('renders the lane for the selected asset', async () => {
    const wrapper = await mountPage(MacTimeseriesPage)

    expect(wrapper.find('[data-testid="rhythm-lane"]').exists()).toBe(true)
    expect(wrapper.find('[data-testid="rhythm-state-chip"]').text()).toContain('Absence active')
  })

  it('clears the shared store on deselect', async () => {
    const wrapper = await mountPage(MacTimeseriesPage)
    const frequencyStore = useFrequencyStore()
    expect(frequencyStore.seriesId).toBe(TEST_MAC)

    wrapper.findComponent({ name: 'MacSelectorTable' }).vm.$emit('select', null)
    await nextTick()

    expect(frequencyStore.seriesId).toBeNull()
    expect(frequencyStore.module).toBeNull()
    expect(wrapper.find('[data-testid="rhythm-lane"]').exists()).toBe(false)
  })

  it('releases the shared store when the page is left', async () => {
    const wrapper = await mountPage(MacTimeseriesPage)
    const frequencyStore = useFrequencyStore()
    expect(frequencyStore.module).toBe('mac_traffic')

    wrapper.unmount()

    expect(frequencyStore.module).toBeNull()
    expect(frequencyStore.profile).toBeNull()
  })
})

describe('Protocols page (proto_traffic) RHYTHM lane', () => {
  it('fetches the profile for the proto_traffic module on selection', async () => {
    await mountPage(ProtoTimeseriesPage)

    const call = frequencyCalls.find((c) => c.module === 'proto_traffic')
    expect(call, 'expected a proto_traffic frequency fetch').toBeDefined()
  })

  it('hashes the readable protocol stack to the persisted series_id', async () => {
    await mountPage(ProtoTimeseriesPage)

    // The page selects "Ethernet:LLDP" but frequency_profiles keys that
    // series by its hash. Sending the readable stack would resolve to
    // has_profile:false for every protocol.
    const ucis = frequencyCalls.filter((c) => c.module === 'proto_traffic').map((c) => c.uci)
    expect(ucis).toContain(TEST_PROTOCOL_HASH)
    expect(ucis).not.toContain(TEST_PROTOCOL)
    expect(TEST_PROTOCOL_HASH).toBe(protoSeriesHash(TEST_PROTOCOL))
  })

  it('shows the readable protocol, not the numeric hash, as the subject', async () => {
    const wrapper = await mountPage(ProtoTimeseriesPage)

    // Requirement: the operator must be able to tell what they selected,
    // even though the lane's series key is an opaque number. The name now
    // heads the whole analysis panel instead of sitting inside the rhythm
    // lane, because it describes the feature plots just as much (UI-094).
    const subject = wrapper.find('[data-testid="panel-subject-heading"]')
    expect(subject.exists()).toBe(true)
    expect(subject.text()).toContain(TEST_PROTOCOL)
    expect(subject.find('.subject-heading__raw-id').text()).toContain(TEST_PROTOCOL)
  })

  it('does not fall back to the raw hash in the heading', async () => {
    const wrapper = await mountPage(ProtoTimeseriesPage)

    // The previous design kept the hash reachable in a tooltip on the lane's
    // own subject span. That span is gone; what matters now is that the
    // heading never degrades to the unreadable key.
    const subject = wrapper.find('[data-testid="panel-subject-heading"]')
    expect(subject.text()).not.toContain(TEST_PROTOCOL_HASH)
  })

  it('renders the lane for the selected protocol', async () => {
    const wrapper = await mountPage(ProtoTimeseriesPage)

    expect(wrapper.find('[data-testid="rhythm-lane"]').exists()).toBe(true)
    expect(wrapper.find('[data-testid="rhythm-state-chip"]').text()).toContain('Absence active')
  })

  it('clears the shared store on deselect', async () => {
    const wrapper = await mountPage(ProtoTimeseriesPage)
    const frequencyStore = useFrequencyStore()
    expect(frequencyStore.seriesId).toBe(TEST_PROTOCOL_HASH)

    wrapper.findComponent({ name: 'ProtoSelectorTable' }).vm.$emit('select', null)
    await nextTick()

    expect(frequencyStore.seriesId).toBeNull()
    expect(wrapper.find('[data-testid="rhythm-lane"]').exists()).toBe(false)
  })

  it('releases the shared store when the page is left', async () => {
    const wrapper = await mountPage(ProtoTimeseriesPage)
    const frequencyStore = useFrequencyStore()
    expect(frequencyStore.module).toBe('proto_traffic')

    wrapper.unmount()

    expect(frequencyStore.module).toBeNull()
  })
})

describe('the shared store does not leak across pages', () => {
  it('does not render an Assets profile on the Protocols page', async () => {
    // Simulate navigation without the unmount hook firing (e.g. a
    // keep-alive route): the Protocols lane must still refuse to paint
    // mac_traffic state, because the store is one singleton.
    const frequencyStore = useFrequencyStore()
    const macSources = useMacSourcesStore()
    macSources.macs = [{ mac: TEST_MAC, name: null, ip: null }]
    await frequencyStore.fetchProfile(TEST_MAC, 'mac_traffic')
    expect(frequencyStore.module).toBe('mac_traffic')

    const protoSources = useProtoSourcesStore()
    protoSources.protos = [{ id: TEST_PROTOCOL, protocol: TEST_PROTOCOL }]
    protoSources.selectProto(TEST_PROTOCOL)

    // The store still holds mac_traffic state at this instant.
    expect(frequencyStore.matches('proto_traffic', TEST_PROTOCOL_HASH)).toBe(false)
    expect(frequencyStore.matches('mac_traffic', TEST_MAC)).toBe(true)
  })

  it('refuses to paint another module state, even mid-navigation', async () => {
    // Direct render-gate check: the store holds a fully valid
    // mac_traffic profile while a proto_traffic lane is mounted for a
    // different series. Without the gate the lane would show the
    // Assets page's cadence under the Protocols page's heading.
    const pinia = createPinia()
    setActivePinia(pinia)
    const frequencyStore = useFrequencyStore()
    await frequencyStore.fetchProfile(TEST_MAC, 'mac_traffic')
    expect(frequencyStore.profile).not.toBeNull()

    const lane = mountWithPlugins(ConnectionRhythmLane, {
      props: {
        selectedUci: TEST_PROTOCOL_HASH,
        module: 'proto_traffic',
        subjectLabel: TEST_PROTOCOL,
        subjectNoun: 'protocol',
        timeRange: { start: '2026-07-26T09:30:00+00:00', stop: '2026-07-26T10:00:00+00:00' },
      },
      global: { plugins: [pinia] },
    })
    await nextTick()

    // The foreign profile's facts must not be rendered at all.
    expect(lane.find('[data-testid="rhythm-cadence"]').exists()).toBe(false)
    expect(lane.find('[data-testid="rhythm-strip"]').exists()).toBe(false)
    expect(lane.find('[data-testid="rhythm-state-chip"]').text()).not.toContain('Absence active')
  })

  it('re-points the store at the newly viewed page after navigation', async () => {
    // `mountWithPlugins` installs a fresh Pinia per mount, so a shared
    // instance has to be pinned explicitly for this to model one running
    // app navigating between two routes rather than two separate apps.
    const pinia = createPinia()
    setActivePinia(pinia)
    const frequencyStore = useFrequencyStore()

    const macWrapper = await mountPage(MacTimeseriesPage, pinia)
    expect(frequencyStore.module).toBe('mac_traffic')
    expect(frequencyStore.seriesId).toBe(TEST_MAC)

    macWrapper.unmount()
    // Leaving the page must hand the singleton back empty.
    expect(frequencyStore.module).toBeNull()

    await mountPage(ProtoTimeseriesPage, pinia)

    expect(frequencyStore.module).toBe('proto_traffic')
    expect(frequencyStore.seriesId).toBe(TEST_PROTOCOL_HASH)
  })
})
