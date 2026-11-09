/**
 * Component tests for ConnectionEmptyMetricsHint.vue (UI-017b Wave D).
 *
 * Validates both hint branches:
 * - concrete rotating-port hint with a named active port + working jump when a
 *   base-key sibling has data in the window;
 * - generic inactive/different-port hint when no sibling has data.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { flushPromises } from '@vue/test-utils'
import ConnectionEmptyMetricsHint from '~/components/connection/ConnectionEmptyMetricsHint.vue'
import type { SiblingsResponse } from '~/types/api'
import { mountWithPlugins } from '../helpers/mount'

const getMock = vi.fn()

vi.stubGlobal('useApi', () => ({ get: getMock, post: vi.fn(), patch: vi.fn(), del: vi.fn() }))

const BASE = 'aa:bb/cc:dd/100/6/192.168.0.4/192.168.0.41'
const PROTO = 'PROFINET_DCE_RPC'
const SELECTED = `${BASE}/50000/41/${PROTO}`
const SIBLING = `${BASE}/50000/53092/${PROTO}`
const TIME_RANGE = { start: '2026-05-05T00:00:00Z', stop: '2026-05-12T00:00:00Z' }

function mountHint() {
  return mountWithPlugins(ConnectionEmptyMetricsHint, {
    props: { selectedUci: SELECTED, timeRange: TIME_RANGE },
  })
}

describe('ConnectionEmptyMetricsHint', () => {
  beforeEach(() => {
    getMock.mockReset()
  })

  it('renders the concrete rotating-port hint when a sibling has data', async () => {
    const resp: SiblingsResponse = {
      uci: SELECTED,
      start: TIME_RANGE.start,
      stop: TIME_RANGE.stop,
      has_active_sibling: true,
      count: 1,
      siblings: [{ uci: SIBLING, src_port: '50000', dst_port: '53092' }],
    }
    getMock.mockResolvedValue(resp)

    const wrapper = mountHint()
    await flushPromises()

    expect(wrapper.find('[data-testid="hint-rotating-title"]').exists()).toBe(true)
    expect(wrapper.text()).toContain('rotating ports')
    expect(wrapper.text()).toContain('53092')
    expect(wrapper.find('[data-testid="hint-jump-button"]').exists()).toBe(true)
  })

  it('emits jump with the sibling UCI when the jump button is clicked', async () => {
    getMock.mockResolvedValue({
      uci: SELECTED,
      start: TIME_RANGE.start,
      stop: TIME_RANGE.stop,
      has_active_sibling: true,
      count: 1,
      siblings: [{ uci: SIBLING, src_port: '50000', dst_port: '53092' }],
    } as SiblingsResponse)

    const wrapper = mountHint()
    await flushPromises()

    await wrapper.find('[data-testid="hint-jump-button"]').trigger('click')

    expect(wrapper.emitted('jump')).toBeTruthy()
    expect(wrapper.emitted('jump')?.[0]).toEqual([SIBLING])
  })

  it('renders the generic hint when no sibling has data', async () => {
    getMock.mockResolvedValue({
      uci: SELECTED,
      start: TIME_RANGE.start,
      stop: TIME_RANGE.stop,
      has_active_sibling: false,
      count: 0,
      siblings: [],
    } as SiblingsResponse)

    const wrapper = mountHint()
    await flushPromises()

    expect(wrapper.find('[data-testid="hint-generic-title"]').exists()).toBe(true)
    expect(wrapper.text()).toContain('inactive')
    expect(wrapper.find('[data-testid="hint-jump-button"]').exists()).toBe(false)
  })

  it('falls back to the generic hint when the API call fails', async () => {
    getMock.mockRejectedValue(new Error('boom'))

    const wrapper = mountHint()
    await flushPromises()

    expect(wrapper.find('[data-testid="hint-generic-title"]').exists()).toBe(true)
  })
})
