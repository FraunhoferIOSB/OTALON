/**
 * Component tests for ConnectionSelectorTable.
 *
 * Validates port-column rendering: concrete ports, backend-wildcard
 * badges with collapsed_port_count, and client-side wildcard badges.
 */
import { describe, it, expect } from 'vitest'

import ConnectionSelectorTable from '~/components/connection/ConnectionSelectorTable.vue'
import { mountWithPlugins } from '../helpers/mount'
import type { Connection } from '~/types/golden-data'

const CONNECTIONS: Connection[] = [
  {
    uci: 'a/b/c/d/e/f/80/443/TCP',
    source: '10.0.0.1',
    destination: '10.0.0.2',
    protocol: 'TCP',
    port: '443',
    state: 'normal',
    isWildcard: false,
    memberCount: 1,
    collapsed_port_count: null,
    ruleTrained: true,
  },
  {
    uci: 'a/b/c/d/e/f//*/*/TCP',
    source: '10.0.0.1',
    destination: '10.0.0.2',
    protocol: 'TCP',
    port: null,
    state: 'normal',
    isWildcard: true,
    memberCount: 1,
    collapsed_port_count: 7,
    ruleTrained: true,
  },
  {
    uci: 'x/y/z/d/e/f//*/*/TCP',
    source: '10.0.0.3',
    destination: '10.0.0.4',
    protocol: 'TCP',
    port: null,
    state: 'normal',
    isWildcard: true,
    memberCount: 3,
    collapsed_port_count: null,
    ruleTrained: false,
  },
]

describe('ConnectionSelectorTable', () => {
  it('renders anomaly red, no-profile yellow, and profiled green dots', () => {
    const rows = CONNECTIONS.map((connection, index) => ({
      ...connection,
      state: index === 0 ? 'anomaly' as const : 'normal' as const,
      profiled: index !== 1,
    }))
    const wrapper = mountWithPlugins(ConnectionSelectorTable, { props: { connections: rows } })
    expect(wrapper.findAll('[data-testid="connection-status-anomaly"]')).toHaveLength(1)
    expect(wrapper.findAll('[data-testid="connection-status-no-profile"]')).toHaveLength(1)
    expect(wrapper.findAll('[data-testid="connection-status-ok"]')).toHaveLength(1)
  })
  it('renders concrete port for non-wildcard connections', () => {
    const wrapper = mountWithPlugins(ConnectionSelectorTable, {
      props: { connections: CONNECTIONS },
    })

    const rows = wrapper.findAll('tbody tr')
    expect(rows).toHaveLength(3)

    const firstRowCells = rows[0].findAll('td')
    expect(firstRowCells[4].text()).toContain('443')
  })

  it('renders backend collapsed_port_count badge when available', () => {
    const wrapper = mountWithPlugins(ConnectionSelectorTable, {
      props: { connections: CONNECTIONS },
    })

    const badges = wrapper.findAll('.q-badge')
    const backendBadge = badges.find((b) => b.text() === '7 ports')
    expect(backendBadge).toBeDefined()
  })

  it('falls back to memberCount for client-side wildcards', () => {
    const wrapper = mountWithPlugins(ConnectionSelectorTable, {
      props: { connections: CONNECTIONS },
    })

    const badges = wrapper.findAll('.q-badge')
    const clientBadge = badges.find((b) => b.text() === '3 ports')
    expect(clientBadge).toBeDefined()
  })

  it('shows the untrained rule badge only for untrained wildcard rows', () => {
    const wrapper = mountWithPlugins(ConnectionSelectorTable, {
      props: { connections: CONNECTIONS },
    })

    expect(wrapper.text()).toContain('Rule not trained yet')
    expect(wrapper.findAll('.q-badge').filter((badge) => badge.text() === 'Rule not trained yet')).toHaveLength(1)
  })

  it('does not show the untrained rule badge for trained or concrete rows', () => {
    const rows = CONNECTIONS.map((connection) => ({ ...connection, ruleTrained: true }))
    const wrapper = mountWithPlugins(ConnectionSelectorTable, {
      props: { connections: rows },
    })

    expect(wrapper.text()).not.toContain('Rule not trained yet')
  })

  it('emits select event on row click', async () => {
    const wrapper = mountWithPlugins(ConnectionSelectorTable, {
      props: { connections: CONNECTIONS },
    })

    // autoSelectFirst emits on mount; clear before testing the click
    wrapper.emitted()['select'] = []

    const rows = wrapper.findAll('tbody tr')
    await rows[0].trigger('click')

    const emitted = wrapper.emitted('select')
    expect(emitted).toBeTruthy()
    expect(emitted).toHaveLength(1)
    expect((emitted![0][0] as Connection).uci).toBe('a/b/c/d/e/f/80/443/TCP')
  })

  describe('profiled-but-silent rows', () => {
    const SILENT: Connection = {
      uci: 's/t/u/d/e/f///PROFINET_RT_IO',
      source: '10.0.0.9',
      destination: '10.0.0.10',
      sourceIp: null,
      sourceMac: null,
      destIp: null,
      destMac: null,
      protocol: 'PROFINET_RT_IO',
      port: null,
      state: 'normal',
      isWildcard: false,
      memberCount: 0,
      collapsed_port_count: null,
      presence: 'silent',
    }
    const MIXED: Connection[] = [...CONNECTIONS.map((c) => ({ ...c, presence: 'live' as const })), SILENT]

    it('marks silent rows visually distinct from live rows', () => {
      const wrapper = mountWithPlugins(ConnectionSelectorTable, {
        props: { connections: MIXED, showSilentProfiled: true, silentProfiledCount: 1 },
      })

      const silentRows = wrapper.findAll('tbody tr.silent-profiled-row')
      expect(silentRows).toHaveLength(1)
      expect(silentRows[0].text()).toContain('10.0.0.9')
      // Live rows keep the plain state dot; only the silent row is marked.
      expect(wrapper.findAll('[data-testid="silent-row-marker"]')).toHaveLength(1)
      expect(wrapper.findAll('tbody tr').filter((r) => !r.classes('silent-profiled-row'))).toHaveLength(3)
    })

    it('selects a silent row on click like any other row', async () => {
      const wrapper = mountWithPlugins(ConnectionSelectorTable, {
        props: { connections: MIXED, showSilentProfiled: true, silentProfiledCount: 1 },
      })
      wrapper.emitted()['select'] = []

      const silentRow = wrapper.findAll('tbody tr').at(-1)!
      await silentRow.trigger('click')

      const emitted = wrapper.emitted('select')
      expect(emitted).toHaveLength(1)
      expect((emitted![0][0] as Connection).uci).toBe(SILENT.uci)
    })

    it('never auto-selects a silent row', () => {
      const wrapper = mountWithPlugins(ConnectionSelectorTable, {
        props: { connections: [SILENT, ...CONNECTIONS], showSilentProfiled: true, silentProfiledCount: 1 },
      })

      const emitted = wrapper.emitted('select')
      expect(emitted).toBeTruthy()
      expect((emitted![0][0] as Connection).presence).not.toBe('silent')
    })

    it('exposes the silent count and a keyboard-reachable explanation', () => {
      const wrapper = mountWithPlugins(ConnectionSelectorTable, {
        props: { connections: CONNECTIONS, showSilentProfiled: false, silentProfiledCount: 4 },
      })

      expect(wrapper.find('[data-testid="silent-profiled-count"]').text()).toBe('4')
      const toggleWrap = wrapper.find('.silent-toggle-wrap')
      expect(toggleWrap.attributes('tabindex')).toBe('0')
      expect(toggleWrap.attributes('aria-label')).toContain('4')
    })

    it('hides the count badge when nothing is silent', () => {
      const wrapper = mountWithPlugins(ConnectionSelectorTable, {
        props: { connections: CONNECTIONS, silentProfiledCount: 0 },
      })

      expect(wrapper.find('[data-testid="silent-profiled-count"]').exists()).toBe(false)
    })
  })
})
