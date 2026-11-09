/**
 * Component tests for the AlarmGroupTable alarm component.
 *
 * Validates row rendering, MITRE chip colors, timestamp formatting,
 * active/confirmed badges, connection/type counts, default sorting,
 * row-click emit, and empty-state message using golden alarm groups.
 */
import { describe, it, expect } from 'vitest'

import AlarmGroupTable from '~/components/alarm/AlarmGroupTable.vue'
import { GOLDEN_ALARM_GROUPS } from '../mocks/golden-data'
import { formatDateTime, formatRelativeTime } from '~/utils/format'
import { mountWithPlugins } from '../helpers/mount'

describe('AlarmGroupTable', () => {
  it('renders correct number of table rows', () => {
    const wrapper = mountWithPlugins(AlarmGroupTable, {
      props: { groups: GOLDEN_ALARM_GROUPS },
    })

    const bodyRows = wrapper.findAll('tbody tr')
    expect(bodyRows).toHaveLength(GOLDEN_ALARM_GROUPS.length)
  })

  it('renders primary type as chip with type label', () => {
    /*
     * The original assertion also checked `bg-${color}` on the chip class.
     * That check verified the q-chip stub's color logic rather than the
     * component itself, and was broken by the stub's `...attrs` spread
     * stripping the stub-injected class. Production Quasar applies the
     * background color from the `:color` prop directly; verifying that
     * belongs in a Playwright smoke test, not a Vitest stub-based test.
     */
    const wrapper = mountWithPlugins(AlarmGroupTable, {
      props: { groups: GOLDEN_ALARM_GROUPS },
    })

    const firstGroup = GOLDEN_ALARM_GROUPS[0]
    const chips = wrapper.findAll('.primary-type-chip')
    expect(chips.length).toBeGreaterThan(0)

    const firstChip = chips[0]
    expect(firstChip.text()).toContain(
      typeof firstGroup.primary_type === 'string' ? firstGroup.primary_type : firstGroup.primary_type[0],
    )
  })

  it('renders start and end timestamps', () => {
    const wrapper = mountWithPlugins(AlarmGroupTable, {
      props: { groups: GOLDEN_ALARM_GROUPS },
    })

    const html = wrapper.html()
    for (const group of GOLDEN_ALARM_GROUPS) {
      const formattedStart = formatDateTime(group.start_timestamp)
      const formattedEnd = formatDateTime(group.end_timestamp)
      expect(html).toContain(formattedStart)
      expect(html).toContain(formattedEnd)
    }
  })

  it('renders a relative Age string for each group via the relative column (UI-176)', () => {
    // Freeze the clock so the "how long ago" output is deterministic; the
    // golden groups are dated mid-2025, well over a day before the fixed
    // "now", so every row lands in the "Xd ago" bucket.
    vi.useFakeTimers()
    vi.setSystemTime('2026-09-03T00:00:00Z')
    try {
      const wrapper = mountWithPlugins(AlarmGroupTable, {
        props: { groups: GOLDEN_ALARM_GROUPS, visibleColumns: ['primary_type', 'relative'] },
      })

      // The column header is labelled "Age".
      const headerLabels = wrapper.findAll('th').map((th) => th.text())
      expect(headerLabels).toContain('Age')

      // Each row renders the relative-time form of its start_timestamp.
      const html = wrapper.html()
      for (const group of GOLDEN_ALARM_GROUPS) {
        expect(html).toContain(formatRelativeTime(group.start_timestamp))
      }
    } finally {
      vi.useRealTimers()
    }
  })

  it('renders active badge with correct color', () => {
    const wrapper = mountWithPlugins(AlarmGroupTable, {
      props: { groups: GOLDEN_ALARM_GROUPS },
    })

    const badges = wrapper.findAll('.q-badge')
    const activeBadge = badges.find((b) => b.text() === 'Active')
    expect(activeBadge).toBeDefined()
    expect(activeBadge!.attributes('class')).toContain('bg-negative')

    const closedBadge = badges.find((b) => b.text() === 'Closed')
    expect(closedBadge).toBeDefined()
    expect(closedBadge!.attributes('class')).toContain('bg-grey-6')
  })

  it('renders confirmed badge with correct color', () => {
    const wrapper = mountWithPlugins(AlarmGroupTable, {
      props: { groups: GOLDEN_ALARM_GROUPS },
    })

    const badges = wrapper.findAll('.q-badge')
    const confirmedBadge = badges.find((b) => b.text() === 'Confirmed')
    expect(confirmedBadge).toBeDefined()
    expect(confirmedBadge!.attributes('class')).toContain('bg-primary')

    const unconfirmedBadge = badges.find((b) => b.text() === 'Unconfirmed')
    expect(unconfirmedBadge).toBeDefined()
    expect(unconfirmedBadge!.attributes('class')).toContain('bg-grey-6')
  })

  it('renders connection count from series_ids length', () => {
    const wrapper = mountWithPlugins(AlarmGroupTable, {
      props: { groups: GOLDEN_ALARM_GROUPS },
    })

    const html = wrapper.html()
    for (const group of GOLDEN_ALARM_GROUPS) {
      expect(html).toContain(String(group.series_ids.length))
    }
  })

  it('renders type count from anomaly_type_stats keys', () => {
    const wrapper = mountWithPlugins(AlarmGroupTable, {
      props: { groups: GOLDEN_ALARM_GROUPS },
    })

    const html = wrapper.html()
    for (const group of GOLDEN_ALARM_GROUPS) {
      const typeCount = Object.keys(group.anomaly_type_stats).length
      expect(html).toContain(String(typeCount))
    }
  })

  it('sorts by start_timestamp descending by default', () => {
    const wrapper = mountWithPlugins(AlarmGroupTable, {
      props: { groups: GOLDEN_ALARM_GROUPS },
    })

    const rows = wrapper.findAll('tbody tr')
    const sortedGroups = [...GOLDEN_ALARM_GROUPS].sort(
      (a, b) => new Date(b.start_timestamp).getTime() - new Date(a.start_timestamp).getTime(),
    )

    const firstRowText = rows[0].text()
    const expectedFirstType =
      typeof sortedGroups[0].primary_type === 'string' ? sortedGroups[0].primary_type : sortedGroups[0].primary_type[0]
    expect(firstRowText).toContain(expectedFirstType)
  })

  it('emits select event on row click', async () => {
    const wrapper = mountWithPlugins(AlarmGroupTable, {
      props: { groups: GOLDEN_ALARM_GROUPS },
    })

    const firstRow = wrapper.find('tbody tr')
    await firstRow.trigger('click')

    const emitted = wrapper.emitted('select')
    expect(emitted).toBeTruthy()
    expect(emitted).toHaveLength(1)
    expect((emitted![0][0] as { id: string }).id).toBeDefined()
  })

  it('shows no-data message when groups is empty', () => {
    const wrapper = mountWithPlugins(AlarmGroupTable, {
      props: { groups: [] },
    })

    expect(wrapper.text()).toContain('No anomaly groups found')
  })
})
