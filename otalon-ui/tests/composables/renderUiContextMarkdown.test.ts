/**
 * Unit tests for ``renderUiContextMarkdown``.
 */
import { describe, expect, it } from 'vitest'

import { renderUiContextMarkdown } from '~~/shared/renderUiContextMarkdown'
import type { UiContext } from '~~/shared/uiContext'

function makeBaseContext(): UiContext {
  return {
    app: {
      version: '0.4.0',
      locale: 'de-DE',
      theme: 'dark',
      timestamp: '2026-05-07T15:42:11Z',
    },
    route: {
      path: '/dashboard',
      name: 'dashboard',
      title: 'Dashboard',
      query: {},
    },
    time: {
      mode: 'live',
      liveIntervalSeconds: 3600,
      start: '2026-05-07T14:42:11Z',
      stop: '2026-05-07T15:42:11Z',
      label: 'Last 60 minutes (live)',
    },
  }
}

describe('renderUiContextMarkdown', () => {
  it('renders the global header with route, time, theme', () => {
    const md = renderUiContextMarkdown(makeBaseContext())
    expect(md).toContain('## UI Context')
    expect(md).toContain('Dashboard (/dashboard)')
    expect(md).toContain('Last 60 minutes (live)')
    expect(md).toContain('Theme: dark')
    expect(md).toContain('locale: de-DE')
  })

  it('renders summary as bullet list', () => {
    const ctx = {
      ...makeBaseContext(),
      summary: { signal: 'warning', anomaly_count: 3 },
    }
    const md = renderUiContextMarkdown(ctx)
    expect(md).toContain('- Summary:')
    expect(md).toContain('signal: warning')
    expect(md).toContain('anomaly_count: 3')
  })

  it('renders selection with kind, id and fields', () => {
    const ctx = {
      ...makeBaseContext(),
      selection: {
        kind: 'alarm',
        id: '1088d146-d807-49d7-b10f-0dc7d7d918a9',
        label: 'out_of_bounds',
        fields: { is_active: true, confirmed: false },
      },
    }
    const md = renderUiContextMarkdown(ctx)
    expect(md).toContain('Selection: alarm')
    expect(md).toContain('1088d146-d807-49d7-b10f-0dc7d7d918a9')
    expect(md).toContain('out_of_bounds')
    expect(md).toContain('is_active: true')
  })

  it('renders visible_data as Markdown tables with header row', () => {
    const ctx = {
      ...makeBaseContext(),
      visible_data: [
        {
          name: 'recent_alarms',
          columns: ['id', 'severity'],
          rows: [
            { id: 'a', severity: 'warning' },
            { id: 'b', severity: 'danger' },
          ],
          total_rows: 5,
          showing_rows: 2,
        },
      ],
    }
    const md = renderUiContextMarkdown(ctx)
    expect(md).toContain('Visible data — recent_alarms (showing 2 of 5)')
    expect(md).toContain('| id | severity |')
    expect(md).toContain('| --- | --- |')
    expect(md).toContain('| a | warning |')
    expect(md).toContain('| b | danger |')
  })

  it('renders widgets list when present', () => {
    const ctx = {
      ...makeBaseContext(),
      widgets: { visible: ['signal', 'throughput'], hidden: ['vulnerabilities'] },
    }
    const md = renderUiContextMarkdown(ctx)
    expect(md).toContain('Visible widgets: signal, throughput')
    expect(md).toContain('Hidden widgets: vulnerabilities')
  })

  it('truncates very long string cells', () => {
    const longValue = 'x'.repeat(500)
    const ctx = {
      ...makeBaseContext(),
      summary: { note: longValue },
    }
    const md = renderUiContextMarkdown(ctx)
    expect(md).toContain('xxxxxxxxx…')
    expect(md.length).toBeLessThan(longValue.length + 200)
  })

  it('handles empty visible_data row list with "(empty)"', () => {
    const ctx = {
      ...makeBaseContext(),
      visible_data: [
        {
          name: 'recent_alarms',
          columns: ['id'],
          rows: [],
          total_rows: 0,
          showing_rows: 0,
        },
      ],
    }
    const md = renderUiContextMarkdown(ctx)
    expect(md).toContain('(empty)')
  })
})
