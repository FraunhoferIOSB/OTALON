import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mountWithPlugins } from '../helpers/mount'
import HistoryPanel from '~/components/subagent/HistoryPanel.vue'

// vi.mock is hoisted file-wide, so a single factory reads jobs from a
// vi.hoisted mutable holder that each test populates before mounting.
const { storeMockHolder } = vi.hoisted(() => ({ storeMockHolder: { jobs: [] as unknown[] } }))

vi.mock('~/stores/subagentStore', () => ({
  useSubagentStore: () => ({
    historyFor: () => storeMockHolder.jobs,
    loadHistory: vi.fn(),
    loadingHistory: {} as Record<string, boolean>,
  }),
}))

const summaryJob = {
  id: 'job-fp-h1',
  alarm_id: 'alarm-1',
  status: 'completed',
  prompt_variant: 'forensic',
  llm_provider: 'azure_openai',
  llm_model: 'gpt-5.4',
  started_at: '2026-09-02T00:00:00Z',
  finished_at: '2026-09-02T00:01:00Z',
  duration_seconds: 60,
  tool_trace_count: 5,
  tokens_total: 150,
  top_step2: null,
  step1_method: null,
  verdict_outcome: 'false_positive',
  created_at: '2026-09-02T00:00:00Z',
}

describe('HistoryPanel verdict badge', () => {
  beforeEach(() => {
    vi.stubGlobal('localStorage', {
      store: {} as Record<string, string>,
      getItem: () => null,
      setItem: () => {},
      removeItem: () => {},
      clear: () => {},
    })
    storeMockHolder.jobs = []
  })

  it('renders "False Positive" badge in warning colour for false_positive verdict_outcome', () => {
    storeMockHolder.jobs = [summaryJob]
    const wrapper = mountWithPlugins(HistoryPanel, {
      props: { alarmId: 'alarm-1' },
    })

    const text = wrapper.text()
    expect(text).toContain('False Positive')
    expect(text).not.toContain('false_positive')

    const fpBadge = wrapper.findAll('.q-badge').find((b) => b.text().includes('False Positive'))
    expect(fpBadge).toBeDefined()
    expect(fpBadge?.classes()).toContain('bg-warning')
  })

  it('renders benign badge in positive colour', () => {
    storeMockHolder.jobs = [{ ...summaryJob, id: 'job-b1', verdict_outcome: 'benign' }]
    const wrapper = mountWithPlugins(HistoryPanel, {
      props: { alarmId: 'alarm-1' },
    })

    const benignBadge = wrapper.findAll('.q-badge').find((b) => b.text().includes('benign'))
    expect(benignBadge).toBeDefined()
    expect(benignBadge?.classes()).toContain('bg-positive')
  })

  it('renders attack verdict_outcome in grey (existing logic preserved)', () => {
    storeMockHolder.jobs = [{ ...summaryJob, id: 'job-a1', verdict_outcome: 'attack' }]
    const wrapper = mountWithPlugins(HistoryPanel, {
      props: { alarmId: 'alarm-1' },
    })

    const attackBadge = wrapper.findAll('.q-badge').find((b) => b.text().includes('attack'))
    expect(attackBadge).toBeDefined()
    expect(attackBadge?.classes()).toContain('bg-grey-7')
  })
})
