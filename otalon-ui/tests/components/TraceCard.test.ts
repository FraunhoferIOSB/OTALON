import { describe, it, expect, vi, beforeEach } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'
import { mountWithPlugins } from '../helpers/mount'
import TraceCard from '~/components/subagent/TraceCard.vue'
import { useSubagentStore } from '~/stores/subagentStore'

// TraceCard opens an EventSource via useSubagentSse on setup. Stub it to a
// no-op so the component test never touches the network or EventSource.
vi.mock('~/composables/useSubagentSse', () => ({
  useSubagentSse: () => ({ connected: { value: false }, lastEvent: { value: null }, close: () => {} }),
}))

function createStoreWithJob(job: unknown) {
  const pinia = createPinia()
  setActivePinia(pinia)
  const store = useSubagentStore()
  if (job && typeof job === 'object' && 'id' in job) {
    store.liveJobsById[String((job as { id: string }).id)] = job as never
  }
  return { pinia }
}

const baseCompletedJob = {
  id: 'job-abc-1234',
  alarm_id: 'alarm-1',
  status: 'completed',
  prompt_variant: 'forensic',
  prompt_hash: '',
  llm_provider: 'azure_openai',
  llm_model: 'gpt-5.4',
  llm_endpoint: null,
  reasoning_effort: null,
  baseline_id: null,
  timeout_seconds: 600,
  trigger_source: 'ui',
  started_at: '2026-09-02T00:00:00Z',
  finished_at: '2026-09-02T00:01:00Z',
  duration_seconds: 60,
  step1_technical: { technical_method: 'none', observed_activity: 'normal traffic' },
  tool_trace: [],
  tokens_prompt: 100,
  tokens_completion: 50,
  error_message: null,
  created_at: '2026-09-02T00:00:00Z',
}

describe('TraceCard verdict rendering', () => {
  beforeEach(() => {
    vi.stubGlobal('localStorage', {
      store: {} as Record<string, string>,
      getItem: () => null,
      setItem: () => {},
      removeItem: () => {},
      clear: () => {},
    })
  })

  it('renders a "False Positive" badge with humanized fp_reason and hides MITRE for false_positive', () => {
    const job = {
      ...baseCompletedJob,
      step2_classification: { classifications: [] },
      verdict: {
        outcome: 'false_positive',
        fp_reason: 'monitoring_tool',
        reasoning: 'matches baseline scanner pattern',
      },
    }
    const { pinia } = createStoreWithJob(job)
    const wrapper = mountWithPlugins(TraceCard, {
      global: { plugins: [pinia] },
      props: { jobId: 'job-abc-1234' },
    })

    const text = wrapper.text()
    expect(text).toContain('False Positive')
    expect(text).toContain('monitoring tool')
    expect(text).toContain('matches baseline scanner pattern')
    // MITRE section hidden
    expect(wrapper.findAll('.mitre-row')).toHaveLength(0)
    // fallback banner hidden (verdict present → v-else-if renders, not v-else)
    expect(text).not.toContain('No attack detected')
    // raw outcome token must not leak
    expect(text).not.toContain('false_positive')

    // badge colour = warning
    const fpBadge = wrapper.findAll('.q-badge').find((b) => b.text().includes('False Positive'))
    expect(fpBadge).toBeDefined()
    expect(fpBadge?.classes()).toContain('bg-warning')
  })

  it('still shows MITRE classifications for an attack verdict', () => {
    const job = {
      ...baseCompletedJob,
      step2_classification: {
        classifications: [{ technique_id: 'T0846', confidence: 0.9, technique_name: 'Scan' }],
      },
      verdict: { outcome: 'attack', reasoning: 'active scanning observed' },
    }
    const { pinia } = createStoreWithJob(job)
    const wrapper = mountWithPlugins(TraceCard, {
      global: { plugins: [pinia] },
      props: { jobId: 'job-abc-1234' },
    })

    expect(wrapper.findAll('.mitre-row')).toHaveLength(1)
    expect(wrapper.text()).toContain('T0846')
    expect(wrapper.text()).not.toContain('No attack detected')
  })
})
