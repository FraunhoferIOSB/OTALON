import { describe, it, expect, vi, beforeEach } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'
import { mountWithPlugins } from '../helpers/mount'
import ForensicTraceModal from '~/components/subagent/ForensicTraceModal.vue'
import { useSubagentStore } from '~/stores/subagentStore'

function createStoreWithJob(job: unknown) {
  const pinia = createPinia()
  setActivePinia(pinia)
  const store = useSubagentStore()
  if (job && typeof job === 'object' && 'id' in job) {
    store.liveJobsById[String((job as { id: string }).id)] = job as never
  }
  return { pinia }
}

const baseJob = {
  id: 'job-abc-1234',
  status: 'completed',
  prompt_variant: 'expert',
  llm_model: 'gpt-5.4',
  duration_seconds: 12.3,
  tokens_prompt: 100,
  tokens_completion: 50,
  tool_trace: [
    {
      round: 1,
      tool: 'postgres.read_anomalies',
      args: { limit: 5 },
      result_chars: 42,
      result_preview: '{"count": 5}',
      duration_ms: 120,
      error: null,
    },
    {
      round: 2,
      tool: 'broken.tool',
      args: {},
      result_chars: 0,
      result_preview: null,
      duration_ms: 30,
      error: 'MCP down',
    },
  ],
  step1_technical: { technical_method: 'Modbus abuse', observed_activity: 'Scan' },
  step2_classification: {
    classifications: [{ technique_id: 'T0846', confidence: 0.92, technique_name: 'Scan', reasoning: 'pattern' }],
  },
}

describe('ForensicTraceModal', () => {
  beforeEach(() => {
    vi.stubGlobal('localStorage', {
      store: {} as Record<string, string>,
      getItem: () => null,
      setItem: () => {},
      removeItem: () => {},
      clear: () => {},
    })
  })

  it('renders N expansion items from a mock job', () => {
    const { pinia } = createStoreWithJob(baseJob)
    const wrapper = mountWithPlugins(ForensicTraceModal, {
      global: { plugins: [pinia] },
      props: { modelValue: true, jobId: 'job-abc-1234' },
    })
    const items = wrapper.findAll('.tool-expansion')
    expect(items.length).toBe(2)
  })

  it('includes error badge for failed tool call', () => {
    const { pinia } = createStoreWithJob(baseJob)
    const wrapper = mountWithPlugins(ForensicTraceModal, {
      global: { plugins: [pinia] },
      props: { modelValue: true, jobId: 'job-abc-1234' },
    })
    const badges = wrapper.findAll('.q-badge')
    const errorBadge = badges.find((b) => b.text().includes('error'))
    expect(errorBadge).toBeDefined()
  })

  it('pretty-prints JSON preview when parseable', () => {
    const { pinia } = createStoreWithJob(baseJob)
    const wrapper = mountWithPlugins(ForensicTraceModal, {
      global: { plugins: [pinia] },
      props: { modelValue: true, jobId: 'job-abc-1234' },
    })
    const pre = wrapper.findAll('.output-pre')[0]
    expect(pre.text()).toContain('"count": 5')
  })

  it('shows fallback caption for null preview', () => {
    const { pinia } = createStoreWithJob(baseJob)
    const wrapper = mountWithPlugins(ForensicTraceModal, {
      global: { plugins: [pinia] },
      props: { modelValue: true, jobId: 'job-abc-1234' },
    })
    const captions = wrapper.findAll('.text-caption.text-muted')
    const nullCaption = captions.find((c) => c.text().includes('Output not recorded'))
    expect(nullCaption).toBeDefined()
  })

  it('shows truncation caption when result_chars > preview length', () => {
    const job = {
      ...baseJob,
      tool_trace: [
        {
          round: 1,
          tool: 'x',
          args: {},
          result_chars: 5000,
          result_preview: 'short',
          duration_ms: 10,
          error: null,
        },
      ],
    }
    const { pinia } = createStoreWithJob(job)
    const wrapper = mountWithPlugins(ForensicTraceModal, {
      global: { plugins: [pinia] },
      props: { modelValue: true, jobId: 'job-abc-1234' },
    })
    const captions = wrapper.findAll('.text-caption.text-muted')
    const truncCaption = captions.find((c) => c.text().includes('truncated'))
    expect(truncCaption).toBeDefined()
  })

  it('renders a "False Positive" badge with humanized fp_reason and hides MITRE for false_positive', () => {
    const job = {
      ...baseJob,
      step1_technical: { technical_method: 'none', observed_activity: 'normal traffic' },
      step2_classification: { classifications: [] },
      verdict: {
        outcome: 'false_positive',
        fp_reason: 'monitoring_tool',
        reasoning: 'matches baseline scanner pattern',
      },
    }
    const { pinia } = createStoreWithJob(job)
    const wrapper = mountWithPlugins(ForensicTraceModal, {
      global: { plugins: [pinia] },
      props: { modelValue: true, jobId: 'job-abc-1234' },
    })

    const text = wrapper.text()
    expect(text).toContain('False Positive')
    expect(text).toContain('monitoring tool')
    expect(text).toContain('matches baseline scanner pattern')
    expect(wrapper.findAll('.mitre-row')).toHaveLength(0)
    expect(text).not.toContain('No attack detected')
    expect(text).not.toContain('false_positive')

    const fpBadge = wrapper.findAll('.q-badge').find((b) => b.text().includes('False Positive'))
    expect(fpBadge).toBeDefined()
    expect(fpBadge?.classes()).toContain('bg-warning')
  })
})
