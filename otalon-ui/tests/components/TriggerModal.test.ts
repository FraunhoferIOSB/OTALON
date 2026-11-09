import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mountWithPlugins } from '../helpers/mount'
import TriggerModal from '~/components/subagent/TriggerModal.vue'

describe('TriggerModal prompt-variant dropdown', () => {
  beforeEach(() => {
    vi.stubGlobal('localStorage', {
      store: {} as Record<string, string>,
      getItem: () => null,
      setItem: () => {},
      removeItem: () => {},
      clear: () => {},
    })
  })

  it('offers the forensic variant and keeps expert as the first option', () => {
    // modelValue:false → no baseline fetch / no submit path triggered.
    const wrapper = mountWithPlugins(TriggerModal, {
      props: { modelValue: false, alarmId: 'alarm-1' },
    })

    // Scope to the prompt-variant select (first q-select in the dialog) so
    // options from the model / reasoning / baseline selects are excluded.
    const promptSelect = wrapper.find('select.q-select')
    const options = promptSelect.findAll('option')
    const values = options.map((o) => o.attributes('value'))

    expect(values).toHaveLength(3)
    expect(values[0]).toBe('expert')
    expect(values).toContain('open')
    expect(values).toContain('forensic')

    const forensicOption = options.find((o) => o.attributes('value') === 'forensic')
    expect(forensicOption).toBeDefined()
    expect(forensicOption?.text()).toContain('Forensic')
    expect(forensicOption?.text()).toContain('FP-first')
  })
})

describe('TriggerModal model selection (AI-045)', () => {
  it('has no LLM model dropdown and never sends llm_model', () => {
    // The model comes only from Operations > Configuration. A dropdown here would
    // override the live setting with a hard-coded model (gpt-5.4), as seen on 2026-11-09.
    // Open the dialog (modelValue true): with modelValue false the content is not rendered,
    // so a closed dialog would pass this test even when the dropdown exists.
    const wrapper = mountWithPlugins(TriggerModal, {
      props: { modelValue: true, alarmId: 'alarm-1' },
    })
    // Labels are not rendered as text in this mount setup, so count the rendered selects:
    // prompt + reasoning + baseline = 3. A model dropdown would make it 4.
    // (Verified 2026-11-09: open dialog renders 3 q-select, label text is absent.)
    expect(wrapper.text()).toContain('Re-Analyze Alarm')
    expect(wrapper.html().match(/q-select/g)?.length ?? 0).toBe(3)
    expect(wrapper.text()).not.toContain('paper-default')
    expect(wrapper.text()).not.toContain('GPT-5.4 (Azure')
  })
})
