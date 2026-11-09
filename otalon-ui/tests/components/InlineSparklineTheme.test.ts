/**
 * Component-level regression test for UI-082.
 *
 * Verifies that InlineSparkline reads the --cd-plot-line theme token from
 * <body> instead of falling back to the hardcoded default, in both dark
 * and light mode. Playwright screenshot verification is not available in
 * this headless Vitest environment, so we intercept the ECharts option
 * via a module mock and assert the resolved color.
 */
import { describe, it, expect, beforeEach, vi } from 'vitest'
import { flushPromises } from '@vue/test-utils'

import { mountWithPlugins } from '../helpers/mount'
import InlineSparkline from '~/components/dashboard/InlineSparkline.vue'

const setOption = vi.fn()
const dispose = vi.fn()
const resize = vi.fn()
const init = vi.fn(() => ({ setOption, dispose, resize }))

vi.mock('echarts', () => ({ init }))
vi.mock('quasar', () => ({
  useQuasar: vi.fn(() => ({ dark: { isActive: false } })),
}))

function stubClientOnly() {
  return {
    template: '<slot />',
  }
}

async function mountWithTheme(themeClass: string, tokenColor: string) {
  document.body.className = ''
  document.body.style.cssText = ''
  document.body.classList.add(themeClass)
  document.body.style.setProperty('--cd-plot-line', tokenColor)

  const wrapper = mountWithPlugins(InlineSparkline, {
    props: { data: [1, 2, 3] },
    global: {
      stubs: {
        ClientOnly: stubClientOnly(),
      },
    },
  })

  await flushPromises()
  return wrapper
}

describe('InlineSparkline theme token usage (UI-082)', () => {
  beforeEach(() => {
    document.body.className = ''
    document.body.style.cssText = ''
    vi.clearAllMocks()
  })

  it('uses --cd-plot-line from body in dark mode', async () => {
    await mountWithTheme('body--dark', '#4dd0e1')

    expect(init).toHaveBeenCalledTimes(1)
    expect(setOption).toHaveBeenCalledTimes(1)

    const option = setOption.mock.calls[0][0] as Record<string, unknown>
    const series = option.series as Array<{
      lineStyle: { color: string }
      itemStyle: { color: string }
    }>

    expect(series[0].lineStyle.color).toBe('#4dd0e1')
    expect(series[0].itemStyle.color).toBe('#4dd0e1')
  })

  it('uses --cd-plot-line from body in light mode', async () => {
    await mountWithTheme('body--light', '#00838f')

    expect(init).toHaveBeenCalledTimes(1)
    expect(setOption).toHaveBeenCalledTimes(1)

    const option = setOption.mock.calls[0][0] as Record<string, unknown>
    const series = option.series as Array<{
      lineStyle: { color: string }
      itemStyle: { color: string }
    }>

    expect(series[0].lineStyle.color).toBe('#00838f')
    expect(series[0].itemStyle.color).toBe('#00838f')
  })
})
