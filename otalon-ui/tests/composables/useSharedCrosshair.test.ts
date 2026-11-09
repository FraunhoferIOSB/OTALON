/**
 * Unit tests for the useSharedCrosshair composable.
 *
 * Verifies the enable/disable contract of the crosshair bus: default state,
 * persistence, publish suppression while disabled, and cleanup of a standing
 * crosshair when it is switched off.
 */
import { beforeEach, describe, expect, it } from 'vitest'
import { effectScope, nextTick } from 'vue'

import { __resetSharedCrosshairHydration, useSharedCrosshair } from '~/composables/useSharedCrosshair'

const STORAGE_KEY = 'display:sharedCrosshair'

/**
 * Run `fn` inside an effect scope so composables that register
 * `onScopeDispose` handlers do not warn, and return its result.
 */
const inScope = <T>(fn: () => T): T => {
  const scope = effectScope()
  const result = scope.run(fn)
  return result as T
}

describe('useSharedCrosshair', () => {
  beforeEach(() => {
    localStorage.clear()
    __resetSharedCrosshairHydration()
  })

  it('defaults to enabled', () => {
    const bus = inScope(() => useSharedCrosshair())
    expect(bus.enabled.value).toBe(true)
  })

  it('delivers published timestamps to subscribers', () => {
    const bus = inScope(() => useSharedCrosshair())
    const seen: (number | null)[] = []
    inScope(() => useSharedCrosshair().subscribe((t: number | null) => seen.push(t)))

    bus.publish(1000)
    bus.publish(null)

    expect(seen).toEqual([1000, null])
  })

  // Regression: the settings menus bind `v-model="sharedCrosshair.enabled"`.
  // While `enabled` was a plain ref, that assignment bypassed setEnabled(), so
  // the toggle neither persisted nor silenced the bus -- it had no effect.
  it('persists and takes effect when assigned through .value (v-model path)', () => {
    const bus = inScope(() => useSharedCrosshair())

    bus.enabled.value = false

    expect(bus.enabled.value).toBe(false)
    expect(localStorage.getItem(STORAGE_KEY)).toBe('false')
  })

  it('stops delivering positions while disabled', () => {
    const bus = inScope(() => useSharedCrosshair())
    const seen: (number | null)[] = []
    inScope(() => useSharedCrosshair().subscribe((t: number | null) => seen.push(t)))

    bus.enabled.value = false
    seen.length = 0
    bus.publish(5000)

    expect(seen).toEqual([])
  })

  it('clears a standing crosshair when switched off', () => {
    const bus = inScope(() => useSharedCrosshair())
    const seen: (number | null)[] = []
    inScope(() => useSharedCrosshair().subscribe((t: number | null) => seen.push(t)))

    bus.publish(1000)
    seen.length = 0
    bus.enabled.value = false

    expect(seen).toEqual([null])
  })

  it('resumes publishing after being re-enabled', () => {
    const bus = inScope(() => useSharedCrosshair())
    const seen: (number | null)[] = []
    inScope(() => useSharedCrosshair().subscribe((t: number | null) => seen.push(t)))

    bus.enabled.value = false
    bus.enabled.value = true
    seen.length = 0
    bus.publish(7000)

    expect(seen).toEqual([7000])
  })

  it('shares state across independent call sites', async () => {
    const a = inScope(() => useSharedCrosshair())
    const b = inScope(() => useSharedCrosshair())

    a.enabled.value = false
    await nextTick()

    expect(b.enabled.value).toBe(false)
  })
})
