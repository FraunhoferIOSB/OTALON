import { beforeEach, describe, expect, it, vi } from 'vitest'

import type { RuntimeConfigItem, RuntimeConfigWrite } from '~/types/api'
import { useDetectionRuntimeGates } from '~/composables/useDetectionRuntimeGates'

const runtimeItem = (key: string, value: string): RuntimeConfigItem => ({
  service: 'otalon-clas',
  key,
  value,
  value_prev: null,
  updated_at: null,
  updated_by: null,
  type: 'bool',
  domain: null,
  description: key,
})

function makeDependencies() {
  const runtimeItems = [
    runtimeItem('detection.conn.bounds_enabled', 'true'),
    runtimeItem('detection.conn.classification_enabled', 'true'),
    runtimeItem('detection.conn.frequency_enabled', 'true'),
  ]
  return {
    runtimeItems,
    getRuntimeItems: () => runtimeItems,
    saveRuntime: vi
      .fn<(request: RuntimeConfigWrite | RuntimeConfigWrite[]) => Promise<unknown>>()
      .mockResolvedValue(undefined),
    refreshRuntime: vi.fn().mockResolvedValue(undefined),
    getRuntimeError: () => '',
    refreshReadiness: vi.fn().mockResolvedValue(undefined),
    getPollIntervalSeconds: () => 5,
  }
}

describe('useDetectionRuntimeGates', () => {
  beforeEach(() => {
    vi.useFakeTimers()
  })

  it('allows an empty reason before sending a write', async () => {
    const dependencies = makeDependencies()
    const gates = useDetectionRuntimeGates(dependencies)
    gates.open('conn')
    gates.draft.bounds_enabled = false

    await expect(gates.submit('  ')).resolves.toBe(true)
    expect(gates.reasonError.value).toBeNull()
  })

  it('sends exactly one changed key in each runtime request', async () => {
    const dependencies = makeDependencies()
    const gates = useDetectionRuntimeGates(dependencies)
    gates.open('conn')
    gates.draft.bounds_enabled = false

    await expect(gates.submit('Pause bounds during commissioning')).resolves.toBe(true)

    expect(dependencies.saveRuntime).toHaveBeenCalledTimes(1)
    expect(dependencies.saveRuntime).toHaveBeenCalledWith({
      service: 'otalon-clas',
      key: 'detection.conn.bounds_enabled',
      value: 'false',
      reason: 'Pause bounds during commissioning',
    })
  })

  it('submits without waiting for a delayed confirmation refresh', async () => {
    const dependencies = makeDependencies()
    const gates = useDetectionRuntimeGates(dependencies)
    gates.open('conn')
    gates.draft.classification_enabled = false

    const result = gates.submit('Pause classifier during maintenance')
    await Promise.resolve()

    await expect(gates.submit('second update')).resolves.toBe(false)
    expect(dependencies.refreshRuntime).not.toHaveBeenCalled()

    await expect(result).resolves.toBe(true)
    expect(gates.pending.value).toBe(false)
  })

  it('preserves confirmed state and clears pending state after a rejected write', async () => {
    const dependencies = makeDependencies()
    dependencies.saveRuntime.mockRejectedValue(new Error('write rejected'))
    const gates = useDetectionRuntimeGates(dependencies)
    gates.open('conn')
    gates.draft.bounds_enabled = false

    await expect(gates.submit('invalid operational change')).resolves.toBe(false)

    expect(gates.confirmed.conn.bounds_enabled).toBe(true)
    expect(gates.draft.bounds_enabled).toBe(true)
    expect(gates.pending.value).toBe(false)
    expect(gates.error.value).toBe('write rejected')
  })

  it('does not inspect delayed refresh errors after job submission', async () => {
    const dependencies = makeDependencies()
    dependencies.refreshRuntime.mockRejectedValue(new Error('runtime repo unavailable'))
    const gates = useDetectionRuntimeGates(dependencies)
    gates.open('conn')
    gates.draft.bounds_enabled = false

    await expect(gates.submit('test refresh failure')).resolves.toBe(true)

    expect(dependencies.refreshReadiness).not.toHaveBeenCalled()
    expect(gates.confirmed.conn.bounds_enabled).toBe(true)
    expect(gates.draft.bounds_enabled).toBe(false)
    expect(gates.pending.value).toBe(false)
    expect(gates.error.value).toBeNull()
  })

  it('rejects an unparseable runtime boolean instead of retaining stale state', () => {
    const dependencies = makeDependencies()
    dependencies.runtimeItems[0].value = 'unknown'
    const gates = useDetectionRuntimeGates(dependencies)

    gates.open('conn')

    expect(gates.error.value).toContain('Unparseable runtime value')
  })

  it('does not refresh runtime or readiness after job submission', async () => {
    const dependencies = makeDependencies()
    const gates = useDetectionRuntimeGates(dependencies)
    gates.open('conn')
    gates.draft.bounds_enabled = false

    const result = gates.submit('wait for live poll')
    await Promise.resolve()
    expect(dependencies.refreshRuntime).not.toHaveBeenCalled()
    expect(dependencies.refreshReadiness).not.toHaveBeenCalled()

    await result
    expect(dependencies.refreshRuntime).not.toHaveBeenCalled()
    expect(dependencies.refreshReadiness).not.toHaveBeenCalled()
  })
})
