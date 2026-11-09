import { computed, reactive, ref } from 'vue'

import type { RuntimeConfigItem, RuntimeConfigWrite } from '~/types/api'

export const DETECTION_GATE_MODULES = ['conn', 'mac_traffic', 'proto_traffic'] as const
export type DetectionGateModule = (typeof DETECTION_GATE_MODULES)[number]

export interface DetectionGateState {
  bounds_enabled: boolean
  classification_enabled: boolean
  frequency_enabled: boolean
}

export interface DetectionRuntimeGateDependencies {
  getRuntimeItems: () => RuntimeConfigItem[]
  saveRuntime: (request: RuntimeConfigWrite | RuntimeConfigWrite[]) => Promise<unknown>
  refreshRuntime: () => Promise<void>
  getRuntimeError?: () => string
  refreshReadiness: () => Promise<void>
  getPollIntervalSeconds: () => number
}

export interface DetectionRuntimeGates {
  selectedModule: ReturnType<typeof ref<DetectionGateModule | null>>
  dialogOpen: ReturnType<typeof ref<boolean>>
  draft: DetectionGateState
  confirmed: Record<DetectionGateModule, DetectionGateState>
  pending: ReturnType<typeof ref<boolean>>
  error: ReturnType<typeof ref<string | null>>
  status: ReturnType<typeof ref<'idle' | 'waiting' | 'saved'>>
  reasonError: ReturnType<typeof ref<string | null>>
  changed: ReturnType<typeof computed<boolean>>
  open: (module: DetectionGateModule) => void
  close: () => void
  syncFromRuntime: (module?: DetectionGateModule) => void
  submit: (reason: string) => Promise<boolean>
}

const defaultGateState = (): DetectionGateState => ({
  bounds_enabled: true,
  classification_enabled: true,
  frequency_enabled: true,
})

function runtimeKey(module: DetectionGateModule, gate: keyof DetectionGateState): string {
  return `detection.${module}.${gate}`
}

function runtimeBoolean(items: RuntimeConfigItem[], key: string): boolean | undefined {
  const item = items.find((candidate) => candidate.service === 'otalon-clas' && candidate.key === key)
  if (!item || (item.value !== 'true' && item.value !== 'false')) return undefined
  return item.value === 'true'
}

function errorMessage(error: unknown): string {
  if (error instanceof Error && error.message) return error.message
  if (error && typeof error === 'object' && 'message' in error && typeof error.message === 'string')
    return error.message
  return 'Live detection gate update could not be saved.'
}

/**
 * Controls per-module live bounds and classification gates.
 *
 * @example
 * ```ts
 * const gates = useDetectionRuntimeGates({ ...dependencies })
 * gates.open('conn')
 * await gates.submit('Pause bounds during commissioning')
 * ```
 */
export function useDetectionRuntimeGates(dependencies: DetectionRuntimeGateDependencies): DetectionRuntimeGates {
  const selectedModule = ref<DetectionGateModule | null>(null)
  const dialogOpen = ref(false)
  const draft = reactive<DetectionGateState>(defaultGateState())
  const confirmed = reactive<Record<DetectionGateModule, DetectionGateState>>({
    conn: defaultGateState(),
    mac_traffic: defaultGateState(),
    proto_traffic: defaultGateState(),
  })
  const pending = ref(false)
  const error = ref<string | null>(null)
  const status = ref<'idle' | 'waiting' | 'saved'>('idle')
  const reasonError = ref<string | null>(null)
  const changed = computed<boolean>(() => {
    const module = selectedModule.value
    if (!module) return false
    return (
      draft.bounds_enabled !== confirmed[module].bounds_enabled ||
      draft.classification_enabled !== confirmed[module].classification_enabled ||
      draft.frequency_enabled !== confirmed[module].frequency_enabled
    )
  })

  function syncFromRuntime(module?: DetectionGateModule): void {
    const items = dependencies.getRuntimeItems()
    const modules = module ? [module] : DETECTION_GATE_MODULES
    for (const candidate of modules) {
      const next = confirmed[candidate]
      const bounds = runtimeBoolean(items, runtimeKey(candidate, 'bounds_enabled'))
      const classification = runtimeBoolean(items, runtimeKey(candidate, 'classification_enabled'))
      const frequency = runtimeBoolean(items, runtimeKey(candidate, 'frequency_enabled'))
      const boundsItem = items.find((entry) => entry.key === runtimeKey(candidate, 'bounds_enabled'))
      const classificationItem = items.find((entry) => entry.key === runtimeKey(candidate, 'classification_enabled'))
      if (boundsItem && bounds === undefined) error.value = 'Unparseable runtime value for bounds_enabled.'
      if (classificationItem && classification === undefined)
        error.value = 'Unparseable runtime value for classification_enabled.'
      if (bounds !== undefined) next.bounds_enabled = bounds
      if (classification !== undefined) next.classification_enabled = classification
      if (frequency !== undefined) next.frequency_enabled = frequency
      if (selectedModule.value === candidate && !pending.value) {
        draft.bounds_enabled = next.bounds_enabled
        draft.classification_enabled = next.classification_enabled
        draft.frequency_enabled = next.frequency_enabled
      }
    }
  }

  function open(module: DetectionGateModule): void {
    selectedModule.value = module
    draft.bounds_enabled = confirmed[module].bounds_enabled
    draft.classification_enabled = confirmed[module].classification_enabled
    draft.frequency_enabled = confirmed[module].frequency_enabled
    reasonError.value = null
    error.value = null
    status.value = 'idle'
    dialogOpen.value = true
    syncFromRuntime(module)
  }

  function close(): void {
    if (pending.value) return
    dialogOpen.value = false
    selectedModule.value = null
    reasonError.value = null
  }

  async function submit(reason: string): Promise<boolean> {
    const module = selectedModule.value
    if (!module || pending.value) return false
    const trimmedReason = reason.trim()
    reasonError.value = null
    if (!changed.value) {
      if (!reasonError.value) reasonError.value = 'Change at least one live detection gate before applying.'
      return false
    }

    pending.value = true
    error.value = null
    status.value = 'waiting'
    try {
      const updates: Array<{ gate: keyof DetectionGateState; value: boolean }> = []
      if (draft.bounds_enabled !== confirmed[module].bounds_enabled)
        updates.push({ gate: 'bounds_enabled', value: draft.bounds_enabled })
      if (draft.classification_enabled !== confirmed[module].classification_enabled)
        updates.push({ gate: 'classification_enabled', value: draft.classification_enabled })
      if (draft.frequency_enabled !== confirmed[module].frequency_enabled)
        updates.push({ gate: 'frequency_enabled', value: draft.frequency_enabled })
      const requests = updates.map((update) => ({
        service: 'otalon-clas',
        key: runtimeKey(module, update.gate),
        value: String(update.value),
        reason: trimmedReason,
      }))
      await dependencies.saveRuntime(requests.length === 1 ? requests[0] : requests)
      dialogOpen.value = false
      selectedModule.value = null
      status.value = 'saved'
      return true
    } catch (caught: unknown) {
      draft.bounds_enabled = confirmed[module].bounds_enabled
      draft.classification_enabled = confirmed[module].classification_enabled
      draft.frequency_enabled = confirmed[module].frequency_enabled
      error.value = errorMessage(caught)
      status.value = 'idle'
      return false
    } finally {
      pending.value = false
    }
  }

  return {
    selectedModule,
    dialogOpen,
    draft,
    confirmed,
    pending,
    error,
    status,
    reasonError,
    changed,
    open,
    close,
    syncFromRuntime,
    submit,
  }
}
