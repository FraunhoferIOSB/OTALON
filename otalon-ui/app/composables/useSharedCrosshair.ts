import { computed, onScopeDispose, ref } from 'vue'

const STORAGE_KEY = 'display:sharedCrosshair'
const CROSSHAIR_EVENT = 'otalon:shared-crosshair'
const enabledState = ref(true)
let initialized = false

interface CrosshairDetail {
  time: number | null
}

function initialize(): void {
  if (initialized || typeof window === 'undefined') return
  initialized = true
  const stored = window.localStorage.getItem(STORAGE_KEY)
  enabledState.value = stored === null ? true : stored === 'true'
}

/**
 * Reset the module-level hydration flag.
 *
 * Test-only seam mirroring ``__resetChatSettingsHydration``: the flag lives at
 * module scope so hydration happens once per page load, which would otherwise
 * leak the toggle state from one test case into the next.
 */
export function __resetSharedCrosshairHydration(): void {
  initialized = false
  enabledState.value = true
}

export function useSharedCrosshair() {
  initialize()

  function setEnabled(value: boolean): void {
    enabledState.value = value
    if (typeof window !== 'undefined') window.localStorage.setItem(STORAGE_KEY, String(value))
    // A disabled crosshair must not leave a frozen line behind in the
    // subscribers that were showing one at the moment it was switched off.
    if (!value && typeof window !== 'undefined') {
      window.dispatchEvent(
        new CustomEvent<CrosshairDetail>(CROSSHAIR_EVENT, { detail: { time: null } }),
      )
    }
  }

  // Writable so `v-model="sharedCrosshair.enabled"` in the settings menus
  // routes through setEnabled() and persists. Assigning to a plain ref would
  // update the state but silently skip persistence.
  const enabled = computed<boolean>({
    get: () => enabledState.value,
    set: setEnabled,
  })

  function publish(time: number | null): void {
    if (typeof window === 'undefined' || !enabledState.value) return
    window.dispatchEvent(new CustomEvent<CrosshairDetail>(CROSSHAIR_EVENT, { detail: { time } }))
  }

  function subscribe(handler: (time: number | null) => void): void {
    if (typeof window === 'undefined') return
    const listener = (event: Event) => {
      const detail = (event as CustomEvent<CrosshairDetail>).detail
      handler(detail?.time ?? null)
    }
    window.addEventListener(CROSSHAIR_EVENT, listener)
    onScopeDispose(() => window.removeEventListener(CROSSHAIR_EVENT, listener))
  }

  return { enabled, setEnabled, publish, subscribe }
}
