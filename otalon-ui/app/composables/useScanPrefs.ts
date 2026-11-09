import { ref, watch } from 'vue'

const STORAGE_KEY = 'otalon-scan-prefs-v1'

export interface ScanPrefs {
  /** Show the recommendation banner + auto-select a module (default true). */
  showRecommendations: boolean
  /** Open the modal directly in JSON mode (default false). */
  alwaysJson: boolean
  /** Expand the Advanced/auth panel by default (default false). */
  expandAdvanced: boolean
}

const DEFAULTS: ScanPrefs = {
  showRecommendations: true,
  alwaysJson: false,
  expandAdvanced: false,
}

function loadPrefs(): ScanPrefs {
  if (typeof localStorage === 'undefined') return { ...DEFAULTS }
  try {
    const raw = localStorage.getItem(STORAGE_KEY)
    if (!raw) return { ...DEFAULTS }
    const parsed = JSON.parse(raw) as Partial<ScanPrefs>
    return {
      showRecommendations: parsed.showRecommendations ?? DEFAULTS.showRecommendations,
      alwaysJson: parsed.alwaysJson ?? DEFAULTS.alwaysJson,
      expandAdvanced: parsed.expandAdvanced ?? DEFAULTS.expandAdvanced,
    }
  } catch {
    return { ...DEFAULTS }
  }
}

function savePrefs(prefs: ScanPrefs): void {
  if (typeof localStorage === 'undefined') return
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(prefs))
  } catch {
    // silently ignore quota/storage errors
  }
}

/**
 * Reactive, localStorage-backed scan preferences.
 *
 * Changes are persisted automatically. Safe for SSR (falls back to defaults
 * when ``localStorage`` is unavailable).
 *
 * @example
 * ```ts
 * const { prefs } = useScanPrefs()
 * if (prefs.value.showRecommendations) { ... }
 * ```
 */
export function useScanPrefs() {
  const prefs = ref<ScanPrefs>(loadPrefs())

  watch(prefs, (next) => savePrefs(next), { deep: true })

  return { prefs }
}
