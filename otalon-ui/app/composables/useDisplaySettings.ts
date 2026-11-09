/**
 * Composable for table-page display settings persisted to ``localStorage``.
 *
 * Encapsulates the load/merge/save lifecycle so multiple pages (Assets,
 * Alarms, …) can share the same UX without duplicating storage code.
 * The page passes its set of columns and a unique storage key; the
 * composable returns a reactive ``settings`` object plus helper actions.
 */
import type { DisplaySettingsValue } from '~/components/shared/DisplaySettingsDialog.vue'

export interface UseDisplaySettingsOptions {
  /** Stable ``localStorage`` key, e.g. ``"assets:displaySettings"``. */
  storageKey: string
  /** List of all column ids the page might toggle. */
  columnDefaults: Record<string, boolean>
  featureToggleDefaults?: Record<string, boolean>
  /** Default font size in pixels (typically 13). */
  defaultFontSize?: number
  /** Default rows-per-page value (0 = all). */
  defaultRowsPerPage?: number
}

/**
 * Build the canonical default settings object for a given option set.
 */
function buildDefaults(opts: UseDisplaySettingsOptions): DisplaySettingsValue {
  return {
    fontSize: opts.defaultFontSize ?? 13,
    density: 'normal',
    rowsPerPage: opts.defaultRowsPerPage ?? 25,
    visibleColumns: { ...opts.columnDefaults },
    featureToggles: { ...(opts.featureToggleDefaults ?? {}) },
  }
}

/**
 * Read a stored settings payload and merge it with the defaults.
 *
 * Unknown / extra keys in storage are silently dropped, missing keys
 * fall back to the default value so newly added columns appear by
 * default after a UI upgrade.
 */
function loadFromStorage(storageKey: string, defaults: DisplaySettingsValue): DisplaySettingsValue {
  if (!import.meta.client) {
    return { ...defaults, visibleColumns: { ...defaults.visibleColumns }, featureToggles: { ...defaults.featureToggles } }
  }
  try {
    const raw = localStorage.getItem(storageKey)
    if (!raw) {
      return { ...defaults, visibleColumns: { ...defaults.visibleColumns }, featureToggles: { ...defaults.featureToggles } }
    }
    const parsed = JSON.parse(raw) as Partial<DisplaySettingsValue>
    return {
      fontSize:
        typeof parsed.fontSize === 'number' && Number.isFinite(parsed.fontSize) ? parsed.fontSize : defaults.fontSize,
      density: parsed.density ?? defaults.density,
      rowsPerPage: typeof parsed.rowsPerPage === 'number' ? parsed.rowsPerPage : defaults.rowsPerPage,
      visibleColumns: {
        ...defaults.visibleColumns,
        ...(parsed.visibleColumns ?? {}),
      },
      featureToggles: { ...defaults.featureToggles, ...(parsed.featureToggles ?? {}) },
    }
  } catch {
    return { ...defaults, visibleColumns: { ...defaults.visibleColumns }, featureToggles: { ...defaults.featureToggles } }
  }
}

/**
 * Provide a reactive {@link DisplaySettingsValue} backed by
 * ``localStorage`` plus helpers to persist/reset.
 */
export function useDisplaySettings(opts: UseDisplaySettingsOptions) {
  const defaults = buildDefaults(opts)
  const settings = ref<DisplaySettingsValue>(loadFromStorage(opts.storageKey, defaults))
  const dialogOpen = ref(false)

  function persist(): void {
    if (!import.meta.client) return
    try {
      localStorage.setItem(opts.storageKey, JSON.stringify(settings.value))
    } catch {
      /* ignore quota errors */
    }
  }

  function reset(): void {
    settings.value = {
      ...defaults,
      visibleColumns: { ...defaults.visibleColumns },
      featureToggles: { ...defaults.featureToggles },
    }
    persist()
  }

  return {
    settings,
    dialogOpen,
    persist,
    reset,
  }
}
