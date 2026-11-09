/**
 * Central application store for cross-page global state.
 *
 * Replaces the legacy `useTimeMode` composable and consolidates
 * theme, sidebar, live/history mode, and SSE
 * connection status into a single Pinia store.
 *
 * Uses the Options API pattern so that `$reset()` works automatically.
 *
 * Persisted to localStorage: `theme`, `liveIntervalSeconds`, `pollingIntervalMs`.
 */
import { defineStore } from 'pinia'

import { formatDateTimeShort } from '~/utils/format'

export interface IntervalOption {
  label: string
  value: number
}

export type Theme = 'light' | 'dark'

export type SseConnectionStatus = 'connected' | 'disconnected' | 'reconnecting'

export interface AppState {
  theme: Theme
  sidebarExpanded: boolean
  liveMode: boolean
  liveIntervalSeconds: number
  timeRange: { start: string; end: string }
  sseConnectionStatus: SseConnectionStatus
  pollingIntervalMs: number
  cveLookupDialogOpen: boolean
  cveLookupDialogJobId: string | null
  scanDetailModalOpen: boolean
  scanDetailModalScanId: string | null
}

const VALID_INTERVALS = new Set([60, 300, 600, 900, 1800, 3600])
const VALID_POLLING_INTERVALS = new Set([5_000, 10_000, 15_000, 30_000, 60_000, 120_000])

const STORAGE_KEY_THEME = 'app:theme'
const STORAGE_KEY_INTERVAL = 'app:liveIntervalSeconds'
const STORAGE_KEY_POLLING = 'app:pollingIntervalMs'

/**
 * Read a value from localStorage, returning `undefined` when unavailable.
 *
 * @param key - The localStorage key.
 * @returns The stored string value or `undefined`.
 */
function readStorage(key: string): string | undefined {
  if (typeof window === 'undefined') return undefined
  try {
    return localStorage.getItem(key) ?? undefined
  } catch {
    return undefined
  }
}

/**
 * Write a value to localStorage, silently ignoring errors.
 *
 * @param key - The localStorage key.
 * @param value - The value to store.
 */
function writeStorage(key: string, value: string): void {
  if (typeof window === 'undefined') return
  try {
    localStorage.setItem(key, value)
  } catch {
    /* quota exceeded or private browsing — ignore */
  }
}

/**
 * Create the default time range (last 1 hour) as ISO 8601 UTC strings.
 *
 * @returns Object with `start` and `end` ISO strings.
 */
function createDefaultTimeRange(): { start: string; end: string } {
  const end = new Date()
  const start = new Date(end.getTime() - 3_600_000)
  return { start: start.toISOString(), end: end.toISOString() }
}

/**
 * Resolve the persisted theme from localStorage, falling back to `'dark'`.
 *
 * @returns The stored theme or the default.
 */
function resolvePersistedTheme(): Theme {
  const stored = readStorage(STORAGE_KEY_THEME)
  return stored === 'light' || stored === 'dark' ? stored : 'dark'
}

/**
 * Resolve the persisted live interval from localStorage, falling back to `300`.
 *
 * @returns A validated interval value.
 */
function resolvePersistedInterval(): number {
  const stored = readStorage(STORAGE_KEY_INTERVAL)
  if (stored === undefined) return 300
  const parsed = Number(stored)
  return VALID_INTERVALS.has(parsed) ? parsed : 300
}

/**
 * Resolve the persisted polling interval from localStorage, falling back to `5000`.
 *
 * @returns A validated polling interval value in milliseconds.
 */
function resolvePersistedPollingInterval(): number {
  const stored = readStorage(STORAGE_KEY_POLLING)
  if (stored === undefined) return 5_000
  const parsed = Number(stored)
  return VALID_POLLING_INTERVALS.has(parsed) ? parsed : 5_000
}

export const useAppStore = defineStore('app', {
  state: (): AppState => ({
    theme: resolvePersistedTheme(),
    sidebarExpanded: false,
    liveMode: true,
    liveIntervalSeconds: resolvePersistedInterval(),
    timeRange: createDefaultTimeRange(),
    sseConnectionStatus: 'disconnected',
    pollingIntervalMs: resolvePersistedPollingInterval(),
    cveLookupDialogOpen: false,
    cveLookupDialogJobId: null,
    scanDetailModalOpen: false,
    scanDetailModalScanId: null,
  }),

  getters: {
    /**
     * Whether dark theme is active.
     *
     * @returns `true` when the theme is `'dark'`.
     */
    isDark(state): boolean {
      return state.theme === 'dark'
    },

    /**
     * Static list of available live-window interval options.
     *
     * @returns Array of `{ label, value }` objects.
     */
    intervalOptions(): IntervalOption[] {
      return [
        { label: '1m', value: 60 },
        { label: '5m', value: 300 },
        { label: '10m', value: 600 },
        { label: '15m', value: 900 },
        { label: '30m', value: 1800 },
        { label: '60m', value: 3600 },
      ]
    },

    /**
     * Static list of available polling refresh rate options.
     *
     * @returns Array of `{ label, value }` objects with values in milliseconds.
     */
    pollingIntervalOptions(): IntervalOption[] {
      return [
        { label: '5s', value: 5_000 },
        { label: '10s', value: 10_000 },
        { label: '15s', value: 15_000 },
        { label: '30s', value: 30_000 },
        { label: '60s', value: 60_000 },
        { label: '120s', value: 120_000 },
      ]
    },

    /**
     * Inverted sidebar state for Quasar `QDrawer` `mini` prop.
     *
     * @returns `true` when the sidebar is collapsed.
     */
    sidebarMini(state): boolean {
      return !state.sidebarExpanded
    },

    /**
     * Effective time range based on the current mode.
     *
     * In live mode, computes a sliding window ending at the current time
     * with a width of `liveIntervalSeconds`. In history mode, returns the
     * manually selected `timeRange` as-is.
     *
     * @returns Object with `start` and `end` as ISO 8601 UTC strings.
     */
    effectiveTimeRange(state): { start: string; end: string } {
      if (state.liveMode) {
        const now = new Date()
        const start = new Date(now.getTime() - state.liveIntervalSeconds * 1000)
        return { start: start.toISOString(), end: now.toISOString() }
      }
      return state.timeRange
    },

    /**
     * Convenience getter that maps {@link effectiveTimeRange} to the
     * query parameter names expected by the backend (`start` / `stop`).
     *
     * @returns Object with `start` and `stop` as ISO 8601 UTC strings.
     */
    apiTimeParams(): { start: string; stop: string } {
      const range = this.effectiveTimeRange
      return { start: range.start, stop: range.end }
    },

    /**
     * Human-readable label for the currently selected time range.
     *
     * In live mode the label names the sliding window ("Last 5m",
     * "Last 60m" ...). In history mode it renders the applied
     * `timeRange` boundaries, so the label always matches the window
     * the widgets are actually querying.
     *
     * @returns A short label such as `Last 5m` or `Jun 1, 00:00 – Jun 1, 12:00`.
     */
    timeRangeLabel(state): string {
      if (state.liveMode) {
        const selected = this.intervalOptions.find((option) => option.value === state.liveIntervalSeconds)
        return `Last ${selected?.label ?? `${state.liveIntervalSeconds}s`}`
      }
      return `${formatDateTimeShort(state.timeRange.start)} – ${formatDateTimeShort(state.timeRange.end)}`
    },
  },

  actions: {
    /**
     * Toggle between live monitoring and history mode.
     */
    toggleLiveMode(): void {
      this.liveMode = !this.liveMode
    },

    /**
     * Explicitly set live/history mode.
     *
     * @param value - `true` for live mode, `false` for history mode.
     */
    setLiveMode(value: boolean): void {
      this.liveMode = value
    },

    /**
     * Re-read all persisted preferences from ``localStorage``.
     *
     * Called from the default layout's ``onMounted`` to recover from
     * Nuxt's SSR run, which builds the initial state with the in-code
     * defaults because ``window``/``localStorage`` are not available
     * on the server. Without this hydration step every reload would
     * revert the operator's theme + interval choices back to defaults.
     */
    hydrateFromStorage(): void {
      this.theme = resolvePersistedTheme()
      this.liveIntervalSeconds = resolvePersistedInterval()
      this.pollingIntervalMs = resolvePersistedPollingInterval()
    },

    /**
     * Set the live polling interval.
     *
     * Only values in the allowed set are accepted: 60, 300, 600, 900, 1800, 3600.
     *
     * @param seconds - The interval in seconds.
     */
    setLiveInterval(seconds: number): void {
      if (!VALID_INTERVALS.has(seconds)) return
      this.liveIntervalSeconds = seconds
      writeStorage(STORAGE_KEY_INTERVAL, String(seconds))
    },

    /**
     * Set the polling refresh interval and persist it to localStorage.
     *
     * Only values in the allowed set are accepted: 10000, 15000, 30000, 60000, 120000.
     *
     * @param ms - The polling interval in milliseconds.
     */
    setPollingInterval(ms: number): void {
      if (!VALID_POLLING_INTERVALS.has(ms)) return
      this.pollingIntervalMs = ms
      writeStorage(STORAGE_KEY_POLLING, String(ms))
    },

    /**
     * Set the history time range.
     *
     * Rejects the update when `start >= end` as a second line of defense
     * behind the per-handler validation in TimeToolbar.
     *
     * @param start - ISO 8601 UTC start timestamp.
     * @param end - ISO 8601 UTC end timestamp.
     * @returns `true` when the range was accepted, `false` when rejected.
     */
    setTimeRange(start: string, end: string): boolean {
      if (new Date(start) >= new Date(end)) {
        console.warn('[appStore] Invalid time range rejected:', start, '>=', end)
        return false
      }
      this.timeRange = { start, end }
      return true
    },

    /**
     * Toggle sidebar between expanded and mini (collapsed) state.
     */
    toggleSidebar(): void {
      this.sidebarExpanded = !this.sidebarExpanded
    },

    /**
     * Set the application theme and persist it to localStorage.
     *
     * @param value - The desired theme.
     */
    setTheme(value: Theme): void {
      this.theme = value
      writeStorage(STORAGE_KEY_THEME, value)
    },

    /**
     * Toggle between light and dark theme.
     */
    toggleTheme(): void {
      this.setTheme(this.theme === 'dark' ? 'light' : 'dark')
    },

    /**
     * Update the SSE connection status indicator.
     *
     * @param status - The current connection status.
     */
    setSseStatus(status: SseConnectionStatus): void {
      this.sseConnectionStatus = status
    },

    /**
     * Compute fresh API time parameters with a new Date() each call.
     *
     * Unlike the cached `apiTimeParams` getter, this method always returns
     * the current wall-clock time for the sliding live window end.
     * Use this in polling callbacks where fresh timestamps are required.
     *
     * @returns Object with `start` and `stop` as ISO 8601 UTC strings.
     */
    freshApiTimeParams(): { start: string; stop: string } {
      if (this.liveMode) {
        const now = new Date()
        const start = new Date(now.getTime() - this.liveIntervalSeconds * 1000)
        return { start: start.toISOString(), stop: now.toISOString() }
      }
      return { start: this.timeRange.start, stop: this.timeRange.end }
    },

    /**
     * Open the CVE Lookup dialog, optionally focused on a specific job.
     *
     * @param jobId - Pre-select this job id in the detail pane.
     */
    openCveLookupDialog(jobId?: string | null): void {
      this.cveLookupDialogJobId = jobId ?? null
      this.cveLookupDialogOpen = true
    },

    /**
     * Close the CVE Lookup dialog and clear the pre-selected job.
     */
    closeCveLookupDialog(): void {
      this.cveLookupDialogOpen = false
      this.cveLookupDialogJobId = null
    },

    /**
     * Open the Scan Detail modal for a given scan id.
     *
     * @param scanId - The scan to display.
     */
    openScanDetailModal(scanId: string): void {
      this.scanDetailModalScanId = scanId
      this.scanDetailModalOpen = true
    },

    /**
     * Close the Scan Detail modal and clear the pre-selected scan.
     */
    closeScanDetailModal(): void {
      this.scanDetailModalOpen = false
      this.scanDetailModalScanId = null
    },
  },
})
