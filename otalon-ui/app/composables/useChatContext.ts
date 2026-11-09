/**
 * Composable for collecting a structured snapshot of the current UI
 * state and forwarding it as ``ui_context`` along with chat messages.
 *
 * Each page registers a small "page provider" via :func:`provideChatContext`
 * that contributes view-specific fields (selection, filters, visible
 * data, summary). The composable also fills in route, time window and
 * app metadata from the route and ``useAppStore`` automatically.
 *
 * The snapshot is intentionally compact (≤ ~2 KB JSON) so it can be
 * embedded into the LLM prompt without bloating the context window.
 */

import { getCurrentScope, onScopeDispose, ref } from 'vue'
import type { Ref } from 'vue'

import { useAppStore } from '~/stores/appStore'

import {
  MAX_CELL_LENGTH,
  MAX_VISIBLE_ROWS,
  type ChatContextCell,
  type ChatContextContribution,
  type ChatContextSelection,
  type ChatVisibleTable,
  type UiContext,
} from '#shared/uiContext'

export { MAX_CELL_LENGTH, MAX_VISIBLE_ROWS }
export type { ChatContextCell, ChatContextContribution, ChatContextSelection, ChatVisibleTable, UiContext }

/** Provider type signature: page builds its contribution lazily. */
export type ChatContextProviderFn = () => ChatContextContribution | null

interface RegisteredProvider {
  id: number
  fn: ChatContextProviderFn
}

interface ChatContextRegistry {
  providers: RegisteredProvider[]
  nextId: number
}

let providerSeq = 0

/**
 * Truncate a string cell to ``MAX_CELL_LENGTH`` characters and append
 * ``…`` when truncation occurred. Non-strings are passed through.
 */
export function truncateCell(value: ChatContextCell): ChatContextCell {
  if (typeof value !== 'string') return value
  if (value.length <= MAX_CELL_LENGTH) return value
  return value.slice(0, MAX_CELL_LENGTH - 1) + '…'
}

/**
 * Cap a row list at ``MAX_VISIBLE_ROWS`` entries and truncate long
 * string cells. Returns the result alongside the original total.
 */
export function compactRows(rows: Array<Record<string, ChatContextCell>>): {
  rows: Array<Record<string, ChatContextCell>>
  total_rows: number
  showing_rows: number
} {
  const total = rows.length
  const sliced = rows.slice(0, MAX_VISIBLE_ROWS)
  const safeRows = sliced.map((row) => {
    const out: Record<string, ChatContextCell> = {}
    for (const [k, v] of Object.entries(row)) out[k] = truncateCell(v)
    return out
  })
  return { rows: safeRows, total_rows: total, showing_rows: safeRows.length }
}

/**
 * Build a complete :class:`ChatVisibleTable` from raw rows. Helper to
 * keep page providers concise.
 */
export function makeVisibleTable(
  name: string,
  columns: string[],
  rawRows: Array<Record<string, ChatContextCell>>,
): ChatVisibleTable {
  const compacted = compactRows(rawRows)
  return { name, columns, ...compacted }
}

/**
 * Map common Quasar / Vue-Router path values to friendly titles. Used
 * when the route does not specify a ``meta.title``.
 */
const ROUTE_TITLES: Record<string, string> = {
  '/dashboard': 'Dashboard',
  '/alarms': 'Alarms',
  '/connections': 'Connections',
  '/devices': 'Assets',
  '/topology': 'Topology',
  '/management': 'Operations Overview',
  '/vulnerabilities': 'Vulnerabilities',
  '/mac-timeseries': 'MAC Traffic',
  '/proto-timeseries': 'Protocol Traffic',
  '/': 'Home',
}

function buildTimeLabel(mode: 'live' | 'manual', liveIntervalSeconds: number, start: string, stop: string): string {
  if (mode === 'live') {
    const minutes = Math.round(liveIntervalSeconds / 60)
    if (minutes >= 60) {
      const hours = Math.round(minutes / 60)
      return `Last ${hours} hour${hours === 1 ? '' : 's'} (live)`
    }
    return `Last ${minutes} minute${minutes === 1 ? '' : 's'} (live)`
  }
  return `${start.slice(0, 16)} .. ${stop.slice(0, 16)} UTC`
}

/**
 * Module-level provider registry.
 *
 * The registry holds function references which cannot be serialized
 * across the SSR/client boundary, so it deliberately does **not** use
 * Nuxt's ``useState``. Provider registration only happens on the
 * client side (during page ``setup`` after hydration); the SSR pass
 * simply sees an empty list, which is exactly what we want.
 */
const chatContextRegistry: Ref<ChatContextRegistry> = ref({
  providers: [],
  nextId: 0,
})

function useChatContextRegistry(): Ref<ChatContextRegistry> {
  return chatContextRegistry
}

/**
 * Register a page-level chat-context provider for the lifetime of the
 * current effect scope. The provider is automatically removed when the
 * page component is unmounted.
 *
 * Pages call this once during ``setup()`` and pass a closure that
 * reads the relevant Pinia stores / refs each time the snapshot is
 * built. This keeps the snapshot always up-to-date without manual
 * watchers.
 */
export function provideChatContext(fn: ChatContextProviderFn): void {
  const registry = useChatContextRegistry()
  const id = ++providerSeq
  registry.value = {
    ...registry.value,
    providers: [...registry.value.providers, { id, fn }],
  }
  if (getCurrentScope()) {
    onScopeDispose(() => {
      registry.value = {
        ...registry.value,
        providers: registry.value.providers.filter((p) => p.id !== id),
      }
    })
  }
}

/**
 * Remove all registered providers. Intended for unit tests; production
 * code relies on ``onScopeDispose``.
 */
export function __clearChatContextProviders(): void {
  chatContextRegistry.value = { providers: [], nextId: 0 }
}

/**
 * Public API: ``snapshot()`` returns the merged context for the
 * current chat-send call. ``providers`` is exposed for tests/preview.
 */
export interface UseChatContextReturn {
  snapshot: () => UiContext
  providerCount: () => number
}

/**
 * Build the global parts of the snapshot (route, app, time) that do
 * not depend on any page provider.
 */
function buildGlobalSnapshot(route: ReturnType<typeof useRoute>, app: ReturnType<typeof useAppStore>): UiContext {
  const path = route.path || '/'
  const title =
    (typeof route.meta?.title === 'string' ? route.meta.title : undefined) ??
    ROUTE_TITLES[path] ??
    path.replace('/', '').replace(/^./, (c) => c.toUpperCase()) ??
    path
  const params = app.freshApiTimeParams()
  const mode: 'live' | 'manual' = app.liveMode ? 'live' : 'manual'
  const time: UiContext['time'] = {
    mode,
    liveIntervalSeconds: mode === 'live' ? app.liveIntervalSeconds : undefined,
    start: params.start,
    stop: params.stop,
    label: buildTimeLabel(mode, app.liveIntervalSeconds, params.start, params.stop),
  }
  const query: Record<string, string> = {}
  for (const [k, v] of Object.entries(route.query ?? {})) {
    if (Array.isArray(v)) {
      const first = v[0]
      if (first != null) query[k] = String(first)
    } else if (v != null) {
      query[k] = String(v)
    }
  }
  const locale =
    typeof navigator !== 'undefined' && typeof navigator.language === 'string' ? navigator.language : 'en-US'
  return {
    app: {
      version: '0.4.0',
      locale,
      theme: app.theme as 'light' | 'dark',
      timestamp: new Date().toISOString(),
    },
    route: {
      path,
      name: typeof route.name === 'string' ? route.name : path.replace('/', '') || 'home',
      title,
      query,
    },
    time,
  }
}

/**
 * Merge a page contribution into a base snapshot. Later contributions
 * win for scalar fields; arrays/objects are concatenated/merged.
 */
function mergeContribution(base: UiContext, contrib: ChatContextContribution): UiContext {
  const next: UiContext = { ...base }
  if (contrib.selection) next.selection = contrib.selection
  if (contrib.filters) next.filters = { ...(next.filters ?? {}), ...contrib.filters }
  if (contrib.summary) next.summary = { ...(next.summary ?? {}), ...contrib.summary }
  if (contrib.widgets) next.widgets = contrib.widgets
  if (contrib.visible_data) next.visible_data = [...(next.visible_data ?? []), ...contrib.visible_data]
  if (contrib.notes) next.notes = [...(next.notes ?? []), ...contrib.notes]
  if (contrib.subagent) next.subagent = [...(next.subagent ?? []), ...contrib.subagent]
  return next
}

/**
 * Public composable for the chat overlay and tests.
 *
 * Returns a ``snapshot()`` function which assembles a fresh
 * :class:`UiContext` on every call. Page providers and the chat
 * settings toggle decide what — if anything — ends up in the
 * outgoing chat request.
 */
export function useChatContext(): UseChatContextReturn {
  const route = useRoute()
  const app = useAppStore()
  const registry = useChatContextRegistry()

  function snapshot(): UiContext {
    let ctx = buildGlobalSnapshot(route, app)
    for (const { fn } of registry.value.providers) {
      try {
        const contrib = fn()
        if (contrib) ctx = mergeContribution(ctx, contrib)
      } catch {
        /* a faulty provider must never break chat sending */
      }
    }
    return ctx
  }

  return {
    snapshot,
    providerCount: () => registry.value.providers.length,
  }
}
