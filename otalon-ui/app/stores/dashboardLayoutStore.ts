import { defineStore } from 'pinia'
import { DEFAULT_LAYOUT, WIDGET_REGISTRY, type WidgetLayoutItem } from '~/components/dashboard/widgets/registry'

const STORAGE_KEY = 'otalon:dashboard-layout:v2'

interface PersistedPayload {
  version: number
  layout: WidgetLayoutItem[]
  hidden: string[]
}

/**
 * Deep-clone a layout item array.
 */
function cloneLayout(layout: WidgetLayoutItem[]): WidgetLayoutItem[] {
  return layout.map((item) => ({ ...item }))
}

/**
 * Reconcile stored layout against the current widget registry.
 *
 * Drops unknown ids, appends missing registry ids below the last row,
 * and clamps every entry to bounds.
 */
function reconcileLayout(stored: WidgetLayoutItem[]): WidgetLayoutItem[] {
  const known = new Set(Object.keys(WIDGET_REGISTRY))
  const filtered = stored.filter((item) => known.has(item.i))

  const maxY = filtered.reduce((m, item) => Math.max(m, item.y + item.h), 0)
  const presentIds = new Set(filtered.map((item) => item.i))
  const appended: WidgetLayoutItem[] = []

  for (const id of Object.keys(WIDGET_REGISTRY)) {
    if (presentIds.has(id)) continue
    const def = DEFAULT_LAYOUT.find((d) => d.i === id)
    appended.push({ ...(def ?? { i: id, x: 0, y: maxY, w: 1, h: 1 }) })
  }

  return [...filtered, ...appended].map(clampItem)
}

/**
 * Clamp a layout item to grid constraints.
 */
function clampItem(item: WidgetLayoutItem): WidgetLayoutItem {
  const def = WIDGET_REGISTRY[item.i]
  const minW = def?.minW ?? 1
  const minH = def?.minH ?? 1
  const w = Math.min(8, Math.max(minW, item.w))
  const h = Math.min(8, Math.max(minH, item.h))
  const x = Math.min(8 - w, Math.max(0, item.x))
  const y = Math.max(0, item.y)
  return { i: item.i, x, y, w, h }
}

/**
 * Compare two layouts for geometric equality (id, x, y, w, h).
 *
 * Used to make layout updates idempotent so a `layout-updated` event that
 * reports no positional change does not trigger a fresh store write (which
 * would feed back into the grid and loop indefinitely).
 */
function sameGeometry(a: WidgetLayoutItem[], b: WidgetLayoutItem[]): boolean {
  if (a.length !== b.length) return false
  const index = new Map(b.map((item) => [item.i, item]))
  for (const item of a) {
    const other = index.get(item.i)
    if (!other) return false
    if (other.x !== item.x || other.y !== item.y || other.w !== item.w || other.h !== item.h) {
      return false
    }
  }
  return true
}

export interface DashboardLayoutState {
  layout: WidgetLayoutItem[]
  hidden: string[]
  editMode: boolean
}

let persistTimer: ReturnType<typeof setTimeout> | null = null

/**
 * Pinia store for dashboard grid layout and widget visibility.
 *
 * Persists to localStorage with a versioned schema and reconciles
 * on load so widget additions/removals do not corrupt stored layouts.
 */
export const useDashboardLayoutStore = defineStore('dashboardLayout', {
  state: (): DashboardLayoutState => ({
    layout: cloneLayout(DEFAULT_LAYOUT),
    hidden: [],
    editMode: false,
  }),

  getters: {
    /**
     * Layout items that are not hidden.
     */
    visibleLayout(state): WidgetLayoutItem[] {
      const hiddenSet = new Set(state.hidden)
      return state.layout.filter((item) => !hiddenSet.has(item.i))
    },

    /**
     * Check whether a widget id is currently visible.
     *
     * @param id - Widget identifier.
     * @returns `true` when the widget is not in the hidden list.
     */
    isVisible(state): (id: string) => boolean {
      const hiddenSet = new Set(state.hidden)
      return (id: string) => !hiddenSet.has(id)
    },
  },

  actions: {
    /**
     * Load layout from the backend, falling back to localStorage and
     * finally to the default layout.
     *
     * Reconciles unknown ids and clamps bounds on every load.
     */
    async load(): Promise<void> {
      if (typeof window === 'undefined') return
      try {
        const remote = await $fetch<PersistedPayload>('/api/v1/dashboard/layout')
        if (remote && remote.version === 2 && Array.isArray(remote.layout) && Array.isArray(remote.hidden)) {
          const known = new Set(Object.keys(WIDGET_REGISTRY))
          this.layout = reconcileLayout(remote.layout)
          this.hidden = remote.hidden.filter((id) => known.has(id))
          this.writeLocalStorage()
          return
        }
      } catch {
        /* fall through to localStorage fallback */
      }

      try {
        const raw = localStorage.getItem(STORAGE_KEY)
        if (raw) {
          const parsed = JSON.parse(raw) as PersistedPayload
          if (parsed.version === 2 && Array.isArray(parsed.layout) && Array.isArray(parsed.hidden)) {
            const known = new Set(Object.keys(WIDGET_REGISTRY))
            this.layout = reconcileLayout(parsed.layout)
            this.hidden = parsed.hidden.filter((id) => known.has(id))
            return
          }
        }
      } catch {
        /* fall through to default */
      }
      this.layout = cloneLayout(DEFAULT_LAYOUT)
      this.hidden = []
    },

    /**
     * Write the current layout and hidden list to localStorage.
     */
    writeLocalStorage(): void {
      if (typeof window === 'undefined') return
      try {
        const payload: PersistedPayload = {
          version: 2,
          layout: this.layout,
          hidden: this.hidden,
        }
        localStorage.setItem(STORAGE_KEY, JSON.stringify(payload))
      } catch {
        /* ignore quota errors */
      }
    },

    /**
     * Persist current layout and hidden list to the backend and to
     * localStorage as an offline fallback.
     */
    async persist(): Promise<void> {
      if (typeof window === 'undefined') return
      this.writeLocalStorage()
      try {
        const payload: PersistedPayload = {
          version: 2,
          layout: this.layout,
          hidden: this.hidden,
        }
        await $fetch<PersistedPayload>('/api/v1/dashboard/layout', {
          method: 'PUT',
          body: payload,
        })
      } catch {
        /* backend is optional; localStorage already holds the fallback */
      }
    },

    /**
     * Replace layout entries for the provided ids and debounce persist.
     *
     * @param next - New layout items (may be a subset during drag/resize).
     */
    updateLayout(next: WidgetLayoutItem[]): void {
      const updatedIds = new Set(next.map((n) => n.i))
      const merged = this.layout.map((item) => {
        const replacement = next.find((n) => n.i === item.i)
        return replacement ? clampItem(replacement) : item
      })
      // Append any ids that were not already in layout (safety net)
      for (const n of next) {
        if (!updatedIds.has(n.i)) continue
        if (!this.layout.some((item) => item.i === n.i)) {
          merged.push(clampItem(n))
        }
      }
      // Idempotency guard: a `layout-updated` event that carries no positional
      // change (e.g. the grid's own normalization on mount) must not reassign
      // `this.layout`. Reassigning a fresh array would recompute `visibleLayout`,
      // re-fire the component watcher, mutate the `v-model:layout` prop and make
      // the grid emit `layout-updated` again, looping forever.
      if (sameGeometry(this.layout, merged)) return
      this.layout = merged
      if (persistTimer) clearTimeout(persistTimer)
      persistTimer = setTimeout(() => this.persist(), 500)
    },

    /**
     * Show or hide a widget by id.
     *
     * Geometry is preserved in the layout array while hidden.
     *
     * @param id - Widget identifier.
     * @param visible - `true` to show, `false` to hide.
     */
    setVisibility(id: string, visible: boolean): void {
      if (visible) {
        this.hidden = this.hidden.filter((h) => h !== id)
      } else if (!this.hidden.includes(id)) {
        this.hidden.push(id)
      }
      this.persist()
    },

    /**
     * Restore the default layout and clear hidden widgets.
     */
    resetToDefault(): void {
      this.layout = cloneLayout(DEFAULT_LAYOUT)
      this.hidden = []
      this.persist()
    },

    /**
     * Toggle edit mode for the dashboard grid.
     */
    toggleEditMode(): void {
      this.editMode = !this.editMode
    },
  },
})
