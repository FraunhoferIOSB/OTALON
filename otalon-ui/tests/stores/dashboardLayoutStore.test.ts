import { describe, it, expect, beforeEach, vi } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'
import { http, HttpResponse } from 'msw'

import { useDashboardLayoutStore } from '~/stores/dashboardLayoutStore'
import { DEFAULT_LAYOUT } from '~/components/dashboard/widgets/registry'
import { errorHandlers } from '../mocks/handlers'
import { server } from '../mocks/server'

const STORAGE_KEY = 'otalon:dashboard-layout:v2'

describe('dashboardLayoutStore', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    vi.stubGlobal('localStorage', {
      store: {} as Record<string, string>,
      getItem(key: string) {
        return this.store[key] ?? null
      },
      setItem(key: string, value: string) {
        this.store[key] = value
      },
      removeItem(key: string) {
        this.store[key] = undefined as unknown as string
      },
      clear() {
        this.store = {}
      },
    })
  })

  it('fresh load uses DEFAULT_LAYOUT with empty hidden', async () => {
    const store = useDashboardLayoutStore()
    await store.load()

    expect(store.layout).toEqual(DEFAULT_LAYOUT)
    expect(store.hidden).toEqual([])
  })

  it('corrupt JSON falls back to default without throwing', async () => {
    localStorage.setItem(STORAGE_KEY, 'not-json')
    const store = useDashboardLayoutStore()
    await expect(store.load()).resolves.not.toThrow()
    expect(store.layout).toEqual(DEFAULT_LAYOUT)
    expect(store.hidden).toEqual([])
  })

  it('version mismatch falls back to default', async () => {
    localStorage.setItem(STORAGE_KEY, JSON.stringify({ version: 0, layout: [], hidden: [] }))
    const store = useDashboardLayoutStore()
    await store.load()

    expect(store.layout).toEqual(DEFAULT_LAYOUT)
    expect(store.hidden).toEqual([])
  })

  it('v1 payload in localStorage resets to default layout', async () => {
    localStorage.setItem(
      STORAGE_KEY,
      JSON.stringify({ version: 1, layout: [{ i: 'signal', x: 0, y: 0, w: 1, h: 1 }], hidden: [] }),
    )
    const store = useDashboardLayoutStore()
    await store.load()

    expect(store.layout).toEqual(DEFAULT_LAYOUT)
    expect(store.hidden).toEqual([])
  })

  it('reconciliation drops unknown ids and appends missing defaults', async () => {
    const stored = [
      { i: 'signal', x: 0, y: 0, w: 2, h: 1 },
      { i: 'ghost', x: 0, y: 0, w: 2, h: 1 },
    ]
    localStorage.setItem(STORAGE_KEY, JSON.stringify({ version: 2, layout: stored, hidden: [] }))
    const store = useDashboardLayoutStore()
    await store.load()

    const ids = store.layout.map((item) => item.i)
    expect(ids).not.toContain('ghost')
    expect(ids).toContain('serviceHealth')
  })

  it('clamps out-of-bounds dimensions and positions to 8 cols', async () => {
    localStorage.setItem(
      STORAGE_KEY,
      JSON.stringify({
        version: 2,
        layout: [{ i: 'signal', x: 7, y: 0, w: 9, h: 1 }],
        hidden: [],
      }),
    )
    const store = useDashboardLayoutStore()
    await store.load()

    const signal = store.layout.find((item) => item.i === 'signal')
    expect(signal).toBeDefined()
    expect(signal!.w).toBe(8)
    expect(signal!.x).toBe(0)
  })

  it('clamp respects registry minimums', async () => {
    localStorage.setItem(
      STORAGE_KEY,
      JSON.stringify({
        version: 2,
        layout: [
          { i: 'topConnections', x: 0, y: 0, w: 1, h: 1 },
          { i: 'throughput', x: 0, y: 1, w: 2, h: 1 },
        ],
        hidden: [],
      }),
    )
    const store = useDashboardLayoutStore()
    await store.load()

    const tc = store.layout.find((item) => item.i === 'topConnections')
    expect(tc).toBeDefined()
    expect(tc!.w).toBe(2)
    expect(tc!.h).toBe(2)

    const th = store.layout.find((item) => item.i === 'throughput')
    expect(th).toBeDefined()
    expect(th!.w).toBe(4)
    expect(th!.h).toBe(1)
  })

  describe('backend sync', () => {
    it('load prefers backend payload over localStorage', async () => {
      const remote = {
        version: 2,
        layout: [{ i: 'signal', x: 4, y: 4, w: 2, h: 1 }],
        hidden: ['recentAlarms'],
      }
      server.use(
        http.get('*/api/v1/dashboard/layout', () => {
          return HttpResponse.json(remote)
        }),
      )
      localStorage.setItem(
        STORAGE_KEY,
        JSON.stringify({ version: 2, layout: [{ i: 'signal', x: 0, y: 0, w: 1, h: 1 }], hidden: [] }),
      )

      const store = useDashboardLayoutStore()
      await store.load()

      const signal = store.layout.find((item) => item.i === 'signal')
      expect(signal).toBeDefined()
      expect(signal!.x).toBe(4)
      expect(store.hidden).toEqual(['recentAlarms'])
    })

    it('load falls back to localStorage when backend returns 404', async () => {
      server.use(
        http.get('*/api/v1/dashboard/layout', () => {
          return HttpResponse.json({ detail: 'No dashboard layout saved' }, { status: 404 })
        }),
      )
      localStorage.setItem(
        STORAGE_KEY,
        JSON.stringify({ version: 2, layout: [{ i: 'signal', x: 1, y: 1, w: 2, h: 1 }], hidden: ['assets'] }),
      )

      const store = useDashboardLayoutStore()
      await store.load()

      const signal = store.layout.find((item) => item.i === 'signal')
      expect(signal).toBeDefined()
      expect(signal!.x).toBe(1)
      expect(store.hidden).toEqual(['assets'])
    })

    it('load falls back to localStorage on backend error', async () => {
      server.use(errorHandlers.layoutGet500)
      localStorage.setItem(
        STORAGE_KEY,
        JSON.stringify({ version: 2, layout: [{ i: 'signal', x: 2, y: 2, w: 2, h: 2 }], hidden: [] }),
      )

      const store = useDashboardLayoutStore()
      await store.load()

      const signal = store.layout.find((item) => item.i === 'signal')
      expect(signal).toBeDefined()
      expect(signal!.x).toBe(2)
    })

    it('load does nothing in SSR environment', async () => {
      const originalWindow = globalThis.window
      // @ts-expect-error simulate SSR by removing window
      globalThis.window = undefined
      try {
        const store = useDashboardLayoutStore()
        await expect(store.load()).resolves.not.toThrow()
        expect(store.layout).toEqual(DEFAULT_LAYOUT)
      } finally {
        globalThis.window = originalWindow
      }
    })

    it('persist writes to backend and localStorage', async () => {
      let capturedBody: unknown = null
      server.use(
        http.put('*/api/v1/dashboard/layout', async ({ request }) => {
          capturedBody = await request.json()
          return HttpResponse.json(capturedBody)
        }),
      )

      const store = useDashboardLayoutStore()
      await store.load()
      store.setVisibility('signal', false)
      // Wait for the debounced persist plus async backend call.
      await new Promise((resolve) => setTimeout(resolve, 700))

      const raw = localStorage.getItem(STORAGE_KEY)
      expect(raw).toBeTruthy()
      const local = JSON.parse(raw!)
      expect(local.hidden).toContain('signal')
      expect(capturedBody).toEqual({ version: 2, layout: store.layout, hidden: ['signal'] })
    })

    it('persist keeps localStorage when backend fails', async () => {
      server.use(errorHandlers.layoutPut500)

      const store = useDashboardLayoutStore()
      await store.load()
      store.setVisibility('signal', false)
      await new Promise((resolve) => setTimeout(resolve, 700))

      const raw = localStorage.getItem(STORAGE_KEY)
      expect(raw).toBeTruthy()
      const local = JSON.parse(raw!)
      expect(local.hidden).toContain('signal')
    })
  })

  it('setVisibility hides widget and preserves geometry', async () => {
    const store = useDashboardLayoutStore()
    await store.load()
    const originalLayout = [...store.layout]

    store.setVisibility('signal', false)
    expect(store.hidden).toContain('signal')
    expect(store.layout).toEqual(originalLayout)
    expect(store.isVisible('signal')).toBe(false)

    store.setVisibility('signal', true)
    expect(store.hidden).not.toContain('signal')
    expect(store.isVisible('signal')).toBe(true)
  })

  it('resetToDefault restores default layout and clears hidden', async () => {
    const store = useDashboardLayoutStore()
    await store.load()
    store.setVisibility('signal', false)
    store.updateLayout([{ i: 'signal', x: 2, y: 2, w: 2, h: 2 }])

    store.resetToDefault()
    expect(store.layout).toEqual(DEFAULT_LAYOUT)
    expect(store.hidden).toEqual([])
  })

  it('updateLayout with identical geometry is a no-op (loop guard)', async () => {
    const store = useDashboardLayoutStore()
    await store.load()
    const before = store.layout
    // Feed back the exact current geometry, as grid-layout-plus does on mount.
    store.updateLayout(store.layout.map((item) => ({ ...item })))
    // Same array identity → dependent getters/watchers do not re-fire.
    expect(store.layout).toBe(before)
  })

  it('updateLayout with a real move reassigns and clamps to 8 cols', async () => {
    const store = useDashboardLayoutStore()
    await store.load()
    const before = store.layout
    store.updateLayout([{ i: 'signal', x: 9, y: 1, w: 2, h: 2 }])
    expect(store.layout).not.toBe(before)
    const signal = store.layout.find((item) => item.i === 'signal')
    expect(signal).toBeDefined()
    expect(signal!.w).toBe(2)
    expect(signal!.x).toBe(6)
    expect(signal!.y).toBe(1)
  })

  it('persist writes versioned payload to localStorage', async () => {
    const store = useDashboardLayoutStore()
    await store.load()
    store.setVisibility('signal', false)

    const raw = localStorage.getItem(STORAGE_KEY)
    expect(raw).toBeTruthy()
    const parsed = JSON.parse(raw!)
    expect(parsed.version).toBe(2)
    expect(parsed.hidden).toContain('signal')
    expect(parsed.layout).toEqual(store.layout)
  })
})
