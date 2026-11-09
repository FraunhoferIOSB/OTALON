/**
 * Unit tests for the chat-context composable.
 *
 * Verifies provider registration/teardown, snapshot merging, the
 * global frame data (route + app + time), and the ``compactRows``
 * helper.
 */
import { effectScope, nextTick } from 'vue'
import { beforeEach, describe, expect, it } from 'vitest'

import {
  __clearChatContextProviders,
  compactRows,
  makeVisibleTable,
  MAX_CELL_LENGTH,
  MAX_VISIBLE_ROWS,
  provideChatContext,
  truncateCell,
  useChatContext,
} from '~/composables/useChatContext'
import { useAppStore } from '~/stores/appStore'
import { createTestingPinia } from '@pinia/testing'

// Mock useRoute / useState are provided via tests/mocks/nuxt-imports.ts.

describe('useChatContext', () => {
  beforeEach(() => {
    __clearChatContextProviders()
    createTestingPinia({ stubActions: false })
  })

  it('returns a base snapshot with route, app and time fields', () => {
    const app = useAppStore()
    app.theme = 'dark'
    app.liveMode = true
    app.liveIntervalSeconds = 3600

    const { snapshot } = useChatContext()
    const ctx = snapshot()

    expect(ctx.route.path).toBeTypeOf('string')
    expect(ctx.app.theme).toBe('dark')
    expect(ctx.time.mode).toBe('live')
    expect(ctx.time.liveIntervalSeconds).toBe(3600)
    expect(ctx.time.label).toContain('1 hour')
  })

  it('time.label uses minutes for short live windows', () => {
    const app = useAppStore()
    app.liveMode = true
    app.liveIntervalSeconds = 600

    const { snapshot } = useChatContext()
    const ctx = snapshot()
    expect(ctx.time.label).toContain('10 minutes')
  })

  it('merges page provider contributions into the snapshot', () => {
    const { snapshot } = useChatContext()

    provideChatContext(() => ({
      summary: { foo: 'bar', count: 7 },
      filters: { status: 'active' },
      widgets: { visible: ['a', 'b'], hidden: ['c'] },
      selection: { kind: 'alarm', id: '123' },
    }))

    const ctx = snapshot()
    expect(ctx.summary).toEqual({ foo: 'bar', count: 7 })
    expect(ctx.filters).toEqual({ status: 'active' })
    expect(ctx.widgets).toEqual({ visible: ['a', 'b'], hidden: ['c'] })
    expect(ctx.selection?.id).toBe('123')
  })

  it('merges multiple providers in registration order', () => {
    provideChatContext(() => ({ summary: { a: 1, both: 'first' } }))
    provideChatContext(() => ({ summary: { b: 2, both: 'second' } }))

    const ctx = useChatContext().snapshot()
    expect(ctx.summary).toEqual({ a: 1, b: 2, both: 'second' })
  })

  it('removes provider when its scope is disposed', async () => {
    const scope = effectScope()
    scope.run(() => {
      provideChatContext(() => ({ summary: { ephemeral: 1 } }))
    })

    const ctxBefore = useChatContext().snapshot()
    expect(ctxBefore.summary).toEqual({ ephemeral: 1 })

    scope.stop()
    await nextTick()

    const ctxAfter = useChatContext().snapshot()
    expect(ctxAfter.summary).toBeUndefined()
  })

  it('is robust against faulty providers', () => {
    provideChatContext(() => {
      throw new Error('boom')
    })
    provideChatContext(() => ({ summary: { ok: true } }))

    const ctx = useChatContext().snapshot()
    expect(ctx.summary).toEqual({ ok: true })
  })

  it('truncateCell shortens strings longer than MAX_CELL_LENGTH', () => {
    const long = 'x'.repeat(MAX_CELL_LENGTH + 10)
    const out = truncateCell(long)
    expect(typeof out).toBe('string')
    expect((out as string).length).toBeLessThanOrEqual(MAX_CELL_LENGTH)
    expect((out as string).endsWith('…')).toBe(true)
  })

  it('compactRows caps at MAX_VISIBLE_ROWS and reports totals', () => {
    const rows = Array.from({ length: 12 }, (_, i) => ({ id: `r${i}` }))
    const result = compactRows(rows)
    expect(result.total_rows).toBe(12)
    expect(result.showing_rows).toBe(MAX_VISIBLE_ROWS)
    expect(result.rows.length).toBe(MAX_VISIBLE_ROWS)
  })

  it('makeVisibleTable produces a complete ChatVisibleTable', () => {
    const t = makeVisibleTable('demo', ['id'], [{ id: 'a' }, { id: 'b' }, { id: 'c' }])
    expect(t.name).toBe('demo')
    expect(t.columns).toEqual(['id'])
    expect(t.total_rows).toBe(3)
    expect(t.showing_rows).toBe(3)
    expect(t.rows).toEqual([{ id: 'a' }, { id: 'b' }, { id: 'c' }])
  })
})
