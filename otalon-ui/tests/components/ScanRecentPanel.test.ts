/**
 * Unit tests for the ScanRecentPanel component.
 *
 * Validates the happy-path render (list of scans), the upstream-404 graceful
 * state ("Scan listing not available yet"), the empty-list state, single delete,
 * bulk delete, selection mechanics, pagination, and live refresh from the global
 * job-notification store. Uses MSW to stub ``GET /api/v1/scans`` and
 * ``DELETE /api/v1/scans``.
 */
import { afterEach, describe, expect, it, vi } from 'vitest'
import { flushPromises } from '@vue/test-utils'
import { http, HttpResponse } from 'msw'

import { mountWithPlugins } from '../helpers/mount'
import { server } from '../mocks/server'

const notifyMock = vi.fn()
const dialogMock = vi.fn()

vi.mock('quasar', () => ({
  useQuasar: () => ({
    dark: { isActive: false },
    notify: notifyMock,
    dialog: dialogMock,
  }),
}))

const ScanRecentPanel = (await import('~/components/scan/ScanRecentPanel.vue')).default
const { useJobNotificationsStore } = await import('~/stores/jobNotificationsStore')

function mockList() {
  return http.get('*/api/v1/scans', () =>
    HttpResponse.json({
      scans: [
        {
          scan_id: 'scan-1',
          module: 'arp_scan',
          status: 'completed',
          started_at: new Date(Date.now() - 60_000).toISOString(),
        },
        {
          scan_id: 'scan-2',
          module: 'port_scan',
          status: 'running',
          started_at: new Date(Date.now() - 5_000).toISOString(),
        },
      ],
    }),
  )
}

describe('ScanRecentPanel', () => {
  beforeEach(() => {
    dialogMock.mockImplementation(() => {
      let okCb: (() => void) | undefined
      return {
        onOk: vi.fn((cb: () => void) => {
          okCb = cb
          return { onOk: vi.fn(), onCancel: vi.fn(), onDismiss: vi.fn() }
        }),
        onCancel: vi.fn(),
        onDismiss: vi.fn(),
        __triggerOk: () => okCb?.(),
      }
    })
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('renders the scan list when the upstream returns a payload', async () => {
    server.use(mockList())

    const wrapper = mountWithPlugins(ScanRecentPanel)
    await flushPromises()

    const list = wrapper.find('[data-testid="recent-scans-list"]')
    expect(list.exists()).toBe(true)
    const labels = wrapper.findAll('[data-testid="recent-scans-row-label"]').map((n) => n.text())
    expect(labels.some((t) => t.startsWith('arp'))).toBe(true)
    expect(labels.some((t) => t.startsWith('port'))).toBe(true)
    expect(list.text()).toContain('scan-1')
    expect(list.text()).toContain('scan-2')
  })

  it('accepts a bare-array response shape (forward-compat normalisation)', async () => {
    server.use(
      http.get('*/api/v1/scans', () =>
        HttpResponse.json([
          {
            scan_id: 'scan-only',
            module: 'snmp_scan',
            status: 'completed',
            started_at: new Date().toISOString(),
          },
        ]),
      ),
    )

    const wrapper = mountWithPlugins(ScanRecentPanel)
    await flushPromises()

    const label = wrapper.find('[data-testid="recent-scans-row-label"]')
    expect(label.text()).toContain('snmp')
    expect(wrapper.text()).toContain('scan-only')
  })

  it('renders the unavailable state on upstream 404', async () => {
    server.use(http.get('*/api/v1/scans', () => HttpResponse.json({ detail: 'not implemented' }, { status: 404 })))

    const wrapper = mountWithPlugins(ScanRecentPanel)
    await flushPromises()

    const empty = wrapper.find('[data-testid="recent-scans-empty-state"]')
    expect(empty.exists()).toBe(true)
    expect(empty.text()).toContain('Scan listing not available yet')
  })

  it('refresh() exposes a callable handle that re-fetches the list', async () => {
    let calls = 0
    server.use(
      http.get('*/api/v1/scans', () => {
        calls += 1
        return HttpResponse.json({ scans: [] })
      }),
    )

    const wrapper = mountWithPlugins(ScanRecentPanel)
    await flushPromises()
    expect(calls).toBe(1)

    const refresh = (wrapper.vm as unknown as { refresh: () => Promise<void> }).refresh
    expect(typeof refresh).toBe('function')
    await refresh()
    await flushPromises()

    expect(calls).toBe(2)
  })

  // ── Pagination (F-13) ────────────────────────────────────────────────

  describe('pagination', () => {
    it('requests offset based on current page', async () => {
      let capturedParams: Record<string, unknown> | null = null
      server.use(
        http.get('*/api/v1/scans', ({ request }) => {
          const url = new URL(request.url)
          capturedParams = Object.fromEntries(url.searchParams)
          return HttpResponse.json({
            scans: Array.from({ length: 10 }, (_, i) => ({
              scan_id: `scan-${i}`,
              module: 'arp_scan',
              status: 'completed',
              started_at: new Date().toISOString(),
            })),
          })
        }),
      )

      const wrapper = mountWithPlugins(ScanRecentPanel)
      await flushPromises()

      expect(capturedParams).not.toBeNull()
      expect(capturedParams!.limit).toBe('10')
      expect(capturedParams!.offset).toBe('0')

      const nextBtn = wrapper.find('[data-testid="recent-scans-next-btn"]')
      expect(nextBtn.exists()).toBe(true)
      await nextBtn.trigger('click')
      await flushPromises()

      expect(capturedParams!.offset).toBe('10')
      expect(wrapper.find('[data-testid="recent-scans-page-label"]').text()).toBe('Page 2')
    })

    it('does not advance page when fewer than limit rows are returned', async () => {
      let calls = 0
      server.use(
        http.get('*/api/v1/scans', () => {
          calls += 1
          return HttpResponse.json({
            scans: [
              {
                scan_id: 'scan-1',
                module: 'arp_scan',
                status: 'completed',
                started_at: new Date().toISOString(),
              },
            ],
          })
        }),
      )

      const wrapper = mountWithPlugins(ScanRecentPanel)
      await flushPromises()
      expect(calls).toBe(1)

      const nextBtn = wrapper.find('[data-testid="recent-scans-next-btn"]')
      await nextBtn.trigger('click')
      await flushPromises()

      expect(calls).toBe(1)
      expect(wrapper.find('[data-testid="recent-scans-page-label"]').text()).toBe('Page 1')
    })

    it('does not go below page 1', async () => {
      server.use(mockList())

      const wrapper = mountWithPlugins(ScanRecentPanel)
      await flushPromises()

      const prevBtn = wrapper.find('[data-testid="recent-scans-prev-btn"]')
      await prevBtn.trigger('click')
      await flushPromises()

      expect(wrapper.find('[data-testid="recent-scans-page-label"]').text()).toBe('Page 1')
    })
  })

  // ── Live refresh (F-02 / F-08) ───────────────────────────────────────

  describe('live refresh', () => {
    it('refreshes when a scan job notification arrives in the global store', async () => {
      let calls = 0
      server.use(
        http.get('*/api/v1/scans', () => {
          calls += 1
          return HttpResponse.json({
            scans: [
              {
                scan_id: 'scan-live',
                module: 'arp_scan',
                status: calls === 1 ? 'running' : 'completed',
                started_at: new Date().toISOString(),
              },
            ],
          })
        }),
      )

      const wrapper = mountWithPlugins(ScanRecentPanel)
      await flushPromises()
      expect(calls).toBe(1)

      const store = useJobNotificationsStore()
      store.$patch({
        pending: [
          {
            id: 'scan:scan-live',
            kind: 'scan',
            jobId: 'scan-live',
            status: 'completed',
            title: 'Scan completed',
            message: 'Done',
            timestamp: Date.now(),
            shown: false,
          },
        ],
      })

      await flushPromises()
      expect(calls).toBe(2)

      const label = wrapper.find('[data-testid="recent-scans-row-label"]')
      expect(label.text()).toContain('arp')
    })

    it('does not refresh on lookup job notifications', async () => {
      let calls = 0
      server.use(
        http.get('*/api/v1/scans', () => {
          calls += 1
          return HttpResponse.json({ scans: [] })
        }),
      )

      mountWithPlugins(ScanRecentPanel)
      await flushPromises()
      expect(calls).toBe(1)

      const store = useJobNotificationsStore()
      store.$patch({
        pending: [
          {
            id: 'lookup:job-1',
            kind: 'lookup',
            jobId: 'job-1',
            status: 'completed',
            title: 'CVE Lookup completed',
            message: 'Done',
            timestamp: Date.now(),
            shown: false,
          },
        ],
      })

      await flushPromises()
      expect(calls).toBe(1)
    })
  })

  // ── Delete ───────────────────────────────────────────────────────────

  describe('delete', () => {
    it('calls DELETE and notifies on successful single delete', async () => {
      let deleteCalled = false
      server.use(
        mockList(),
        http.delete('*/api/v1/scans/scan-1', () => {
          deleteCalled = true
          return new HttpResponse(null, { status: 204 })
        }),
      )

      const wrapper = mountWithPlugins(ScanRecentPanel)
      await flushPromises()

      const deleteBtn = wrapper.findAll('[data-testid="recent-scans-row-delete-btn"]')[0]
      await deleteBtn.trigger('click')
      await flushPromises()

      const dlg = dialogMock.mock.results[0].value as { __triggerOk: () => void }
      dlg.__triggerOk()
      await flushPromises()
      await flushPromises()

      expect(deleteCalled).toBe(true)
      expect(notifyMock).toHaveBeenCalledWith(expect.objectContaining({ type: 'positive', message: 'Scan deleted' }))
    })

    it('shows a bulk toolbar when a row is selected', async () => {
      server.use(mockList())

      const wrapper = mountWithPlugins(ScanRecentPanel)
      await flushPromises()

      expect(wrapper.find('[data-testid="recent-scans-bulk-delete-btn"]').exists()).toBe(false)

      const checkbox = wrapper.findAll('[data-testid="recent-scans-row-checkbox"]')[0]
      await checkbox.find('input').setValue(true)
      await flushPromises()

      expect(wrapper.find('[data-testid="recent-scans-bulk-delete-btn"]').exists()).toBe(true)
      expect(wrapper.text()).toContain('1 selected')
    })

    it('calls bulk DELETE and notifies on success', async () => {
      let deleteBody: { ids: string[] } | null = null
      server.use(
        mockList(),
        http.delete('*/api/v1/scans', async ({ request }) => {
          deleteBody = (await request.json()) as { ids: string[] }
          return HttpResponse.json({ deleted: deleteBody.ids, not_found: [] })
        }),
      )

      const wrapper = mountWithPlugins(ScanRecentPanel)
      await flushPromises()

      const checkboxes = wrapper.findAll('[data-testid="recent-scans-row-checkbox"]')
      await checkboxes[0].find('input').setValue(true)
      await checkboxes[1].find('input').setValue(true)
      await flushPromises()

      const bulkDeleteBtn = wrapper.find('[data-testid="recent-scans-bulk-delete-btn"]')
      await bulkDeleteBtn.trigger('click')
      await flushPromises()

      const dlg = dialogMock.mock.results[1].value as { __triggerOk: () => void }
      dlg.__triggerOk()
      await flushPromises()
      await flushPromises()

      expect(deleteBody).not.toBeNull()
      expect(deleteBody!.ids).toContain('scan-1')
      expect(deleteBody!.ids).toContain('scan-2')
      expect(notifyMock).toHaveBeenCalledWith(expect.objectContaining({ type: 'positive', message: '2 deleted' }))
    })

    it('clears selection when clear button is clicked', async () => {
      server.use(mockList())

      const wrapper = mountWithPlugins(ScanRecentPanel)
      await flushPromises()

      const checkbox = wrapper.findAll('[data-testid="recent-scans-row-checkbox"]')[0]
      await checkbox.find('input').setValue(true)
      await flushPromises()

      expect(wrapper.find('[data-testid="recent-scans-bulk-delete-btn"]').exists()).toBe(true)

      await wrapper.find('[data-testid="recent-scans-bulk-clear-btn"]').trigger('click')
      await flushPromises()

      expect(wrapper.find('[data-testid="recent-scans-bulk-delete-btn"]').exists()).toBe(false)
    })
  })
})
