/**
 * Unit tests for ScanDetailModal (L-02: findings in past-scan detail).
 *
 * Validates that a past scan's persisted ``findings`` snapshot is rendered as
 * a result section (not just metadata), the empty-findings state, and the
 * legacy no-snapshot state. Uses MSW to stub ``GET /api/v1/scans/{id}``.
 */
import { describe, expect, it } from 'vitest'
import { flushPromises } from '@vue/test-utils'
import { http, HttpResponse } from 'msw'

import { mountWithPlugins } from '../helpers/mount'
import { server } from '../mocks/server'

const ScanDetailModal = (await import('~/components/scan/ScanDetailModal.vue')).default

async function mountDetail(scanId = 'scan-pn') {
  // The modal's open-watcher is not immediate (the real app keeps it mounted
  // and toggles ``modelValue``), so mount closed then open to trigger the
  // detail fetch.
  const wrapper = mountWithPlugins(ScanDetailModal, {
    props: { modelValue: false, scanId },
  })
  await wrapper.setProps({ modelValue: true })
  await flushPromises()
  return wrapper
}

describe('ScanDetailModal', () => {
  it('renders persisted findings for a past scan (L-02)', async () => {
    server.use(
      http.get('*/api/v1/scans/scan-pn', () =>
        HttpResponse.json({
          scan_id: 'scan-pn',
          module: 'pn_discovery',
          status: 'completed',
          started_at: '2026-06-28T11:00:00Z',
          finished_at: '2026-06-28T11:00:04Z',
          findings: [
            { ipv4: '192.168.0.1', mac: '30:b8:51:31:06:84', vendor: 'Siemens' },
            { ipv4: '192.168.0.10', mac: 'a8:74:1d:18:c6:96', vendor: 'PHOENIX CONTACT' },
          ],
        }),
      ),
    )

    const wrapper = await mountDetail()
    await flushPromises()

    expect(wrapper.find('[data-testid="scan-detail-findings"]').exists()).toBe(true)
    expect(wrapper.text()).toContain('192.168.0.1')
    expect(wrapper.text()).toContain('Siemens')
    expect(wrapper.find('[data-testid="scan-detail-no-findings"]').exists()).toBe(false)
  })

  it('shows a no-findings note when the scan recorded an empty snapshot', async () => {
    server.use(
      http.get('*/api/v1/scans/scan-empty', () =>
        HttpResponse.json({
          scan_id: 'scan-empty',
          module: 'arp_scan',
          status: 'completed',
          started_at: '2026-06-28T11:00:00Z',
          finished_at: '2026-06-28T11:00:18Z',
          findings: [],
        }),
      ),
    )

    const wrapper = await mountDetail('scan-empty')
    await flushPromises()

    expect(wrapper.find('[data-testid="scan-detail-no-findings"]').exists()).toBe(true)
    expect(wrapper.find('[data-testid="scan-detail-findings"]').exists()).toBe(false)
  })

  it('omits the findings section for a legacy scan without a snapshot', async () => {
    server.use(
      http.get('*/api/v1/scans/scan-legacy', () =>
        HttpResponse.json({
          scan_id: 'scan-legacy',
          module: 'arp_scan',
          status: 'completed',
          started_at: '2026-06-28T11:00:00Z',
          finished_at: '2026-06-28T11:00:18Z',
          // no ``findings`` key — predates the L-02 snapshot column
        }),
      ),
    )

    const wrapper = await mountDetail('scan-legacy')
    await flushPromises()

    expect(wrapper.find('[data-testid="scan-detail-findings"]').exists()).toBe(false)
    expect(wrapper.find('[data-testid="scan-detail-no-findings"]').exists()).toBe(false)
    expect(wrapper.find('[data-testid="scan-detail-content"]').exists()).toBe(true)
  })
})
