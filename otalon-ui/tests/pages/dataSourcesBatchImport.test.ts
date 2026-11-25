import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises } from '@vue/test-utils'
import { reactive } from 'vue'
import type { QDialogOptions } from 'quasar'

import type { ImportQueueItem, useDataSourcesStore } from '~/stores/dataSourcesStore'
import type { CaptureStatus } from '~/types/api'
import type { PcapImportAccepted, PcapImportState, PcapImportStatus } from '~/composables/usePcapImport'
import { useOperationsRefresh } from '~/composables/useOperationsRefresh'
import { usePolling } from '~/composables/usePolling'
import { mountWithPlugins } from '../helpers/mount'

// Explicit page-consumption seam: the real store helper and real refresh/polling
// composables remain in use. Queue scheduling/transport are tested by their owners.
type PageStore = Pick<
  ReturnType<typeof useDataSourcesStore>,
  | 'pipeline'
  | 'captureStatus'
  | 'passiveDiscovery'
  | 'seederStatus'
  | 'isLoading'
  | 'pipelineError'
  | 'captureError'
  | 'passiveError'
  | 'seederError'
  | 'sourceRows'
  | 'staleBanner'
  | 'passiveBadge'
  | 'seederBadge'
  | 'seederState'
  | 'importQueue'
  | 'importQueueError'
  | 'importAuthStopped'
  | 'recentImports'
  | 'recentError'
  | 'recentLoaded'
  | 'loadAll'
  | 'enqueueImports'
  | 'startImportQueue'
  | 'stopImportQueue'
  | 'cancelQueueImport'
  | 'confirmImportForce'
  | 'refreshImportQueue'
  | 'resumeImportQueue'
>

const store: PageStore = reactive({
  pipeline: null,
  captureStatus: null,
  passiveDiscovery: null,
  seederStatus: null,
  isLoading: false,
  pipelineError: null,
  captureError: null,
  passiveError: null,
  seederError: null,
  sourceRows: [],
  staleBanner: null,
  passiveBadge: { label: 'no data', kind: 'muted' },
  seederBadge: { label: 'unknown', kind: 'muted' },
  seederState: 'unknown',
  importQueue: [],
  importQueueError: null,
  importAuthStopped: false,
  recentImports: [],
  recentError: null,
  recentLoaded: true,
  loadAll: vi.fn(async () => {}),
  enqueueImports: vi.fn(() => []),
  startImportQueue: vi.fn(async () => {}),
  stopImportQueue: vi.fn(),
  cancelQueueImport: vi.fn(async () => {}),
  confirmImportForce: vi.fn(),
  refreshImportQueue: vi.fn(async () => {}),
  resumeImportQueue: vi.fn(async () => {}),
})

vi.mock('~/stores/dataSourcesStore', async (importOriginal) => ({
  ...(await importOriginal<typeof import('~/stores/dataSourcesStore')>()),
  useDataSourcesStore: () => store,
}))

const app = { setLiveMode: vi.fn(), setTimeRange: vi.fn(() => true) }
vi.mock('~/stores/appStore', async (importOriginal) => ({
  ...(await importOriginal<typeof import('~/stores/appStore')>()),
  useAppStore: () => app,
}))

let dialogOptions: QDialogOptions | undefined
let consent: (() => void) | undefined
let dismiss: (() => void) | undefined
const notify = vi.fn()
const dialog = vi.fn((options: QDialogOptions) => {
  dialogOptions = options
  let cancelCallback: (() => void) | undefined
  dismiss = () => cancelCallback?.()
  const chain = {
    onOk(cb: () => void) {
      consent = cb
      return chain
    },
    onCancel(cb: () => void) {
      cancelCallback = cb
      return chain
    },
    onDismiss() {
      return chain
    },
    hide() {},
    update() {
      return chain
    },
  }
  return chain
})
vi.mock('quasar', async (importOriginal) => ({
  ...(await importOriginal<typeof import('quasar')>()),
  useQuasar: () => ({ notify, dialog }),
}))

const unavailable: CaptureStatus = {
  interface: null,
  link_up: null,
  recording: null,
  drops_24h_pct: null,
  overflows: null,
  capture_type: null,
  backend: null,
  source_state: 'degraded',
  reason_code: 'upstream_unavailable',
  retry_attempt: null,
  retry_limit: null,
  retry_in_seconds: null,
  retry_exhausted: null,
  observation_age_seconds: null,
}
const start = '2026-01-01T12:00:00.375Z'
const end = '2026-01-01T12:01:00.750Z'
const resultStart = '2026-01-01T12:00:01.375Z'
const resultEnd = '2026-01-01T12:00:59.750Z'
const marker = 'Cancellation needs reconciliation; worker settlement is unverified.'

function job(state: PcapImportState = 'running', patch: Partial<PcapImportStatus> = {}): PcapImportStatus {
  return {
    display_id: 'ING-TEST-1',
    job_id: 1,
    state,
    phase_current: 2,
    phase_total: 4,
    phase_label: 'Writing records',
    latest_event: 'Actual worker event',
    original_filename: 'capture.pcap',
    size_bytes: 3,
    time_start: start,
    time_end: end,
    forced: false,
    started_at: null,
    ended_at: null,
    error: null,
    result: null,
    ...patch,
  }
}

function acceptance(state: PcapImportState): PcapImportAccepted {
  return {
    display_id: 'ING-TEST-1',
    job_id: 1,
    state,
    filename: 'internal-storage.pcap',
    original_filename: 'capture.pcap',
    size_bytes: 3,
    sha256: 'test-digest',
    time_start: start,
    time_end: end,
    forced: false,
    delivered: false,
  }
}

function row(localId: number, patch: Partial<ImportQueueItem> = {}): ImportQueueItem {
  const file = new File(['abc'], 'capture.pcap')
  return {
    localId,
    sequence: localId,
    file,
    name: file.name,
    sizeBytes: file.size,
    lastModified: file.lastModified,
    uploadState: 'pending',
    uploadLoaded: null,
    uploadTotal: null,
    accepted: null,
    observedDisplayId: null,
    status: null,
    rejection: null,
    cancelError: null,
    pollError: null,
    cancellationRequested: false,
    forceConfirmed: false,
    forceSequence: null,
    ...patch,
  }
}

function conflict(localId: number): ImportQueueItem {
  return row(localId, {
    name: `conflict-${localId}.pcap`,
    uploadState: 'conflict',
    rejection: {
      kind: 'conflict',
      status: 409,
      message: 'Existing data overlaps this capture.',
      limitBytes: null,
      conflict: {
        message: 'Existing data overlaps this capture.',
        measurement: 'network_metrics',
        conflict_start: start,
        conflict_end: end,
      },
    },
  })
}

let wrapper: ReturnType<typeof mountWithPlugins> | undefined
const navigate = vi.fn()

async function mountPage() {
  const page = await import('~/pages/operations/data-sources.vue')
  wrapper = mountWithPlugins(page.default)
  await flushPromises()
  return wrapper
}

beforeEach(() => {
  vi.clearAllMocks()
  vi.useFakeTimers()
  vi.stubGlobal('usePolling', usePolling)
  vi.stubGlobal('navigateTo', navigate)
  Object.assign(store, {
    captureStatus: null,
    captureError: null,
    pipelineError: null,
    importQueue: [],
    importQueueError: null,
    importAuthStopped: false,
    recentImports: [],
    recentError: null,
    recentLoaded: true,
  })
  dialogOptions = undefined
  consent = undefined
  dismiss = undefined
  vi.mocked(store.enqueueImports).mockImplementation((files) => {
    const materialized = Array.from(files)
    for (const file of materialized) {
      store.importQueue.push(row(store.importQueue.length + 1, { file, name: file.name, sizeBytes: file.size }))
    }
    return store.importQueue.map((item) => item.localId)
  })
})

afterEach(() => {
  wrapper?.unmount()
  wrapper = undefined
  consent = undefined
  dismiss = undefined
  dialogOptions = undefined
  vi.clearAllTimers()
  vi.useRealTimers()
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

describe('C3 compact all-file selection', () => {
  it('materializes every picker file in order including duplicate names and invalid extensions, then resets', async () => {
    const page = await mountPage()
    const input = page.get('[data-test="file-input"]').element as HTMLInputElement
    const files = [new File(['a'], 'same.pcap'), new File(['b'], 'same.pcap'), new File(['x'], 'invalid.txt')]
    Object.defineProperty(input, 'files', { configurable: true, value: files })
    // FileList materialization is the unit seam; browsers forbid assigning a
    // nonempty native file-input value without an actual picker interaction.
    Object.defineProperty(input, 'value', { configurable: true, writable: true, value: 'capture.pcap' })
    await page.get('[data-test="file-input"]').trigger('change')
    expect(input.multiple).toBe(true)
    expect(store.enqueueImports).toHaveBeenCalledExactlyOnceWith(files)
    expect(input.value).toBe('')
    expect(page.findAll('[data-test="queue-row"]').map((item) => item.get('[data-test="queue-name"]').text())).toEqual([
      'same.pcap',
      'same.pcap',
      'invalid.txt',
    ])
    await page.get('[data-test="file-input"]').trigger('change')
    expect(store.enqueueImports).toHaveBeenCalledTimes(2)
    expect(page.findAll('[data-test="queue-row"]')).toHaveLength(6)
  })

  it('appends every dropped file while uploading without replacing prior rows', async () => {
    store.importQueue = [row(1, { name: 'active.pcap', uploadState: 'uploading' })]
    const page = await mountPage()
    const files = [new File(['a'], 'drop-a.pcapng'), new File(['b'], 'bad.bin')]
    await page.get('[data-test="dropzone"]').trigger('drop', { dataTransfer: { files } })
    expect(store.enqueueImports).toHaveBeenCalledExactlyOnceWith(files)
    expect(page.findAll('[data-test="queue-name"]').map((item) => item.text())).toEqual([
      'active.pcap',
      'drop-a.pcapng',
      'bad.bin',
    ])
  })

  it.each(['Enter', ' '])('keeps keyboard %s browsing active while processing', async (key) => {
    store.importQueue = [row(1, { uploadState: 'accepted', status: job() })]
    const page = await mountPage()
    const click = vi.spyOn(page.get('[data-test="file-input"]').element as HTMLInputElement, 'click')
    await page.get('[data-test="dropzone"]').trigger('keydown', { key })
    expect(click).toHaveBeenCalledOnce()
  })

  it('allows picker additions while an upload is active', async () => {
    store.importQueue = [row(1, { uploadState: 'uploading' })]
    const page = await mountPage()
    const files = [new File(['a'], 'addition.pcap')]
    Object.defineProperty(page.get('[data-test="file-input"]').element, 'files', { configurable: true, value: files })
    await page.get('[data-test="file-input"]').trigger('change')
    expect(store.enqueueImports).toHaveBeenCalledWith(files)
    expect(page.findAll('[data-test="queue-row"]')).toHaveLength(2)
  })

  it.each([undefined, { files: [] }])(
    'reports an unusable drop without resetting any row: %j',
    async (dataTransfer) => {
      store.importQueue = [conflict(1)]
      const page = await mountPage()
      await page.get('[data-test="dropzone"]').trigger('drop', { dataTransfer })
      expect(page.get('[data-test="selection-notice"]').text()).toContain('No files added')
      expect(store.enqueueImports).not.toHaveBeenCalled()
      expect(store.importQueue[0]?.uploadState).toBe('conflict')
      expect(page.findAll('[data-test="queue-row"]')).toHaveLength(1)
    },
  )

  it('renders full accessible filenames, nullable size, and stable local row identity with no internal storage names', async () => {
    const name = `${'long-'.repeat(40)}capture.pcap`
    store.importQueue = [
      row(8, { name, sizeBytes: null, accepted: acceptance('running'), uploadState: 'accepted' }),
      row(9, { name }),
    ]
    const page = await mountPage()
    const first = page.get('[data-local-id="8"]')
    const element = first.element
    expect(first.get('[data-test="queue-name"]').text()).toBe(name)
    expect(first.get('[data-test="queue-name"]').attributes('title')).toBe(name)
    expect(first.get('[data-test="queue-size"]').text()).toBe('Size unavailable')
    expect(first.get('[data-test="queue-cancel"]').attributes('aria-label')).toContain(name)
    expect(first.text()).not.toContain('internal-storage.pcap')
    expect(first.text()).not.toContain('UI-206')
    store.importQueue.reverse()
    await flushPromises()
    expect(page.get('[data-local-id="8"]').element).toBe(element)
    expect(page.find('.q-expansion-item').exists()).toBe(false)
  })

  it('states the default payload ceiling and truthful app-memory versus durable history lifetime', async () => {
    const page = await mountPage()
    const limit = page.get('[data-test="upload-limit"]').text()
    expect(limit).toContain('Default')
    expect(limit).toContain('1024 MiB')
    expect(limit).toContain('1073741824')
    expect(limit).toContain('payload')
    expect(limit).toContain('server')
    expect(limit).not.toContain('1073807360')
    const notice = page.get('[data-test="import-lifetime"]').text()
    expect(notice).toContain('app/tab memory')
    expect(notice).toContain('Navigating within the app retains')
    expect(notice).toContain('full reload')
    expect(notice).toContain('re-selection')
    expect(notice).toContain('server-persisted')
    expect(page.text()).not.toContain('Start batch')
  })

  it('retains cancelled local filenames after bytes are released and separates nameless recovered job identity', async () => {
    store.importQueue = [
      row(1, { name: 'cancelled-local.pcap', file: null, uploadState: 'cancelled' }),
      row(2, {
        name: 'ING-RECOVERED',
        file: null,
        uploadState: 'accepted',
        status: job('running', { display_id: 'ING-RECOVERED', original_filename: null }),
      }),
    ]
    const page = await mountPage()
    expect(page.get('[data-local-id="1"] [data-test="queue-name"]').text()).toBe('cancelled-local.pcap')
    expect(page.get('[data-local-id="1"]').find('[data-test="queue-cancel"]').exists()).toBe(false)
    expect(page.get('[data-local-id="2"] [data-test="queue-name"]').text()).toBe('Unknown capture')
    expect(page.get('[data-local-id="2"]').text()).toContain('Job: ING-RECOVERED')
  })
})

describe('C3 transfer versus persisted worker truth', () => {
  it.each([
    [null, null],
    [5, null],
    [null, 100],
  ])('keeps nullable request measurements indeterminate: %j/%j', async (loaded, total) => {
    store.importQueue = [row(1, { uploadState: 'uploading', uploadLoaded: loaded, uploadTotal: total })]
    const page = await mountPage()
    const transfer = page.get('[data-test="queue-transfer"]')
    expect(transfer.text()).toContain('indeterminate')
    expect(transfer.text()).not.toMatch(/\b0 B\b/)
    expect(transfer.text()).not.toContain('3 B')
    expect(transfer.attributes('aria-valuenow')).toBeUndefined()
  })

  it('uses measured multipart request bytes and labels 100% waiting for acceptance, not import completion', async () => {
    store.importQueue = [row(1, { uploadState: 'uploading', uploadLoaded: 128, uploadTotal: 256 })]
    const page = await mountPage()
    expect(page.get('[data-test="queue-transfer"]').text()).toContain('128 B / 256 B')
    expect(page.get('[data-test="queue-transfer"]').text()).toContain('multipart overhead')
    expect(page.get('[data-test="queue-transfer"]').attributes('aria-valuenow')).toBe('50')
    store.importQueue[0]!.uploadLoaded = 256
    await flushPromises()
    expect(page.get('[data-test="queue-transfer"]').text()).toContain('Transfer complete; waiting for acceptance')
    expect(page.get('[data-test="queue-worker"]').text()).not.toContain('completed')
  })

  it.each(['queued', 'running', 'cancelling', 'completed', 'failed', 'cancelled', 'rejected'] as const)(
    'shows actual acceptance state %s without normalizing SHA-reused terminal state',
    async (state) => {
      store.importQueue = [row(1, { uploadState: 'accepted', accepted: acceptance(state) })]
      const page = await mountPage()
      expect(page.get('[data-test="queue-upload-state"]').text()).toContain('accepted')
      expect(page.get('[data-test="queue-worker"]').text()).toContain(state)
      expect(page.get('[data-test="queue-worker"]').text()).not.toContain('%')
    },
  )

  it('shows real status, phase, event, error, results and retained local errors separately', async () => {
    store.importQueue = [
      row(1, {
        uploadState: 'accepted',
        accepted: acceptance('queued'),
        status: job('failed', { error: 'Partial writes failed', result: { records_processed: 7, points_written: 9 } }),
        cancelError: 'Cancel delivery failed',
        pollError: 'Status read unavailable',
      }),
    ]
    const page = await mountPage()
    const text = page.get('[data-test="queue-row"]').text()
    for (const fact of [
      'failed',
      'Phase 2/4',
      'Writing records',
      'Actual worker event',
      'Partial writes failed',
      '7 Records',
      '9 points',
      'Cancel delivery failed',
      'Status read unavailable',
    ])
      expect(text).toContain(fact)
    expect(page.get('[data-test="queue-worker"]').text()).not.toContain('queued')
    expect(page.get('[data-test="queue-worker"]').text()).not.toContain('%')
  })

  it('retains authoritative custom 413 and explicit invalid-file outcomes alongside other rows', async () => {
    store.importQueue = [
      row(1, {
        uploadState: 'failed',
        rejection: {
          kind: 'too-large',
          status: 413,
          message: 'Upload exceeds the configured limit of 4096 bytes',
          limitBytes: 4096,
          conflict: null,
        },
      }),
      row(2, {
        name: 'invalid.txt',
        uploadState: 'failed',
        rejection: {
          kind: 'unsupported',
          status: 422,
          message: 'File is not a pcap or pcapng capture',
          limitBytes: null,
          conflict: null,
        },
      }),
      row(3),
    ]
    const page = await mountPage()
    expect(page.findAll('[data-test="queue-row"]')).toHaveLength(3)
    expect(page.get('[data-local-id="1"]').text()).toContain('4096 bytes')
    expect(page.get('[data-local-id="2"]').text()).toContain('File is not a pcap or pcapng capture')
  })
})

describe('C3 file-specific consent, cancellation and recovery', () => {
  it('names exact conflict file, measurement and window and mutates only after positive consent', async () => {
    store.importQueue = [conflict(1), conflict(2)]
    const retained = store.importQueue[1]!.file
    const page = await mountPage()
    const selected = page.get('[data-local-id="2"]')
    expect(selected.text()).toContain('network_metrics')
    expect(selected.text()).toContain(start)
    expect(selected.text()).toContain(end)
    await selected.get('[data-test="queue-force"]').trigger('click')
    expect(store.confirmImportForce).not.toHaveBeenCalled()
    expect(dialogOptions?.message).toContain('conflict-2.pcap')
    expect(dialogOptions?.message).toContain('network_metrics')
    expect(dialogOptions?.message).toContain(start)
    expect(dialogOptions?.message).toContain(end)
    expect(dialogOptions?.message).toContain('cannot be undone')
    expect(dialogOptions?.html).not.toBe(true)
    consent?.()
    expect(store.confirmImportForce).toHaveBeenCalledExactlyOnceWith(2)
    expect(store.importQueue[1]!.file).toBe(retained)
    expect(store.importQueue[0]!.forceConfirmed).toBe(false)
  })

  it('cancelled overwrite dialog causes no mutation and retains all conflicts and bytes', async () => {
    store.importQueue = [conflict(4), conflict(5)]
    const page = await mountPage()
    await page.get('[data-local-id="4"] [data-test="queue-force"]').trigger('click')
    expect(dismiss).toBeTypeOf('function')
    dismiss!()
    expect(store.confirmImportForce).not.toHaveBeenCalled()
    expect(store.cancelQueueImport).not.toHaveBeenCalled()
    expect(store.importQueue.every((item) => item.file && item.uploadState === 'conflict')).toBe(true)
  })

  it.each(['pending', 'conflict', 'failed', 'uploading'] as const)(
    'targets only localId for %s cancellation',
    async (uploadState) => {
      store.importQueue = [row(1), row(7, { uploadState })]
      const page = await mountPage()
      const button = page.get('[data-local-id="7"] [data-test="queue-cancel"]')
      if (uploadState === 'uploading') expect(button.text()).toContain('Stop upload')
      await button.trigger('click')
      expect(store.cancelQueueImport).toHaveBeenCalledExactlyOnceWith(7)
      expect(store.importQueue).toHaveLength(2)
    },
  )

  it.each(['queued', 'running', 'cancelling'] as const)(
    'keeps %s barrier and requests exact-row cancellation without undo promise',
    async (state) => {
      store.importQueue = [row(3, { uploadState: 'accepted', status: job(state) }), row(4)]
      const page = await mountPage()
      const button = page.get('[data-local-id="3"] [data-test="queue-cancel"]')
      expect(button.text()).toContain(state === 'cancelling' ? 'Reconcile cancellation' : 'Request cancellation')
      await button.trigger('click')
      expect(store.cancelQueueImport).toHaveBeenCalledExactlyOnceWith(3)
      expect(store.importQueue[0]?.status?.state).toBe(state)
      expect(page.get('[data-test="queue-cancellation-note"]').text()).toContain('does not undo')
    },
  )

  it('shows exact blocked marker and explicit same-ID reconciliation action', async () => {
    store.importQueue = [
      row(2, { uploadState: 'accepted', status: job('cancelling', { error: marker, latest_event: marker }) }),
    ]
    const page = await mountPage()
    expect(page.get('[data-test="queue-row"]').text()).toContain(marker)
    await page.get('[data-test="queue-cancel"]').trigger('click')
    expect(store.cancelQueueImport).toHaveBeenCalledExactlyOnceWith(2)
  })

  it('lost-ID uncertainty stays visible with separate history and no no-op cancel or File retry', async () => {
    store.importQueue = [
      row(2, { uploadState: 'uncertain', cancellationRequested: true, pollError: 'Acceptance unverified' }),
    ]
    store.recentImports = [job('running')]
    const page = await mountPage()
    const uncertain = page.get('[data-test="queue-row"]')
    expect(uncertain.text()).toContain('Server acceptance is unverified')
    expect(uncertain.text()).toContain('history cannot prove this file')
    expect(uncertain.find('[data-test="queue-cancel"]').exists()).toBe(false)
    expect(uncertain.find('[data-test="queue-force"]').exists()).toBe(false)
    expect(page.findAll('[data-test="recent-import-row"]')).toHaveLength(1)
    expect(store.cancelQueueImport).not.toHaveBeenCalled()
    expect(store.enqueueImports).not.toHaveBeenCalled()
  })

  it('observed-ID uncertainty offers same-owner cancellation, not upload retry', async () => {
    store.importQueue = [row(2, { uploadState: 'uncertain', observedDisplayId: 'ING-OBSERVED' })]
    const page = await mountPage()
    await page.get('[data-test="queue-cancel"]').trigger('click')
    expect(store.cancelQueueImport).toHaveBeenCalledExactlyOnceWith(2)
    expect(store.enqueueImports).not.toHaveBeenCalled()
  })

  it('exposes explicit queue refresh and session recovery, retaining all rows', async () => {
    store.importQueue = [row(1)]
    store.importQueueError = 'Import reconciliation blocked: listing reached 200 entries'
    const page = await mountPage()
    expect(page.get('[data-test="queue-error"]').text()).toContain(store.importQueueError)
    await page.get('[data-test="queue-refresh"]').trigger('click')
    expect(store.refreshImportQueue).toHaveBeenCalledOnce()
    store.importAuthStopped = true
    await flushPromises()
    expect(page.get('[data-test="queue-auth-note"]').text()).toContain('login/permission')
    expect(page.find('[data-test="queue-refresh"]').exists()).toBe(false)
    await page.get('[data-test="queue-resume"]').trigger('click')
    expect(store.resumeImportQueue).toHaveBeenCalledOnce()
    expect(page.findAll('[data-test="queue-row"]')).toHaveLength(1)
  })
})

describe('C3 history, original range, informational actions and lifecycle', () => {
  it('uses result-preferred exact timestamps for completed local row with no navigation or automatic Detection', async () => {
    store.importQueue = [
      row(1, {
        uploadState: 'accepted',
        status: job('completed', {
          result: { time_start: resultStart, time_end: resultEnd, points_written: 12 },
        }),
      }),
    ]
    const page = await mountPage()
    expect(notify).not.toHaveBeenCalled()
    expect(navigate).not.toHaveBeenCalled()
    await page.get('[data-test="queue-range"]').trigger('click')
    expect(app.setLiveMode).toHaveBeenCalledExactlyOnceWith(false)
    expect(app.setTimeRange).toHaveBeenCalledExactlyOnceWith(resultStart, resultEnd)
    expect(navigate).not.toHaveBeenCalled()
    await page.get('[data-test="queue-detection"]').trigger('click')
    expect(notify).toHaveBeenLastCalledWith(
      expect.objectContaining({ type: 'info', message: expect.stringContaining('no endpoint') }),
    )
    expect(navigate).not.toHaveBeenCalled()
    const notice = notify.mock.calls.at(-1)?.[0] as { actions: { handler: () => void }[] }
    notice.actions[0]!.handler()
    expect(navigate).toHaveBeenCalledExactlyOnceWith('/operations/detection')
  })

  it('preserves server history ordering, errors, job identity labels and result-preferred range', async () => {
    store.recentImports = [
      job('completed', {
        display_id: 'ING-NEW',
        original_filename: 'new.pcap',
        result: { time_start: resultStart, time_end: resultEnd, points_written: 21 },
      }),
      job('failed', { display_id: 'ING-OLD', original_filename: 'old.pcap', error: 'Persisted failure' }),
    ]
    const page = await mountPage()
    expect(page.findAll('[data-test="recent-import-filename"]').map((item) => item.text())).toEqual([
      'new.pcap',
      'old.pcap',
    ])
    expect(page.get('[data-import-id="ING-OLD"]').text()).toContain('Persisted failure')
    expect(page.get('[data-import-id="ING-NEW"]').text()).toContain('Job: ING-NEW')
    await page.get('[data-import-id="ING-NEW"] [data-test="recent-import-jump"]').trigger('click')
    expect(app.setTimeRange).toHaveBeenCalledExactlyOnceWith(resultStart, resultEnd)
    expect(navigate).not.toHaveBeenCalled()
    expect(page.get('[data-test="seeder-runtime-link"]').attributes('to')).toBe('/operations/configuration')
  })

  it.each([null, 'Failed to load recent imports'])(
    'distinguishes empty history from unavailable: %j',
    async (error) => {
      store.recentError = error
      const page = await mountPage()
      expect(page.get('[data-test="recent-imports-empty"]').text()).toContain(
        error ? 'unavailable' : 'empty, not unavailable',
      )
    },
  )

  it('starts the store owner once on mount, only polls status refresh at 5000ms, and unmount never stops global queue', async () => {
    const interval = vi.spyOn(globalThis, 'setInterval')
    const refresh = useOperationsRefresh()
    const page = await mountPage()
    expect(store.startImportQueue).toHaveBeenCalledOnce()
    expect(store.loadAll).toHaveBeenCalledOnce()
    expect(refresh.isAvailable.value).toBe(true)
    expect(interval.mock.calls.map((call) => call[1])).toEqual([5000])
    await vi.advanceTimersByTimeAsync(5000)
    expect(store.loadAll).toHaveBeenCalledTimes(2)
    expect(store.startImportQueue).toHaveBeenCalledOnce()
    page.unmount()
    wrapper = undefined
    expect(refresh.isAvailable.value).toBe(false)
    expect(store.stopImportQueue).not.toHaveBeenCalled()
    expect(store.cancelQueueImport).not.toHaveBeenCalled()
    expect(vi.getTimerCount()).toBe(0)
  })
})

describe('C3 actual additive capture facts', () => {
  it('native NONE shows neutral intentional disablement and known local process absence, with null link/counters', async () => {
    store.captureStatus = {
      ...unavailable,
      capture_type: 'NONE',
      backend: 'native',
      source_state: 'disabled',
      reason_code: 'none_selected',
      recording: false,
      retry_attempt: 0,
      retry_limit: 5,
      retry_exhausted: false,
    }
    const page = await mountPage()
    expect(page.get('[data-test="capture-mode"]').text()).toBe('NONE')
    expect(page.get('[data-test="capture-backend"]').text()).toBe('native')
    expect(page.get('[data-test="capture-source-state"]').text()).toBe('disabled')
    expect(page.get('[data-test="capture-recording"]').text()).toContain('not recording')
    expect(page.get('[data-test="capture-recording"]').attributes('aria-label')).toContain('grey')
    expect(page.get('[data-test="capture-link"]').text()).toBe('unknown')
    expect(page.get('[data-test="capture-drops"]').text()).toBe('—')
    expect(page.get('[data-test="capture-overflows"]').text()).toBe('—')
  })

  it.each(['waiting', 'degraded'] as const)(
    'native LIVE process recording is distinct from %s producer-pair readiness',
    async (source_state) => {
      store.captureStatus = {
        ...unavailable,
        capture_type: 'LIVE',
        backend: 'native',
        source_state,
        recording: true,
        link_up: true,
        reason_code: 'dependency_unavailable',
        retry_attempt: 2,
        retry_limit: 5,
        retry_in_seconds: 4.5,
        retry_exhausted: false,
      }
      const page = await mountPage()
      expect(page.get('[data-test="capture-recording"]').text()).toBe('recording')
      expect(page.get('[data-test="capture-source-state"]').text()).toBe(source_state)
      expect(page.get('[data-test="capture-retry"]').text()).toContain('2/5')
      expect(page.get('[data-test="capture-retry"]').text()).toContain('4.5 s')
      expect(page.get('[data-test="capture-reason"]').text()).toContain('Dependency unavailable')
      expect(page.text()).toContain('Carrier-up is not traffic-present')
      expect(page.text()).toContain('not authenticated metric-write success')
    },
  )

  it('WSL NONE distinguishes disabled receiver/processor from unknown remote collector with no Windows stop claim', async () => {
    store.captureStatus = {
      ...unavailable,
      capture_type: 'NONE',
      backend: 'wsl',
      source_state: 'disabled',
      reason_code: 'none_selected',
    }
    const page = await mountPage()
    expect(page.get('[data-test="capture-source-state"]').text()).toBe('disabled')
    expect(page.get('[data-test="capture-recording"]').text()).toBe('unknown')
    expect(page.get('[data-test="capture-semantics"]').text()).toContain('receiver/processor')
    expect(page.get('[data-test="capture-semantics"]').text()).toContain('Windows collector must be stopped explicitly')
    expect(page.text()).not.toContain('Windows stopped')
  })

  it.each([true, false, null])(
    'WSL LIVE shows exact fresh remote recording=%j and receipt age separately',
    async (recording) => {
      store.captureStatus = {
        ...unavailable,
        capture_type: 'LIVE',
        backend: 'wsl',
        recording,
        source_state: recording === true ? 'recording' : 'waiting',
        reason_code: null,
        observation_age_seconds: 1.25,
      }
      const page = await mountPage()
      expect(page.get('[data-test="capture-recording"]').text()).toBe(
        recording === null ? 'unknown' : recording ? 'recording' : 'not recording',
      )
      expect(page.get('[data-test="capture-observation-age"]').text()).toBe('1.25 s since receipt')
      expect(page.get('[data-test="capture-semantics"]').text()).toContain('current collector readiness')
    },
  )

  it('WSL stale current observation keeps recording unknown and exhausted retry evidence finite', async () => {
    store.captureStatus = {
      ...unavailable,
      capture_type: 'LIVE',
      backend: 'wsl',
      source_state: 'degraded',
      reason_code: 'collector_stale',
      observation_age_seconds: 7,
      retry_attempt: 5,
      retry_limit: 5,
      retry_exhausted: true,
    }
    const page = await mountPage()
    expect(page.get('[data-test="capture-recording"]').text()).toBe('unknown')
    expect(page.get('[data-test="capture-source-state"]').text()).toBe('degraded')
    expect(page.get('[data-test="capture-reason"]').text()).toContain('Collector observation stale')
    expect(page.get('[data-test="capture-retry"]').text()).toContain('exhausted')
  })

  it('API degraded fallback does not infer mode, backend, source readiness, recording or zero counters from liveness', async () => {
    store.captureStatus = { ...unavailable }
    const page = await mountPage()
    expect(page.get('[data-test="capture-mode"]').text()).toBe('unknown')
    expect(page.get('[data-test="capture-backend"]').text()).toBe('unknown')
    expect(page.get('[data-test="capture-source-state"]').text()).toBe('degraded')
    expect(page.get('[data-test="capture-reason"]').text()).toBe('Upstream unavailable')
    expect(page.get('[data-test="capture-recording"]').text()).toBe('unknown')
    expect(page.get('[data-test="capture-retry"]').text()).toBe('Unavailable')
    expect(page.get('[data-test="capture-drops"]').text()).toBe('—')
    expect(page.get('[data-test="capture-overflows"]').text()).toBe('—')
    expect(page.findAllComponents({ name: 'QToggle' })).toHaveLength(0)
    expect(page.findAllComponents({ name: 'QSelect' })).toHaveLength(0)
  })

  it('renders blocked sanitized reason without exposing unrecognized raw reason or nonfinite retries', async () => {
    store.captureStatus = { ...unavailable, source_state: 'blocked', reason_code: 'privilege_denied' }
    const page = await mountPage()
    expect(page.get('[data-test="capture-source-state"]').text()).toBe('blocked')
    expect(page.get('[data-test="capture-reason"]').text()).toBe('Privilege denied')
    Object.assign(store.captureStatus, {
      reason_code: 'raw-sensitive-exception',
      retry_in_seconds: Infinity,
      observation_age_seconds: NaN,
      retry_attempt: 6,
      retry_limit: 12,
    })
    await flushPromises()
    expect(page.text()).not.toContain('raw-sensitive-exception')
    expect(page.get('[data-test="capture-retry"]').text()).not.toContain('Infinity')
    expect(page.get('[data-test="capture-retry"]').text()).not.toContain('6/12')
    expect(page.get('[data-test="capture-observation-age"]').text()).not.toContain('NaN')
  })
})
