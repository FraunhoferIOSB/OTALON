/**
 * PCAP import workflow client (UI-078, Wave D).
 *
 * Wraps the operator-key-protected import surface of otalon-api. All
 * calls go to `/api/v1/operations/pcap-import*` and are therefore relayed by
 * the server-side operator proxy (`server/api/v1/operations/[...path].ts`),
 * which injects the operator key — no key is ever present in the browser
 * bundle.
 *
 * The upload is `multipart/form-data`. The API parses the envelope itself:
 * the capture part is recognised by carrying a `filename`, and `force` is an
 * ordinary text field (`1|true|yes|on`), never a query parameter. The
 * `Content-Type` header is deliberately not set by hand so the browser emits
 * the multipart boundary.
 *
 * @example
 * ```ts
 * const { uploadCapture } = usePcapImport()
 * const accepted = await uploadCapture(file)
 * // conflict? re-post the very same file with force
 * const forced = await uploadCapture(file, { force: true })
 * ```
 */

/** Lifecycle states an import job can hold (mirrors the PG CHECK). */
export type PcapImportState = 'queued' | 'running' | 'cancelling' | 'completed' | 'failed' | 'cancelled' | 'rejected'

/** States after which no further progress will be reported. */
export const PCAP_IMPORT_TERMINAL_STATES: readonly PcapImportState[] = [
  'completed',
  'failed',
  'cancelled',
  'rejected',
] as const

/** Outcome payload, populated only once `state === 'completed'`. */
export interface PcapImportResult {
  records_processed?: number | null
  points_written?: number | null
  time_start?: string | null
  time_end?: string | null
}

/** Envelope returned by a successful (201) upload. */
export interface PcapImportAccepted {
  display_id: string
  job_id: number
  state: PcapImportState
  filename: string
  original_filename: string | null
  size_bytes: number
  sha256: string
  time_start: string | null
  time_end: string | null
  forced: boolean
  delivered: boolean
}

/** Progress/outcome envelope shared by the detail and list endpoints. */
export interface PcapImportStatus {
  display_id: string
  job_id: number
  state: PcapImportState
  phase_current: number | null
  phase_total: number | null
  phase_label: string | null
  latest_event: string | null
  original_filename: string | null
  size_bytes: number | null
  time_start: string | null
  time_end: string | null
  forced: boolean
  started_at: string | null
  ended_at: string | null
  error: string | null
  result: PcapImportResult | null
}

/** Newest-first listing envelope. */
export interface PcapImportList {
  items: PcapImportStatus[]
  total: number
}

/**
 * Body of the HTTP 409 raised when the capture window overlaps data that
 * already exists in Influx. Note `detail` is an **object** here, not a
 * string — rendering it with `String(detail)` would print `[object Object]`.
 */
export interface PcapImportConflict {
  message: string
  conflict_start: string
  conflict_end: string
  measurement: string
}

/** Discriminated rejection surfaced to the page. */
export type PcapImportRejectionKind =
  'unsupported' | 'too-large' | 'conflict' | 'unauthorized' | 'malformed' | 'unknown'

/**
 * Normalised upload rejection. `message` is always the server's own wording
 * where the server provided one — it is never replaced by a generic string
 * (pattern: runtime-tab error handling, commit `05cce0e0`).
 */
export interface PcapImportRejection {
  kind: PcapImportRejectionKind
  status: number
  message: string
  conflict: PcapImportConflict | null
  /** Byte ceiling parsed out of the server's 413 wording, when present. */
  limitBytes: number | null
}

const BASE_URL = '/api/v1/operations/pcap-import'

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null
}

/**
 * Read the `detail` member out of whatever the fetch layer threw.
 *
 * `useApi` surfaces it directly; a raw `$fetch` failure carries it under
 * `data`. Both shapes are accepted so the caller never has to care which
 * transport raised.
 */
function extractDetail(error: unknown): unknown {
  if (!isRecord(error)) return undefined
  if ('detail' in error) return error.detail
  const data = error.data
  if (isRecord(data) && 'detail' in data) return data.detail
  return undefined
}

function extractStatus(error: unknown): number {
  if (!isRecord(error)) return 0
  const direct = error.status
  if (typeof direct === 'number') return direct
  const response = error.response
  if (isRecord(response) && typeof response.status === 'number') return response.status
  return 0
}

/**
 * Narrow an unknown `detail` payload to the 409 conflict object.
 *
 * @param detail - The `detail` member of the error body.
 * @returns The conflict object, or `null` when the payload is not one.
 */
export function parseConflictDetail(detail: unknown): PcapImportConflict | null {
  if (!isRecord(detail)) return null
  const { message, conflict_start: start, conflict_end: end, measurement } = detail
  if (typeof start !== 'string' || typeof end !== 'string') return null
  return {
    message: typeof message === 'string' ? message : '',
    conflict_start: start,
    conflict_end: end,
    measurement: typeof measurement === 'string' ? measurement : '',
  }
}

/**
 * Pull the byte ceiling out of the server's 413 wording so the page can
 * render it human-readably while still showing the original sentence.
 *
 * @param message - The server's `detail` string.
 * @returns The limit in bytes, or `null` when the sentence carries none.
 */
export function parseLimitBytes(message: string): number | null {
  const match = /(\d{4,})\s*bytes/i.exec(message)
  if (!match?.[1]) return null
  const parsed = Number(match[1])
  return Number.isFinite(parsed) ? parsed : null
}

function detailToMessage(detail: unknown, fallback: string): string {
  if (typeof detail === 'string' && detail.length > 0) return detail
  if (Array.isArray(detail)) {
    const first = detail[0]
    if (isRecord(first) && typeof first.msg === 'string') return first.msg
  }
  if (isRecord(detail) && typeof detail.message === 'string' && detail.message.length > 0) {
    return detail.message
  }
  return fallback
}

/**
 * Classify a failed upload into a rejection the page can render
 * distinguishably, preserving the server's own message verbatim.
 *
 * @param error - The value thrown by the upload call.
 * @returns A normalised {@link PcapImportRejection}.
 */
export function toRejection(error: unknown): PcapImportRejection {
  const status = extractStatus(error)
  const detail = extractDetail(error)
  const fallback =
    isRecord(error) && typeof error.message === 'string' && error.message.length > 0
      ? error.message
      : 'Upload failed for an unknown reason.'

  if (status === 409) {
    const conflict = parseConflictDetail(detail)
    return {
      kind: 'conflict',
      status,
      message: conflict?.message || detailToMessage(detail, fallback),
      conflict,
      limitBytes: null,
    }
  }

  const message = detailToMessage(detail, fallback)
  if (status === 413) {
    return { kind: 'too-large', status, message, conflict: null, limitBytes: parseLimitBytes(message) }
  }
  if (status === 422) {
    return { kind: 'unsupported', status, message, conflict: null, limitBytes: null }
  }
  if (status === 400) {
    return { kind: 'malformed', status, message, conflict: null, limitBytes: null }
  }
  if (status === 401 || status === 403) {
    return { kind: 'unauthorized', status, message, conflict: null, limitBytes: null }
  }
  return { kind: 'unknown', status, message, conflict: null, limitBytes: null }
}

/** Options accepted by {@link UsePcapImportReturn.uploadCapture}. */
export interface UploadCaptureOptions {
  /** Bypass the server-side overlap check (the "trotzdem importieren" path). */
  force?: boolean
  /** Transport cancellation; abort alone does not prove server nonacceptance. */
  signal?: AbortSignal
  /** Measured request transfer bytes, not file processing or completion. */
  onUploadProgress?: (progress: UploadCaptureProgress) => void
}

/** Nullable transfer measurements supplied by the C2 transport. */
export interface UploadCaptureProgress {
  loaded: number | null
  total: number | null
}

/** Persisted states that must be reconciled before local dispatch. */
export type PcapImportActiveState = 'queued' | 'running' | 'cancelling'

/** Return type of {@link usePcapImport}. */
export interface UsePcapImportReturn {
  uploadCapture: (file: File, options?: UploadCaptureOptions) => Promise<PcapImportAccepted>
  fetchStatus: (displayId: string) => Promise<PcapImportStatus>
  fetchRecent: (limit?: number) => Promise<PcapImportStatus[]>
  fetchByState: (state: PcapImportActiveState, limit?: number) => Promise<PcapImportList>
  cancelImport: (displayId: string) => Promise<PcapImportStatus>
}

/**
 * Compose the PCAP import client.
 *
 * @returns Upload, status, listing and cancel operations.
 */
export function usePcapImport(): UsePcapImportReturn {
  /**
   * POST one capture upload.
   *
   * @param file - The capture chosen by the operator.
   * @param options - `force: true` re-posts past an overlap conflict.
   * @returns The 201 acceptance envelope.
   * @throws A status/detail transport error; pass it through {@link toRejection}.
   */
  async function uploadCapture(file: File, options?: UploadCaptureOptions): Promise<PcapImportAccepted> {
    return await new Promise<PcapImportAccepted>((resolve, reject) => {
      let xhr: XMLHttpRequest | null = null
      let settled = false
      let observed: PcapImportAccepted | null = null
      const detach: (() => void)[] = []

      function cleanup(): void {
        for (const remove of detach) remove()
        detach.length = 0
      }

      function succeed(envelope: PcapImportAccepted): void {
        if (settled) return
        settled = true
        cleanup()
        resolve(envelope)
      }

      function fail(message: string, status = 0, data?: unknown, name = 'Error'): void {
        if (settled) return
        settled = true
        cleanup()
        reject(
          Object.assign(new Error(message), {
            name,
            status,
            data,
            acceptanceUncertain: status === 0 || (status >= 200 && status < 300) || status >= 500,
            ...(observed ? { display_id: observed.display_id, accepted: observed } : {}),
          }),
        )
      }

      // Only a complete response envelope proves identity. Partial JSON, a
      // filename, and a history candidate cannot become cancellation authority.
      function isAcceptance(value: unknown): value is PcapImportAccepted {
        if (!isRecord(value)) return false
        const nullableString = (field: unknown) => field === null || typeof field === 'string'
        return (
          typeof value.display_id === 'string' &&
          value.display_id.length > 0 &&
          Number.isInteger(value.job_id) &&
          [...PCAP_IMPORT_TERMINAL_STATES, 'queued', 'running', 'cancelling'].includes(
            value.state as PcapImportState,
          ) &&
          typeof value.filename === 'string' &&
          nullableString(value.original_filename) &&
          typeof value.size_bytes === 'number' &&
          Number.isFinite(value.size_bytes) &&
          value.size_bytes >= 0 &&
          typeof value.sha256 === 'string' &&
          nullableString(value.time_start) &&
          nullableString(value.time_end) &&
          typeof value.forced === 'boolean' &&
          typeof value.delivered === 'boolean'
        )
      }

      function observeAcceptance(): void {
        if (settled || !xhr || xhr.readyState !== 4 || xhr.status < 200 || xhr.status >= 300) return
        try {
          const body: unknown = JSON.parse(xhr.responseText)
          if (isAcceptance(body)) observed = body
        } catch {
          // An incomplete or opaque response leaves acceptance unverified.
        }
      }

      function onLoad(): void {
        if (settled || !xhr) return
        const status = xhr.status
        if (status === 0) {
          fail('Upload response was lost; server acceptance is unverified.')
          return
        }
        let data: unknown
        try {
          data = JSON.parse(xhr.responseText)
        } catch {
          data = undefined
        }
        if (status >= 200 && status < 300) {
          if (isAcceptance(data)) succeed(data)
          else fail('Upload response is incomplete or unreadable; server acceptance is unverified.', status, data)
          return
        }
        const message =
          isRecord(data) && typeof data.message === 'string' && data.message.length > 0
            ? data.message
            : xhr.responseText || `HTTP ${status}${xhr.statusText ? ` ${xhr.statusText}` : ''}`
        fail(message, status, data)
      }

      function onProgress(event: ProgressEvent): void {
        if (settled) return
        const loaded =
          typeof event.loaded === 'number' && Number.isFinite(event.loaded) && event.loaded >= 0 ? event.loaded : null
        const total =
          event.lengthComputable === true &&
          loaded !== null &&
          typeof event.total === 'number' &&
          Number.isFinite(event.total) &&
          event.total > 0 &&
          loaded <= event.total
            ? event.total
            : null
        options?.onUploadProgress?.({ loaded, total })
      }

      function onAbort(): void {
        if (settled) return
        observeAcceptance()
        if (observed) succeed(observed)
        else fail('Upload aborted; server acceptance is unverified.', 0, undefined, 'AbortError')
      }

      function onSignalAbort(): void {
        if (settled) return
        // Snapshot before abort(), which normally clears status/responseText.
        // The store, not the transport, owns any exact-ID server cancellation.
        onAbort()
        xhr?.abort()
      }

      function onError(): void {
        observeAcceptance()
        fail('Upload network response failed; server acceptance is unverified.')
      }

      function onTimeout(): void {
        observeAcceptance()
        fail('Upload timed out; server acceptance is unverified.')
      }

      function onLoadEnd(): void {
        if (settled) return
        if (xhr?.readyState === 4 && xhr.status !== 0) onLoad()
        else fail('Upload ended without a response; server acceptance is unverified.')
      }

      function listen(target: EventTarget, type: string, listener: EventListener): void {
        target.addEventListener(type, listener)
        detach.push(() => target.removeEventListener(type, listener))
      }

      try {
        if (options?.signal?.aborted) {
          onAbort()
          return
        }
        xhr = new XMLHttpRequest()
        listen(xhr, 'readystatechange', observeAcceptance)
        listen(xhr, 'load', onLoad)
        listen(xhr, 'error', onError)
        listen(xhr, 'timeout', onTimeout)
        listen(xhr, 'abort', onAbort)
        listen(xhr, 'loadend', onLoadEnd)
        listen(xhr.upload, 'progress', onProgress as EventListener)
        if (options?.signal) listen(options.signal, 'abort', onSignalAbort)
        xhr.open('POST', BASE_URL, true)
        const form = new FormData()
        form.append('file', file, file.name)
        if (options?.force === true) form.append('force', 'true')
        // Same-origin cookies are automatic. No browser key or manual boundary.
        if (options?.signal?.aborted) onSignalAbort()
        if (!settled) xhr.send(form)
      } catch (error: unknown) {
        const reason = error instanceof Error ? error.message : 'Transport initialization failed'
        fail(`${reason}; server acceptance is unverified.`)
        xhr?.abort()
      }
    })
  }

  /**
   * Read the current state of one import job.
   *
   * @param displayId - Public job id from the acceptance envelope.
   * @returns The status envelope.
   */
  async function fetchStatus(displayId: string): Promise<PcapImportStatus> {
    return await $fetch<PcapImportStatus>(`${BASE_URL}/${encodeURIComponent(displayId)}`)
  }

  /**
   * Read the newest import jobs for the "Recent Imports" surface.
   *
   * @param limit - Maximum entries to request (server default 20).
   * @returns The newest-first entries.
   */
  async function fetchRecent(limit = 20): Promise<PcapImportStatus[]> {
    const response = await $fetch<PcapImportList>(BASE_URL, { query: { limit } })
    return response.items ?? []
  }

  /** Read a bounded, producer-filtered domain, retaining its returned-count envelope. */
  async function fetchByState(state: PcapImportActiveState, limit = 200): Promise<PcapImportList> {
    return await $fetch<PcapImportList>(BASE_URL, { query: { limit, state } })
  }

  /**
   * Ask the backend to stop a queued or running import.
   *
   * @param displayId - Public job id.
   * @returns The status envelope after the cancel request.
   */
  async function cancelImport(displayId: string): Promise<PcapImportStatus> {
    return await $fetch<PcapImportStatus>(`${BASE_URL}/${encodeURIComponent(displayId)}/cancel`, { method: 'POST' })
  }

  return { uploadCapture, fetchStatus, fetchRecent, fetchByState, cancelImport }
}
