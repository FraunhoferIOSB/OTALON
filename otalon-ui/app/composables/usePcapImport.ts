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
  | 'unsupported'
  | 'too-large'
  | 'conflict'
  | 'unauthorized'
  | 'malformed'
  | 'unknown'

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
}

/** Return type of {@link usePcapImport}. */
export interface UsePcapImportReturn {
  uploadCapture: (file: File, options?: UploadCaptureOptions) => Promise<PcapImportAccepted>
  fetchStatus: (displayId: string) => Promise<PcapImportStatus>
  fetchRecent: (limit?: number) => Promise<PcapImportStatus[]>
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
   * @throws The raw fetch error; pass it through {@link toRejection}.
   */
  async function uploadCapture(file: File, options?: UploadCaptureOptions): Promise<PcapImportAccepted> {
    const form = new FormData()
    // The API identifies the capture part by the presence of a filename in
    // its Content-Disposition, not by the field name.
    form.append('file', file, file.name)
    if (options?.force) {
      form.append('force', 'true')
    }
    // No explicit Content-Type: the browser must set the multipart boundary.
    return await $fetch<PcapImportAccepted>(BASE_URL, { method: 'POST', body: form })
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

  /**
   * Ask the backend to stop a queued or running import.
   *
   * @param displayId - Public job id.
   * @returns The status envelope after the cancel request.
   */
  async function cancelImport(displayId: string): Promise<PcapImportStatus> {
    return await $fetch<PcapImportStatus>(`${BASE_URL}/${encodeURIComponent(displayId)}/cancel`, { method: 'POST' })
  }

  return { uploadCapture, fetchStatus, fetchRecent, cancelImport }
}
