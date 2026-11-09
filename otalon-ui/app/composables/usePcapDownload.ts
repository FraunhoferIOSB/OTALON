/**
 * Structured error raised by {@link usePcapDownload} when the backend
 * rejects the request. Mirrors the relevant fields of the more general
 * {@link import('./useApi').ApiError} surface but keeps this composable
 * free of cross-imports.
 */
export interface PcapDownloadError {
  status: number
  message: string
}

/**
 * Return type for {@link usePcapDownload}.
 */
export interface UsePcapDownloadReturn {
  /**
   * Fetch the PCAP-bundle ZIP for an alarm group.
   *
   * Hits ``GET /api/v1/pcap/by-alarm/{alarmId}/zip`` and returns the
   * response body as a {@link Blob}. Throws {@link PcapDownloadError}
   * on any non-2xx response so the caller can map status codes to
   * user-facing toasts.
   *
   * @param alarmId - Anomaly-group id.
   * @returns Blob containing the streamed ``application/zip``.
   */
  fetchAlarmPcapZip: (alarmId: string) => Promise<Blob>
  /**
   * Trigger a browser-initiated file download for a Blob.
   *
   * Wrapped in a separate function so that component tests can stub
   * the side-effects (``URL.createObjectURL`` + temporary `<a>` click)
   * without touching the real DOM.
   *
   * @param blob - File payload.
   * @param filename - Suggested filename presented to the operator.
   */
  triggerBrowserDownload: (blob: Blob, filename: string) => void
}

/**
 * Composable that wraps the PCAP-by-alarm ZIP endpoint.
 *
 * The endpoint returns ``application/zip`` (streamed), so we cannot
 * route it through {@link import('./useApi').useApi} which always
 * decodes JSON. ``$fetch`` with ``responseType: 'blob'`` keeps us on
 * Nuxt's standard transport while preserving binary integrity.
 *
 * @example
 * ```ts
 * const { fetchAlarmPcapZip, triggerBrowserDownload } = usePcapDownload()
 * const blob = await fetchAlarmPcapZip(alarmId)
 * triggerBrowserDownload(blob, `alarm-${alarmId}-pcap.zip`)
 * ```
 */
export function usePcapDownload(): UsePcapDownloadReturn {
  async function fetchAlarmPcapZip(alarmId: string): Promise<Blob> {
    try {
      const blob = await $fetch<Blob>(`/api/v1/pcap/by-alarm/${encodeURIComponent(alarmId)}/zip`, {
        method: 'GET',
        responseType: 'blob',
      })
      return blob
    } catch (error: unknown) {
      if (
        error &&
        typeof error === 'object' &&
        'response' in error &&
        (error as { response?: { status?: number } }).response
      ) {
        const fetchError = error as {
          response: { status: number; statusText?: string }
        }
        const err: PcapDownloadError = {
          status: fetchError.response.status,
          message: fetchError.response.statusText ?? 'Request failed',
        }
        throw err
      }
      if (error instanceof Error) {
        const err: PcapDownloadError = { status: 0, message: error.message }
        throw err
      }
      const err: PcapDownloadError = { status: 0, message: 'Unknown error' }
      throw err
    }
  }

  function triggerBrowserDownload(blob: Blob, filename: string): void {
    const url = URL.createObjectURL(blob)
    try {
      const anchor = document.createElement('a')
      anchor.href = url
      anchor.download = filename
      document.body.appendChild(anchor)
      anchor.click()
      document.body.removeChild(anchor)
    } finally {
      URL.revokeObjectURL(url)
    }
  }

  return { fetchAlarmPcapZip, triggerBrowserDownload }
}
