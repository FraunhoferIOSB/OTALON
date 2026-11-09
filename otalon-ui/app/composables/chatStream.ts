/**
 * Pure, testable SSE stream parser for the chat streaming endpoint.
 *
 * Consumes a :class:`ReadableStreamDefaultReader` and invokes a
 * callback for each JSON event envelope.  Malformed frames are
 * skipped with a warning — the parser never throws.
 */

export interface SseEvent {
  type: string
  [key: string]: unknown
}

/**
 * Read an SSE stream line-by-line and emit parsed JSON events.
 *
 * @param reader - The ReadableStream reader from a fetch response.
 * @param onEvent - Called for every successfully parsed event.
 */
export async function parseSseStream(
  reader: ReadableStreamDefaultReader<Uint8Array>,
  onEvent: (evt: SseEvent) => void,
): Promise<void> {
  const decoder = new TextDecoder()
  let buffer = ''

  while (true) {
    const { done, value } = await reader.read()
    if (value) {
      buffer += decoder.decode(value, { stream: !done })
    }

    // Split on double-newline (SSE frame boundary).
    let boundary: number
    while ((boundary = buffer.indexOf('\n\n')) !== -1) {
      const frame = buffer.slice(0, boundary)
      buffer = buffer.slice(boundary + 2)
      _processFrame(frame, onEvent)
    }

    if (done) {
      // Process any trailing frame without a trailing double-newline.
      if (buffer.trim()) {
        _processFrame(buffer, onEvent)
      }
      break
    }
  }
}

function _processFrame(frame: string, onEvent: (evt: SseEvent) => void): void {
  const dataLines: string[] = []
  for (const line of frame.split('\n')) {
    if (line.startsWith('data: ')) {
      dataLines.push(line.slice(6))
    }
  }
  if (dataLines.length === 0) return
  const payload = dataLines.join('\n')
  try {
    const parsed = JSON.parse(payload) as SseEvent
    onEvent(parsed)
  } catch {
    if (typeof console !== 'undefined' && console.warn) {
      console.warn(' chatStream: malformed SSE frame skipped')
    }
  }
}
