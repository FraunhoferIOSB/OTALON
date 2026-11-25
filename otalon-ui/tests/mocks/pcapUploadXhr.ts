/** Declared upload-only XHR unit seam; read/cancel requests retain their $fetch doubles. */
import { vi } from 'vitest'

type Options = { method: string; body: FormData }
type Responder = (url: string, options: Options) => unknown

/** Execute each test's existing response oracle through browser-like XHR events. */
export class PcapUploadXHR extends EventTarget {
  static instances: PcapUploadXHR[] = []
  static respond: Responder
  upload = new EventTarget()
  readyState = 0
  status = 0
  statusText = ''
  responseText = ''
  abortCount = 0
  aborted = false
  method = ''
  url = ''
  headers: Record<string, string> = {}

  open(method: string, url: string): void {
    this.method = method
    this.url = url
    this.readyState = 1
  }

  setRequestHeader(name: string, value: string): void {
    this.headers[name] = value
  }

  send(body: FormData): void {
    PcapUploadXHR.instances.push(this)
    let response: unknown
    try {
      response = PcapUploadXHR.respond(this.url, {
        method: this.method,
        body,
        ...(Object.keys(this.headers).length ? { headers: this.headers } : {}),
      })
    } catch (error) {
      this.refuse(error)
      return
    }
    void Promise.resolve(response).then(
      (value) => {
        if (!this.aborted) this.complete(201, value)
      },
      (error: unknown) => {
        if (!this.aborted) this.refuse(error)
      },
    )
  }

  /** A complete response becomes observable before a load/abort/error event. */
  observe(code: number, value: unknown): void {
    this.status = code
    this.responseText = JSON.stringify(value)
    this.readyState = 4
    this.dispatchEvent(new Event('readystatechange'))
  }

  complete(code: number, value: unknown): void {
    this.observe(code, value)
    this.dispatchEvent(new Event('load'))
    this.dispatchEvent(new Event('loadend'))
  }

  failNetwork(): void {
    this.status = 0
    this.responseText = ''
    this.dispatchEvent(new Event('error'))
    this.dispatchEvent(new Event('loadend'))
  }

  abort(): void {
    this.abortCount++
    this.aborted = true
    this.status = 0
    this.responseText = ''
    this.readyState = 0
    this.dispatchEvent(new Event('abort'))
    this.dispatchEvent(new Event('loadend'))
  }

  private refuse(error: unknown): void {
    if (typeof error === 'object' && error !== null && 'status' in error && typeof error.status === 'number') {
      const payload = 'data' in error ? error.data : 'detail' in error ? { detail: error.detail } : error
      this.complete(error.status, payload)
    } else this.failNetwork()
  }
}

/** Install an explicitly synthetic event transport without replacing production modules. */
export function installPcapUploadXHR(respond: Responder): void {
  PcapUploadXHR.instances = []
  PcapUploadXHR.respond = respond
  vi.stubGlobal('XMLHttpRequest', PcapUploadXHR)
}
