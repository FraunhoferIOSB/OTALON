/**
 * Tests for the shared SSE disconnect-propagation helper
 * (`server/utils/sseProxy.ts`, UI-083).
 *
 * These assert the behaviour that fixes the connection-count leak: the
 * client-disconnect `AbortController` fires on the raw request `close` event,
 * aborts at most once (no double-abort of the upstream fetch), detaches its
 * listeners, aborts eagerly when the request is already gone at wire-up, and
 * that `streamUpstreamSse` pipes the upstream body through, forwards
 * buffering-disabled SSE headers, and aborts the client-disconnect controller
 * when the downstream stream is cancelled (browser gone).
 */

import { EventEmitter } from 'node:events'

import type { H3Event } from 'h3'
import { describe, expect, it, vi } from 'vitest'

import { clientDisconnectSignal, streamUpstreamSse } from '~~/server/utils/sseProxy'

class FakeReq extends EventEmitter {
  headers: Record<string, string> = {}
  aborted = false
  destroyed = false
}

function makeEvent(req: FakeReq): H3Event {
  return { node: { req } } as unknown as H3Event
}

function makeUpstreamBody(chunks: Uint8Array[]): ReadableStream<Uint8Array> {
  let i = 0
  return new ReadableStream<Uint8Array>({
    pull(controller) {
      if (i < chunks.length) {
        controller.enqueue(chunks[i++])
      } else {
        controller.close()
      }
    },
  })
}

describe('clientDisconnectSignal — wiring', () => {
  it('aborts when the request emits close', () => {
    const req = new FakeReq()
    const { signal } = clientDisconnectSignal(makeEvent(req))
    expect(signal.aborted).toBe(false)
    req.emit('close')
    expect(signal.aborted).toBe(true)
  })

  it('aborts when the request emits aborted', () => {
    const req = new FakeReq()
    const { signal } = clientDisconnectSignal(makeEvent(req))
    req.emit('aborted')
    expect(signal.aborted).toBe(true)
  })

  it('aborts at most once across close + manual abort (no double-abort)', () => {
    const req = new FakeReq()
    const disconnect = clientDisconnectSignal(makeEvent(req))
    const onAbort = vi.fn()
    disconnect.signal.addEventListener('abort', onAbort)
    req.emit('close')
    disconnect.abort()
    req.emit('close')
    expect(onAbort).toHaveBeenCalledTimes(1)
  })

  it('detaches the close/aborted listeners after settling', () => {
    const req = new FakeReq()
    const disconnect = clientDisconnectSignal(makeEvent(req))
    expect(req.listenerCount('close')).toBe(1)
    expect(req.listenerCount('aborted')).toBe(1)
    disconnect.detach()
    expect(req.listenerCount('close')).toBe(0)
    expect(req.listenerCount('aborted')).toBe(0)
  })

  it('detach does not abort (normal completion path)', () => {
    const req = new FakeReq()
    const disconnect = clientDisconnectSignal(makeEvent(req))
    disconnect.detach()
    req.emit('close')
    expect(disconnect.signal.aborted).toBe(false)
  })

  it('aborts eagerly when the request is already aborted at wire-up', () => {
    const req = new FakeReq()
    req.aborted = true
    const { signal } = clientDisconnectSignal(makeEvent(req))
    expect(signal.aborted).toBe(true)
    // No listener should linger when it aborted synchronously.
    expect(req.listenerCount('close')).toBe(0)
  })

  it('does NOT abort eagerly for a consumed (destroyed) POST body request', () => {
    // A POST request stream is already `destroyed` once its body is read; that
    // is normal body completion, not a client disconnect. Keying off it would
    // abort the upstream fetch before it started (regression: chat 502).
    const req = new FakeReq()
    req.destroyed = true
    const disconnect = clientDisconnectSignal(makeEvent(req))
    expect(disconnect.signal.aborted).toBe(false)
    // The close listener is still armed so a real later disconnect aborts.
    expect(req.listenerCount('close')).toBe(1)
    req.emit('close')
    expect(disconnect.signal.aborted).toBe(true)
  })

  it('tolerates an event without a raw request', () => {
    const disconnect = clientDisconnectSignal({ node: {} } as unknown as H3Event)
    expect(disconnect.signal.aborted).toBe(false)
    // abort / detach must not throw with no request to detach from.
    expect(() => disconnect.abort()).not.toThrow()
  })
})

describe('streamUpstreamSse — piping + headers', () => {
  it('forwards buffering-disabled SSE headers and default status', async () => {
    const req = new FakeReq()
    const disconnect = clientDisconnectSignal(makeEvent(req))
    const body = makeUpstreamBody([new TextEncoder().encode('event: ping\ndata: {}\n\n')])
    const res = streamUpstreamSse(body, disconnect)
    expect(res).toBeInstanceOf(Response)
    expect(res.status).toBe(200)
    expect(res.headers.get('content-type')).toBe('text/event-stream')
    expect(res.headers.get('cache-control')).toBe('no-cache')
    expect(res.headers.get('x-accel-buffering')).toBe('no')
  })

  it('forwards the upstream status and content-type override', () => {
    const req = new FakeReq()
    const disconnect = clientDisconnectSignal(makeEvent(req))
    const body = makeUpstreamBody([new Uint8Array([1])])
    const res = streamUpstreamSse(body, disconnect, 206, 'Partial', 'text/event-stream; charset=utf-8')
    expect(res.status).toBe(206)
    expect(res.headers.get('content-type')).toBe('text/event-stream; charset=utf-8')
  })

  it('pipes upstream chunks through to the client stream', async () => {
    const req = new FakeReq()
    const disconnect = clientDisconnectSignal(makeEvent(req))
    const payload = 'event: status\ndata: {"phase":"running"}\n\n'
    const body = makeUpstreamBody([new TextEncoder().encode(payload)])
    const res = streamUpstreamSse(body, disconnect)
    const text = await res.text()
    expect(text).toBe(payload)
    // Normal end detaches the disconnect listener.
    expect(req.listenerCount('close')).toBe(0)
  })

  it('aborts the client-disconnect controller when the client stream is cancelled', async () => {
    const req = new FakeReq()
    const disconnect = clientDisconnectSignal(makeEvent(req))
    // Never-ending upstream so cancel is the only way it stops.
    const body = new ReadableStream<Uint8Array>({
      pull(controller) {
        controller.enqueue(new TextEncoder().encode('data: keep-alive\n\n'))
      },
    })
    const res = streamUpstreamSse(body, disconnect)
    const reader = res.body!.getReader()
    await reader.read()
    await reader.cancel()
    expect(disconnect.signal.aborted).toBe(true)
  })
})
