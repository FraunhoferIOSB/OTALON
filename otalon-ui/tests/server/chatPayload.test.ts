/**
 * Unit tests for the chat payload builder (UI-076 b/c).
 *
 * (b) OT asset/vuln fields are redacted by default and only pass
 *     through under the documented on-prem-LLM opt-in flag.
 * (c) The UI context travels over exactly one channel —
 *     ``metadata.ui_context_markdown``.
 */
import { afterEach, describe, expect, it } from 'vitest'

import {
  MAX_UI_CONTEXT_BYTES,
  ON_PREM_LLM_CONTEXT_ENV,
  OT_REDACTION_PLACEHOLDER,
  buildChatPayload,
  isOnPremLlmContextEnabled,
  redactOtContext,
} from '~~/server/utils/chatPayload'
import type { UiContext } from '~~/shared/uiContext'

function makeContext(): UiContext {
  return {
    app: { version: '1', locale: 'en', theme: 'dark', timestamp: 'now' },
    route: { path: '/devices', name: 'devices', title: 'Assets', query: {} },
    time: { mode: 'manual', start: 'a', stop: 'b', label: 'range' },
    summary: { total_devices: 12, vulnerability_count: 3 },
    filters: { vendor: 'Siemens', search_term: 'plc' },
    selection: {
      kind: 'asset',
      id: '42',
      label: 'S7-1500',
      fields: {
        vendor: 'Siemens',
        device_family: 'S7-1500',
        firmware_version: 'v2.1',
        primary_ip: '10.0.0.10',
        primary_mac: 'aa:bb:cc:dd:ee:ff',
        vulnerability_count: 3,
      },
    },
    visible_data: [
      {
        name: 'assets_list',
        columns: ['id', 'vendor', 'firmware_version', 'ip', 'mac', 'vulnerability_count'],
        rows: [
          {
            id: 42,
            vendor: 'Siemens',
            firmware_version: 'v2.1',
            ip: '10.0.0.10',
            mac: 'aa:bb:cc:dd:ee:ff',
            vulnerability_count: 3,
          },
        ],
        total_rows: 1,
        showing_rows: 1,
      },
      {
        name: 'asset_vulnerabilities',
        columns: ['vuln_id', 'severity', 'cvss_score'],
        rows: [{ vuln_id: 'CVE-2026-1234', severity: 'high', cvss_score: 9.1 }],
        total_rows: 1,
        showing_rows: 1,
      },
      {
        name: 'asset_opcua_endpoints',
        columns: ['port_transport', 'endpoint_url', 'security_mode'],
        rows: [{ port_transport: '4840/tcp', endpoint_url: 'opc.tcp://10.0.0.10:4840', security_mode: 'None' }],
        total_rows: 1,
        showing_rows: 1,
      },
    ],
  }
}

const OT_VALUES = ['10.0.0.10', 'aa:bb:cc:dd:ee:ff', 'v2.1', 'CVE-2026-1234', 'opc.tcp://']

afterEach(() => {
  process.env[ON_PREM_LLM_CONTEXT_ENV] = ''
})

describe('redactOtContext', () => {
  it('replaces OT identifier values with the placeholder', () => {
    const out = redactOtContext(makeContext()) as UiContext
    expect(out.selection?.fields?.primary_ip).toBe(OT_REDACTION_PLACEHOLDER)
    expect(out.selection?.fields?.primary_mac).toBe(OT_REDACTION_PLACEHOLDER)
    expect(out.selection?.fields?.firmware_version).toBe(OT_REDACTION_PLACEHOLDER)
    expect(out.visible_data?.[0]?.rows[0]?.ip).toBe(OT_REDACTION_PLACEHOLDER)
    expect(out.visible_data?.[0]?.rows[0]?.mac).toBe(OT_REDACTION_PLACEHOLDER)
    expect(out.visible_data?.[1]?.rows[0]?.vuln_id).toBe(OT_REDACTION_PLACEHOLDER)
    expect(out.visible_data?.[2]?.rows[0]?.endpoint_url).toBe(OT_REDACTION_PLACEHOLDER)
  })

  it('leaves non-sensitive context fields untouched', () => {
    const out = redactOtContext(makeContext()) as UiContext
    expect(out.route.path).toBe('/devices')
    expect(out.app.locale).toBe('en')
    expect(out.time.label).toBe('range')
    expect(out.summary?.total_devices).toBe(12)
    expect(out.filters?.vendor).toBe('Siemens')
    expect(out.selection?.label).toBe('S7-1500')
    expect(out.selection?.fields?.device_family).toBe('S7-1500')
    expect(out.visible_data?.[0]?.rows[0]?.vendor).toBe('Siemens')
    expect(out.visible_data?.[1]?.rows[0]?.severity).toBe('high')
  })

  it('preserves keys, structure and null values', () => {
    const out = redactOtContext(makeContext()) as UiContext
    expect(out.visible_data?.[0]?.columns).toEqual([
      'id',
      'vendor',
      'firmware_version',
      'ip',
      'mac',
      'vulnerability_count',
    ])
    expect(out.visible_data?.[0]?.total_rows).toBe(1)
    expect(redactOtContext({ ip: null, mac: undefined })).toEqual({ ip: null, mac: undefined })
  })

  it('passes primitives through unchanged', () => {
    expect(redactOtContext('plain')).toBe('plain')
    expect(redactOtContext(7)).toBe(7)
    expect(redactOtContext(null)).toBe(null)
  })
})

describe('isOnPremLlmContextEnabled', () => {
  it('is false unless the flag is exactly "true"', () => {
    expect(isOnPremLlmContextEnabled()).toBe(false)
    process.env[ON_PREM_LLM_CONTEXT_ENV] = '1'
    expect(isOnPremLlmContextEnabled()).toBe(false)
    process.env[ON_PREM_LLM_CONTEXT_ENV] = 'true'
    expect(isOnPremLlmContextEnabled()).toBe(true)
  })
})

describe('buildChatPayload OT handling', () => {
  it('redacts OT identifiers by default', () => {
    const { payload } = buildChatPayload('status', makeContext(), 'session', [])
    const serialized = JSON.stringify(payload)
    for (const value of OT_VALUES) expect(serialized).not.toContain(value)
    expect(serialized).toContain('Siemens')
    expect(serialized).toContain(OT_REDACTION_PLACEHOLDER)
  })

  it('allows full OT context only with explicit on-prem opt-in', () => {
    process.env[ON_PREM_LLM_CONTEXT_ENV] = 'true'
    const { payload } = buildChatPayload('status', makeContext(), 'session', [])
    const serialized = JSON.stringify(payload)
    for (const value of OT_VALUES) expect(serialized).toContain(value)
    expect(serialized).not.toContain(OT_REDACTION_PLACEHOLDER)
  })
})

describe('buildChatPayload single-channel shape', () => {
  it('sends the context only as metadata.ui_context_markdown', () => {
    const { payload } = buildChatPayload('what is broken?', makeContext(), 'session', [])
    expect(payload.metadata.ui_context_markdown).toContain('## UI Context')
    expect(payload.metadata.ui_context).toBeUndefined()
    expect(payload.message).toBe('what is broken?')
    expect(payload.message).not.toContain('## UI Context')
  })

  it('forwards session, history and source metadata unchanged', () => {
    const history = [{ role: 'user', content: 'hi' }]
    const { payload } = buildChatPayload('hello', undefined, 'session-1', history)
    expect(payload.session_id).toBe('session-1')
    expect(payload.history).toEqual(history)
    expect(payload.metadata.source).toBe('otalon-ui')
  })

  it('omits the context channel entirely when no context is supplied', () => {
    const { payload, uiContextBytes } = buildChatPayload('hello', undefined, 'session', [])
    expect(payload.metadata).toEqual({ source: 'otalon-ui' })
    expect(payload.message).toBe('hello')
    expect(uiContextBytes).toBe(0)
  })

  it('reports the redacted byte count, not the raw one', () => {
    const { uiContextBytes } = buildChatPayload('hello', makeContext(), 'session', [])
    const rawBytes = Buffer.byteLength(JSON.stringify(makeContext()), 'utf8')
    expect(uiContextBytes).toBeGreaterThan(0)
    expect(uiContextBytes).not.toBe(rawBytes)
  })

  it('drops an oversized context but still forwards the message', () => {
    const ctx = makeContext()
    ctx.summary = {}
    for (let i = 0; i < 2000; i++) ctx.summary[`key_${i}`] = 'x'.repeat(80)
    const { payload, uiContextBytes } = buildChatPayload('hello', ctx, 'session', [])
    expect(uiContextBytes).toBeGreaterThan(MAX_UI_CONTEXT_BYTES)
    expect(payload.metadata.ui_context_markdown).toBeUndefined()
    expect(payload.message).toBe('hello')
  })
})
