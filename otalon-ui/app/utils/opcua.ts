/**
 * Parse OPC-UA endpoint fields from raw backend objects.
 *
 * Normalises multiple upstream naming conventions into a canonical
 * ``OpcUaEndpoint`` shape used by the UI renderer.
 */

export interface OpcUaEndpoint {
  url: string
  applicationUri: string
  applicationName: string
  securityMode: string
  securityPolicy: string
  securityLevel: number
}

/**
 * Map an endpoint object (from backend JSON) into the canonical shape.
 */
export function parseOpcUaEndpoint(obj: Record<string, unknown>): OpcUaEndpoint {
  const url = String(obj['Endpoint URL'] ?? obj['Discovery URL'] ?? obj.endpoint_url ?? obj.url ?? '')
  const applicationUri = String(obj['Application URI'] ?? obj.application_uri ?? '')
  const applicationName = String(obj['Application Name'] ?? obj.application_name ?? '')
  const rawMode = String(obj['Security Mode'] ?? obj['SecurityMode'] ?? obj.security_mode ?? '')
  const securityMode = normalizeSecurityMode(rawMode)
  const securityPolicy = String(obj['Security Policy'] ?? obj['SecurityPolicy'] ?? obj.security_policy ?? '')
  const securityLevel = Number(obj['Security Level'] ?? obj['SecurityLevel'] ?? obj.security_level ?? 0)
  return { url, applicationUri, applicationName, securityMode, securityPolicy, securityLevel }
}

function normalizeSecurityMode(raw: string): string {
  const trimmed = raw.trim()
  const lower = trimmed.toLowerCase()
  if (lower === '1' || lower === 'none') return 'None'
  if (lower === '2' || lower === 'sign') return 'Sign'
  if (lower === '3' || lower === 'signandencrypt') return 'SignAndEncrypt'
  return trimmed
}

/**
 * Extract OPC-UA endpoints from a scan finding's ``extra`` blob.
 *
 * Supports both ``extra.endpoints`` (array) and ``extra.endpoint`` (single).
 */
export function extractEndpointsFromExtra(extra: Record<string, unknown> | null | undefined): OpcUaEndpoint[] {
  if (!extra || typeof extra !== 'object') return []
  const endpoints = extra.endpoints
  if (Array.isArray(endpoints)) {
    return endpoints
      .filter((e): e is Record<string, unknown> => e !== null && typeof e === 'object')
      .map(parseOpcUaEndpoint)
  }
  const single = extra.endpoint
  if (single !== null && typeof single === 'object') {
    return [parseOpcUaEndpoint(single as Record<string, unknown>)]
  }
  return []
}

/**
 * Extract OPC-UA endpoints from a JSON string (e.g. ``extra_info`` column).
 */
export function extractEndpointsFromJsonString(text: string | null | undefined): OpcUaEndpoint[] {
  if (!text) return []
  try {
    const parsed = JSON.parse(text)
    if (Array.isArray(parsed)) {
      return parsed
        .filter((e): e is Record<string, unknown> => e !== null && typeof e === 'object')
        .map(parseOpcUaEndpoint)
    }
    if (parsed !== null && typeof parsed === 'object') {
      return [parseOpcUaEndpoint(parsed as Record<string, unknown>)]
    }
  } catch {
    // Not valid JSON — no endpoints to extract.
  }
  return []
}
