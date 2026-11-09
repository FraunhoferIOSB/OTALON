import type { DeviceItem } from '~/types/api'

/**
 * Shared formatting utilities for dates, times, and numbers.
 *
 * Uses a consistent locale (en-US) across all components to avoid
 * mixed locale formatting in the UI.
 */

const LOCALE = 'en-US'

/**
 * Parse an ISO 8601 timestamp returned by the backend API.
 *
 * The OTALON backend serializes ``datetime`` objects as naive ISO
 * strings in the configured local timezone (e.g. ``"2026-05-08T16:24:00"``
 * for Europe/Berlin during CEST). The JavaScript ``Date`` constructor
 * already interprets such strings as local time, so this helper is a
 * thin wrapper that exists for two reasons:
 *
 * 1. **Documentation** – every call site that handles API timestamps is
 *    explicitly tagged so the timezone convention is discoverable.
 * 2. **Forward compatibility** – if the backend ever switches to UTC
 *    serialization with an explicit ``Z`` suffix, the helper transparently
 *    handles both forms because ``Date`` honors any offset that is present.
 *
 * @param iso - ISO 8601 timestamp string from the API.
 * @returns A {@link Date} instance reflecting the absolute instant.
 */
export function parseApiTimestamp(iso: string): Date {
  if (!iso) return new Date(NaN)
  return new Date(iso)
}

/**
 * Format an ISO datetime string to a readable locale representation.
 *
 * @param isoString - ISO 8601 timestamp or null.
 * @param fallback - Text to show when the input is null/empty. Defaults to "—".
 * @returns Formatted date-time string in the browser's local timezone.
 */
export function formatDateTime(isoString: string | null, fallback: string = '—'): string {
  if (!isoString) return fallback
  const d = parseApiTimestamp(isoString)
  return d.toLocaleString(LOCALE, {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  })
}

/**
 * Format an ISO datetime string to a short date-time without seconds.
 *
 * @param isoString - ISO 8601 timestamp or null.
 * @param fallback - Text to show when the input is null/empty. Defaults to "—".
 * @returns Formatted short date-time string in the browser's local timezone.
 */
export function formatDateTimeShort(isoString: string | null, fallback: string = '—'): string {
  if (!isoString) return fallback
  const d = parseApiTimestamp(isoString)
  return d.toLocaleString(LOCALE, {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  })
}

/**
 * Format an ISO date string to a short date representation.
 *
 * @param isoString - ISO 8601 date or null.
 * @returns Formatted date string in the browser's local timezone.
 */
export function formatDate(isoString: string | null): string {
  if (!isoString) return '—'
  const d = parseApiTimestamp(isoString)
  return d.toLocaleDateString(LOCALE, {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
  })
}

/**
 * Format a number with locale-aware thousand separators.
 *
 * @param value - Numeric value to format.
 * @returns Formatted number string.
 */
export function formatNumber(value: number): string {
  return value.toLocaleString(LOCALE)
}

/**
 * Format a Unix timestamp (seconds) to a readable locale string.
 *
 * @param ts - Unix timestamp in seconds.
 * @returns Formatted date-time string.
 */
export function formatTimestamp(ts: number): string {
  if (!ts) return '—'
  const d = new Date(ts * 1000)
  return d.toLocaleString(LOCALE, {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  })
}

/**
 * Format a byte count to a human-readable string with appropriate unit.
 *
 * @param bytes - Number of bytes.
 * @param decimals - Number of decimal places. Defaults to 1.
 * @returns Formatted string like "12.4 MB" or "0 B".
 */
export function formatBytes(bytes: number, decimals: number = 1): string {
  if (bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB']
  const i = Math.floor(Math.log(Math.abs(bytes)) / Math.log(k))
  const index = Math.min(i, sizes.length - 1)
  return `${(bytes / Math.pow(k, index)).toFixed(decimals)} ${sizes[index]}`
}

const BROADCAST_MAC = 'ff:ff:ff:ff:ff:ff'

/**
 * Normalize a MAC address for case- and separator-insensitive comparison.
 *
 * Strips all non-hex characters and lower-cases the result so
 * ``aa:bb:cc:dd:ee:ff``, ``AA-BB-CC-DD-EE-FF`` and ``aabbccddeeff`` compare equal.
 *
 * @param mac - Raw MAC string.
 * @returns Normalized hex string, e.g. ``aabbccddeeff``.
 */
export function normalizeMac(mac: string): string {
  return mac.toLowerCase().replace(/[^0-9a-f]/g, '')
}

/**
 * Format a raw UCI string into a human-readable connection label.
 *
 * UCI format: `src_mac/dst_mac/vlan/ip_proto/src_ip/dst_ip/src_port/dst_port/protocols`
 *
 * Display logic:
 * - Uses IP addresses when available, otherwise full MAC addresses.
 * - Broadcast MAC (ff:ff:ff:ff:ff:ff) is displayed as "Broadcast".
 * - Protocol is the last segment of the protocol chain (e.g. "PROFINET_RT_IO"
 *   instead of "Ethernet:VLAN:PROFINET_RT:PROFINET_RT_IO").
 *
 * @param uci - Raw UCI string.
 * @returns Human-readable label like "192.168.0.1 → 192.168.0.2 · TCP"
 *          or "30:b8:51:31:06:84 → 00:01:05:2b:ae:a2 · PROFINET_RT_IO".
 */
export function formatUci(uci: string): string {
  const parts = uci.split('/')
  if (parts.length < 9) return uci

  const [srcMac, dstMac, , , srcIp, dstIp, , , protocols] = parts

  const hasIp = srcIp !== '' && dstIp !== ''
  let src: string
  let dst: string

  if (hasIp) {
    src = srcIp
    dst = dstIp
  } else {
    src = srcMac.toLowerCase() === BROADCAST_MAC ? 'Broadcast' : srcMac
    dst = dstMac.toLowerCase() === BROADCAST_MAC ? 'Broadcast' : dstMac
  }

  const protoChain = protocols || ''
  const proto = protoChain.split(':').pop() || protoChain

  return `${src} → ${dst} · ${proto}`
}

/**
 * Decide whether a device's most recent scan timestamp counts as "online".
 *
 * A device is considered online when the last scan happened within the
 * configured grace period (default: one hour).
 */
export function isRecent(timestamp: string | null, graceMinutes: number = 60): boolean {
  if (!timestamp) return false
  const t = new Date(timestamp).getTime()
  if (Number.isNaN(t)) return false
  return Date.now() - t <= graceMinutes * 60_000
}

/**
 * Format an ISO timestamp as a relative time string.
 *
 * Returns "just now" for < 60s, "Xm ago" for < 1h, "Xh ago" for < 1d, "Xd ago" for >= 1d.
 */
export function formatRelativeTime(isoString: string): string {
  const now = Date.now()
  const then = parseApiTimestamp(isoString).getTime()
  const diffSeconds = Math.floor((now - then) / 1000)
  if (diffSeconds < 60) return 'just now'
  if (diffSeconds < 3600) return `${Math.floor(diffSeconds / 60)}m ago`
  if (diffSeconds < 86400) return `${Math.floor(diffSeconds / 3600)}h ago`
  return `${Math.floor(diffSeconds / 86400)}d ago`
}

/**
 * Check whether a raw series identifier looks like a MAC address.
 *
 * Accepts colon- or hyphen-separated hex octets.
 *
 * @param id - Raw identifier string.
 * @returns `true` when the string matches a MAC address pattern.
 */
export function isMacAddress(id: string): boolean {
  return /^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$/.test(id)
}

/**
 * Return whether a MAC address is multicast or broadcast rather than unicast.
 *
 * The I/G bit is the least-significant bit of the first octet: when it is
 * set the address is a group (multicast) address, with
 * ``ff:ff:ff:ff:ff:ff`` being the broadcast address. Such addresses do not
 * identify a device and must not be offered as a navigable asset.
 *
 * @param id - Raw identifier string.
 * @returns `true` when the value is a MAC address that is not unicast.
 */
export function isNonUnicastMac(id: string): boolean {
  if (!isMacAddress(id)) return false
  const firstOctet = Number.parseInt(id.slice(0, 2), 16)
  return (firstOctet & 1) === 1
}

/**
 * Resolve the best human-readable label for a MAC asset from device inventory.
 *
 * Priority: product_name / description / vendor  >  interface ipv4  >  MAC.
 *
 * @param mac - The raw MAC address.
 * @param devices - Device inventory from the topology endpoint.
 * @returns Display string (name, ip, or the original MAC).
 */
export function resolveAssetDisplay(mac: string, devices: DeviceItem[]): string {
  const normId = normalizeMac(mac)
  for (const device of devices) {
    const iface = device.interfaces.find((i) => normalizeMac(i.mac_address ?? '') === normId)
    if (!iface) continue
    const name = device.product_name || device.description || device.vendor
    if (name) return name
    const ip = iface.ipv4_address
    if (ip) return ip
    break
  }
  return mac
}
