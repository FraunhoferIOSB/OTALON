/**
 * Client-side mirror of the backend's `proto_series_hash`.
 *
 * The Protocols page selects a READABLE protocol stack (since API-011
 * `GET /api/v1/timeseries/proto/ids` returns e.g. `"Ethernet:LLDP"` as
 * the row id), but the detection pipeline persists `proto_traffic`
 * rows — including `frequency_profiles.series_id` — under a stable hash
 * of that stack. Endpoints that were built for the Protocols page
 * translate server-side (see `get_proto_anomaly_intervals`, which calls
 * `proto_series_hash(series_id)`), but `GET /api/v1/frequency/profile`
 * matches `series_id` verbatim, so a readable stack sent there resolves
 * to `has_profile: false` for every protocol.
 *
 * Source of truth: `otalon-api/src/domain/netcap/models.py`
 * (`proto_series_hash`, `_PROTO_HASH_MODULUS`):
 *
 *     digest = hashlib.sha1(protocol.encode("utf-8")).digest()
 *     return str(int.from_bytes(digest[:8], "big") % 2**31)
 *
 * Reimplementing a backend invariant in a second language is a drift
 * hazard, so `tests/utils/protoHash.test.ts` pins the exact vectors
 * observed in the live `frequency_profiles` table. Should the backend
 * ever change the encoding, that test fails loudly instead of the lane
 * silently reporting "No profile".
 *
 * `crypto.subtle` is deliberately NOT used: it is only defined in a
 * secure context, and this UI is served over plain HTTP from a LAN IP
 * (same constraint documented in `utils/uuid.ts`). The digest is
 * therefore computed synchronously in pure TypeScript.
 */

/** Modulus applied to the truncated digest, mirroring `2**31`. */
const PROTO_HASH_MODULUS = 2n ** 31n

/**
 * Rotate a 32-bit word left, keeping the result unsigned.
 *
 * @param value - The 32-bit word to rotate.
 * @param shift - Number of bits to rotate by.
 * @returns The rotated word as an unsigned 32-bit number.
 */
function rotateLeft(value: number, shift: number): number {
  return ((value << shift) | (value >>> (32 - shift))) >>> 0
}

/**
 * Compute the SHA-1 digest of a byte sequence.
 *
 * A local implementation is required because the Web Crypto API is
 * unavailable in the non-secure contexts this UI is served from.
 *
 * @param bytes - The message to digest.
 * @returns The 20-byte SHA-1 digest.
 */
function sha1(bytes: Uint8Array): Uint8Array {
  const bitLength = bytes.length * 8
  // Message + 0x80 terminator + zero padding to 56 mod 64 + 8-byte length.
  const paddedLength = (((bytes.length + 8) >> 6) + 1) << 6
  const block = new Uint8Array(paddedLength)
  block.set(bytes)
  block[bytes.length] = 0x80

  const view = new DataView(block.buffer)
  // The length field is 64-bit; messages here are far below 2^32 bits,
  // so the high word stays zero.
  view.setUint32(paddedLength - 4, bitLength >>> 0, false)
  view.setUint32(paddedLength - 8, Math.floor(bitLength / 2 ** 32), false)

  let h0 = 0x67452301
  let h1 = 0xefcdab89
  let h2 = 0x98badcfe
  let h3 = 0x10325476
  let h4 = 0xc3d2e1f0

  const words = new Uint32Array(80)

  for (let offset = 0; offset < paddedLength; offset += 64) {
    for (let i = 0; i < 16; i++) {
      words[i] = view.getUint32(offset + i * 4, false)
    }
    for (let i = 16; i < 80; i++) {
      words[i] = rotateLeft(words[i - 3]! ^ words[i - 8]! ^ words[i - 14]! ^ words[i - 16]!, 1)
    }

    let a = h0
    let b = h1
    let c = h2
    let d = h3
    let e = h4

    for (let i = 0; i < 80; i++) {
      let f: number
      let k: number
      if (i < 20) {
        f = (b & c) | (~b & d)
        k = 0x5a827999
      } else if (i < 40) {
        f = b ^ c ^ d
        k = 0x6ed9eba1
      } else if (i < 60) {
        f = (b & c) | (b & d) | (c & d)
        k = 0x8f1bbcdc
      } else {
        f = b ^ c ^ d
        k = 0xca62c1d6
      }
      const temp = (rotateLeft(a, 5) + f + e + k + words[i]!) >>> 0
      e = d
      d = c
      c = rotateLeft(b, 30)
      b = a
      a = temp
    }

    h0 = (h0 + a) >>> 0
    h1 = (h1 + b) >>> 0
    h2 = (h2 + c) >>> 0
    h3 = (h3 + d) >>> 0
    h4 = (h4 + e) >>> 0
  }

  const digest = new Uint8Array(20)
  const digestView = new DataView(digest.buffer)
  digestView.setUint32(0, h0, false)
  digestView.setUint32(4, h1, false)
  digestView.setUint32(8, h2, false)
  digestView.setUint32(12, h3, false)
  digestView.setUint32(16, h4, false)
  return digest
}

/**
 * Hash a protocol stack to the series identifier the detector persists.
 *
 * @param protocol - Protocol-stack string, e.g. `"Ethernet:ARP"`.
 * @returns The stringified hash matching the persisted `series_id`.
 */
export function protoSeriesHash(protocol: string): string {
  const digest = sha1(new TextEncoder().encode(protocol))
  let value = 0n
  for (let i = 0; i < 8; i++) {
    value = (value << 8n) | BigInt(digest[i]!)
  }
  return (value % PROTO_HASH_MODULUS).toString()
}

/**
 * Resolve a Protocols-page row id to the detector's frequency series key.
 *
 * Rows may carry either representation depending on the endpoint
 * version (the same defensiveness `utils/proto-match.ts` applies to
 * alarm correlation), so an id that is already a numeric hash is passed
 * through unchanged rather than being hashed a second time.
 *
 * @param id - The row id selected on the Protocols page.
 * @returns The identifier to query `GET /api/v1/frequency/profile` with.
 */
export function protoFrequencySeriesId(id: string): string {
  if (!id) return id
  if (/^\d+$/.test(id)) return id
  return protoSeriesHash(id)
}

/**
 * Protocol stacks the capture pipeline is known to emit.
 *
 * Used as a fallback when resolving a hash whose stack is not in the page's
 * currently loaded window — a protocol that has been silent for a while is
 * exactly the case the SILENT toggle exists for, yet it is by definition
 * missing from the live list (UI-093). Read from the live
 * `timeseries/proto/ids` endpoint over an eight-day window on 2026-07-27.
 *
 * An unknown stack simply falls through to the raw id, so an incomplete list
 * degrades to the previous behaviour rather than showing a wrong name.
 */
const WELL_KNOWN_PROTOCOL_STACKS: readonly string[] = [
  'Ethernet:ARP',
  'Ethernet:IPv4:ICMP',
  'Ethernet:IPv4:IGMPv3',
  'Ethernet:IPv4:TCP',
  'Ethernet:IPv4:TCP:HTTPRequest',
  'Ethernet:IPv4:TCP:HTTPResponse',
  'Ethernet:IPv4:TCP:OPC-UA',
  'Ethernet:IPv4:TCP:SSH',
  'Ethernet:IPv4:UDP',
  'Ethernet:IPv4:UDP:DNS',
  'Ethernet:IPv4:UDP:PROFINET_DCE_RPC',
  'Ethernet:IPv6:ICMPv6',
  'Ethernet:IPv6:UDP',
  'Ethernet:IPv6:UDP:DNS',
  'Ethernet:LLDP',
  'Ethernet:PROFINET_RT',
  'Ethernet:PROFINET_RT:PROFINET_RT_DCP',
  'Ethernet:PROFINET_RT:PROFINET_RT_IO',
  'Ethernet:PROFINET_RT:PROFINET_RT_PTCP',
  'Ethernet:VLAN:PROFINET_RT',
  'Ethernet:VLAN:PROFINET_RT:PROFINET_RT_DCP',
  'Ethernet:VLAN:PROFINET_RT:PROFINET_RT_IO',
]

/**
 * Resolve a persisted numeric series hash back to its readable protocol stack.
 *
 * The hash is one-way, so the readable name cannot be computed from it. The
 * candidate names are hashed instead and the match is looked up — the same
 * trick the Protocols page already uses in the forward direction.
 *
 * Needed because `GET /api/v1/frequency/profiles` keys profiles by hash while
 * the protocol list endpoint returns readable stacks: a profiled-but-silent
 * protocol is absent from the live list, so without this it could only be
 * shown as a bare hash (UI-093).
 *
 * Candidates come from whatever window the page happens to have loaded, so a
 * protocol that fell silent before that window began is not among them. The
 * well-known stacks below are therefore tried as a fallback: they are the
 * standard combinations the capture pipeline emits, and hashing a handful of
 * strings is cheaper than widening every page's query.
 *
 * @param id - A persisted `series_id`, either a numeric hash or already readable.
 * @param candidates - Known readable protocol stacks to match against.
 * @returns The readable protocol stack, or *id* when nothing matches.
 */
export function protoLabelFromSeriesId(id: string, candidates: readonly string[]): string {
  if (!id || !/^\d+$/.test(id)) return id
  for (const candidate of candidates) {
    if (!candidate || /^\d+$/.test(candidate)) continue
    if (protoSeriesHash(candidate) === id) return candidate
  }
  for (const candidate of WELL_KNOWN_PROTOCOL_STACKS) {
    if (protoSeriesHash(candidate) === id) return candidate
  }
  return id
}

/**
 * Convert either protocol id representation to a comparable readable key.
 *
 * @param id - Readable protocol stack or persisted numeric hash.
 * @param candidates - Readable stacks available in the current page state.
 * @returns Readable stack when the hash resolves, otherwise the original id.
 */
export function protoComparisonKey(id: string, candidates: readonly string[]): string {
  return protoLabelFromSeriesId(id, candidates)
}
