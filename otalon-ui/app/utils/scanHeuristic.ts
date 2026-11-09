import type { DeviceItem } from '~/types/api'

/**
 * Return the primary IPv4 address for a device: the first interface's
 * ``ipv4_address``, or ``null`` when the device, its interfaces, or the first
 * interface's address is missing.
 *
 * Exported because both the scan heuristic and the modal prefill logic need the
 * same extraction rule.
 *
 * @param device - Target device. May be null/undefined.
 * @returns First interface IPv4 address, or null.
 */
export function primaryIpOf(device: DeviceItem | null | undefined): string | null {
  const iface = device?.interfaces?.[0]
  return iface?.ipv4_address ?? null
}

/**
 * Result of the module-recommendation heuristic.
 */
export interface HeuristicResult {
  /** Recommended module name (e.g. ``opcua_discover``). */
  module: string
  /** Human-readable one-sentence reason for the recommendation. */
  reason: string
  /** Prefilled target IP derived from the device's first interface (single-device only). */
  targetIp: string | null
  /** Prefilled subnet derived from the device's first interface (single-device only). */
  targetSubnet: string | null
}

const OPC_UA_PORT = 4840
const SNMP_PORT = 161

/**
 * Inspect a single device's ``open_ports_summary`` and return the best-fitting
 * active-scan module + prefill values.
 *
 * Rules (port-based):
 * - OPC-UA port 4840 open → ``opcua_discover``
 * - SNMP port 161 open → ``snmp_scan``
 * - else → ``port_scan`` (fallback)
 *
 * Target IP is taken from ``interfaces[0].ipv4_address`` when available.
 *
 * @param device - The target device. May be null/undefined.
 * @returns Heuristic result. On missing device the fallback is ``port_scan``
 *   with no prefill.
 */
function recommendForDevice(device: DeviceItem | null | undefined): HeuristicResult {
  const iface = device?.interfaces?.[0]
  const ip = primaryIpOf(device)
  const ports = iface?.open_ports_summary ?? []

  const hasOpcUa = ports.some((p) => p.port === OPC_UA_PORT)
  const hasSnmp = ports.some((p) => p.port === SNMP_PORT)

  if (hasOpcUa) {
    return { module: 'opcua_discover', reason: `Port ${OPC_UA_PORT} (OPC-UA) open`, targetIp: ip, targetSubnet: null }
  }
  if (hasSnmp) {
    return { module: 'snmp_scan', reason: `Port ${SNMP_PORT} (SNMP) open`, targetIp: ip, targetSubnet: null }
  }
  return {
    module: 'port_scan',
    reason: 'No specific port signal — fallback port scan',
    targetIp: ip,
    targetSubnet: null,
  }
}

/**
 * Recommend a subnet-wide scan module for multi-target / "scan all" mode.
 *
 * Rules:
 * - If ``hasProfinetInSubnet`` is true → ``pn_discovery``
 * - Else → ``arp_scan``
 *
 * @param hasProfinetInSubnet - Whether PROFINET has ever been passively observed
 *   in the target subnet. The caller derives this from topology data.
 * @returns Heuristic result with no IP prefill (subnet scans need CIDR instead).
 */
function recommendForSubnet(hasProfinetInSubnet: boolean): HeuristicResult {
  if (hasProfinetInSubnet) {
    return { module: 'pn_discovery', reason: 'PROFINET observed in subnet', targetIp: null, targetSubnet: null }
  }
  return { module: 'arp_scan', reason: 'No PROFINET signal — fallback ARP scan', targetIp: null, targetSubnet: null }
}

/**
 * Compute a module recommendation based on scan context.
 *
 * - **Single device** (``devices.length === 1``): port-based heuristic.
 * - **Multi / "scan all"** (``devices.length !== 1``): subnet-wide heuristic.
 *
 * The ``hasProfinetInSubnet`` flag is ignored for single-device mode.
 *
 * @param devices - Target device list (may be empty/null).
 * @param hasProfinetInSubnet - Topology-derived PROFINET signal for subnet mode.
 * @returns Recommendation + prefill values. Never throws.
 */
export function computeScanHeuristic(
  devices: DeviceItem[] | null | undefined,
  hasProfinetInSubnet = false,
): HeuristicResult {
  const list = devices ?? []
  if (list.length === 1) {
    return recommendForDevice(list[0] ?? null)
  }
  return recommendForSubnet(hasProfinetInSubnet)
}
