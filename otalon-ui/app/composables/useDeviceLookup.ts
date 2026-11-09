/**
 * Shared composable for hostname / device-label lookups by MAC or IP.
 *
 * Builds reactive lookup maps from the devices store so that both the
 * MAC-timeseries page (NAME column) and the connections page
 * (SOURCE/DESTINATION labels) resolve human-readable hostnames without
 * touching the backend.
 *
 * @example
 * const labels = useDeviceLookup()
 * const name = labels.nameForMac('00:01:05:2b:ae:a2')
 * const sourceLabel = labels.labelForEndpoint('192.168.1.10', '00:01:05:2b:ae:a2')
 */

import { useDevicesStore } from '~/stores/devicesStore'
import type { DeviceItem } from '~/types/api'

/**
 * Resolved display label information for a single device.
 */
export interface DeviceLabelInfo {
  hostname: string | null
  productName: string | null
  deviceFamily: string | null
}

/**
 * Return the best human-readable name for a device object.
 *
 * Precedence: hostname → product_name → device_family → null.
 *
 * @param device - Device item from the topology endpoint.
 * @returns Best available display name, or null when no field is set.
 */
export function deviceDisplayName(device: {
  hostname: string | null
  product_name: string | null
  device_family: string | null
}): string | null {
  return device.hostname || device.product_name || device.device_family || null
}

/**
 * Build MAC/IP lookup maps from a list of devices.
 *
 * @param devices - Device items from the topology endpoint.
 * @returns Object containing `byMac` and `byIp` Maps.
 */
export function buildDeviceLookupMaps(devices: DeviceItem[]): {
  byMac: Map<string, DeviceLabelInfo>
  byIp: Map<string, DeviceLabelInfo>
} {
  const byMac = new Map<string, DeviceLabelInfo>()
  const byIp = new Map<string, DeviceLabelInfo>()

  for (const device of devices) {
    const info: DeviceLabelInfo = {
      hostname: device.hostname ?? null,
      productName: device.product_name ?? null,
      deviceFamily: device.device_family ?? null,
    }

    for (const iface of device.interfaces ?? []) {
      const mac = iface.mac_address?.trim().toLowerCase()
      if (mac && !byMac.has(mac)) {
        byMac.set(mac, info)
      }
      const ip = iface.ipv4_address?.trim()
      if (ip && !byIp.has(ip)) {
        byIp.set(ip, info)
      }
    }
  }

  return { byMac, byIp }
}

/**
 * Composable that provides reactive hostname lookups.
 *
 * @returns Functions for resolving MAC-based names and endpoint labels.
 */
export function useDeviceLookup(): {
  nameForMac: (mac: string) => string | null
  nameForEndpoint: (ip: string | null, mac: string | null) => string | null
  labelForEndpoint: (ip: string | null, mac: string | null) => string
} {
  const devicesStore = useDevicesStore()

  /**
   * Resolve the best display name for a MAC address.
   *
   * Precedence: hostname → product_name → device_family → null.
   *
   * @param mac - MAC address string (case-insensitive).
   * @returns Best available display name, or null when no match.
   */
  function nameForMac(mac: string): string | null {
    const { byMac } = buildDeviceLookupMaps(devicesStore.devices)
    const normalized = mac.trim().toLowerCase()
    const info = byMac.get(normalized)
    if (!info) return null
    return info.hostname || info.productName || info.deviceFamily || null
  }

  /**
   * Resolve the best asset name for an endpoint (IP + MAC).
   *
   * Precedence: hostname(byIp[ip]) → product_name(byIp[ip]) → device_family(byIp[ip])
   * → hostname(byMac[mac]) → product_name(byMac[mac]) → device_family(byMac[mac]) → null.
   *
   * This is the asset-list style name; it intentionally falls back to null rather
   * than raw IP/MAC so callers can decide when to show identifiers.
   *
   * @param ip - IPv4 address string, or null/empty.
   * @param mac - MAC address string, or null/empty.
   * @returns Best available asset name, or null when no device matches.
   */
  function nameForEndpoint(ip: string | null, mac: string | null): string | null {
    const { byMac, byIp } = buildDeviceLookupMaps(devicesStore.devices)
    const ipStr = (ip ?? '').trim()
    const macStr = (mac ?? '').trim().toLowerCase()

    if (ipStr) {
      const ipInfo = byIp.get(ipStr)
      if (ipInfo) {
        const ipName = ipInfo.hostname || ipInfo.productName || ipInfo.deviceFamily || null
        if (ipName) return ipName
      }
    }
    if (macStr) {
      const macInfo = byMac.get(macStr)
      if (macInfo) {
        const macName = macInfo.hostname || macInfo.productName || macInfo.deviceFamily || null
        if (macName) return macName
      }
    }
    return null
  }

  /**
   * Resolve the best display label for an endpoint (IP + MAC).
   *
   * Precedence: hostname(byIp[ip]) → hostname(byMac[mac]) → ip → mac.
   *
   * @param ip - IPv4 address string, or null/empty.
   * @param mac - MAC address string, or null/empty.
   * @returns Best available label string. Falls back to ip, then mac, then empty string.
   */
  function labelForEndpoint(ip: string | null, mac: string | null): string {
    const { byMac, byIp } = buildDeviceLookupMaps(devicesStore.devices)
    const ipStr = (ip ?? '').trim()
    const macStr = (mac ?? '').trim()

    if (ipStr) {
      const ipInfo = byIp.get(ipStr)
      if (ipInfo?.hostname) return ipInfo.hostname
    }
    if (macStr) {
      const macInfo = byMac.get(macStr.toLowerCase())
      if (macInfo?.hostname) return macInfo.hostname
    }
    return ipStr || macStr || ''
  }

  return {
    nameForMac,
    nameForEndpoint,
    labelForEndpoint,
  }
}
