/**
 * Page-level tests for devices.vue time-range reactivity (UI-121).
 *
 * Validates that the LIVE-mode time window advances on each refresh tick
 * instead of caching a stale `new Date()` value, which would filter out
 * devices whose timestamps moved past the frozen `stop` bound.
 */
import { describe, it, expect, beforeEach, vi } from 'vitest'
import { setActivePinia, createPinia } from 'pinia'
import { ref } from 'vue'

import { useAppStore } from '~/stores/appStore'
import { useDevicesStore } from '~/stores/devicesStore'
import type { DeviceItem } from '~/types/api'

/**
 * Build a minimal DeviceItem suitable for time-filter testing.
 *
 * @param id - Device identifier.
 * @param hostname - Device hostname.
 * @param lastScanAt - ISO 8601 timestamp for last_scan_at (or null).
 * @param interfaceScanAt - ISO 8601 timestamp for interface last_scan_at (or null).
 * @returns A partial-but-sufficient DeviceItem.
 */
function makeDevice(
  id: number,
  hostname: string,
  lastScanAt: string | null,
  interfaceScanAt: string | null,
): DeviceItem {
  return {
    id,
    hostname,
    vendor: 'TestVendor',
    device_family: null,
    device_type: 'PLC',
    description: null,
    article_number: null,
    device_role: null,
    firmware_version: null,
    product_name: null,
    hw_version: null,
    sw_version: null,
    serial_number: null,
    vulnerabilities: null,
    update_available: false,
    last_scan_at: lastScanAt,
    notes: null,
    created_at: '2026-01-01T00:00:00Z',
    updated_at: null,
    interfaces: [
      {
        id: 100 + id,
        device_id: id,
        mac_address: `00:1b:1b:f8:3a:0${id}`,
        ipv4_address: `192.168.1.${id}`,
        ipv6_address: null,
        interface_name: 'eth0',
        interface_description: null,
        subnet: null,
        source: 'arp_scan' as const,
        first_seen_at: '2026-01-01T00:00:00Z',
        last_scan_at: interfaceScanAt,
        last_seen_at: interfaceScanAt,
        speed_mbps: null,
        duplex: null,
        switch_port: null,
        vlan_id: null,
        manufacturer: null,
        is_virtual: false,
        is_trunk: false,
      },
    ],
  }
}

describe('UI-121 devices.vue timeRange caching fix', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
  })

  describe('applyTimeWindow mechanism (direct pattern test)', () => {
    it('advances the time window after a simulated refresh tick in LIVE mode', () => {
      vi.useFakeTimers()
      vi.setSystemTime('2026-08-04T12:00:00Z')

      const appStore = useAppStore()
      appStore.setLiveMode(true)
      appStore.setLiveInterval(600) // 10-min window → [11:50, 12:00]

      // Simulate the page's pattern: a ref + applyTimeWindow function
      const timeRange = ref(appStore.freshApiTimeParams())

      function applyTimeWindow(): { start: string; stop: string } {
        const params = appStore.freshApiTimeParams()
        timeRange.value = params
        return params
      }

      // Capture initial window
      const initialStop = timeRange.value.stop
      expect(initialStop).toBe('2026-08-04T12:00:00.000Z')

      // Advance time past the original stop bound
      vi.advanceTimersByTime(15 * 60 * 1000) // → 12:15:00

      // Apply the window again — this is what happens on every refresh tick
      applyTimeWindow()

      // The window must have advanced — it must NOT be frozen at 12:00
      expect(timeRange.value.stop).toBe('2026-08-04T12:15:00.000Z')
      expect(new Date(timeRange.value.stop).getTime()).toBeGreaterThan(
        new Date(initialStop).getTime(),
      )
    })

    it('non-LIVE (manual) mode is unaffected — freshApiTimeParams returns configured range', () => {
      vi.useFakeTimers()
      vi.setSystemTime('2026-08-04T12:00:00Z')

      const appStore = useAppStore()
      appStore.setLiveMode(false)
      appStore.setTimeRange('2026-08-04T08:00:00Z', '2026-08-04T10:00:00Z')

      const timeRange = ref(appStore.freshApiTimeParams())

      function applyTimeWindow(): { start: string; stop: string } {
        const params = appStore.freshApiTimeParams()
        timeRange.value = params
        return params
      }

      // Manual range should NOT be affected by advancing time.
      // Note: setTimeRange stores timestamps without millisecond
      // component, so no `.000` suffix.
      expect(timeRange.value.start).toBe('2026-08-04T08:00:00Z')
      expect(timeRange.value.stop).toBe('2026-08-04T10:00:00Z')

      vi.advanceTimersByTime(60 * 60 * 1000) // → 13:00

      applyTimeWindow()

      // Still the same manual range
      expect(timeRange.value.start).toBe('2026-08-04T08:00:00Z')
      expect(timeRange.value.stop).toBe('2026-08-04T10:00:00Z')
    })
  })

  describe('timeFilteredDevices integration (simulated page logic)', () => {
    it('includes a device whose timestamp is inside the advancing LIVE window', () => {
      vi.useFakeTimers()
      // Fix "now" to a known time
      vi.setSystemTime('2026-08-04T12:00:00Z')

      const appStore = useAppStore()
      const devicesStore = useDevicesStore()

      appStore.setLiveMode(true)
      appStore.setLiveInterval(600) // 10-min window: [11:50, 12:00]

      // Devices: one inside initial window, one just outside
      const inside = makeDevice(1, 'device-inside', '2026-08-04T11:55:00Z', '2026-08-04T11:55:00Z')
      const outside = makeDevice(2, 'device-outside', '2026-08-04T12:05:00Z', null)

      devicesStore.devices = [inside, outside]
      devicesStore.total = 2

      // Simulate the page's pattern
      const timeRange = ref(appStore.freshApiTimeParams())

      function applyTimeWindow(): { start: string; stop: string } {
        const params = appStore.freshApiTimeParams()
        timeRange.value = params
        return params
      }

      /** Simulate `latestDeviceTimestamp` from devices.vue. */
      function latestDeviceTimestamp(device: DeviceItem): number | null {
        const timestamps = [
          device.last_scan_at,
          ...device.interfaces.map((iface) => iface.last_scan_at),
        ]
          .filter((t): t is string => Boolean(t))
          .map((t) => new Date(t).getTime())
          .filter((t) => Number.isFinite(t))
        return timestamps.length > 0 ? Math.max(...timestamps) : null
      }

      /** Simulate `timeFilteredDevices` computed from devices.vue. */
      function filterByTimeRange(devices: DeviceItem[]) {
        const start = new Date(timeRange.value.start).getTime()
        const stop = new Date(timeRange.value.stop).getTime()
        return devices.filter((device) => {
          const ts = latestDeviceTimestamp(device)
          return ts !== null && ts >= start && ts <= stop
        })
      }

      // Initial window: only `inside` should pass (timestamp 11:55 ∈ [11:50, 12:00])
      let filtered = filterByTimeRange(devicesStore.devices)
      expect(filtered).toHaveLength(1)
      expect(filtered[0]!.id).toBe(1)

      // Advance time past the original stop bound
      vi.advanceTimersByTime(15 * 60 * 1000) // → 12:15

      // Apply fresh window → [12:05, 12:15]
      applyTimeWindow()

      // Re-filter. `inside` (11:55) is now BEFORE the new window [12:05, 12:15]
      // so it is excluded — that is correct: the window rolled forward.
      // CRITICAL: `outside` (12:05) is now INCLUDED because its timestamp
      // (12:05) falls inside the new window. Without the fix, `timeRange`
      // would still be frozen at [11:50, 12:00], `outside` would remain
      // excluded, and the list would gradually go empty.
      filtered = filterByTimeRange(devicesStore.devices)
      expect(filtered).toHaveLength(1)
      expect(filtered[0]!.id).toBe(2)
    })

    it('non-LIVE mode filter is unaffected by wall-clock advancement', () => {
      vi.useFakeTimers()
      vi.setSystemTime('2026-08-04T12:00:00Z')

      const appStore = useAppStore()
      const devicesStore = useDevicesStore()

      // Custom/history mode with a fixed window
      appStore.setLiveMode(false)
      appStore.setTimeRange('2026-08-04T08:00:00Z', '2026-08-04T18:00:00Z')

      const deviceA = makeDevice(1, 'device-a', '2026-08-04T10:00:00Z', '2026-08-04T10:00:00Z')
      devicesStore.devices = [deviceA]
      devicesStore.total = 1

      const timeRange = ref(appStore.freshApiTimeParams())

      function applyTimeWindow(): { start: string; stop: string } {
        const params = appStore.freshApiTimeParams()
        timeRange.value = params
        return params
      }

      function latestDeviceTimestamp(device: DeviceItem): number | null {
        const timestamps = [
          device.last_scan_at,
          ...device.interfaces.map((iface) => iface.last_scan_at),
        ]
          .filter((t): t is string => Boolean(t))
          .map((t) => new Date(t).getTime())
          .filter((t) => Number.isFinite(t))
        return timestamps.length > 0 ? Math.max(...timestamps) : null
      }

      function filterByTimeRange(devices: DeviceItem[]) {
        const start = new Date(timeRange.value.start).getTime()
        const stop = new Date(timeRange.value.stop).getTime()
        return devices.filter((device) => {
          const ts = latestDeviceTimestamp(device)
          return ts !== null && ts >= start && ts <= stop
        })
      }

      // Device is within the manual window
      expect(filterByTimeRange(devicesStore.devices)).toHaveLength(1)

      // Advance time — manual window should not change
      vi.advanceTimersByTime(60 * 60 * 1000)
      applyTimeWindow()

      // Still within the manual window
      expect(filterByTimeRange(devicesStore.devices)).toHaveLength(1)
      expect(timeRange.value.start).toBe('2026-08-04T08:00:00Z')
      expect(timeRange.value.stop).toBe('2026-08-04T18:00:00Z')
    })
  })
})
