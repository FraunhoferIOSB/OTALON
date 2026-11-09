import type { DeviceItem } from '~/types/api'

/**
 * Returns true when a device carries enough identifying metadata to be
 * looked up against a vulnerability database (vendor, product name,
 * firmware version).
 */
export function isLookupEligible(device: DeviceItem): boolean {
  const hasVendor = !!device.vendor && device.vendor.trim().length > 0
  const hasProduct = !!device.product_name && device.product_name.trim().length > 0
  const hasFirmware = !!device.firmware_version && device.firmware_version.trim().length > 0
  return hasVendor && hasProduct && hasFirmware
}
