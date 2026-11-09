/**
 * Map a CVE severity string to a Quasar palette color name.
 *
 * Used consistently across the device table (CVE badge), the
 * vulnerabilities page, and any other severity-driven UI element.
 */
export function severityColor(severity: string | null): string {
  switch ((severity || '').toLowerCase()) {
    case 'critical':
      return 'negative'
    case 'high':
      return 'orange-9'
    case 'medium':
      return 'warning'
    case 'low':
      return 'blue-grey-6'
    default:
      return 'grey-6'
  }
}
