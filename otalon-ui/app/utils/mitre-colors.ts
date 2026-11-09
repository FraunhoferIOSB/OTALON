/**
 * Shared MITRE ATT&CK technique color mapping for Quasar chip components.
 *
 * Maps MITRE ICS technique IDs to Quasar color names for consistent
 * visual representation across alarm and classification views.
 */

const MITRE_COLOR_MAP: [string, string][] = [
  ['T0802', 'deep-orange'],
  ['T0846', 'blue'],
  ['T0830', 'red'],
  ['T0814', 'purple'],
  ['T0888', 'teal'],
]

const DEFAULT_COLOR = 'grey-7'

/**
 * Return a Quasar color name for a MITRE technique chip.
 *
 * @param techniqueId - MITRE technique ID or composite key (e.g. "T0802/opcua_enum").
 * @returns Quasar color name string.
 */
export function mitreChipColor(techniqueId: string): string {
  for (const [prefix, color] of MITRE_COLOR_MAP) {
    if (techniqueId.startsWith(prefix)) return color
  }
  return DEFAULT_COLOR
}
