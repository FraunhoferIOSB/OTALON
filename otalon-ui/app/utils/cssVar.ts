/**
 * Read a CSS custom property value from `<body>` (where Quasar's theme
 * class `.body--dark` / `.body--light` lives), falling back to a literal
 * value when the property is absent or during SSR.
 *
 * Custom properties inherit downward, so variables declared on `:root`
 * are still reachable via `document.body`.
 *
 * @example
 * const textColor = getCssVar('--cd-plot-text', '#37474f')
 */
export function getCssVar(name: string, fallback: string): string {
  if (typeof document === 'undefined') return fallback
  return getComputedStyle(document.body).getPropertyValue(name).trim() || fallback
}
