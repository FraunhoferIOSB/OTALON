import type { SubagentVerdict } from '~/types/api'

/**
 * Resolved verdict outcome, nullable for jobs without a verdict yet.
 */
type VerdictOutcome = SubagentVerdict['outcome'] | null | undefined

/**
 * Maps a verdict outcome to the Quasar badge colour used across the
 * subagent UI components.
 *
 * - `benign`        → `positive` (green)
 * - `false_positive`→ `warning` (orange)
 * - anything else (attack / inconclusive / unknown / null) → `grey-7`
 *
 * @example
 * verdictBadgeColor('false_positive') // 'warning'
 */
export function verdictBadgeColor(outcome: VerdictOutcome): string {
  switch (outcome) {
    case 'benign':
      return 'positive'
    case 'false_positive':
      return 'warning'
    default:
      return 'grey-7'
  }
}

/**
 * Maps a verdict outcome to the banner background/text colour classes.
 *
 * - `benign`         → green banner
 * - `false_positive` → orange banner
 * - anything else    → grey banner
 *
 * @example
 * verdictBannerClass('false_positive') // 'bg-orange-1 text-orange-9'
 */
export function verdictBannerClass(outcome: VerdictOutcome): string {
  switch (outcome) {
    case 'benign':
      return 'bg-green-1 text-green-9'
    case 'false_positive':
      return 'bg-orange-1 text-orange-9'
    default:
      return 'bg-grey-2 text-grey-8'
  }
}

/**
 * Returns the human-readable badge label for a verdict outcome.
 *
 * `false_positive` is rendered as "False Positive"; every other outcome
 * passes through verbatim. `null`/`undefined` yields an empty string.
 *
 * @example
 * verdictBadgeLabel('false_positive') // 'False Positive'
 * verdictBadgeLabel('attack')          // 'attack'
 */
export function verdictBadgeLabel(outcome: VerdictOutcome): string {
  if (outcome == null) return ''
  if (outcome === 'false_positive') return 'False Positive'
  return outcome
}

/**
 * Humanizes a `false_positive` reason token by replacing underscores with
 * spaces. Returns an empty string for null/undefined/empty input.
 *
 * @example
 * humanizeFpReason('monitoring_tool') // 'monitoring tool'
 */
export function humanizeFpReason(reason: string | null | undefined): string {
  if (!reason) return ''
  return reason.replace(/_/g, ' ')
}

/**
 * Decides whether the MITRE ICS classification rows should be rendered.
 *
 * For `benign`, `inconclusive` and `false_positive` outcomes the rows are
 * hidden unless classifications are actually present (defensive). For an
 * `attack` verdict (or no verdict yet) the section is always shown.
 *
 * @example
 * shouldShowMitreClassifications('false_positive', 0) // false
 * shouldShowMitreClassifications('attack', 0)        // true
 */
export function shouldShowMitreClassifications(outcome: VerdictOutcome, classificationCount: number): boolean {
  if (outcome === 'benign' || outcome === 'inconclusive' || outcome === 'false_positive') {
    return classificationCount > 0
  }
  return true
}
