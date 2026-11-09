import { describe, it, expect } from 'vitest'

import {
  verdictBadgeColor,
  verdictBannerClass,
  verdictBadgeLabel,
  humanizeFpReason,
  shouldShowMitreClassifications,
} from '~/utils/subagentVerdict'

describe('subagentVerdict helpers', () => {
  describe('verdictBadgeColor', () => {
    it('maps benign to positive', () => {
      expect(verdictBadgeColor('benign')).toBe('positive')
    })
    it('maps false_positive to warning', () => {
      expect(verdictBadgeColor('false_positive')).toBe('warning')
    })
    it('maps attack to grey-7', () => {
      expect(verdictBadgeColor('attack')).toBe('grey-7')
    })
    it('maps inconclusive to grey-7', () => {
      expect(verdictBadgeColor('inconclusive')).toBe('grey-7')
    })
    it('falls back to grey-7 for null/undefined/unknown', () => {
      expect(verdictBadgeColor(null)).toBe('grey-7')
      expect(verdictBadgeColor(undefined)).toBe('grey-7')
      expect(verdictBadgeColor('something_new')).toBe('grey-7')
    })
  })

  describe('verdictBannerClass', () => {
    it('maps benign to green banner', () => {
      expect(verdictBannerClass('benign')).toBe('bg-green-1 text-green-9')
    })
    it('maps false_positive to orange banner', () => {
      expect(verdictBannerClass('false_positive')).toBe('bg-orange-1 text-orange-9')
    })
    it('maps attack/inconclusive to grey banner', () => {
      expect(verdictBannerClass('attack')).toBe('bg-grey-2 text-grey-8')
      expect(verdictBannerClass('inconclusive')).toBe('bg-grey-2 text-grey-8')
    })
  })

  describe('verdictBadgeLabel', () => {
    it('renders false_positive as "False Positive"', () => {
      expect(verdictBadgeLabel('false_positive')).toBe('False Positive')
    })
    it('passes through other outcomes verbatim', () => {
      expect(verdictBadgeLabel('attack')).toBe('attack')
      expect(verdictBadgeLabel('benign')).toBe('benign')
      expect(verdictBadgeLabel('inconclusive')).toBe('inconclusive')
    })
    it('returns empty string for null/undefined', () => {
      expect(verdictBadgeLabel(null)).toBe('')
      expect(verdictBadgeLabel(undefined)).toBe('')
    })
  })

  describe('humanizeFpReason', () => {
    it('replaces underscores with spaces', () => {
      expect(humanizeFpReason('monitoring_tool')).toBe('monitoring tool')
      expect(humanizeFpReason('baseline_too_narrow')).toBe('baseline too narrow')
    })
    it('returns empty string for null/undefined/empty', () => {
      expect(humanizeFpReason(null)).toBe('')
      expect(humanizeFpReason(undefined)).toBe('')
      expect(humanizeFpReason('')).toBe('')
    })
  })

  describe('shouldShowMitreClassifications', () => {
    it('shows for attack regardless of classification count', () => {
      expect(shouldShowMitreClassifications('attack', 1)).toBe(true)
      expect(shouldShowMitreClassifications('attack', 0)).toBe(true)
    })
    it('hides for benign/inconclusive/false_positive when no classifications', () => {
      expect(shouldShowMitreClassifications('benign', 0)).toBe(false)
      expect(shouldShowMitreClassifications('inconclusive', 0)).toBe(false)
      expect(shouldShowMitreClassifications('false_positive', 0)).toBe(false)
    })
    it('defensively shows when classifications are present even for fp', () => {
      expect(shouldShowMitreClassifications('false_positive', 1)).toBe(true)
      expect(shouldShowMitreClassifications('benign', 2)).toBe(true)
    })
    it('shows for null/undefined outcome (no verdict yet)', () => {
      expect(shouldShowMitreClassifications(null, 0)).toBe(true)
      expect(shouldShowMitreClassifications(undefined, 0)).toBe(true)
    })
  })
})
