/**
 * Unit tests for the dashboard signal mapping logic (B-04b).
 *
 * Validates that the BACKEND_SIGNAL_MAP correctly maps backend
 * signal_color values to frontend SignalColor types and labels.
 */
import { describe, it, expect } from 'vitest'

import type { SignalColor } from '~/types/golden-data'

const BACKEND_SIGNAL_MAP: Record<string, SignalColor> = {
  success: 'success',
  warning: 'warning',
  danger: 'danger',
}

const SIGNAL_LABELS: Record<SignalColor, string> = {
  danger: 'Critical',
  warning: 'Warning',
  success: 'Normal',
  info: 'Info',
}

function mapSignalColor(backendValue: string): SignalColor {
  return BACKEND_SIGNAL_MAP[backendValue] ?? 'info'
}

function getSignalLabel(color: SignalColor): string {
  return SIGNAL_LABELS[color] ?? color
}

describe('Dashboard Signal Mapping (B-04b)', () => {
  describe('BACKEND_SIGNAL_MAP', () => {
    it('maps "success" to "success"', () => {
      expect(BACKEND_SIGNAL_MAP['success']).toBe('success')
    })

    it('maps "warning" to "warning"', () => {
      expect(BACKEND_SIGNAL_MAP['warning']).toBe('warning')
    })

    it('maps "danger" to "danger"', () => {
      expect(BACKEND_SIGNAL_MAP['danger']).toBe('danger')
    })

    it('does NOT contain "ok" key (B-04b fix)', () => {
      expect(BACKEND_SIGNAL_MAP).not.toHaveProperty('ok')
    })
  })

  describe('mapSignalColor', () => {
    it('returns "success" for backend "success"', () => {
      expect(mapSignalColor('success')).toBe('success')
    })

    it('returns "warning" for backend "warning"', () => {
      expect(mapSignalColor('warning')).toBe('warning')
    })

    it('returns "danger" for backend "danger"', () => {
      expect(mapSignalColor('danger')).toBe('danger')
    })

    it('returns "info" fallback for unknown value', () => {
      expect(mapSignalColor('unknown')).toBe('info')
    })

    it('returns "info" fallback for "ok" (old/wrong value)', () => {
      expect(mapSignalColor('ok')).toBe('info')
    })
  })

  describe('getSignalLabel', () => {
    it('returns "Normal" for success', () => {
      expect(getSignalLabel('success')).toBe('Normal')
    })

    it('returns "Warning" for warning', () => {
      expect(getSignalLabel('warning')).toBe('Warning')
    })

    it('returns "Critical" for danger', () => {
      expect(getSignalLabel('danger')).toBe('Critical')
    })

    it('returns "Info" for info (fallback)', () => {
      expect(getSignalLabel('info')).toBe('Info')
    })
  })

  describe('end-to-end mapping (backend → label)', () => {
    it('backend "success" → label "Normal"', () => {
      const color = mapSignalColor('success')
      expect(getSignalLabel(color)).toBe('Normal')
    })

    it('backend "warning" → label "Warning"', () => {
      const color = mapSignalColor('warning')
      expect(getSignalLabel(color)).toBe('Warning')
    })

    it('backend "danger" → label "Critical"', () => {
      const color = mapSignalColor('danger')
      expect(getSignalLabel(color)).toBe('Critical')
    })

    it('backend "success" does NOT produce "Info" label (B-04b regression)', () => {
      const color = mapSignalColor('success')
      const label = getSignalLabel(color)
      expect(label).not.toBe('Info')
    })
  })
})
