/**
 * UI-201 — the feature is labelled "Cadence" uniformly across all visible UI
 * text. Internal identifiers (store names, `rhythm-*` CSS classes,
 * `data-test`/`data-testid` attributes, the PascalCase anomaly-type constants
 * `FrequencyAnomaly`/`AbsenceAnomaly` and the `frequency_anomaly` state key)
 * are out of scope by the operator decision of 2026-11-04 and must stay
 * unchanged.
 */
import { describe, expect, it } from 'vitest'

import { readFileSync } from 'node:fs'

const read = (path: string): string => readFileSync(path, 'utf8')

const rhythmLane = read('app/components/connection/RhythmLane.vue')
const panelHeading = read('app/components/shared/PanelSubjectHeading.vue')
const selectorTable = read('app/components/connection/ConnectionSelectorTable.vue')
const displaySettings = read('app/components/shared/DisplaySettingsDialog.vue')

describe('UI-201: visible Cadence wording', () => {
  const VISIBLE_DRIPPY_WORDS =
    /Rhythm Review|RHYTHM|Frequency anomaly|Frequency anomalies|Frequency profiles|Frequency threshold|Frequency detection|Frequency training|'Rhythm'|"Rhythm"|rhythm lane|learned rhythm|rhythm profile|frequency anomaly|frequency profiles|frequency-deviation|frequency endpoint|frequency monitor/

  const files = {
    'app/components/connection/RhythmLane.vue': rhythmLane,
    'app/components/shared/PanelSubjectHeading.vue': panelHeading,
    'app/components/connection/ConnectionSelectorTable.vue': selectorTable,
    'app/components/shared/DisplaySettingsDialog.vue': displaySettings,
  }

  it('keeps the canonical identifiers and type constants unchanged', () => {
    expect(rhythmLane).toContain('data-testid="rhythm-lane"')
    expect(rhythmLane).toContain("frequency_anomaly: 'Cadence anomaly'")
    expect(panelHeading).toContain('label="Cadence"')
    expect(panelHeading).toContain('data-testid="rhythm-anomaly-badge"')
  })

  it('labels the lane title and lane-unavailable copy as Cadence', () => {
    expect(rhythmLane).toContain('>CADENCE</span>')
    expect(rhythmLane).toContain('Cadence data unavailable')
    expect(rhythmLane).not.toMatch(/RHYTHM lane title|Rhythm data unavailable/)
  })

  it('uses Cadence for the toggle, training and review wording on the detection page', () => {
    const page = read('app/pages/operations/detection.vue')
    expect(page).toContain('label="Cadence Review" data-test="tab-rhythm"')
    expect(page).toContain('Bounds &amp; Cadence Training')
    expect(page).toContain('About bounds and cadence training')
    expect(page).toContain('label="Cadence"')
    expect(page).toContain('Cadence threshold = max(tolerance × std, 0.5 × mean)')
    expect(page).toContain("label: 'Cadence anomaly'")
    expect(page).toContain("return 'This series matches its learned cadence. No correction is required.'")
  })

  it('uses the Cadence term in shared panel, selector and settings copy', () => {
    expect(selectorTable).toContain('learned cadence profile')
    expect(selectorTable).toContain('open their CADENCE lane')
    expect(displaySettings).toContain('across CADENCE and feature plots')
  })

  it('carries no visible Rhythm/Frequency feature wording in the reworked files', () => {
    const stripComments = (source: string): string =>
      source.replace(/\/\*[\s\S]*?\*\//g, '').replace(/<!--[\s\S]*?-->/g, '')
    for (const [name, source] of Object.entries(files)) {
      const codeOnly = stripComments(source)
        .split('\n')
        .filter((line) => !/^\s*(\/\/|\/?\*|\*)/.test(line))
        .join('\n')
      expect(codeOnly, `${name} still carries visible Rhythm/Frequency wording`).not.toMatch(VISIBLE_DRIPPY_WORDS)
    }
  })
})
