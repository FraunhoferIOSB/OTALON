/**
 * Component tests for ConnectionRhythmLane.
 *
 * The lane's contract is as much semantic as visual, so these tests pin
 * the rules the design record makes binding: no profile is a normal
 * state, absence is missing evidence rather than an alarm, markers are
 * observations and not per-arrival verdicts, explanatory prose lives in
 * tooltips, and every tooltip trigger is keyboard reachable.
 */
import { describe, it, expect, beforeEach } from 'vitest'
import { nextTick } from 'vue'
import { createPinia, setActivePinia } from 'pinia'

import RhythmLane from '~/components/connection/RhythmLane.vue'
import { useFrequencyStore } from '~/stores/frequencyStore'
import type { FrequencyProfileResponse } from '~/types/api'
import { mountWithPlugins } from '../helpers/mount'

const NOW = '2026-07-26T10:00:00+00:00'
const UCI = 'aa:bb:cc:dd:ee:ff/11:22:33:44:55:66/0//////Ethernet:VLAN:PROFINET_RT'

const TIME_RANGE = { start: '2026-07-26T09:30:00+00:00', stop: '2026-07-26T10:00:00+00:00' }

function makeProfile(overrides: Partial<FrequencyProfileResponse> = {}): FrequencyProfileResponse {
  return {
    module: 'conn',
    series_id: UCI,
    state: 'normal',
    has_profile: true,
    mean_interval_seconds: 5,
    std_interval_seconds: 0.4,
    tolerance_factor: { value: 2, source: 'global_default', override: null, global_default: 2 },
    absence_factor: { value: 3, source: 'global_default', override: null, global_default: 3 },
    last_seen: '2026-07-26T09:59:55+00:00',
    trained_at: '2026-07-24T01:11:35+00:00',
    now: NOW,
    absence_deadline: '2026-07-26T10:00:10+00:00',
    absence_timeout_seconds: 15,
    seconds_until_deadline: 10,
    seconds_since_last_seen: 5,
    active_anomaly_type: null,
    active_anomaly_since: null,
    ...overrides,
  }
}

/**
 * Mount the lane with the frequency store pre-seeded.
 *
 * `mountWithPlugins` installs its own Pinia instance and activates it, so
 * the store has to be seeded *after* mounting and the component re-rendered.
 *
 * `module` is part of the seed because the store is a singleton shared by
 * the connections, Assets and Protocols pages: the lane only renders state
 * whose module AND series match its own props, so a seed without the module
 * would (correctly) be treated as another page's state and ignored.
 */
async function mountLane(
  profile: FrequencyProfileResponse | null,
  storePatch: Record<string, unknown> = {},
  arrivalTimes: string[] = [],
  propsPatch: Record<string, unknown> = {},
) {
  const wrapper = mountWithPlugins(RhythmLane, {
    props: { selectedUci: UCI, timeRange: TIME_RANGE, arrivalTimes, ...propsPatch },
  })
  const store = useFrequencyStore()
  store.$patch({ profile, seriesId: UCI, module: 'conn', isLoading: false, error: null, ...storePatch })
  await nextTick()
  return wrapper
}

/**
 * Switch the `Windows` toggle on through its rendered control.
 *
 * Driven via the DOM rather than by reaching into component state, so
 * the toggle's actual v-model binding is part of what is verified.
 */
describe('ConnectionRhythmLane', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
  })

  describe('states', () => {
    it('renders the normal state for a healthy connection', async () => {
      const wrapper = await mountLane(makeProfile())

      expect(wrapper.find('[data-testid="rhythm-state-chip"]').text()).toContain('Normal')
    })

    it('treats a missing profile as a normal state, not an error', async () => {
      const wrapper = await mountLane(makeProfile({ state: 'no_profile', has_profile: false }))

      const chip = wrapper.find('[data-testid="rhythm-state-chip"]')
      expect(chip.text()).toContain('No profile')
      expect(chip.attributes('aria-label')).toContain('normal state, not an error')
      expect(wrapper.find('[data-testid="rhythm-unavailable"]').exists()).toBe(false)
    })

    it('omits cadence facts when there is no profile', async () => {
      const wrapper = await mountLane(makeProfile({ state: 'no_profile', has_profile: false }))

      expect(wrapper.find('[data-testid="rhythm-cadence"]').exists()).toBe(false)
      expect(wrapper.find('[data-testid="rhythm-deadline"]').exists()).toBe(false)
    })

    it('does not claim the deadline passed while the verdict is normal', async () => {
      // The persisted last_seen trails live traffic by up to one batched
      // write interval, so a healthy fast-cadence connection routinely
      // reports a negative countdown. Saying "passed" there would
      // contradict the Normal chip sitting right next to it.
      const wrapper = await mountLane(makeProfile({ state: 'normal', seconds_until_deadline: -31 }))

      const text = wrapper.find('[data-testid="rhythm-deadline"]').text()
      expect(text).not.toContain('passed')
      expect(text).toContain('after last seen')
    })

    it('renders the absence state', async () => {
      const wrapper = await mountLane(
        makeProfile({
          state: 'absence_active',
          seconds_until_deadline: -120,
          active_anomaly_type: 'AbsenceAnomaly',
        }),
      )

      expect(wrapper.find('[data-testid="rhythm-state-chip"]').text()).toContain('Absence active')
      expect(wrapper.find('[data-testid="rhythm-deadline"]').text()).toContain('passed')
    })

    it('renders the frequency-anomaly state', async () => {
      const wrapper = await mountLane(
        makeProfile({ state: 'frequency_anomaly', active_anomaly_type: 'FrequencyAnomaly' }),
      )

      expect(wrapper.find('[data-testid="rhythm-state-chip"]').text()).toContain('Cadence anomaly')
    })

    it('renders the never-observed state', async () => {
      const wrapper = await mountLane(
        makeProfile({ state: 'no_last_seen', last_seen: null, absence_deadline: null, seconds_until_deadline: null }),
      )

      expect(wrapper.find('[data-testid="rhythm-state-chip"]').text()).toContain('Never observed')
      expect(wrapper.find('[data-testid="rhythm-last-seen"]').text()).toContain('never seen')
    })
  })

  describe('degradation', () => {
    it('shows a quiet unavailable marker when the endpoint fails', async () => {
      const wrapper = await mountLane(null, { error: 'Backend is unavailable' })

      expect(wrapper.find('[data-testid="rhythm-unavailable"]').exists()).toBe(true)
      expect(wrapper.find('[data-testid="rhythm-state-chip"]').text()).toContain('Unavailable')
    })

    it('still renders the lane container when the profile is missing', async () => {
      const wrapper = await mountLane(null, { error: 'boom' })

      expect(wrapper.find('[data-testid="rhythm-lane"]').exists()).toBe(true)
    })

    it('shows a spinner while loading', async () => {
      const wrapper = await mountLane(null, { isLoading: true })

      expect(wrapper.find('[data-testid="rhythm-loading"]').exists()).toBe(true)
    })
  })

  describe('information lives in tooltips, not plain strings', () => {
    it('keeps the detector explanation out of the visible facts', async () => {
      const wrapper = await mountLane(makeProfile())

      const chip = wrapper.find('[data-testid="rhythm-state-chip"]')
      const tooltip = chip.find('.q-tooltip')
      expect(tooltip.text()).toContain('at least five intervals')
      expect(chip.text().replace(tooltip.text(), '')).not.toContain('at least five intervals')
    })

    it('explains the deadline arithmetic in its tooltip', async () => {
      const wrapper = await mountLane(makeProfile())

      const tooltip = wrapper.find('[data-testid="rhythm-deadline"] .q-tooltip')
      expect(tooltip.text()).toContain('AbsenceAnomaly')
      expect(tooltip.text()).toContain('grace')
    })

    it('names override provenance in the tuning tooltip', async () => {
      const wrapper = await mountLane(
        makeProfile({
          tolerance_factor: { value: 4, source: 'override', override: 4, global_default: 2 },
        }),
      )

      expect(wrapper.find('[data-testid="rhythm-tuning"]').text()).toContain('operator-tuned')
      const tooltip = wrapper.find('[data-testid="rhythm-tuning"] .q-tooltip')
      expect(tooltip.text()).toContain('operator override')
      expect(tooltip.text()).toContain('default 2')
    })

    it('names the global default when no override is set', async () => {
      const wrapper = await mountLane(makeProfile())

      expect(wrapper.find('[data-testid="rhythm-tuning"]').text()).toContain('default tuning')
      expect(wrapper.find('[data-testid="rhythm-tuning"] .q-tooltip').text()).toContain('global default')
    })
  })

  describe('accessibility', () => {
    it('makes every tooltip trigger keyboard focusable', async () => {
      const wrapper = await mountLane(makeProfile())

      const triggers = wrapper.findAll('.q-tooltip')
      expect(triggers.length).toBeGreaterThan(0)
      for (const testid of ['rhythm-state-chip', 'rhythm-cadence', 'rhythm-last-seen', 'rhythm-deadline']) {
        const el = wrapper.find(`[data-testid="${testid}"]`)
        expect(el.exists()).toBe(true)
        expect(el.attributes('tabindex')).toBe('0')
      }
    })

    it('keeps the state chip focusable via a real DOM node', async () => {
      // Regression: q-chip does not forward tabindex to its rendered
      // element, which left the detector explanation hover-only. Live
      // Playwright verification caught this; the chip is now wrapped in
      // a focusable span.
      const wrapper = await mountLane(makeProfile())

      const chip = wrapper.find('[data-testid="rhythm-state-chip"]')
      expect(chip.attributes('tabindex')).toBe('0')
      expect(chip.element.tagName.toLowerCase()).toBe('span')
    })

    it('mirrors the tooltip content into an aria-label', async () => {
      const wrapper = await mountLane(makeProfile())

      const label = wrapper.find('[data-testid="rhythm-cadence"]').attributes('aria-label')
      expect(label).toContain('Learned cadence')
    })
  })

  describe('markers are observations, not verdicts', () => {
    it('positions arrivals proportionally inside the window', async () => {
      // A 900s cadence puts exactly two beats in the 30-min window, so
      // the two arrivals are consecutive beats and no beat is skipped.
      const wrapper = await mountLane(makeProfile({ mean_interval_seconds: 900, std_interval_seconds: 10 }), {}, [
        '2026-07-26T09:30:00+00:00',
        '2026-07-26T09:45:00+00:00',
      ])

      const markers = wrapper.findAll('.marker')
      expect(markers).toHaveLength(2)
      expect(markers[0]!.attributes('style')).toContain('left: 0%')
      expect(markers[1]!.attributes('style')).toContain('left: 50%')
    })

    it('ignores arrivals outside the selected window', async () => {
      const wrapper = await mountLane(makeProfile({ mean_interval_seconds: 900, std_interval_seconds: 10 }), {}, [
        '2026-07-26T08:00:00+00:00',
        '2026-07-26T09:45:00+00:00',
      ])

      expect(wrapper.findAll('.marker')).toHaveLength(1)
    })

    it('renders no strip at all without a profile', async () => {
      const wrapper = await mountLane(makeProfile({ state: 'no_profile', has_profile: false }))

      expect(wrapper.find('[data-testid="rhythm-strip"]').exists()).toBe(false)
    })

    it('keeps marker timestamps in accessible/tooltip content without inline labels', async () => {
      const wrapper = await mountLane(makeProfile({ mean_interval_seconds: 600 }), {}, [
        '2026-07-26T09:30:00+00:00',
        '2026-07-26T09:40:00+00:00',
      ])

      expect(wrapper.findAll('.marker-label')).toHaveLength(0)
      expect(wrapper.findAll('.marker')).toHaveLength(2)
      const firstTimestamp = new Date('2026-07-26T09:30:00+00:00').toLocaleTimeString(undefined, { hour12: false })
      expect(wrapper.find('.marker').attributes('aria-label')).toContain(firstTimestamp)
      expect(wrapper.find('.marker .q-tooltip').text()).toContain(firstTimestamp)
    })

    it('renders the time axis below the marker strip as a sibling', async () => {
      const wrapper = await mountLane(makeProfile(), {}, ['2026-07-26T09:45:00+00:00'])

      const strip = wrapper.find('[data-testid="rhythm-strip"]')
      const axis = wrapper.find('[data-testid="rhythm-time-axis"]')
      expect(axis.exists()).toBe(true)
      expect(strip.find('[data-testid="rhythm-time-axis"]').exists()).toBe(false)
      expect(axis.element.parentElement).toBe(strip.element.parentElement)
    })
  })

  describe('marker classification against the learned cadence', () => {
    /** 600s cadence over the 30-min window: 3 beats, each 33.3% wide. */
    const cadence = { mean_interval_seconds: 600, std_interval_seconds: 20 }

    it('marks an arrival landing on the expected beat as on-time', async () => {
      const wrapper = await mountLane(makeProfile(cadence), {}, [
        '2026-07-26T09:30:00+00:00',
        '2026-07-26T09:40:00+00:00',
      ])

      const kinds = wrapper.findAll('.marker').map((m) => m.attributes('data-kind'))
      expect(kinds).toEqual(['on-time', 'on-time'])
    })

    it('keeps normal classification when 1s cadence uses 1s buckets', async () => {
      const wrapper = await mountLane(makeProfile({ mean_interval_seconds: 1, std_interval_seconds: 0 }), {}, [
        '2026-07-26T09:59:58+00:00',
        '2026-07-26T09:59:59+00:00',
      ])

      expect(wrapper.findAll('.marker').map((marker) => marker.attributes('data-kind'))).toEqual(['on-time', 'on-time'])
    })

    it('uses aggregated markers when 1s cadence uses 2s buckets', async () => {
      const wrapper = await mountLane(makeProfile({ mean_interval_seconds: 1, std_interval_seconds: 0 }), {}, [
        '2026-07-26T09:59:56+00:00',
        '2026-07-26T09:59:58+00:00',
      ])

      expect(wrapper.findAll('.marker').map((marker) => marker.attributes('data-kind'))).toEqual([
        'aggregated',
        'aggregated',
      ])
      expect(wrapper.findAll('.marker--late')).toHaveLength(0)
      expect(wrapper.find('[data-testid="rhythm-marker-legend"]').text()).toContain('aggregated')
    })

    it('keeps a genuinely delayed arrival late at a resolvable bucket size', async () => {
      const wrapper = await mountLane(makeProfile({ mean_interval_seconds: 1, std_interval_seconds: 0 }), {}, [
        '2026-07-26T09:59:56+00:00',
        '2026-07-26T09:59:57+00:00',
        '2026-07-26T09:59:59+00:00',
      ])

      expect(wrapper.findAll('.marker').map((marker) => marker.attributes('data-kind'))).toContain('late')
    })

    it('marks an arrival well before its beat as early', async () => {
      // Expected 09:40:00, tolerance ±150s (0.25 × mean floor);
      // arriving at 09:35:00 is 300s early.
      const wrapper = await mountLane(makeProfile(cadence), {}, [
        '2026-07-26T09:30:00+00:00',
        '2026-07-26T09:35:00+00:00',
      ])

      const kinds = wrapper.findAll('.marker').map((m) => m.attributes('data-kind'))
      expect(kinds).toContain('early')
    })

    it('marks an arrival past its beat but inside the next as late', async () => {
      // Expected 09:40:00, arriving 09:44:00 is 240s late — beyond the
      // ±150s corridor but short of the following beat's corridor.
      const wrapper = await mountLane(makeProfile(cadence), {}, [
        '2026-07-26T09:30:00+00:00',
        '2026-07-26T09:31:00+00:00',
        '2026-07-26T09:44:00+00:00',
      ])

      const kinds = wrapper.findAll('.marker').map((m) => m.attributes('data-kind'))
      expect(kinds).toContain('late')
    })

    it('infers a missed beat when a whole expected arrival is skipped', async () => {
      const wrapper = await mountLane(makeProfile(cadence), {}, [
        '2026-07-26T09:30:00+00:00',
        '2026-07-26T09:35:00+00:00',
        '2026-07-26T09:40:00+00:00',
        '2026-07-26T10:00:00+00:00',
      ])

      const missed = wrapper.findAll('.marker--inferred-missed')
      expect(missed).toHaveLength(1)
      expect(missed[0]!.attributes('style')).toContain('left: 66.66')
    })

    it('names an inferred miss as an inference, never as received data', async () => {
      const wrapper = await mountLane(makeProfile(cadence), {}, [
        '2026-07-26T09:30:00+00:00',
        '2026-07-26T09:35:00+00:00',
        '2026-07-26T09:40:00+00:00',
        '2026-07-26T10:00:00+00:00',
      ])

      const label = wrapper.find('.marker--inferred-missed').attributes('aria-label')
      expect(label).toContain('Inferred missed arrival')
      expect(label).toContain('not a received data point')
    })

    it('suppresses per-beat miss marks at cadences too dense to read', async () => {
      // 5s cadence over 30 min is ~0.28% of the strip per beat: drawing
      // every skipped beat would be an unreadable barcode.
      const wrapper = await mountLane(makeProfile({ mean_interval_seconds: 5, std_interval_seconds: 0.4 }), {}, [
        '2026-07-26T09:30:00+00:00',
        '2026-07-26T09:45:00+00:00',
      ])

      expect(wrapper.findAll('.marker--inferred-missed')).toHaveLength(0)
      expect(wrapper.findAll('.marker')).toHaveLength(2)
    })

    it('keeps the marker legend explanation in a tooltip, not on the strip', async () => {
      const wrapper = await mountLane(makeProfile(cadence), {}, [
        '2026-07-26T09:30:00+00:00',
        '2026-07-26T09:35:00+00:00',
        '2026-07-26T09:50:00+00:00',
      ])

      const legend = wrapper.find('[data-testid="rhythm-marker-legend"]')
      expect(legend.exists()).toBe(true)
      expect(legend.attributes('tabindex')).toBe('0')
      const tooltip = legend.find('.q-tooltip')
      expect(tooltip.text()).toContain('never per-arrival alarms')
      expect(tooltip.text()).toContain('inference from the cadence')
    })
  })

  describe('absence is legible from the strip alone', () => {
    const absent = {
      state: 'absence_active' as const,
      last_seen: '2026-07-26T09:45:00+00:00',
      seconds_until_deadline: -120,
    }

    it('renders a visible silence zone anchored at last seen', async () => {
      const wrapper = await mountLane(makeProfile(absent))

      const zone = wrapper.find('[data-testid="rhythm-silence-zone"]')
      expect(zone.exists()).toBe(true)
      expect(zone.attributes('style')).toContain('left: 50%')
      expect(zone.text()).toContain('NO DATA')
    })

    it('makes the silence zone keyboard reachable and explained', async () => {
      const wrapper = await mountLane(makeProfile(absent))

      const zone = wrapper.find('[data-testid="rhythm-silence-zone"]')
      expect(zone.attributes('tabindex')).toBe('0')
      expect(zone.attributes('aria-label')).toContain('missing evidence')
      expect(zone.find('.q-tooltip').text()).toContain('no new interval and no new feature value exists')
    })

    it('draws no silence zone while the connection is healthy', async () => {
      const wrapper = await mountLane(makeProfile())

      expect(wrapper.find('[data-testid="rhythm-silence-zone"]').exists()).toBe(false)
    })

    it('marks the deadline line as exceeded in the absent state', async () => {
      const wrapper = await mountLane(makeProfile({ ...absent, absence_deadline: '2026-07-26T09:50:00+00:00' }))

      const line = wrapper.find('[data-testid="rhythm-deadline-line"]')
      expect(line.exists()).toBe(true)
      expect(line.classes()).toContain('deadline-line--exceeded')
      expect(line.attributes('aria-label')).toContain('exceeded')
    })
  })

  describe('now and deadline lines are time-consistent with the chip', () => {
    it('places the NOW line at the server reference instant', async () => {
      const wrapper = await mountLane(makeProfile())

      // now = 10:00:00 is the right edge of the 09:30–10:00 window.
      const line = wrapper.find('[data-testid="rhythm-now-line"]')
      expect(line.exists()).toBe(true)
      expect(line.attributes('style')).toContain('left: 100%')
      expect(line.text()).toContain('NOW')
    })

    it('places the deadline line at the deadline the chip reports', async () => {
      const wrapper = await mountLane(makeProfile({ absence_deadline: '2026-07-26T09:45:00+00:00' }))

      const line = wrapper.find('[data-testid="rhythm-deadline-line"]')
      expect(line.attributes('style')).toContain('left: 50%')
      expect(line.attributes('aria-label')).toContain('not yet reached')
    })

    it('omits a deadline line that falls outside the selected window', async () => {
      const wrapper = await mountLane(makeProfile({ absence_deadline: '2026-07-26T11:00:00+00:00' }))

      expect(wrapper.find('[data-testid="rhythm-deadline-line"]').exists()).toBe(false)
    })

    it('keeps both axis lines keyboard reachable', async () => {
      const wrapper = await mountLane(makeProfile({ absence_deadline: '2026-07-26T09:45:00+00:00' }))

      for (const testid of ['rhythm-now-line', 'rhythm-deadline-line']) {
        expect(wrapper.find(`[data-testid="${testid}"]`).attributes('tabindex')).toBe('0')
      }
    })
  })

  describe('absence cross marks where the deadline was crossed', () => {
    /** Deadline at 09:45 = 50% of the 09:30–10:00 window. */
    const absentAt50 = {
      state: 'absence_active' as const,
      last_seen: '2026-07-26T09:40:00+00:00',
      absence_deadline: '2026-07-26T09:45:00+00:00',
      seconds_until_deadline: -900,
      active_anomaly_type: 'AbsenceAnomaly',
    }

    it('renders a cross glyph at the instant the deadline was crossed', async () => {
      const wrapper = await mountLane(makeProfile(absentAt50))

      const cross = wrapper.find('[data-testid="rhythm-absence-cross"]')
      expect(cross.exists()).toBe(true)
      expect(cross.text()).toContain('✕')
      expect(cross.attributes('style')).toContain('left: 50%')
    })

    it('coexists with the silence zone rather than replacing it', async () => {
      // The hatch carries the EXTENT of the silence, the cross its ONSET.
      // Regressing either into the other loses information.
      const wrapper = await mountLane(makeProfile(absentAt50))

      expect(wrapper.find('[data-testid="rhythm-silence-zone"]').exists()).toBe(true)
      expect(wrapper.find('[data-testid="rhythm-absence-cross"]').exists()).toBe(true)
    })

    it('draws no cross while the connection is healthy', async () => {
      const wrapper = await mountLane(makeProfile())

      expect(wrapper.find('[data-testid="rhythm-absence-cross"]').exists()).toBe(false)
    })

    it('draws no cross for a deadline that is merely negative under a normal verdict', async () => {
      // A batched last_seen write routinely reports a passed deadline on a
      // healthy connection; only the detector's own absence state may
      // produce the cross.
      const wrapper = await mountLane(makeProfile({ state: 'normal', seconds_until_deadline: -31 }))

      expect(wrapper.find('[data-testid="rhythm-absence-cross"]').exists()).toBe(false)
    })

    it('omits the cross when the crossing point lies outside the window', async () => {
      const wrapper = await mountLane(makeProfile({ ...absentAt50, absence_deadline: '2026-07-26T08:00:00+00:00' }))

      expect(wrapper.find('[data-testid="rhythm-absence-cross"]').exists()).toBe(false)
    })

    it('names the cross as an inference and explains the arithmetic', async () => {
      const wrapper = await mountLane(makeProfile(absentAt50))

      const label = wrapper.find('[data-testid="rhythm-absence-cross"]').attributes('aria-label')
      expect(label).toContain('Absence deadline crossed')
      expect(label).toContain('not a received data point')
      expect(label).toContain('AbsenceAnomaly became active')
    })

    it('keeps the cross keyboard reachable', async () => {
      const wrapper = await mountLane(makeProfile(absentAt50))

      expect(wrapper.find('[data-testid="rhythm-absence-cross"]').attributes('tabindex')).toBe('0')
    })
  })

  describe('expectation horizon projects upcoming ticks right of now', () => {
    it('renders dashed tolerance windows for expected future arrivals', async () => {
      const wrapper = await mountLane(makeProfile({ mean_interval_seconds: 600, std_interval_seconds: 20 }), {}, [
        '2026-07-26T09:40:00+00:00',
        '2026-07-26T09:50:00+00:00',
      ])

      const windows = wrapper.findAll('[data-testid="rhythm-forecast-window"]')
      expect(windows.length).toBeGreaterThan(0)
      expect(wrapper.find('[data-testid="rhythm-forecast"]').exists()).toBe(true)
    })

    it('hides the forecast strip when the Forecast toggle is switched off', async () => {
      const wrapper = await mountLane(makeProfile({ mean_interval_seconds: 600, std_interval_seconds: 20 }), {}, [
        '2026-07-26T09:40:00+00:00',
        '2026-07-26T09:50:00+00:00',
      ], { forecastVisible: false })

      expect(wrapper.find('[data-testid="rhythm-forecast"]').exists()).toBe(false)
      expect(wrapper.find('[data-testid="rhythm-forecast-window"]').exists()).toBe(false)
      expect(wrapper.find('[data-testid="rhythm-forecast-deadline"]').exists()).toBe(false)
    })

    it('anchors expected windows at the last observed arrival plus k x mean', async () => {
      const wrapper = await mountLane(makeProfile({ mean_interval_seconds: 600, std_interval_seconds: 20 }), {}, [
        '2026-07-26T09:40:00+00:00',
        '2026-07-26T09:50:00+00:00',
      ])

      // Last arrival 09:50 + 1x600s = 10:00 is the first expected beat at
      // or after now (10:00:00), so it must be the first window drawn.
      const first = wrapper.find('[data-testid="rhythm-forecast-window"]').attributes('aria-label')
      const expected = new Date('2026-07-26T10:00:00+00:00').toLocaleTimeString(undefined, { hour12: false })
      expect(first).toContain(expected)
      expect(first).toContain('last observed arrival')
    })

    it('labels the horizon as projection outside the query window', async () => {
      const wrapper = await mountLane(makeProfile({ mean_interval_seconds: 600, std_interval_seconds: 20 }), {}, [
        '2026-07-26T09:50:00+00:00',
      ])

      expect(wrapper.find('[data-testid="rhythm-forecast-tag"]').text()).toContain('FORECAST')
      expect(wrapper.find('[data-testid="rhythm-forecast-note"]').text()).toContain('outside query window')
      const label = wrapper.find('[data-testid="rhythm-forecast"]').attributes('aria-label')
      expect(label).toContain('projections')
      expect(label).toContain('not observations')
    })

    it('positions every forecast window inside its own track', async () => {
      // The forecast is a projection and must never leak into the marker
      // strip, whose domain is the query window and stays aligned with
      // the feature plots below.
      const wrapper = await mountLane(makeProfile({ mean_interval_seconds: 600, std_interval_seconds: 20 }), {}, [
        '2026-07-26T09:50:00+00:00',
      ])

      expect(wrapper.find('[data-testid="rhythm-strip"] [data-testid="rhythm-forecast-window"]').exists()).toBe(false)
      for (const win of wrapper.findAll('[data-testid="rhythm-forecast-window"]')) {
        const left = Number(/left: ([\d.]+)%/.exec(win.attributes('style') ?? '')?.[1] ?? '-1')
        expect(left).toBeGreaterThanOrEqual(0)
        expect(left).toBeLessThanOrEqual(100)
      }
    })

    it('derives the corridor from the learned mean and std, not a second request', async () => {
      const wrapper = await mountLane(
        makeProfile({ mean_interval_seconds: 600, std_interval_seconds: 30, state: 'normal' }),
        {},
        ['2026-07-26T09:50:00+00:00'],
      )

      // tolerance = max(std x tol_factor, mean x 0.25) = max(60, 150) = 150s
      const label = wrapper.find('[data-testid="rhythm-forecast-window"]').attributes('aria-label')
      expect(label).toContain('± 150.00s')
    })

    it('places a still-pending deadline inside the horizon', async () => {
      const wrapper = await mountLane(
        makeProfile({
          mean_interval_seconds: 600,
          std_interval_seconds: 20,
          absence_deadline: '2026-07-26T10:10:00+00:00',
          seconds_until_deadline: 600,
        }),
        {},
        ['2026-07-26T09:50:00+00:00'],
      )

      const line = wrapper.find('[data-testid="rhythm-forecast-deadline"]')
      expect(line.exists()).toBe(true)
      expect(line.text()).toContain('DEADLINE')
    })

    it('omits the forecast deadline once it has already been crossed', async () => {
      const wrapper = await mountLane(
        makeProfile({
          mean_interval_seconds: 600,
          std_interval_seconds: 20,
          state: 'absence_active',
          absence_deadline: '2026-07-26T09:45:00+00:00',
          seconds_until_deadline: -900,
        }),
        {},
        ['2026-07-26T09:40:00+00:00'],
      )

      // An exceeded deadline is marked in the strip by the absence cross.
      expect(wrapper.find('[data-testid="rhythm-forecast-deadline"]').exists()).toBe(false)
      expect(wrapper.find('[data-testid="rhythm-absence-cross"]').exists()).toBe(true)
    })

    it('projects from last_seen when no arrival remains inside the window', async () => {
      const wrapper = await mountLane(
        makeProfile({
          mean_interval_seconds: 600,
          std_interval_seconds: 20,
          last_seen: '2026-07-26T09:55:00+00:00',
        }),
        {},
        [],
      )

      expect(wrapper.findAll('[data-testid="rhythm-forecast-window"]').length).toBeGreaterThan(0)
    })

    it('renders no horizon without a learned cadence', async () => {
      const wrapper = await mountLane(makeProfile({ state: 'no_profile', has_profile: false }))

      expect(wrapper.find('[data-testid="rhythm-forecast"]').exists()).toBe(false)
    })
  })

  describe('windows toggle controls historical expected corridors', () => {
    const cadence = { mean_interval_seconds: 600, std_interval_seconds: 20 }
    const arrivals = ['2026-07-26T09:30:00+00:00', '2026-07-26T09:40:00+00:00', '2026-07-26T09:50:00+00:00']

    it('hides historical corridors by default', async () => {
      const wrapper = await mountLane(makeProfile(cadence), {}, arrivals)

      expect(wrapper.find('[data-testid="rhythm-window-past"]').exists()).toBe(false)
    })

    it('shows historical corridors once the toggle is switched on', async () => {
      const wrapper = await mountLane(makeProfile(cadence), {}, arrivals, { windowsVisible: true })

      const windows = wrapper.findAll('[data-testid="rhythm-window-past"]')
      expect(windows.length).toBeGreaterThan(0)
      expect(windows[0]!.attributes('aria-label')).toContain('Expected arrival')
    })

    it('aggregates the corridors at cadences too dense to draw individually', async () => {
      const wrapper = await mountLane(makeProfile({ mean_interval_seconds: 5, std_interval_seconds: 0.4 }), {}, [
        '2026-07-26T09:30:00+00:00',
        '2026-07-26T09:45:00+00:00',
      ], { windowsVisible: true })

      expect(wrapper.find('[data-testid="rhythm-window-past"]').exists()).toBe(false)
      const aggregate = wrapper.find('[data-testid="rhythm-window-aggregate"]')
      expect(aggregate.exists()).toBe(true)
      expect(aggregate.attributes('aria-label')).toContain('aggregated at this zoom')
    })

    it('leaves markers and axis lines untouched when the toggle is on', async () => {
      const wrapper = await mountLane(makeProfile(cadence), {}, arrivals, { windowsVisible: true })
      const markersBefore = wrapper.findAll('.marker').length

      expect(wrapper.findAll('.marker')).toHaveLength(markersBefore)
      expect(wrapper.find('[data-testid="rhythm-now-line"]').exists()).toBe(true)
    })
  })

  describe('displayed times are self-consistent', () => {
    it('derives the last-seen age from the server reference instant', async () => {
      const wrapper = await mountLane(makeProfile({ seconds_since_last_seen: 125 }))

      expect(wrapper.find('[data-testid="rhythm-last-seen"]').text()).toContain('2m 5s ago')
    })

    it('formats the cadence from the learned mean interval', async () => {
      const wrapper = await mountLane(makeProfile({ mean_interval_seconds: 3600 }))

      expect(wrapper.find('[data-testid="rhythm-cadence"]').text()).toContain('every 1h 0m')
    })
  })
})
