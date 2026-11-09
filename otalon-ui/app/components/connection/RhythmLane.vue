<template>
  <div class="rhythm-lane" data-testid="rhythm-lane">
    <div class="row items-center no-wrap q-gutter-x-sm">
      <q-icon name="graphic_eq" size="18px" color="primary" />
      <span class="text-caption text-weight-bold rhythm-title">CADENCE</span>

      <!-- The chip is wrapped in a focusable span because q-chip does not
           forward tabindex to its DOM node, which would leave the state
           explanation reachable by hover only. -->
      <span
        class="state-chip-focus"
        tabindex="0"
        role="status"
        :aria-label="`Detector state: ${stateLabel}. ${stateExplanation}`"
        data-testid="rhythm-state-chip"
      >
        <q-chip dense square outline :color="stateColor" :icon="stateIcon" class="state-chip">
          {{ stateLabel }}
        </q-chip>
        <q-tooltip anchor="bottom left" self="top left" :offset="[0, 6]" max-width="360px">
          <div class="text-weight-bold q-mb-xs">{{ stateLabel }}</div>
          <div>{{ stateExplanation }}</div>
        </q-tooltip>
      </span>

      <template v-if="profile?.has_profile">
        <span
          class="text-caption text-mono fact"
          :tabindex="0"
          :aria-label="`Learned cadence ${cadenceText}. ${cadenceExplanation}`"
          data-testid="rhythm-cadence"
        >
          {{ cadenceText }}
          <q-tooltip anchor="bottom middle" self="top middle" :offset="[0, 6]" max-width="360px">
            <div class="text-weight-bold q-mb-xs">Learned cadence</div>
            <div>{{ cadenceExplanation }}</div>
          </q-tooltip>
        </span>

        <span
          class="text-caption text-mono fact"
          :tabindex="0"
          :aria-label="`Last seen ${lastSeenText}. ${lastSeenExplanation}`"
          data-testid="rhythm-last-seen"
        >
          {{ lastSeenText }}
          <q-tooltip anchor="bottom middle" self="top middle" :offset="[0, 6]" max-width="360px">
            <div class="text-weight-bold q-mb-xs">Last seen</div>
            <div>{{ lastSeenExplanation }}</div>
          </q-tooltip>
        </span>

        <span
          v-if="deadlineText"
          class="text-caption text-mono fact"
          :class="{ 'text-negative': isAbsent }"
          :tabindex="0"
          :aria-label="`Absence deadline ${deadlineText}. ${deadlineExplanation}`"
          data-testid="rhythm-deadline"
        >
          {{ deadlineText }}
          <q-tooltip anchor="bottom middle" self="top middle" :offset="[0, 6]" max-width="360px">
            <div class="text-weight-bold q-mb-xs">Absence deadline</div>
            <div>{{ deadlineExplanation }}</div>
          </q-tooltip>
        </span>

        <span
          class="text-caption fact tuning"
          :class="{ 'text-warning': hasOverride }"
          :tabindex="0"
          :aria-label="`Detector tuning: ${tuningText}. ${tuningExplanation}`"
          data-testid="rhythm-tuning"
        >
          {{ tuningText }}
          <q-tooltip anchor="bottom middle" self="top middle" :offset="[0, 6]" max-width="360px">
            <div class="text-weight-bold q-mb-xs">Detector tuning</div>
            <div>{{ tuningExplanation }}</div>
          </q-tooltip>
        </span>
      </template>

      <q-space />

      <q-spinner v-if="isLoading" size="14px" color="primary" data-testid="rhythm-loading" />
      <q-icon
        v-else-if="error"
        name="cloud_off"
        size="16px"
        color="grey-6"
        :tabindex="0"
        aria-label="Cadence data unavailable"
        data-testid="rhythm-unavailable"
      >
        <q-tooltip anchor="bottom right" self="top right" :offset="[0, 6]" max-width="360px">
          <div class="text-weight-bold q-mb-xs">Cadence data unavailable</div>
          <div>{{ error }}</div>
        </q-tooltip>
      </q-icon>
    </div>

    <div
      v-if="profile?.has_profile"
      class="marker-strip q-mt-xs"
      data-testid="rhythm-strip"
      @mousemove="onStripMouseMove"
      @mouseleave="onStripMouseLeave"
    >
      <!-- Historical expected windows, behind the `Windows` toggle. Drawn
           first so every marker, line and the absence cross stay above
           them. At dense cadences the individual rects collapse into one
           aggregate band (level-of-detail, sketch 006 correction B). -->
      <template v-if="windowsVisible">
        <div
          v-if="historicalWindowAggregate"
          class="expected-window expected-window--aggregate"
          :style="{ left: `${historicalWindowAggregate.left}%`, width: `${historicalWindowAggregate.width}%` }"
          :tabindex="0"
          role="img"
          :aria-label="historicalWindowAggregate.label"
          data-testid="rhythm-window-aggregate"
        >
          <q-tooltip anchor="top middle" self="bottom middle" :offset="[0, 6]" max-width="360px">
            <div class="text-weight-bold q-mb-xs">Expected cadence</div>
            <div>{{ historicalWindowAggregate.label }}</div>
          </q-tooltip>
        </div>
        <div
          v-for="win in historicalWindows"
          v-else
          :key="win.key"
          class="expected-window expected-window--past"
          :style="{ left: `${win.left}%`, width: `${win.width}%` }"
          :aria-label="win.label"
          data-testid="rhythm-window-past"
        >
          <q-tooltip anchor="top middle" self="bottom middle" :offset="[0, 6]" max-width="360px">
            <div class="text-weight-bold q-mb-xs">Expected window</div>
            <div>{{ win.label }}</div>
          </q-tooltip>
        </div>
      </template>

      <div
        v-if="silenceLeft !== null"
        class="silence-zone"
        :style="{ left: `${silenceLeft}%` }"
        :tabindex="0"
        role="img"
        :aria-label="`Silence zone. ${silenceExplanation}`"
        data-testid="rhythm-silence-zone"
      >
        <span class="silence-tag">NO DATA</span>
        <q-tooltip anchor="top middle" self="bottom middle" :offset="[0, 6]" max-width="360px">
          <div class="text-weight-bold q-mb-xs">Silence — missing evidence</div>
          <div>{{ silenceExplanation }}</div>
        </q-tooltip>
      </div>

      <div
        v-for="marker in markers"
        :key="marker.key"
        class="marker"
        :class="[`marker--${marker.kind}`, { 'marker--active': marker.active }]"
        :style="{ left: `${marker.left}%` }"
        :data-kind="marker.kind"
        :data-testid="marker.active ? 'rhythm-marker-active' : undefined"
        :aria-label="marker.label"
      >
        <span class="marker-tick" aria-hidden="true" />
        <q-tooltip anchor="top middle" self="bottom middle" :offset="[0, 6]" max-width="360px">
          <div class="text-weight-bold q-mb-xs">
            {{ MARKER_KIND_LABELS[marker.kind] }}
          </div>
          <div>{{ marker.label }}</div>
        </q-tooltip>
      </div>

      <!-- The absence cross marks the instant the deadline was crossed.
           It coexists with the silence hatching by design: the hatch
           shows the EXTENT of the silence, the cross marks its onset. -->
      <div
        v-if="absenceCrossLeft !== null"
        class="absence-cross"
        :style="{ left: `${absenceCrossLeft}%` }"
        :tabindex="0"
        role="img"
        :aria-label="absenceCrossLabel"
        data-testid="rhythm-absence-cross"
      >
        <span class="absence-cross-glyph" aria-hidden="true">✕</span>
        <q-tooltip anchor="top middle" self="bottom middle" :offset="[0, 6]" max-width="360px">
          <div class="text-weight-bold q-mb-xs">Absence deadline crossed</div>
          <div>{{ absenceCrossLabel }}</div>
        </q-tooltip>
      </div>

      <div
        v-if="crosshairLeft !== null"
        class="shared-crosshair"
        data-testid="rhythm-crosshair"
        :style="{ left: `${crosshairLeft}%` }"
      />

      <div
        v-if="deadlineLeft !== null"
        class="axis-line deadline-line"
        :class="{ 'deadline-line--exceeded': isAbsent }"
        :style="{ left: `${deadlineLeft}%` }"
        :tabindex="0"
        role="img"
        :aria-label="deadlineLineLabel"
        data-testid="rhythm-deadline-line"
      >
        <span class="axis-tag axis-tag--deadline">DEADLINE</span>
        <q-tooltip anchor="top middle" self="bottom middle" :offset="[0, 6]" max-width="360px">
          <div class="text-weight-bold q-mb-xs">Absence deadline</div>
          <div>{{ deadlineLineLabel }}</div>
        </q-tooltip>
      </div>

      <div
        v-if="nowLeft !== null"
        class="axis-line now-line"
        :style="{ left: `${nowLeft}%` }"
        :tabindex="0"
        role="img"
        :aria-label="nowLineLabel"
        data-testid="rhythm-now-line"
      >
        <span class="axis-tag axis-tag--now">NOW</span>
        <q-tooltip anchor="top middle" self="bottom middle" :offset="[0, 6]" max-width="360px">
          <div class="text-weight-bold q-mb-xs">Server reference time</div>
          <div>{{ nowLineLabel }}</div>
        </q-tooltip>
      </div>
    </div>

    <!-- Expectation horizon (sketch 004): expected arrivals AFTER now.
         It is a projection, so it never shares the marker strip's time
         domain — that domain is the query window and stays pixel-aligned
         with the feature plots below (UI-094). The forecast therefore
         owns a separate, explicitly labelled region right of NOW. -->
    <div
      v-if="profile?.has_profile && forecastVisible && forecastWindows.length > 0"
      class="forecast-strip"
      data-testid="rhythm-forecast"
      :aria-label="forecastExplanation"
    >
      <span class="forecast-tag" data-testid="rhythm-forecast-tag">FORECAST</span>
      <div class="forecast-track">
        <div
          v-for="win in forecastWindows"
          :key="win.key"
          class="expected-window expected-window--future"
          :style="{ left: `${win.left}%`, width: `${win.width}%` }"
          :tabindex="0"
          role="img"
          :aria-label="win.label"
          data-testid="rhythm-forecast-window"
        >
          <q-tooltip anchor="top middle" self="bottom middle" :offset="[0, 6]" max-width="360px">
            <div class="text-weight-bold q-mb-xs">Expected window (forecast)</div>
            <div>{{ win.label }}</div>
          </q-tooltip>
        </div>
        <div
          v-if="forecastDeadlineLeft !== null"
          class="axis-line deadline-line forecast-deadline"
          :style="{ left: `${forecastDeadlineLeft}%` }"
          :tabindex="0"
          role="img"
          :aria-label="deadlineLineLabel"
          data-testid="rhythm-forecast-deadline"
        >
          <span class="axis-tag axis-tag--deadline">DEADLINE</span>
          <q-tooltip anchor="top middle" self="bottom middle" :offset="[0, 6]" max-width="360px">
            <div class="text-weight-bold q-mb-xs">Absence deadline</div>
            <div>{{ deadlineLineLabel }}</div>
          </q-tooltip>
        </div>
      </div>
      <span class="forecast-note" :tabindex="0" :aria-label="forecastExplanation" data-testid="rhythm-forecast-note">
        outside query window
        <q-tooltip anchor="bottom right" self="top right" :offset="[0, 6]" max-width="380px">
          <div class="text-weight-bold q-mb-xs">Projection, not observation</div>
          <div>{{ forecastExplanation }}</div>
        </q-tooltip>
      </span>
    </div>

    <div v-if="profile?.has_profile" class="time-axis" data-testid="rhythm-time-axis" aria-label="CADENCE time axis">
      <span v-for="tick in timeTicks" :key="tick.key" class="time-tick" :style="{ left: `${tick.left}%` }">
        <span class="time-tick-mark" />
        <span class="time-tick-label">{{ tick.label }}</span>
      </span>
    </div>

    <div v-if="profile?.has_profile && markers.length > 0" class="row items-center q-mt-xs marker-legend-row">
      <span
        class="text-caption text-mono marker-legend"
        :tabindex="0"
        :aria-label="`Marker legend: ${markerLegendExplanation}`"
        data-testid="rhythm-marker-legend"
      >
        {{ markerLegendText }}
        <q-tooltip anchor="bottom left" self="top left" :offset="[0, 6]" max-width="380px">
          <div class="text-weight-bold q-mb-xs">Arrival markers</div>
          <div>{{ markerLegendExplanation }}</div>
        </q-tooltip>
      </span>
    </div>
  </div>
</template>

<script setup lang="ts">
import type { FrequencyProfileResponse } from '~/types/api'
import type { FrequencyModule } from '~/stores/frequencyStore'
import { useFrequencyStore } from '~/stores/frequencyStore'
import { useSharedCrosshair } from '~/composables/useSharedCrosshair'
import { getPlotSamplingSummary } from '~/utils/plotSampling'

/**
 * Series-level RHYTHM lane.
 *
 * Shows the frequency detector's view of ONE selected series above the
 * unchanged feature-plot grid: the learned cadence, real freshness,
 * absence deadline and current verdict.
 *
 * The detector produces AbsenceAnomaly for three modules, so this lane
 * is module-agnostic and is rendered by the connections (`conn`),
 * Assets (`mac_traffic`) and Protocols (`proto_traffic`) pages alike.
 * `selectedUci` is always the identifier the DETECTOR keys the profile
 * by; `subjectLabel` is what the operator should read when those two
 * differ (proto_traffic hashes its protocol stack).
 *
 * Two semantic rules from the approved design are load-bearing here:
 *
 * - Arrival markers are observations against the learned cadence, never
 *   per-arrival alarms. The detector judges the mean over at least five
 *   intervals, so an off-beat marker may legitimately coexist with a
 *   `normal` verdict. Markers carry shape and colour by cadence relation
 *   (● on-time, ◀ early, ▶ late) and `✕` marks an INFERRED missed beat —
 *   an expected arrival that was not observed, never a received point.
 * - Absence is missing evidence. It is rendered in this lane only; the
 *   feature plots simply stop at last seen and are never shaded red for
 *   a silence. Within this lane the silence zone IS red-toned, so the
 *   absent state is legible from the strip without reading the chip.
 *
 * The strip also carries a `NOW` line and an absence `Deadline` line,
 * both positioned from the same server-supplied instants the chip text
 * uses, so strip and text can never disagree about the clock.
 *
 * Explanatory prose lives in tooltips rather than on-screen text, and
 * every tooltip trigger is focusable so the information is reachable by
 * keyboard, not hover alone.
 */
const props = withDefaults(
  defineProps<{
    selectedUci: string | null
    arrivalTimes?: string[]
    timeRange?: { start: string; stop: string }
    module?: FrequencyModule
    subjectNoun?: string
    windowsVisible?: boolean
    forecastVisible?: boolean
  }>(),
  {
    arrivalTimes: () => [],
    timeRange: undefined,
    module: 'conn',
    subjectNoun: 'connection',
    windowsVisible: false,
    forecastVisible: true,
  },
)

const frequencyStore = useFrequencyStore()
const sharedCrosshair = useSharedCrosshair()
const crosshairTime = ref<number | null>(null)
sharedCrosshair.subscribe((time) => {
  crosshairTime.value = time
})

/**
 * Whether the store currently holds THIS lane's module and series.
 *
 * The frequency store is a singleton shared by the connections, Assets
 * and Protocols pages. Without this gate a lane would briefly paint the
 * previous page's cadence after a route change, since the store still
 * carries that state until the new fetch resolves.
 */
const ownsStoreState = computed<boolean>(() => frequencyStore.matches(props.module, props.selectedUci))

const profile = computed<FrequencyProfileResponse | null>(() => (ownsStoreState.value ? frequencyStore.profile : null))

/**
 * Loading/error are only this lane's while the store's selection is
 * this lane's, or while a fetch for it is still resolving.
 */
const isLoading = computed<boolean>(() => frequencyStore.isLoading)

const error = computed<string | null>(() => (ownsStoreState.value ? frequencyStore.error : null))

const isAbsent = computed<boolean>(() => profile.value?.state === 'absence_active')

const STATE_LABELS: Record<string, string> = {
  no_profile: 'No profile',
  no_last_seen: 'Never observed',
  normal: 'Normal',
  frequency_anomaly: 'Cadence anomaly',
  absence_active: 'Absence active',
}

const STATE_COLORS: Record<string, string> = {
  no_profile: 'grey-6',
  no_last_seen: 'grey-6',
  normal: 'positive',
  frequency_anomaly: 'warning',
  absence_active: 'negative',
}

const STATE_ICONS: Record<string, string> = {
  no_profile: 'help_outline',
  no_last_seen: 'hourglass_empty',
  normal: 'check_circle',
  frequency_anomaly: 'warning_amber',
  absence_active: 'notifications_off',
}

const stateLabel = computed<string>(() => {
  if (!props.selectedUci) return `No ${props.subjectNoun} selected`
  if (error.value && !profile.value) return 'Unavailable'
  return STATE_LABELS[profile.value?.state ?? 'no_profile'] ?? 'Unknown'
})

const stateColor = computed<string>(() => {
  if (error.value && !profile.value) return 'grey-6'
  return STATE_COLORS[profile.value?.state ?? 'no_profile'] ?? 'grey-6'
})

const stateIcon = computed<string>(() => {
  if (error.value && !profile.value) return 'cloud_off'
  return STATE_ICONS[profile.value?.state ?? 'no_profile'] ?? 'help_outline'
})

/**
 * Long-form explanation of the current detector state.
 *
 * Deliberately states what the detector actually evaluates, so the lane
 * never implies a per-arrival verdict the backend does not produce.
 */
const stateExplanation = computed<string>(() => {
  if (!props.selectedUci) return `Select a ${props.subjectNoun} to see its timing profile.`
  if (error.value && !profile.value) {
    return 'The cadence endpoint could not be reached. The feature plots below are unaffected.'
  }
  const p = profile.value
  if (!p || !p.has_profile) {
    return (
      `The cadence detector has not learned a cadence for this ${props.subjectNoun}, so no timing ` +
      'verdict exists for it. This is a normal state, not an error.'
    )
  }
  switch (p.state) {
    case 'no_last_seen':
      return (
        `A cadence was trained for this ${props.subjectNoun}, but it has not been observed since. ` +
        'Absence cannot be evaluated without a reference observation.'
      )
    case 'frequency_anomaly':
      return 'The observed mean inter-arrival time deviates from the learned cadence beyond the tolerance threshold. This is a verdict over at least five intervals, not over a single arrival.'
    case 'absence_active':
      return 'No data has arrived since the absence deadline passed. Absence is missing evidence: the feature plots simply stop at last seen rather than showing an anomaly.'
    default:
      return 'The observed mean inter-arrival time is within the tolerance threshold. Individual markers may still sit off-beat: the detector judges the mean over at least five intervals, not single arrivals.'
  }
})

/**
 * Format a duration in seconds as a compact human-readable string.
 */
function formatDuration(seconds: number): string {
  const abs = Math.abs(Math.round(seconds))
  if (abs < 60) return `${abs}s`
  if (abs < 3600) return `${Math.floor(abs / 60)}m ${abs % 60}s`
  if (abs < 86400) return `${Math.floor(abs / 3600)}h ${Math.floor((abs % 3600) / 60)}m`
  return `${Math.floor(abs / 86400)}d ${Math.floor((abs % 86400) / 3600)}h`
}

/**
 * Format an ISO instant as a local wall-clock time at second resolution.
 *
 * Second resolution throughout keeps `now`, last seen and the deadline
 * mutually reconcilable; minute resolution would make instants that fall
 * seconds apart look identical.
 */
function formatInstant(iso: string | null): string {
  if (!iso) return '—'
  const date = new Date(iso)
  if (Number.isNaN(date.getTime())) return '—'
  return date.toLocaleTimeString(undefined, { hour12: false })
}

const cadenceText = computed<string>(() => {
  const mean = profile.value?.mean_interval_seconds
  if (mean === null || mean === undefined) return 'cadence —'
  return `every ${formatDuration(mean)}`
})

const cadenceExplanation = computed<string>(() => {
  const p = profile.value
  if (!p || p.mean_interval_seconds === null) return 'No cadence learned.'
  const std = p.std_interval_seconds ?? 0
  return (
    `Mean inter-arrival interval ${p.mean_interval_seconds.toFixed(2)}s ` +
    `(standard deviation ${std.toFixed(2)}s), learned from aggregation buckets ` +
    `during training on ${formatInstant(p.trained_at)}. This is the ${props.subjectNoun}'s ` +
    `expected cadence, not a packet-level inter-arrival time.`
  )
})

const lastSeenText = computed<string>(() => {
  const p = profile.value
  if (!p?.last_seen) return 'never seen'
  const age = p.seconds_since_last_seen
  return age === null ? formatInstant(p.last_seen) : `seen ${formatDuration(age)} ago`
})

const lastSeenExplanation = computed<string>(() => {
  const p = profile.value
  if (!p?.last_seen) {
    return `This ${props.subjectNoun} has not been observed since its profile was trained.`
  }
  return (
    `Last observed at ${formatInstant(p.last_seen)}, ` +
    `${formatDuration(p.seconds_since_last_seen ?? 0)} before the server reference time ` +
    `${formatInstant(p.now)}. The detector records this timestamp in memory on every ` +
    `observation and persists it in batches, so it may trail live traffic slightly.`
  )
})

/**
 * Countdown text for the absence deadline.
 *
 * Only claims the deadline has passed when the detector agrees. The
 * persisted `last_seen` trails live traffic by up to one batched write
 * interval, so for a fast cadence it routinely reads as "older than the
 * deadline" while the connection is perfectly healthy. Saying "passed"
 * there would contradict the `Normal` verdict shown next to it.
 */
const deadlineText = computed<string>(() => {
  const p = profile.value
  if (!p?.absence_deadline || p.seconds_until_deadline === null) return ''
  if (p.seconds_until_deadline >= 0) {
    return `deadline in ${formatDuration(p.seconds_until_deadline)}`
  }
  if (isAbsent.value) {
    return `deadline passed ${formatDuration(p.seconds_until_deadline)} ago`
  }
  return `deadline ${formatDuration(p.absence_timeout_seconds ?? 0)} after last seen`
})

const deadlineExplanation = computed<string>(() => {
  const p = profile.value
  if (!p?.absence_deadline) return 'No absence deadline without a reference observation.'
  const mean = p.mean_interval_seconds ?? 0
  const factor = p.absence_factor?.value ?? 0
  const base =
    `Silence becomes an AbsenceAnomaly at ${formatInstant(p.absence_deadline)}, computed as ` +
    `last seen + ${mean.toFixed(2)}s × ${factor} = ${formatDuration(p.absence_timeout_seconds ?? 0)} ` +
    `of grace. This threshold is separate from the cadence-deviation threshold.`
  if (!isAbsent.value && (p.seconds_until_deadline ?? 0) < 0) {
    return (
      `${base} The stored last-seen timestamp is written in batches and can trail live ` +
      `traffic, so it may read as older than this deadline while the detector still ` +
      `considers the ${props.subjectNoun} healthy.`
    )
  }
  return base
})

const hasOverride = computed<boolean>(() => {
  const p = profile.value
  return p?.tolerance_factor?.source === 'override' || p?.absence_factor?.source === 'override'
})

const tuningText = computed<string>(() => (hasOverride.value ? 'operator-tuned' : 'default tuning'))

const tuningExplanation = computed<string>(() => {
  const p = profile.value
  if (!p?.tolerance_factor || !p.absence_factor) return 'No detector factors available.'
  const tol = p.tolerance_factor
  const abs = p.absence_factor
  const describe = (label: string, f: { value: number; source: string; global_default: number }): string =>
    f.source === 'override'
      ? `${label} ${f.value} (operator override, default ${f.global_default})`
      : `${label} ${f.value} (global default)`
  return `${describe('Tolerance factor', tol)}. ${describe('Absence factor', abs)}.`
})

type MarkerKind = 'on-time' | 'early' | 'late' | 'aggregated' | 'inferred-missed'

interface RhythmMarker {
  key: string
  left: number
  kind: MarkerKind
  label: string
  timestamp: string
  active: boolean
}

const MARKER_GLYPHS: Record<MarkerKind, string> = {
  'on-time': '│',
  early: '│',
  late: '│',
  'inferred-missed': '│',
  aggregated: '│',
}

const MARKER_KIND_LABELS: Record<MarkerKind, string> = {
  'on-time': 'On-time arrival',
  early: 'Early arrival',
  late: 'Late arrival',
  'inferred-missed': 'Inferred missed arrival',
  aggregated: 'Aggregated arrivals',
}

/**
 * Millisecond bounds of the selected window, or null when unusable.
 */
const windowBounds = computed<{ start: number; stop: number; span: number } | null>(() => {
  const range = props.timeRange
  if (!range) return null
  const start = new Date(range.start).getTime()
  const stop = new Date(range.stop).getTime()
  const span = stop - start
  if (!Number.isFinite(span) || span <= 0) return null
  return { start, stop, span }
})

/**
 * Convert an epoch instant to a percentage offset across the window.
 *
 * Returns null when the instant falls outside the window, so callers
 * never position an element off-strip.
 */
function toPercent(t: number): number | null {
  const bounds = windowBounds.value
  if (!bounds || Number.isNaN(t)) return null
  if (t < bounds.start || t > bounds.stop) return null
  return ((t - bounds.start) / bounds.span) * 100
}

/**
 * Half-width (seconds) of the on-time band around an expected beat.
 *
 * Mirrors the detector's own dispersion bound
 * (`tolerance_factor × std_interval`) with a mean-relative floor, so an
 * arrival is only called early/late when it sits outside the same
 * corridor the detector would consider dispersion. The floor keeps
 * strictly periodic traffic from painting every bucket off-beat.
 */
const beatTolerance = computed<number | null>(() => {
  const p = profile.value
  const mean = p?.mean_interval_seconds
  if (!p || mean === null || mean === undefined || mean <= 0) return null
  const std = p.std_interval_seconds ?? 0
  const factor = p.tolerance_factor?.value ?? 2
  return Math.max(std * factor, mean * 0.25)
})

const samplingSummary = computed(() => getPlotSamplingSummary((props.arrivalTimes ?? []).map((time) => ({ time }))))

/**
 * Per-arrival timing is meaningful while bucket spacing does not exceed the
 * learned cadence. Equal-sized buckets preserve one marker per beat; wider
 * buckets may contain multiple beats and are therefore aggregated.
 */
const cadenceIsResolvable = computed<boolean>(() => {
  const bucketSeconds = samplingSummary.value.bucketSeconds
  const mean = profile.value?.mean_interval_seconds
  return bucketSeconds === null || mean === null || mean === undefined || mean <= 0 || bucketSeconds <= mean
})

const aggregatedExplanation = computed<string>(() => {
  const bucket = samplingSummary.value.bucketSeconds
  const mean = profile.value?.mean_interval_seconds
  const bucketText = bucket === null ? 'irregular spacing' : `${bucket}s`
  const meanText = mean === null || mean === undefined ? 'the learned cadence' : `${mean.toFixed(1)}s`
  return `Aggregated arrivals — the plot bucket (${bucketText}) is coarser than the learned cadence (${meanText}), so each mark stands for one or more arrivals and cannot be judged early or late. Narrow the time window or raise the sample point limit to restore per-arrival timing.`
})

/**
 * Sorted, in-window arrival instants (ms) backing the marker strip.
 */
const arrivalInstants = computed<number[]>(() => {
  const bounds = windowBounds.value
  const times = props.arrivalTimes ?? []
  if (!bounds || times.length === 0) return []
  const result: number[] = []
  for (const iso of times) {
    const t = new Date(iso).getTime()
    if (Number.isNaN(t) || t < bounds.start || t > bounds.stop) continue
    result.push(t)
  }
  return result.sort((a, b) => a - b)
})

const nearestMarkerInstant = computed<number | null>(() => {
  const time = crosshairTime.value
  const arrivals = arrivalInstants.value
  if (!sharedCrosshair.enabled.value || time === null || arrivals.length === 0) return null
  const nearest = arrivals.reduce((current, candidate) =>
    Math.abs(candidate - time) < Math.abs(current - time) ? candidate : current,
  )
  const snapSeconds =
    samplingSummary.value.bucketSeconds !== null
      ? samplingSummary.value.bucketSeconds / 2
      : (beatTolerance.value ?? (profile.value?.mean_interval_seconds ?? 0) / 2)
  return Math.abs(nearest - time) <= snapSeconds * 1000 ? nearest : null
})

/**
 * Classify one arrival against the beat it was expected to land on.
 *
 * `delta` is the signed offset from the expected instant: negative is
 * early, positive is late. Inside the tolerance corridor the arrival is
 * on-time.
 */
function classifyArrival(delta: number, toleranceSeconds: number): MarkerKind {
  const deltaSeconds = delta / 1000
  if (Math.abs(deltaSeconds) <= toleranceSeconds) return 'on-time'
  return deltaSeconds < 0 ? 'early' : 'late'
}

/**
 * Arrival markers classified against the learned cadence.
 *
 * Each arrival after the first is compared with the beat projected from
 * its predecessor (`previous + mean_interval`). Beats projected forward
 * from a predecessor that no arrival ever claimed are emitted as
 * `inferred-missed` — an INFERENCE that an expected arrival was not
 * observed, never a received data point.
 *
 * These are observations against the learned cadence and carry no
 * individual verdict: the detector judges the mean over at least five
 * intervals, so off-beat markers legitimately coexist with `normal`.
 */
const markers = computed<RhythmMarker[]>(() => {
  const instants = arrivalInstants.value
  const bounds = windowBounds.value
  const mean = profile.value?.mean_interval_seconds ?? null
  const tolerance = beatTolerance.value
  const aggregated = !cadenceIsResolvable.value
  const active = nearestMarkerInstant.value
  if (!bounds || instants.length === 0) return []

  const result: RhythmMarker[] = []
  const first = instants[0]!
  result.push({
    key: `a-${first}`,
    left: toPercent(first) ?? 0,
    kind: aggregated ? 'aggregated' : 'on-time',
    label: labelFor(aggregated ? 'aggregated' : 'on-time', first),
    timestamp: new Date(first).toISOString(),
    active: active === first,
  })

  if (mean === null || mean <= 0 || tolerance === null) {
    for (const t of instants.slice(1)) {
      result.push({
        key: `a-${t}`,
        left: toPercent(t) ?? 0,
        kind: aggregated ? 'aggregated' : 'on-time',
        label: labelFor(aggregated ? 'aggregated' : 'on-time', t),
        timestamp: new Date(t).toISOString(),
        active: active === t,
      })
    }
    return result
  }

  if (aggregated) {
    for (const current of instants.slice(1)) {
      result.push({
        key: `a-${current}`,
        left: toPercent(current) ?? 0,
        kind: 'aggregated',
        label: labelFor('aggregated', current),
        timestamp: new Date(current).toISOString(),
        active: active === current,
      })
    }
    return result
  }

  const beatMs = mean * 1000
  for (let i = 1; i < instants.length; i++) {
    const previous = instants[i - 1]!
    const current = instants[i]!
    const expected = previous + beatMs
    result.push(...missedBeats(previous, current, beatMs, tolerance))
    const kind = classifyArrival(current - expected, tolerance)
    result.push({
      key: `a-${current}`,
      left: toPercent(current) ?? 0,
      kind,
      label: labelFor(kind, current),
      timestamp: new Date(current).toISOString(),
      active: active === current,
    })
  }
  return result
})

const MIN_MISSED_BEAT_SPACING_PERCENT = 1.5
/**
 * Level-of-detail floor for inferred-missed marks, in percent of window
 * width. Below roughly 20px per beat the marks degenerate into an
 * unreadable barcode and imply a beat-to-mark mapping the zoom cannot
 * support, so at dense cadences the inference is not drawn per beat —
 * the missing arrivals are already legible as the empty stretch between
 * observed markers, and the silence zone carries the absent state.
 */

const MAX_MISSED_MARKERS = 40
/** Hard cap so a pathological gap can never flood the strip. */

/**
 * True when expected beats are far enough apart to mark individually.
 */
const missedBeatsAreLegible = computed<boolean>(() => {
  const bounds = windowBounds.value
  const mean = profile.value?.mean_interval_seconds ?? null
  if (!bounds || mean === null || mean <= 0) return false
  return ((mean * 1000) / bounds.span) * 100 >= MIN_MISSED_BEAT_SPACING_PERCENT
})

/**
 * Emit inferred-missed markers for beats skipped between two arrivals.
 *
 * Only whole beats that fall clear of the tolerance corridor around the
 * next real arrival are emitted, so a merely late arrival is reported
 * as late rather than as a miss plus an arrival. Suppressed entirely at
 * cadences too dense to render legibly (see
 * `MIN_MISSED_BEAT_SPACING_PERCENT`).
 */
function missedBeats(previous: number, current: number, beatMs: number, tolerance: number): RhythmMarker[] {
  if (!missedBeatsAreLegible.value) return []
  const out: RhythmMarker[] = []
  const toleranceMs = tolerance * 1000
  let expected = previous + beatMs
  while (current - expected > toleranceMs && out.length < MAX_MISSED_MARKERS) {
    const left = toPercent(expected)
    if (left !== null) {
      out.push({
        key: `m-${expected}`,
        left,
        kind: 'inferred-missed',
        label: labelFor('inferred-missed', expected),
        timestamp: new Date(expected).toISOString(),
        active: false,
      })
    }
    expected += beatMs
  }
  return out
}

/**
 * Accessible label for one marker, naming inference as inference.
 */
function labelFor(kind: MarkerKind, instant: number): string {
  const at = formatInstant(new Date(instant).toISOString())
  if (kind === 'aggregated') return `${aggregatedExplanation.value} Mark at ${at}.`
  if (kind === 'inferred-missed') {
    return `Inferred missed arrival at ${at}: an expected beat with no observed arrival. This is an inference from the learned cadence, not a received data point.`
  }
  return `${MARKER_KIND_LABELS[kind]} at ${at}, relative to the learned cadence. Markers are observations, not per-arrival alarms.`
}

const markerCounts = computed<Record<MarkerKind, number>>(() => {
  const counts: Record<MarkerKind, number> = { 'on-time': 0, early: 0, late: 0, aggregated: 0, 'inferred-missed': 0 }
  for (const marker of markers.value) counts[marker.kind] += 1
  return counts
})

/**
 * Summary of the marker legend, kept to a compact single string.
 */
const markerLegendText = computed<string>(() => {
  const c = markerCounts.value
  if (c.aggregated > 0) return `${MARKER_GLYPHS.aggregated} ${c.aggregated} aggregated`
  const parts: string[] = [`${MARKER_GLYPHS['on-time']} ${c['on-time']}`]
  if (c.early > 0) parts.push(`${MARKER_GLYPHS.early} ${c.early}`)
  if (c.late > 0) parts.push(`${MARKER_GLYPHS.late} ${c.late}`)
  if (c['inferred-missed'] > 0) parts.push(`${MARKER_GLYPHS['inferred-missed']} ${c['inferred-missed']}`)
  return parts.join(' ')
})

const markerLegendExplanation = computed<string>(() => {
  const c = markerCounts.value
  if (c.aggregated > 0) return aggregatedExplanation.value
  const tol = beatTolerance.value
  const band = tol === null ? 'the learned tolerance' : `± ${tol.toFixed(2)}s`
  return (
    `Arrival markers against the learned cadence: ${MARKER_GLYPHS['on-time']} on-time ${c['on-time']}, ` +
    `${MARKER_GLYPHS.early} early ${c.early}, ${MARKER_GLYPHS.late} late ${c.late}, ` +
    `${MARKER_GLYPHS['inferred-missed']} inferred missed ${c['inferred-missed']}. ` +
    `A beat counts as on-time within ${band} of the expected instant. ` +
    `Inferred-missed marks are expected beats with no observed arrival — an inference from the cadence, ` +
    `not received data. Markers are observations, never per-arrival alarms: the detector judges the mean ` +
    `over at least five intervals, so off-beat markers may coexist with a normal verdict.`
  )
})

/**
 * `Windows` toggle: historical expected corridors on/off.
 *
 * Kept element of the approved synthesis (DECISION.md, "001 Rhythm
 * Corridor → Windows toggle"). Default off, matching the sketch's own
 * default state: the corridors are a deliberate opt-in overlay, so the
 * lane's resting appearance is unchanged from before this feature.
 */
const windowsVisible = computed<boolean>(() => props.windowsVisible)

const _windowsToggleExplanation = computed<string>(() => {
  const tol = beatTolerance.value
  const band = tol === null ? 'the learned tolerance' : `± ${tol.toFixed(2)}s`
  return (
    `Show the expected arrival corridors (${band} around each expected beat) for the part of the ` +
    `window that has already happened. They visualise where an arrival was expected, so an off-beat ` +
    `marker can be read against its corridor. Off by default to keep the strip quiet.`
  )
})

const forecastVisible = computed<boolean>(() => props.forecastVisible)

const _forecastToggleExplanation = computed<string>(
  () =>
    'Show the expected arrival corridor and deadline marker for ticks that have not happened yet (right of NOW). Off hides the forecast strip entirely to keep the lane focused on history.',
)

interface ExpectedWindow {
  key: string
  left: number
  width: number
  label: string
}

/** Below this width per corridor the individual rects are visual noise. */
const MIN_WINDOW_WIDTH_PERCENT = 0.55

/**
 * Expected corridors for beats that already passed, anchored honestly at
 * `previous arrival + k × mean_interval`.
 *
 * Only emitted while each corridor is wide enough to read; below that
 * floor `historicalWindowAggregate` takes over, mirroring the sketch's
 * level-of-detail rule rather than painting an unreadable barcode.
 */
const historicalWindows = computed<ExpectedWindow[]>(() => {
  const bounds = windowBounds.value
  const mean = profile.value?.mean_interval_seconds ?? null
  const tolerance = beatTolerance.value
  const instants = arrivalInstants.value
  if (!bounds || mean === null || mean <= 0 || tolerance === null) return []
  if (!cadenceIsResolvable.value || instants.length < 2) return []
  if (!historicalWindowsAreLegible.value) return []

  const beatMs = mean * 1000
  const halfMs = tolerance * 1000
  const out: ExpectedWindow[] = []
  for (let i = 1; i < instants.length && out.length < MAX_EXPECTED_WINDOWS; i++) {
    const anchor = instants[i - 1]!
    const arrival = instants[i]!
    const beats = Math.max(1, Math.round((arrival - anchor) / beatMs))
    for (let k = 1; k <= beats && out.length < MAX_EXPECTED_WINDOWS; k++) {
      const expected = anchor + k * beatMs
      const win = windowGeometry(expected - halfMs, expected + halfMs)
      if (!win) continue
      out.push({
        key: `w-${expected}`,
        left: win.left,
        width: win.width,
        label:
          `Expected arrival ${formatInstant(new Date(expected).toISOString())} ± ${tolerance.toFixed(2)}s, ` +
          `anchored at the previous arrival + ${mean.toFixed(2)}s. The corridor shows where an arrival was ` +
          `expected; it is not itself a verdict.`,
      })
    }
  }
  return out
})

/** Hard cap so a pathological window can never flood the strip. */
const MAX_EXPECTED_WINDOWS = 240

/**
 * True while one cadence period is wide enough to draw individually.
 */
const historicalWindowsAreLegible = computed<boolean>(() => {
  const bounds = windowBounds.value
  const mean = profile.value?.mean_interval_seconds ?? null
  if (!bounds || mean === null || mean <= 0) return false
  return ((mean * 1000) / bounds.span) * 100 >= MIN_WINDOW_WIDTH_PERCENT
})

/**
 * Single aggregate band replacing the corridors at dense cadences.
 *
 * States plainly that the windows were aggregated, so the operator is
 * never shown a texture that implies an addressable per-beat mapping the
 * zoom cannot support.
 */
const historicalWindowAggregate = computed<ExpectedWindow | null>(() => {
  const bounds = windowBounds.value
  const mean = profile.value?.mean_interval_seconds ?? null
  const instants = arrivalInstants.value
  if (!bounds || mean === null || mean <= 0 || instants.length < 2) return null
  if (historicalWindowsAreLegible.value && cadenceIsResolvable.value) return null
  const win = windowGeometry(instants[0]!, instants[instants.length - 1]!)
  if (!win) return null
  return {
    key: 'w-aggregate',
    left: win.left,
    width: win.width,
    label:
      `Expected cadence every ${mean.toFixed(2)}s — the individual expected windows are aggregated at this ` +
      `zoom because each would be too narrow to read. Narrow the time window to see them individually.`,
  }
})

/**
 * Clamp a time span to the window and express it as percent geometry.
 */
function windowGeometry(startMs: number, stopMs: number): { left: number; width: number } | null {
  const bounds = windowBounds.value
  if (!bounds) return null
  const from = Math.max(startMs, bounds.start)
  const to = Math.min(stopMs, bounds.stop)
  if (to <= from) return null
  return {
    left: ((from - bounds.start) / bounds.span) * 100,
    width: ((to - from) / bounds.span) * 100,
  }
}

interface RhythmTimeTick {
  key: string
  left: number
  label: string
}
const timeTicks = computed<RhythmTimeTick[]>(() => {
  const bounds = windowBounds.value
  if (!bounds) return []
  return Array.from({ length: 5 }, (_, index) => {
    const left = (index / 4) * 100
    const time = new Date(bounds.start + (bounds.span * index) / 4)
    return { key: time.toISOString(), left, label: formatInstant(time.toISOString()) }
  })
})

const crosshairLeft = computed<number | null>(() => {
  if (!sharedCrosshair.enabled.value || crosshairTime.value === null) return null
  return toPercent(crosshairTime.value)
})

function onStripMouseMove(event: MouseEvent): void {
  if (!sharedCrosshair.enabled.value) return
  const element = event.currentTarget
  if (!(element instanceof HTMLElement)) return
  const bounds = windowBounds.value
  if (!bounds) return
  // `offsetX` is relative to the *target* node, not `currentTarget`. Hovering a
  // marker tick would therefore measure against that few-pixel-wide child and
  // report a ratio of ~0, snapping every sibling plot to its first sample.
  // Measure against the strip's own box instead.
  const rect = element.getBoundingClientRect()
  if (rect.width <= 0) return
  const ratio = (event.clientX - rect.left) / rect.width
  sharedCrosshair.publish(bounds.start + Math.max(0, Math.min(1, ratio)) * bounds.span)
}

function onStripMouseLeave(): void {
  if (sharedCrosshair.enabled.value) sharedCrosshair.publish(null)
}

/**
 * Left edge (percent) at which the silence region begins, or null.
 *
 * The zone spans last seen → the right edge of the window. It is the
 * lane's own depiction of missing evidence and is deliberately
 * red-toned so the absent state is readable from the strip alone. The
 * feature plots below are never shaded red for a silence — that binding
 * rule is unaffected, this element lives only in the RHYTHM lane.
 */
const silenceLeft = computed<number | null>(() => {
  const p = profile.value
  const bounds = windowBounds.value
  if (!p?.last_seen || !bounds || !isAbsent.value) return null
  const seen = new Date(p.last_seen).getTime()
  if (Number.isNaN(seen)) return null
  if (seen <= bounds.start) return 0
  if (seen >= bounds.stop) return null
  return ((seen - bounds.start) / bounds.span) * 100
})

const silenceExplanation = computed<string>(() => {
  const p = profile.value
  if (!p) return ''
  return (
    `No data observed since ${formatInstant(p.last_seen)}. This zone marks missing evidence, not measured ` +
    `values: during silence no new interval and no new feature value exists, which is why the feature plots ` +
    `below simply stop rather than showing an anomaly.`
  )
})

/**
 * Position (percent) of the NOW reference line, or null when off-window.
 *
 * Uses the server's own `now` so the line, the chip text and the
 * deadline all reconcile against one clock.
 */
const nowLeft = computed<number | null>(() => {
  const p = profile.value
  if (!p?.now) return null
  return toPercent(new Date(p.now).getTime())
})

/**
 * Position (percent) of the absence-deadline line, or null.
 */
const deadlineLeft = computed<number | null>(() => {
  const p = profile.value
  if (!p?.absence_deadline) return null
  return toPercent(new Date(p.absence_deadline).getTime())
})

/**
 * Position (percent) of the absence cross, or null.
 *
 * The cross marks the point where the deadline was crossed — the instant
 * the silence became an `AbsenceAnomaly`. It is drawn only for an active
 * absence episode and only while that instant falls inside the window,
 * so it can never appear detached from the episode it belongs to.
 *
 * It deliberately coexists with the silence hatching: the hatch carries
 * the EXTENT of the missing evidence, the cross carries its ONSET. The
 * hatch alone left the crossing point itself unmarked.
 */
const absenceCrossLeft = computed<number | null>(() => {
  const p = profile.value
  if (!p?.absence_deadline || !isAbsent.value) return null
  return toPercent(new Date(p.absence_deadline).getTime())
})

const absenceCrossLabel = computed<string>(() => {
  const p = profile.value
  if (!p?.absence_deadline) return ''
  const mean = p.mean_interval_seconds ?? 0
  const factor = p.absence_factor?.value ?? 0
  const since = p.seconds_until_deadline === null ? null : formatDuration(p.seconds_until_deadline)
  return (
    `Absence deadline crossed at ${formatInstant(p.absence_deadline)}` +
    `${since === null ? '' : ` — ${since} ago`}: no arrival was observed by last seen + ` +
    `${mean.toFixed(2)}s × ${factor}, so AbsenceAnomaly became active here. This mark is an inference ` +
    `from the learned cadence, not a received data point; the hatched zone right of it shows how long ` +
    `the silence has lasted.`
  )
})

/**
 * Expected arrival corridors that lie AFTER the server's `now`.
 *
 * Anchored honestly at `last observed arrival + k × mean_interval` and
 * computed from the same profile the NOW/DEADLINE lines already use — no
 * second timeseries or API request is introduced.
 *
 * These are projections, so they are positioned inside their own
 * forecast track (0-100% of the horizon span) rather than in the marker
 * strip, whose domain is the query window and must stay aligned with the
 * feature plots below.
 */
const forecastWindows = computed<ExpectedWindow[]>(() => {
  const p = profile.value
  const span = forecastSpanMs.value
  const mean = p?.mean_interval_seconds ?? null
  const tolerance = beatTolerance.value
  const anchor = forecastAnchor.value
  const now = forecastNow.value
  if (!p || span === null || mean === null || mean <= 0 || tolerance === null || anchor === null || now === null) {
    return []
  }

  const beatMs = mean * 1000
  const halfMs = tolerance * 1000
  const horizonEnd = now + span
  const out: ExpectedWindow[] = []
  let k = Math.max(1, Math.ceil((now - anchor) / beatMs))
  for (; out.length < MAX_FORECAST_WINDOWS; k++) {
    const expected = anchor + k * beatMs
    if (expected - halfMs > horizonEnd) break
    if (expected + halfMs <= now) continue
    const from = Math.max(expected - halfMs, now)
    const to = Math.min(expected + halfMs, horizonEnd)
    if (to <= from) continue
    out.push({
      key: `f-${expected}`,
      left: ((from - now) / span) * 100,
      width: Math.max(((to - from) / span) * 100, MIN_FORECAST_WIDTH_PERCENT),
      label:
        `Expected arrival ${formatInstant(new Date(expected).toISOString())} ± ${tolerance.toFixed(2)}s, ` +
        `anchored at the last observed arrival + ${k} × ${mean.toFixed(2)}s. This is a projection from the ` +
        `learned cadence: it lies outside the selected query window and no arrival has been observed for it.`,
    })
  }
  return out
})

/** Enough windows to read the rhythm, few enough to stay legible. */
const MAX_FORECAST_WINDOWS = 12

/** Keeps a very narrow corridor from collapsing to an invisible sliver. */
const MIN_FORECAST_WIDTH_PERCENT = 0.8

/**
 * Server reference instant (ms) the forecast starts from.
 */
const forecastNow = computed<number | null>(() => {
  const raw = profile.value?.now
  if (!raw) return null
  const t = new Date(raw).getTime()
  return Number.isNaN(t) ? null : t
})

/**
 * Instant (ms) the expected beats are counted from.
 *
 * The last observed arrival when the plot supplies one — that is the
 * anchor the design record names. Falls back to the profile's own
 * `last_seen` so a silent series (whose arrivals left the window
 * entirely) still projects its beats from a real observation.
 */
const forecastAnchor = computed<number | null>(() => {
  const instants = arrivalInstants.value
  if (instants.length > 0) return instants[instants.length - 1]!
  const seen = profile.value?.last_seen
  if (!seen) return null
  const t = new Date(seen).getTime()
  return Number.isNaN(t) ? null : t
})

/**
 * Width (ms) of the projected horizon.
 *
 * Scaled to the learned cadence so a slow flow still shows several
 * upcoming beats and a fast one does not project absurdly far, and
 * always wide enough to contain a pending deadline — the countdown and
 * the horizon must not disagree about whether the deadline is ahead.
 */
const forecastSpanMs = computed<number | null>(() => {
  const p = profile.value
  const mean = p?.mean_interval_seconds ?? null
  const now = forecastNow.value
  if (!p || mean === null || mean <= 0 || now === null) return null
  let span = mean * 1000 * FORECAST_BEATS
  const deadline = p.absence_deadline ? new Date(p.absence_deadline).getTime() : NaN
  if (!Number.isNaN(deadline) && deadline > now) {
    span = Math.max(span, (deadline - now) * 1.15)
  }
  return span > 0 ? span : null
})

/** Number of expected beats the horizon aims to cover. */
const FORECAST_BEATS = 6

/**
 * Deadline position inside the forecast track, or null when it is not
 * ahead of `now` (an already-exceeded deadline is marked in the strip by
 * the absence cross instead).
 */
const forecastDeadlineLeft = computed<number | null>(() => {
  const p = profile.value
  const now = forecastNow.value
  const span = forecastSpanMs.value
  if (!p?.absence_deadline || now === null || span === null) return null
  const deadline = new Date(p.absence_deadline).getTime()
  if (Number.isNaN(deadline) || deadline <= now || deadline > now + span) return null
  return ((deadline - now) / span) * 100
})

const forecastExplanation = computed<string>(() => {
  const p = profile.value
  const mean = p?.mean_interval_seconds ?? 0
  const tol = beatTolerance.value
  const span = forecastSpanMs.value
  const band = tol === null ? 'the learned tolerance' : `± ${tol.toFixed(2)}s`
  const horizon = span === null ? '' : ` over the next ${formatDuration(span / 1000)}`
  return (
    `Expected arrivals${horizon}, projected from the last observed arrival + k × ${mean.toFixed(2)}s ` +
    `with a ${band} corridor. Everything here lies to the right of NOW and therefore outside the ` +
    `selected query window: these are projections from the learned cadence, not observations, and they ` +
    `are drawn dashed to say so. No arrival has been recorded for any of them yet.`
  )
})

const nowLineLabel = computed<string>(() => {
  const p = profile.value
  return `NOW ${formatInstant(p?.now ?? null)}. Server reference time; every duration in this lane is derived from it.`
})

const deadlineLineLabel = computed<string>(() => {
  const p = profile.value
  if (!p?.absence_deadline) return ''
  const state = isAbsent.value ? 'exceeded' : 'not yet reached'
  return (
    `Absence deadline ${formatInstant(p.absence_deadline)} (${state}): last seen + ` +
    `${(p.mean_interval_seconds ?? 0).toFixed(2)}s × ${p.absence_factor?.value ?? 0}. ` +
    `Separate from the cadence-deviation threshold.`
  )
})
</script>

<style scoped lang="scss">
.rhythm-lane {
  flex-shrink: 0;
  padding: $spacing-xs $spacing-sm;
  margin-bottom: $spacing-xs;
  border: 1px solid var(--cd-border);
  border-radius: $border-radius-md;
  background-color: var(--cd-surface);
}

.rhythm-title {
  letter-spacing: 1px;
}

.state-chip {
  font-size: 11px;
  margin: 0;
}

.state-chip-focus {
  display: inline-flex;
  border-radius: $border-radius-md;
  cursor: help;

  &:focus-visible {
    outline: 2px solid var(--q-primary);
    outline-offset: 2px;
  }
}

.fact {
  white-space: nowrap;
  cursor: help;
  border-bottom: 1px dotted var(--cd-border);

  &:focus-visible {
    outline: 2px solid var(--q-primary);
    outline-offset: 2px;
  }
}

.tuning {
  font-family: $font-family-base;
}

/* The strip is the lane's time axis and must line up with the feature plots
   stacked underneath it, whose ECharts grid insets the drawing area by
   `left: 60` / `right: 20` for the y-axis labels (TimeseriesChart.vue). The
   same insets are applied here so a marker and a plot point at the same
   instant share an x position (UI-094). */
.marker-strip {
  position: relative;
  height: 22px;
  margin-left: 50px;
  margin-right: 12px;
  border-radius: $border-radius-sm;
  background-color: var(--cd-border);
  overflow: hidden;
}

/* Kept flush with the strip above it rather than the lane's outer edge. */
.marker-legend-row {
  margin-left: 50px;
  margin-right: 12px;
}

.marker {
  position: absolute;
  top: 0;
  height: 22px;
  width: 14px;
  margin-left: -7px;
  /* Markers must receive hover so the per-marker tooltip can explain why a
     glyph is a cross or an arrow (UI-094). They previously opted out of
     pointer events entirely; `cursor: help` signals that they answer. */
  pointer-events: auto;
  cursor: help;
  user-select: none;
}

.marker-tick {
  display: block;
  width: 2px;
  height: 10px;
  margin: 6px auto 0;
  border-radius: 1px;
  background: currentColor;
}

.marker--on-time {
  color: var(--q-primary);
}

.marker--early {
  color: #ffb74d;
}

.marker--late {
  color: #ff7043;
}

.marker--aggregated {
  color: #78909c;
}

.marker--active .marker-tick {
  width: 4px;
  height: 18px;
  margin-top: 2px;
  background: #b3e5fc;
  box-shadow: 0 0 5px #81d4fa;
}

/* An inference, not a received data point: rendered hollow-bright and
   labelled as such in its aria-label and the legend tooltip. */
.marker--inferred-missed {
  color: #ef5350;
  font-weight: 700;
}

.time-axis {
  position: relative;
  height: 18px;
  margin: 0 12px 0 50px;
  border-top: 1px solid var(--cd-border);
}
.time-tick {
  position: absolute;
  top: 0;
  transform: translateX(-50%);
}
.time-tick-mark {
  display: block;
  width: 1px;
  height: 4px;
  background: var(--cd-text-secondary, #90a4ae);
}
.time-tick-label {
  display: block;
  font: 9px $font-family-mono;
  color: var(--cd-text-secondary, #90a4ae);
  white-space: nowrap;
}
.time-tick:first-child {
  transform: none;
}
.time-tick:last-child {
  transform: translateX(-100%);
}
.shared-crosshair {
  position: absolute;
  top: 0;
  bottom: 0;
  width: 1px;
  width: 0;
  border-left: 1px dashed var(--q-primary);
  pointer-events: none;
  z-index: 5;
}

/* Absence is missing evidence, but the operator must be able to read the
   state off the strip itself without the chip. The zone is therefore
   high-contrast and red-toned. This applies to the RHYTHM lane ONLY —
   the feature plots below are never shaded red for a silence. */
.silence-zone {
  position: absolute;
  top: 0;
  right: 0;
  bottom: 0;
  border-left: 2px solid rgba(239, 83, 80, 0.95);
  background-color: rgba(239, 83, 80, 0.22);
  background-image: repeating-linear-gradient(
    45deg,
    rgba(239, 83, 80, 0.55),
    rgba(239, 83, 80, 0.55) 3px,
    transparent 3px,
    transparent 7px
  );
  cursor: help;

  &:focus-visible {
    outline: 2px solid var(--q-primary);
    outline-offset: -2px;
  }
}

.silence-tag {
  position: absolute;
  top: 50%;
  left: 4px;
  transform: translateY(-50%);
  font-family: $font-family-mono;
  font-size: 9px;
  font-weight: 700;
  letter-spacing: 0.5px;
  color: #ffebee;
  text-shadow: 0 0 3px rgba(0, 0, 0, 0.9);
  white-space: nowrap;
  pointer-events: none;
}

/* The absence cross marks WHERE the deadline was crossed; the silence
   hatch beside it marks HOW LONG the silence has lasted. Both are shown
   together on purpose — neither replaces the other. Drawn above the zone
   so the glyph stays readable against the hatching. */
.absence-cross {
  position: absolute;
  top: 0;
  bottom: 0;
  width: 16px;
  margin-left: -8px;
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 4;
  cursor: help;

  &:focus-visible {
    outline: 2px solid var(--q-primary);
    outline-offset: -2px;
  }
}

.absence-cross-glyph {
  font-family: $font-family-mono;
  font-size: 13px;
  font-weight: 700;
  line-height: 1;
  color: #ef5350;
  /* Dark halo so the glyph reads against the red hatching it sits on. */
  text-shadow:
    0 0 3px rgba(0, 0, 0, 0.95),
    0 0 2px rgba(0, 0, 0, 0.95);
  pointer-events: none;
}

/* Expected corridors. Past = filled teal (it happened, the corridor is a
   fact); future = dashed outline (prospective, not yet observed). The
   two classes are deliberately distinguishable at a glance. */
.expected-window {
  position: absolute;
  top: 4px;
  bottom: 4px;
  border-radius: 1px;
  pointer-events: auto;
  cursor: help;

  &:focus-visible {
    outline: 2px solid var(--q-primary);
    outline-offset: -1px;
  }
}

.expected-window--past {
  background-color: rgba(77, 208, 225, 0.16);
  border: 1px solid rgba(77, 208, 225, 0.45);
}

.expected-window--aggregate {
  border: 1px solid rgba(77, 208, 225, 0.45);
  background-color: rgba(77, 208, 225, 0.1);
  background-image: repeating-linear-gradient(
    -45deg,
    rgba(77, 208, 225, 0.4),
    rgba(77, 208, 225, 0.4) 1px,
    transparent 1px,
    transparent 6px
  );
}

.expected-window--future {
  background-color: rgba(77, 208, 225, 0.1);
  border: 1px dashed rgba(77, 208, 225, 0.55);
}

/* The forecast is a projection and never shares the marker strip's time
   domain, which stays pixel-aligned with the feature plots (UI-094).
   It therefore gets its own track, explicitly labelled as being outside
   the query window. */
.forecast-strip {
  position: relative;
  display: flex;
  align-items: center;
  gap: 6px;
  margin: 2px 12px 0 50px;
  height: 16px;
}

.forecast-track {
  position: relative;
  flex: 1 1 auto;
  height: 14px;
  border-radius: $border-radius-sm;
  border-left: 1px solid var(--cd-info, #29b6f6);
  background-color: rgba(120, 144, 156, 0.1);
}

.forecast-tag,
.forecast-note {
  font-family: $font-family-mono;
  font-size: 9px;
  font-weight: 700;
  letter-spacing: 0.5px;
  white-space: nowrap;
  color: var(--cd-text-secondary, #90a4ae);
}

.forecast-note {
  font-weight: 400;
  cursor: help;

  &:focus-visible {
    outline: 2px solid var(--q-primary);
    outline-offset: 2px;
  }
}

.forecast-deadline {
  z-index: 2;
}

.windows-toggle {
  font-size: 11px;
}

.axis-line {
  position: absolute;
  top: 0;
  bottom: 0;
  width: 2px;
  margin-left: -1px;
  cursor: help;

  &:focus-visible {
    outline: 2px solid var(--q-primary);
    outline-offset: 1px;
  }
}

.now-line {
  background-color: var(--cd-info, #29b6f6);
  z-index: 3;
}

/* Dashed while the deadline is still ahead, solid once exceeded — the
   line states whether the threshold has actually been crossed. */
.deadline-line {
  z-index: 2;
  background-image: linear-gradient(
    to bottom,
    rgba(239, 83, 80, 0.95) 0,
    rgba(239, 83, 80, 0.95) 4px,
    transparent 4px,
    transparent 8px
  );
  background-size: 2px 8px;
  background-repeat: repeat-y;
}

.deadline-line--exceeded {
  background-image: none;
  background-color: rgba(239, 83, 80, 0.95);
}

.axis-tag {
  position: absolute;
  top: 1px;
  font-family: $font-family-mono;
  font-size: 9px;
  font-weight: 700;
  letter-spacing: 0.5px;
  white-space: nowrap;
  text-shadow: 0 0 3px rgba(0, 0, 0, 0.9);
  pointer-events: none;
}

.axis-tag--now {
  left: 3px;
  color: var(--cd-info, #29b6f6);
}

.axis-tag--deadline {
  right: 3px;
  color: #ef5350;
}

.marker-legend {
  cursor: help;
  letter-spacing: 1px;
  color: var(--cd-text-secondary, #90a4ae);

  &:focus-visible {
    outline: 2px solid var(--q-primary);
    outline-offset: 2px;
  }
}
</style>
