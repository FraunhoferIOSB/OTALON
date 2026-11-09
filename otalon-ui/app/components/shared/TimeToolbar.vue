<template>
  <div class="time-toolbar row items-center q-gutter-x-sm q-mb-md no-wrap">
    <q-toggle
      :model-value="appStore.liveMode"
      label="LIVE"
      color="teal"
      dense
      class="live-toggle"
      @update:model-value="onLiveToggle"
    />

    <q-select
      :model-value="appStore.liveIntervalSeconds"
      :options="appStore.intervalOptions"
      option-value="value"
      option-label="label"
      emit-value
      map-options
      dense
      outlined
      :disable="!appStore.liveMode"
      class="interval-select"
      @update:model-value="onIntervalChange"
    >
      <template #prepend>
        <q-icon name="timer" size="18px" />
      </template>
    </q-select>

    <q-input
      :model-value="formattedStart"
      label="Start"
      dense
      outlined
      readonly
      :disable="appStore.liveMode"
      class="datetime-input"
      @click="appStore.liveMode ? null : (showStartPicker = true)"
    >
      <template #prepend>
        <q-icon name="event" size="18px" />
      </template>
      <q-popup-proxy
        v-if="!appStore.liveMode"
        v-model="showStartPicker"
        transition-show="scale"
        transition-hide="scale"
      >
        <div class="row">
          <q-date :model-value="startDateStr" mask="YYYY-MM-DD" minimal @update:model-value="onStartDateChange" />
          <q-time :model-value="startTimeStr" mask="HH:mm" format24h @update:model-value="onStartTimeChange" />
        </div>
      </q-popup-proxy>
    </q-input>

    <span class="text-muted text-caption q-px-xs">—</span>

    <q-input
      :model-value="formattedEnd"
      label="End"
      dense
      outlined
      readonly
      :disable="appStore.liveMode"
      class="datetime-input"
      @click="appStore.liveMode ? null : (showEndPicker = true)"
    >
      <template #prepend>
        <q-icon name="event" size="18px" />
      </template>
      <q-popup-proxy v-if="!appStore.liveMode" v-model="showEndPicker" transition-show="scale" transition-hide="scale">
        <div class="row">
          <q-date :model-value="endDateStr" mask="YYYY-MM-DD" minimal @update:model-value="onEndDateChange" />
          <q-time :model-value="endTimeStr" mask="HH:mm" format24h @update:model-value="onEndTimeChange" />
        </div>
      </q-popup-proxy>
    </q-input>

    <q-btn flat dense round icon="refresh" color="primary" aria-label="Update data" @click="onUpdate">
      <q-tooltip>Update data</q-tooltip>
    </q-btn>

    <q-btn flat dense round icon="settings" color="primary" aria-label="Settings">
      <q-tooltip>Settings</q-tooltip>
      <q-menu anchor="bottom right" self="top right" class="settings-menu">
        <q-list dense style="min-width: 220px">
          <q-item-label header>Refresh Rate</q-item-label>
          <q-item
            v-for="opt in appStore.pollingIntervalOptions"
            :key="opt.value"
            v-close-popup
            clickable
            :active="appStore.pollingIntervalMs === opt.value"
            active-class="text-primary"
            @click="onPollingIntervalChange(opt.value)"
          >
            <q-item-section>{{ opt.label }}</q-item-section>
            <q-item-section v-if="appStore.pollingIntervalMs === opt.value" side>
              <q-icon name="check" color="primary" size="16px" />
            </q-item-section>
          </q-item>
          <template v-if="$slots.settings">
            <q-separator />
            <slot name="settings" />
          </template>
        </q-list>
      </q-menu>
    </q-btn>

    <q-banner v-if="timeRangeError" dense rounded class="time-range-error bg-negative text-white q-ml-sm">
      <template #avatar>
        <q-icon name="warning" size="20px" />
      </template>
      {{ timeRangeError }}
    </q-banner>

    <div v-if="isCurrentRangeEmpty" class="data-extent-hint q-ml-sm row items-center no-wrap" data-testid="data-extent-hint">
      <q-icon name="info" size="16px" color="grey-5" class="q-mr-xs" />
      <span class="data-extent-hint__text">
        No data in the selected range · available {{ formatExtent(firstTs) }} – {{ formatExtent(lastTs) }}
      </span>
      <q-btn
        flat
        dense
        no-caps
        size="sm"
        color="info"
        class="q-ml-sm"
        label="Use available range"
        data-testid="show-data-extent"
        @click="showDataExtent"
      />
    </div>
  </div>
</template>

<script setup lang="ts">
/**
 * Time mode toolbar for switching between live monitoring and history mode.
 *
 * Reads and writes global time state through `appStore` instead of the
 * legacy `useTimeMode` composable. Emits an `update` event when the user
 * triggers an explicit data refresh.
 */
import { useAppStore } from '~/stores/appStore'
import { useDataExtent } from '~/composables/useDataExtent'

const emit = defineEmits<{
  update: []
}>()

const appStore = useAppStore()
const { firstTs, lastTs, isCurrentRangeEmpty } = useDataExtent()

const showStartPicker = ref(false)
const showEndPicker = ref(false)

const timeRangeError = ref<string | null>(null)
let errorTimeout: ReturnType<typeof setTimeout> | undefined

function showTimeRangeError(): void {
  timeRangeError.value = 'Invalid time range: start must be before end.'
  clearTimeout(errorTimeout)
  errorTimeout = setTimeout(() => {
    timeRangeError.value = null
  }, 5000)
}

function padTwo(n: number): string {
  return n.toString().padStart(2, '0')
}

function formatDatetime(date: Date): string {
  const y = date.getFullYear()
  const mo = padTwo(date.getMonth() + 1)
  const d = padTwo(date.getDate())
  const h = padTwo(date.getHours())
  const mi = padTwo(date.getMinutes())
  return `${y}-${mo}-${d} ${h}:${mi}`
}

function toDateStr(date: Date): string {
  return `${date.getFullYear()}-${padTwo(date.getMonth() + 1)}-${padTwo(date.getDate())}`
}

function toTimeStr(date: Date): string {
  return `${padTwo(date.getHours())}:${padTwo(date.getMinutes())}`
}

const historyStart = computed(() => new Date(appStore.timeRange.start))
const historyEnd = computed(() => new Date(appStore.timeRange.end))

const formattedStart = computed(() => formatDatetime(historyStart.value))
const formattedEnd = computed(() => formatDatetime(historyEnd.value))
const startDateStr = computed(() => toDateStr(historyStart.value))
const startTimeStr = computed(() => toTimeStr(historyStart.value))
const endDateStr = computed(() => toDateStr(historyEnd.value))
const endTimeStr = computed(() => toTimeStr(historyEnd.value))

function onLiveToggle(value: boolean | null): void {
  appStore.setLiveMode(value === true)
}

function onIntervalChange(value: number): void {
  appStore.setLiveInterval(value)
  emit('update')
}

function mergeDatetime(dateStr: string, timeStr: string): Date {
  const [year, month, day] = dateStr.split('-').map(Number)
  const [hours, minutes] = timeStr.split(':').map(Number)
  return new Date(year, month - 1, day, hours, minutes)
}

function onStartDateChange(value: string | null): void {
  if (!value) return
  const newStart = mergeDatetime(value, startTimeStr.value)
  if (newStart >= historyEnd.value) {
    showTimeRangeError()
    return
  }
  timeRangeError.value = null
  appStore.setTimeRange(newStart.toISOString(), historyEnd.value.toISOString())
}

function onStartTimeChange(value: string | null): void {
  if (!value) return
  const newStart = mergeDatetime(startDateStr.value, value)
  if (newStart >= historyEnd.value) {
    showTimeRangeError()
    return
  }
  timeRangeError.value = null
  appStore.setTimeRange(newStart.toISOString(), historyEnd.value.toISOString())
}

function onEndDateChange(value: string | null): void {
  if (!value) return
  const newEnd = mergeDatetime(value, endTimeStr.value)
  if (historyStart.value >= newEnd) {
    showTimeRangeError()
    return
  }
  timeRangeError.value = null
  appStore.setTimeRange(historyStart.value.toISOString(), newEnd.toISOString())
}

function onEndTimeChange(value: string | null): void {
  if (!value) return
  const newEnd = mergeDatetime(endDateStr.value, value)
  if (historyStart.value >= newEnd) {
    showTimeRangeError()
    return
  }
  timeRangeError.value = null
  appStore.setTimeRange(historyStart.value.toISOString(), newEnd.toISOString())
}

/**
 * Apply a new polling refresh interval via the app store.
 *
 * @param ms - The polling interval in milliseconds.
 */
function onPollingIntervalChange(ms: number): void {
  appStore.setPollingInterval(ms)
  emit('update')
}

function onUpdate(): void {
  emit('update')
}

/**
 * Format an extent boundary for the compact hint, or an empty string.
 *
 * @param value - ISO 8601 timestamp, or `null` when the extent is unknown.
 * @returns A short localized date-time string.
 */
function formatExtent(value: string | null): string {
  return value ? new Date(value).toLocaleString('en-GB', { dateStyle: 'short', timeStyle: 'short' }) : ''
}

function showDataExtent(): void {
  if (!firstTs.value || !lastTs.value) return
  appStore.setLiveMode(false)
  appStore.setTimeRange(firstTs.value, lastTs.value)
  emit('update')
}
</script>

<style scoped lang="scss">
.time-toolbar {
  padding: 6px 12px;
  border-radius: $border-radius-md;
  background-color: var(--cd-surface);
  border: 1px solid var(--cd-border);
}

.live-toggle {
  flex-shrink: 0;

  :deep(.q-toggle__label) {
    font-weight: 700;
    font-size: 12px;
    letter-spacing: 0.8px;
  }
}

.interval-select {
  min-width: 110px;
  max-width: 130px;
}

.datetime-input {
  min-width: 160px;
  max-width: 180px;
}

.time-range-error {
  font-size: 12px;
  padding: 4px 12px;
  min-height: unset;
}

// Deliberately not a q-banner: its `#action` slot stacks below the text at
// this width, which made the hint two rows tall and pushed the whole page
// down. A plain inline flex row keeps the toolbar at its original height.
.data-extent-hint {
  color: var(--cd-primary-text);
  background-color: rgba(var(--cd-info-rgb), 0.12);
  border-left: 3px solid var(--cd-info);
  border-radius: $border-radius-md;
  font-size: 12px;
  line-height: 1.2;
  padding: 2px 8px;
  min-height: unset;
  min-width: 0;
  overflow: hidden;

  .q-btn {
    flex-shrink: 0;
  }
}

.data-extent-hint__text {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
</style>
