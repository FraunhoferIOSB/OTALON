<template>
  <div style="position: relative; height: 100%">
    <SharedKpiCard
      :value="signalLabel"
      label="Signal"
      icon="traffic"
      :signal-color="mappedSignalColor"
      :trend-label="dashboardStore.anomalyCount > 0 ? `${dashboardStore.anomalyCount} active` : 'All clear'"
      to="/alarms"
    />
  </div>
</template>

<script setup lang="ts">
import type { SignalColor } from '~/types/golden-data'
import { useDashboardStore } from '~/stores/dashboardStore'

const dashboardStore = useDashboardStore()

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

const mappedSignalColor = computed<SignalColor>(() => {
  return BACKEND_SIGNAL_MAP[dashboardStore.signalColor] ?? 'info'
})

const signalLabel = computed(() => SIGNAL_LABELS[mappedSignalColor.value] ?? dashboardStore.signalColor)
</script>
