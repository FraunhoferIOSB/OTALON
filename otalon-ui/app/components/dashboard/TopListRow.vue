<template>
  <q-item dense class="dashboard-top-list-row">
    <q-item-section avatar>
      <q-icon name="circle" size="10px" :color="props.isAnomaly ? 'negative' : 'positive'" />
    </q-item-section>
    <q-item-section>
      <q-item-label class="text-body2 ellipsis">
        {{ props.label }}
        <q-tooltip v-if="props.tooltip" class="text-caption">{{ props.tooltip }}</q-tooltip>
      </q-item-label>
      <q-item-label caption>
        {{ formatBytes(props.byteCount) }} · {{ formatNumber(props.packetCount) }} pkts
      </q-item-label>
    </q-item-section>
    <q-item-section v-if="hasSparkline" side class="q-pr-xs">
      <DashboardInlineSparkline :data="props.sparkline" :width="60" :height="20" />
    </q-item-section>
    <q-item-section side>
      <q-badge :color="props.isAnomaly ? 'negative' : 'grey'" :label="props.isAnomaly ? 'Anomaly' : 'Normal'" />
    </q-item-section>
  </q-item>
</template>

<script setup lang="ts">
import { formatBytes, formatNumber } from '~/utils/format'

/**
 * Shared list row for Top Connections, Top Assets, and Top Protocols widgets.
 *
 * Renders an anomaly status dot, a primary label with optional tooltip,
 * a "Bytes · Packets" caption, an inline sparkline, and an Anomaly/Normal badge.
 */
const props = defineProps<{
  label: string
  tooltip?: string
  byteCount: number
  packetCount: number
  isAnomaly: boolean
  sparkline?: number[]
}>()

const hasSparkline = computed(() => {
  return (props.sparkline?.length ?? 0) > 0
})
</script>

<style scoped lang="scss">
.dashboard-top-list-row {
  min-height: 44px;
  border-radius: 4px;
}
</style>
