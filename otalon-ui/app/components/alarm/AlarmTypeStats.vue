<template>
  <q-card flat bordered>
    <q-card-section class="q-pb-none">
      <div class="row items-center no-wrap">
        <q-icon name="bar_chart" color="primary" size="20px" />
        <span class="text-subtitle2 text-weight-bold q-ml-sm">Anomaly Type Statistics</span>
        <q-space />
        <q-badge color="primary" :label="`${rows.length} types`" />
      </div>
    </q-card-section>
    <q-card-section class="q-pt-sm">
      <div v-for="row in rows" :key="row.type" class="type-stat-row q-mb-md">
        <div class="row items-center no-wrap q-mb-xs">
          <q-chip dense size="sm" :color="mitreChipColor(row.type)" text-color="white">
            {{ row.type }}
          </q-chip>
          <q-space />
          <span class="text-caption text-weight-bold"> Score: {{ row.score_norm.toFixed(2) }} </span>
        </div>

        <q-linear-progress
          :value="row.score_norm"
          :color="scoreBarColor(row.score_norm)"
          :track-color="$q.dark.isActive ? 'grey-9' : 'grey-3'"
          rounded
          size="6px"
          class="q-mb-xs"
        />

        <div class="row q-col-gutter-sm text-caption text-muted">
          <div class="col"><strong>Confidence:</strong> {{ (row.confidence_mean * 100).toFixed(0) }}%</div>
          <div class="col"><strong>Intervals:</strong> {{ row.interval_count }}</div>
          <div class="col"><strong>Anomalies:</strong> {{ row.count }}</div>
          <div class="col"><strong>Pkt/s:</strong> {{ row.packet_rate_mean?.toFixed(1) ?? '—' }}</div>
          <div class="col"><strong>B/s:</strong> {{ row.byte_rate_mean?.toFixed(0) ?? '—' }}</div>
        </div>
      </div>

      <div v-if="rows.length === 0" class="text-caption text-muted text-center q-pa-md">
        No anomaly type statistics available.
      </div>
    </q-card-section>
  </q-card>
</template>

<script setup lang="ts">
import { useQuasar } from 'quasar'
import type { AnomalyTypeStat } from '~/types/golden-data'
import { mitreChipColor } from '~/utils/mitre-colors'

/**
 * Display detailed anomaly type statistics with score bars and metrics.
 *
 * Accepts the `anomaly_type_stats` Record from a RealAlarmGroup and renders
 * each type with score, confidence, interval/anomaly counts, and rates.
 */

interface TypeStatRow extends AnomalyTypeStat {
  type: string
}

interface Props {
  stats: Record<string, AnomalyTypeStat>
}

const props = defineProps<Props>()
const $q = useQuasar()

const rows = computed<TypeStatRow[]>(() =>
  Object.entries(props.stats)
    .map(([type, stat]) => ({ type, ...stat }))
    .sort((a, b) => b.score_norm - a.score_norm),
)

/**
 * Return a color for the score progress bar.
 */
function scoreBarColor(score: number): string {
  if (score >= 0.8) return 'negative'
  if (score >= 0.5) return 'warning'
  return 'positive'
}
</script>

<style scoped lang="scss">
.type-stat-row {
  padding: 8px;
  border-radius: 4px;
  background: var(--cd-table-row-even);
}
</style>
