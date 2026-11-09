<template>
  <div ref="widgetRoot" class="widget-root">
    <q-card flat bordered class="widget-card full-height">
      <q-card-section class="q-pb-none">
        <div class="row items-center no-wrap q-mb-sm">
          <q-icon name="notification_important" color="negative" size="20px" />
          <span class="text-subtitle1 text-weight-bold q-ml-sm">Recent Alarms</span>
          <q-space />
          <q-btn flat dense size="sm" label="View All" color="primary" no-caps to="/alarms" />
        </div>
      </q-card-section>
      <q-card-section class="q-pt-xs" style="overflow: auto; flex: 1 1 auto">
        <q-list v-if="displayedAlarms.length > 0" dense separator>
          <q-item
            v-for="group in displayedAlarms"
            :key="group.id"
            v-ripple
            clickable
            :to="`/alarms?group=${group.id}`"
            class="alarm-item"
          >
            <q-item-section avatar>
              <q-icon name="error_outline" :color="alarmIconColor(group)" size="18px" />
            </q-item-section>
            <q-item-section>
              <q-item-label class="text-body2 ellipsis"> {{ group.primary_type }} ({{ group.module }}) </q-item-label>
              <q-item-label caption class="ellipsis">
                {{ anomalyCountForGroup(group) }} anomalies · {{ group.series_ids.length }} connections
              </q-item-label>
            </q-item-section>
            <q-item-section side class="items-end">
              <q-badge :color="group.is_active ? 'negative' : 'grey'" :label="group.is_active ? 'Active' : 'Closed'" />
              <span class="text-caption text-muted q-mt-xs">{{ formatRelativeTime(group.start_timestamp) }}</span>
            </q-item-section>
          </q-item>
        </q-list>
        <div v-else class="text-center text-grey q-pa-lg">
          <q-icon name="check_circle_outline" size="32px" class="q-mb-xs" />
          <div class="text-body2">No recent alarms</div>
        </div>
      </q-card-section>
    </q-card>
  </div>
</template>

<script setup lang="ts">
import type { AnomalyGroupItem } from '~/types/api'
import { useDashboardStore } from '~/stores/dashboardStore'
import { formatRelativeTime } from '~/utils/format'
import { useWidgetSize } from '~/composables/useWidgetSize'

const dashboardStore = useDashboardStore()
const widgetRoot = ref<HTMLElement | null>(null)
const { height } = useWidgetSize(widgetRoot)

const maxRows = computed(() => {
  const rows = Math.floor((height.value - 64) / 36)
  return Math.min(8, Math.max(2, rows))
})

const displayedAlarms = computed(() => dashboardStore.recentAlarms.slice(0, maxRows.value))

function anomalyCountForGroup(group: AnomalyGroupItem): number {
  return Object.values(group.anomaly_type_stats).reduce((sum, stat) => sum + stat.count, 0)
}

function alarmIconColor(group: AnomalyGroupItem): string {
  if (group.is_active) return 'negative'
  if (!group.confirmed) return 'warning'
  return 'positive'
}
</script>

<style scoped lang="scss">
.widget-root {
  height: 100%;
}

.widget-card {
  display: flex;
  flex-direction: column;
  transition: box-shadow 0.2s ease;

  &:hover {
    box-shadow: 0 4px 16px rgba(0, 0, 0, 0.1);
  }
}

.alarm-item {
  border-radius: 4px;
  min-height: 48px;
}
</style>
