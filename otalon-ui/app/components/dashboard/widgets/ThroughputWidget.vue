<template>
  <div class="widget-root">
    <q-card flat bordered class="widget-card full-height">
      <q-card-section class="q-py-sm q-px-md">
        <div class="row items-center no-wrap q-mb-xs">
          <q-icon name="show_chart" size="18px" color="primary" />
          <span class="text-subtitle2 text-weight-bold q-ml-sm">Network Throughput</span>
          <q-space />
          <span class="text-caption text-muted q-ml-sm" data-testid="throughput-range-label">{{
            appStore.timeRangeLabel
          }}</span>
        </div>
        <DashboardThroughputSparkline :data="dashboardStore.throughputData" />
      </q-card-section>
    </q-card>
  </div>
</template>

<script setup lang="ts">
import { useAppStore } from '~/stores/appStore'
import { useDashboardStore } from '~/stores/dashboardStore'

const appStore = useAppStore()
const dashboardStore = useDashboardStore()
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
</style>
