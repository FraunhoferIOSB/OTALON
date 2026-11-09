<template>
  <div ref="widgetRoot" class="widget-root">
    <q-card flat bordered class="widget-card full-height">
      <q-card-section class="q-pb-none">
        <div class="row items-center no-wrap q-mb-sm">
          <q-icon :name="DOMAIN_ICONS.protocols" color="primary" size="20px" />
          <span class="text-subtitle1 text-weight-bold q-ml-sm">Top Protocols</span>
          <q-space />
          <q-btn flat dense size="sm" label="View All" color="primary" no-caps to="/proto-timeseries" />
        </div>
      </q-card-section>
      <q-card-section class="q-pt-xs" style="overflow: auto; flex: 1 1 auto">
        <q-list v-if="displayedProtocols.length > 0" dense separator>
          <DashboardTopListRow
            v-for="proto in displayedProtocols"
            :key="proto.id"
            :label="humanizeProtocolStack(proto.protocol || proto.id)"
            :tooltip="proto.id"
            :byte-count="proto.byte_count"
            :packet-count="proto.packet_count"
            :is-anomaly="proto.is_anomaly"
            :sparkline="proto.sparkline"
          />
        </q-list>
        <div v-else class="text-center text-grey q-pa-lg">
          <q-icon :name="DOMAIN_ICONS.protocols" size="32px" class="q-mb-xs" />
          <div class="text-body2">No protocol traffic in window</div>
        </div>
      </q-card-section>
    </q-card>
  </div>
</template>

<script setup lang="ts">
import { useDashboardStore } from '~/stores/dashboardStore'
import { DOMAIN_ICONS } from '~/composables/useNavigation'
import { humanizeProtocolStack } from '~/utils/protocol'
import { useWidgetSize } from '~/composables/useWidgetSize'

const dashboardStore = useDashboardStore()
const widgetRoot = ref<HTMLElement | null>(null)
const { height } = useWidgetSize(widgetRoot)

const maxRows = computed(() => {
  const rows = Math.floor((height.value - 64) / 36)
  return Math.min(8, Math.max(2, rows))
})

const displayedProtocols = computed(() => dashboardStore.protocolIds.slice(0, maxRows.value))
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
