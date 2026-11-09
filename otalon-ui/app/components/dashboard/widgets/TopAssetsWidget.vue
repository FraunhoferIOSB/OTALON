<template>
  <div ref="widgetRoot" class="widget-root">
    <q-card flat bordered class="widget-card full-height">
      <q-card-section class="q-pb-none">
        <div class="row items-center no-wrap q-mb-sm">
          <q-icon :name="DOMAIN_ICONS.assets" color="primary" size="20px" />
          <span class="text-subtitle1 text-weight-bold q-ml-sm">Top Assets</span>
          <q-space />
          <q-btn flat dense size="sm" label="View All" color="primary" no-caps to="/mac-timeseries" />
        </div>
      </q-card-section>
      <q-card-section class="q-pt-xs" style="overflow: auto; flex: 1 1 auto">
        <q-list v-if="displayedAssets.length > 0" dense separator>
          <DashboardTopListRow
            v-for="asset in displayedAssets"
            :key="asset.id"
            :label="formatAssetDisplay(asset)"
            :tooltip="asset.id"
            :byte-count="asset.byte_count"
            :packet-count="asset.packet_count"
            :is-anomaly="asset.is_anomaly"
            :sparkline="asset.sparkline"
          />
        </q-list>
        <div v-else class="text-center text-grey q-pa-lg">
          <q-icon :name="DOMAIN_ICONS.assets" size="32px" class="q-mb-xs" />
          <div class="text-body2">No MAC traffic in window</div>
        </div>
      </q-card-section>
    </q-card>
  </div>
</template>

<script setup lang="ts">
import { useDashboardStore } from '~/stores/dashboardStore'
import { normalizeMac } from '~/utils/format'
import { useWidgetSize } from '~/composables/useWidgetSize'
import { DOMAIN_ICONS } from '~/composables/useNavigation'

const dashboardStore = useDashboardStore()
const widgetRoot = ref<HTMLElement | null>(null)
const { height } = useWidgetSize(widgetRoot)

const maxRows = computed(() => {
  const rows = Math.floor((height.value - 64) / 36)
  return Math.min(8, Math.max(2, rows))
})

const displayedAssets = computed(() => dashboardStore.macAssetList.slice(0, maxRows.value))

function formatAssetDisplay(asset: { id: string }): string {
  const normId = normalizeMac(asset.id)
  for (const device of dashboardStore.deviceInventory) {
    const iface = device.interfaces.find((i) => normalizeMac(i.mac_address ?? '') === normId)
    if (!iface) continue
    const name = device.product_name || device.description || device.vendor
    if (name) return name
    const ip = iface.ipv4_address
    if (ip) return ip
    break
  }
  return asset.id
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
</style>
