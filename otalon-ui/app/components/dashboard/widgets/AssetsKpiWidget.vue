<template>
  <div style="position: relative; height: 100%">
    <SharedKpiCard :value="dashboardStore.deviceCount" label="Assets" :icon="DOMAIN_ICONS.assets" to="/mac-timeseries" />
  </div>
</template>

<script setup lang="ts">
import { useDashboardStore } from '~/stores/dashboardStore'
import { DOMAIN_ICONS } from '~/composables/useNavigation'

const dashboardStore = useDashboardStore()
</script>
