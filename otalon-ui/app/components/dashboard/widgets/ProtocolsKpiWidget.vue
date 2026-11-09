<template>
  <div style="position: relative; height: 100%">
    <SharedKpiCard
      :value="dashboardStore.protocolCount"
      label="Protocols"
      :icon="DOMAIN_ICONS.protocols"
      to="/proto-timeseries"
    />
  </div>
</template>

<script setup lang="ts">
import { useDashboardStore } from '~/stores/dashboardStore'
import { DOMAIN_ICONS } from '~/composables/useNavigation'

const dashboardStore = useDashboardStore()
</script>
