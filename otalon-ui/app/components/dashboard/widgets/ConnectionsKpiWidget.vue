<template>
  <div style="position: relative; height: 100%">
    <SharedKpiCard
      :value="dashboardStore.connectionCount"
      label="Connections"
      :icon="DOMAIN_ICONS.connections"
      to="/connections"
    />
  </div>
</template>

<script setup lang="ts">
import { useDashboardStore } from '~/stores/dashboardStore'
import { DOMAIN_ICONS } from '~/composables/useNavigation'

const dashboardStore = useDashboardStore()
</script>
