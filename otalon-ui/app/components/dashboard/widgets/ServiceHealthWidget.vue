<template>
  <div class="widget-root">
    <q-card flat bordered class="full-height">
      <q-card-section class="q-py-sm q-px-md">
        <div class="row items-center no-wrap q-mb-xs">
          <q-icon name="monitor_heart" size="18px" color="primary" />
          <span class="text-subtitle2 text-weight-bold q-ml-sm">Service Health</span>
          <q-space />
          <NuxtLink to="/operations/overview" class="text-caption text-primary" style="text-decoration: none"
            >View Details</NuxtLink
          >
        </div>
        <div class="row items-center q-gutter-x-lg q-gutter-y-xs">
          <div
            v-for="svc in dashboardStore.healthServices"
            :key="svc.name"
            class="row items-center no-wrap health-compact-item"
          >
            <span class="status-dot" :class="svc.running ? 'status-dot--green' : 'status-dot--red'" />
            <span class="text-body2 q-ml-xs">{{ svc.name }}</span>
            <q-tooltip>{{ svc.detail }}</q-tooltip>
          </div>
        </div>
      </q-card-section>
    </q-card>
  </div>
</template>

<script setup lang="ts">
import { useDashboardStore } from '~/stores/dashboardStore'

const dashboardStore = useDashboardStore()
</script>

<style scoped lang="scss">
.widget-root {
  height: 100%;
}

.health-compact-item {
  padding: 4px 0;
  cursor: default;
}

.status-dot {
  width: 10px;
  height: 10px;
  border-radius: 50%;
  display: inline-block;

  &--green {
    background-color: var(--q-positive, #21ba45);
  }

  &--red {
    background-color: var(--q-negative, #c10015);
  }
}
</style>
