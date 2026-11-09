<script setup lang="ts">
import { watch } from 'vue'

import { useSse } from '~/composables/useSse'
import { useAppStore } from '~/stores/appStore'
import { useDashboardStore } from '~/stores/dashboardStore'
import { useOperationsOverviewStore } from '~/stores/operationsOverviewStore'
import { useHealthIncidentsStore } from '~/stores/healthIncidentsStore'
import type { HealthResponse } from '~/types/api'

/**
 * Invisible shell component that owns the single global `health` SSE stream.
 *
 * Mounted once in the default layout so the persistent header indicators stay
 * truthful on every route, without any page opening its own health stream:
 *
 * - It mirrors the live SSE connection status into {@link useAppStore} so the
 *   header `.sse-dot` turns green while the `health` stream is connected and
 *   reflects reconnecting/disconnected honestly (previously `setSseStatus` had
 *   no production caller, so the dot was permanently red — UI-085).
 * - It performs a bounded initial `fetchHealth()` and fans every pushed
 *   `health` event out to both the dashboard store (header system-status chip)
 *   and the operations-overview store (Service Health / Suite KPI), so the
 *   header chip reflects real `/api/v1/status/health` instead of `—` on
 *   Operations pages (UI-086).
 *
 * `useSse` registers its own `onUnmounted` teardown (closes the EventSource,
 * clears reconnect/heartbeat timers). Because this component lives in the
 * persistent layout it is never unmounted during normal navigation, so exactly
 * one upstream health stream exists for the whole SPA — no duplication or leak.
 */
const appStore = useAppStore()
const dashboardStore = useDashboardStore()
const overviewStore = useOperationsOverviewStore()
const incidentsStore = useHealthIncidentsStore()

const { status } = useSse('health', {
  onEvent: (_topic: string, data: unknown) => {
    const health = data as HealthResponse
    dashboardStore.handleHealthUpdate(health)
    overviewStore.handleHealthUpdate(health)
    incidentsStore.applyHealth(health)
  },
})

// Mirror the live stream status into the app store so the header dot is truthful.
watch(
  status,
  (value) => {
    appStore.setSseStatus(value)
  },
  { immediate: true },
)

onMounted(() => {
  // Bounded initial read so the header status chip is correct immediately,
  // before the first SSE health push arrives.
  dashboardStore.fetchHealth().then(() => {
    if (dashboardStore.health) incidentsStore.applyHealth(dashboardStore.health)
  }).catch(() => {
    /* non-fatal for the shell indicator */
  })
})
</script>

<template>
  <span style="display: none" aria-hidden="true"></span>
</template>
