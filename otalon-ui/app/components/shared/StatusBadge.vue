<template>
  <q-badge :color="colorMap[status] ?? 'grey'" :label="label" class="status-badge" />
</template>

<script setup lang="ts">
/**
 * Status badge showing running/stopped/error/missing states.
 */
type StatusType = 'running' | 'stopped' | 'error' | 'missing'

defineProps<{
  status: StatusType
  label: string
}>()

const colorMap: Record<StatusType, string> = {
  running: 'positive',
  stopped: 'grey-6',
  error: 'negative',
  missing: 'grey-4',
}
</script>

<style scoped lang="scss">
.status-badge {
  font-size: $font-size-sm;
  padding: 4px 10px;
}
</style>
