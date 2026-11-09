<template>
  <div class="opcua-endpoint-list">
    <div v-for="(ep, idx) in endpoints" :key="idx" class="opcua-endpoint-list__row row items-center">
      <q-badge :color="modeColor(ep.securityMode)" class="opcua-endpoint-list__mode q-mr-sm">
        {{ ep.securityMode || '—' }}
      </q-badge>
      <span class="opcua-endpoint-list__policy text-mono text-caption">
        {{ ep.securityPolicy || '—' }}
      </span>
      <q-space />
      <span v-if="ep.securityLevel != null" class="opcua-endpoint-list__level text-caption text-grey-6">
        Level {{ ep.securityLevel }}
      </span>
    </div>
  </div>
</template>

<script setup lang="ts">
import type { OpcUaEndpoint } from '~/utils/opcua'

interface Props {
  endpoints: OpcUaEndpoint[]
}

defineProps<Props>()

function modeColor(mode: string): string {
  const m = mode.toLowerCase()
  if (m.includes('signandencrypt')) return 'positive'
  if (m.includes('sign')) return 'info'
  if (m.includes('none')) return 'warning'
  return 'grey-6'
}
</script>

<style scoped lang="scss">
.opcua-endpoint-list {
  display: flex;
  flex-direction: column;
  gap: 6px;
}

.opcua-endpoint-list__row {
  border: 1px solid var(--cd-border, rgba(0, 0, 0, 0.08));
  border-radius: 6px;
  padding: 6px 10px;
}

.opcua-endpoint-list__mode {
  font-family: $font-family-mono;
  font-weight: 600;
  min-width: 120px;
  justify-content: center;
}

.opcua-endpoint-list__policy {
  font-size: 11.5px;
}

.opcua-endpoint-list__level {
  font-size: 11px;
}
</style>
