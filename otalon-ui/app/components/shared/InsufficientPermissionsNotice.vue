<template>
  <q-banner v-if="visible" rounded dense class="cd-permissions-notice q-mb-md" role="alert" data-test="insufficient-permissions">
    <template #avatar>
      <q-icon name="lock" color="negative" size="20px" />
    </template>
    <span>Insufficient permissions to access this Operations resource.</span>
  </q-banner>
</template>

<script setup lang="ts">
import { computed } from 'vue'

import { isInsufficientPermissionsMessage } from '~/utils/permissions'

const props = defineProps<{ message: string | null | undefined }>()
const visible = computed(() => isInsufficientPermissionsMessage(props.message))
</script>

<style scoped>
.cd-permissions-notice {
  border: 1px solid rgba(var(--cd-danger-rgb), 0.45);
  background: rgba(var(--cd-danger-rgb), 0.1);
  color: var(--cd-surface-text);
}
</style>
