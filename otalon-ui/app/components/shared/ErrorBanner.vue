<template>
  <q-banner v-if="message" class="bg-negative text-white q-mb-md" rounded>
    <template #avatar>
      <q-icon name="error" />
    </template>
    {{ message }}
    <template #action>
      <q-btn flat label="Retry" @click="$emit('retry')" />
      <q-btn flat label="Dismiss" @click="$emit('dismiss')" />
    </template>
  </q-banner>
</template>

<script setup lang="ts">
/**
 * Reusable error banner for data page error states.
 *
 * Displays a red banner with the error message and action buttons
 * for retrying the failed operation or dismissing the error.
 */

defineProps<{
  message: string | null
}>()

defineEmits<{
  retry: []
  dismiss: []
}>()
</script>
