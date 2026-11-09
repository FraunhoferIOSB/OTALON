<template>
  <q-card flat bordered class="health-indicator full-height">
    <q-card-section class="row items-center q-gutter-sm">
      <q-icon :name="running ? 'check_circle' : 'cancel'" :color="running ? 'positive' : 'grey-6'" size="28px" />
      <div>
        <div class="text-subtitle1 text-weight-medium">{{ name }}</div>
        <div class="text-caption text-muted">{{ detail }}</div>
      </div>
    </q-card-section>
  </q-card>
</template>

<script setup lang="ts">
/**
 * Health indicator card for a single service showing running/stopped status.
 */
defineProps<{
  name: string
  running: boolean
  detail: string
}>()
</script>

<style scoped lang="scss">
.health-indicator {
  transition: box-shadow 0.2s ease;

  &:hover {
    box-shadow: $shadow-sm;
  }
}
</style>
