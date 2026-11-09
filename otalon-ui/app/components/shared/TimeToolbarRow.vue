<template>
  <div class="time-toolbar-row row items-start q-gutter-sm q-mb-md">
    <SharedTimeToolbar :class="toolbarClass" @update="onToolbarUpdate" />
    <slot />
  </div>
</template>

<script setup lang="ts">
withDefaults(
  defineProps<{
    toolbarClass?: string
  }>(),
  {
    toolbarClass: undefined,
  },
)

const emit = defineEmits<{
  update: []
}>()

function onToolbarUpdate(): void {
  emit('update')
}
</script>

<style scoped lang="scss">
.time-toolbar-row :deep(.time-toolbar) {
  margin-bottom: 0;
}

.time-toolbar-row {
  flex-shrink: 0;
}
</style>
