<template>
  <span class="cd-capability-note" data-test="capability-note">
    <q-icon :name="iconName" size="12px" class="q-mr-xs" :class="colorClass" />
    <span>{{ labelText }}</span>
    <span v-if="context" class="cd-capability-note__context">· {{ context }}</span>
  </span>
</template>

<script setup lang="ts">
/**
 * Production section-level capability-maturity note.
 *
 * Promoted from the UI-075 concept tree so production pages do not import
 * concept-only components. Places a single restrained semantic marker at the
 * section or workflow level (e.g. `backend-pending · UI-078`) instead of
 * per-control badge spam.
 */
const props = defineProps<{
  level: 'available' | 'partial' | 'backend-pending'
  context?: string
}>()

const iconName = computed(() => {
  switch (props.level) {
    case 'available':
      return 'check_circle'
    case 'partial':
      return 'construction'
    default:
      return 'hourglass_top'
  }
})

const colorClass = computed(() => {
  switch (props.level) {
    case 'available':
      return 'text-positive'
    case 'partial':
      return 'text-warning'
    default:
      return 'text-muted'
  }
})

const labelText = computed(() => {
  switch (props.level) {
    case 'available':
      return 'Available'
    case 'partial':
      return 'Partial'
    default:
      return 'Backend pending'
  }
})
</script>

<style scoped lang="scss">
.cd-capability-note {
  display: inline-flex;
  align-items: center;
  font-size: 11px;
  font-weight: 600;
  letter-spacing: 0.3px;
  color: var(--cd-muted);

  &__context {
    margin-left: 4px;
  }
}
</style>
