<template>
  <span
    class="context-help"
    tabindex="0"
    role="button"
    :aria-label="label"
    @focus="focused = true"
    @blur="focused = false"
    @mouseenter="hovered = true"
    @mouseleave="hovered = false"
    @keydown.escape="blurTrigger"
  >
    <slot><q-icon name="info" color="grey-5" :size="size" /></slot>
    <q-tooltip :model-value="visible" :max-width="maxWidth">{{ text }}</q-tooltip>
  </span>
</template>

<script setup lang="ts">
withDefaults(
  defineProps<{
    label: string
    text: string
    size?: string
    maxWidth?: string
  }>(),
  { size: '16px', maxWidth: '320px' },
)

const focused = ref(false)
const hovered = ref(false)
const visible = computed(() => focused.value || hovered.value)

function blurTrigger(event: KeyboardEvent): void {
  ;(event.currentTarget as HTMLElement | null)?.blur()
}
</script>

<style scoped lang="scss">
.context-help {
  display: inline-flex;
  flex: 0 0 auto;
  align-items: center;
  justify-content: center;
  border-radius: $border-radius-sm;
  color: var(--cd-muted);
  line-height: 1;
  cursor: help;
}

.context-help:focus-visible {
  outline: 2px solid var(--q-primary);
  outline-offset: 1px;
}
</style>
