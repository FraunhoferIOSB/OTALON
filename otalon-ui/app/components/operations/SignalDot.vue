<template>
  <span class="cd-signal" :aria-label="ariaLabel">
    <span class="status-dot" :class="dotClass" />
    <span v-if="label" class="cd-signal__label">{{ label }}</span>
  </span>
</template>

<script setup lang="ts">
import { computed } from 'vue'

/**
 * Green/yellow/red/blue/grey indicator dot with optional text label.
 *
 * Promoted from the UI-075 concept preview; status is always conveyed by
 * text + icon, never color alone.
 */

type SignalColor = 'green' | 'amber' | 'red' | 'info' | 'grey'

const props = withDefaults(
  defineProps<{
    signal: SignalColor
    label?: string
  }>(),
  { label: undefined },
)

const dotClass = computed(() => {
  switch (props.signal) {
    case 'green':
      return 'status-dot--green'
    case 'amber':
      return 'status-dot--amber'
    case 'red':
      return 'status-dot--red'
    case 'info':
      return 'status-dot--info'
    default:
      return 'cd-signal__dot--grey'
  }
})

const ariaLabel = computed(() => (props.label ? `status ${props.signal}: ${props.label}` : `status ${props.signal}`))
</script>

<style scoped lang="scss">
.cd-signal {
  display: inline-flex;
  align-items: center;
  gap: 6px;

  &__label {
    font-size: 13px;
    font-weight: 600;
  }

  &__dot--grey {
    background-color: $status-missing;
  }
}

.status-dot--info {
  background-color: var(--cd-info, #0288d1);
}
</style>
