<template>
  <span class="cd-state-badge" :class="`cd-state-badge--${kind}`">
    <q-icon v-if="icon" :name="icon" size="12px" class="q-mr-xs" />
    {{ label }}
  </span>
</template>

<script setup lang="ts">
/**
 * Equal-width state badge for status columns.
 *
 * Promoted from the UI-075 concept preview; state is conveyed by text plus
 * optional icon, never by color alone.
 */

withDefaults(
  defineProps<{
    kind: 'ok' | 'warn' | 'err' | 'muted' | 'info'
    label: string
    icon?: string
  }>(),
  { icon: undefined },
)
</script>

<style scoped lang="scss">
.cd-state-badge {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  min-width: 104px;
  padding: 2px 10px;
  border-radius: $border-radius-sm;
  font-size: 12px;
  font-weight: 600;
  letter-spacing: 0.2px;
  border: 1px solid transparent;

  &--ok {
    color: $color-success;
    background: rgba(var(--cd-success-rgb), 0.1);
    border-color: rgba(var(--cd-success-rgb), 0.3);
  }

  &--warn {
    color: var(--q-warning);
    background: rgba(var(--cd-warning-rgb), 0.12);
    border-color: rgba(var(--cd-warning-rgb), 0.35);
  }

  &--err {
    color: $color-danger;
    background: rgba(var(--cd-danger-rgb), 0.08);
    border-color: rgba(var(--cd-danger-rgb), 0.3);
  }

  &--info {
    color: var(--cd-info);
    background: rgba(var(--cd-info-rgb), 0.08);
    border-color: rgba(var(--cd-info-rgb), 0.3);
  }

  &--muted {
    color: var(--cd-muted);
    background: rgba(127, 127, 127, 0.08);
    border-color: var(--cd-border);
  }
}

.body--dark .cd-state-badge--warn {
  color: #fbbf24;
}
</style>
