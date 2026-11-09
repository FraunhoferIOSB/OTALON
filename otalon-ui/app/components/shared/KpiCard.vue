<template>
  <q-card
    flat
    bordered
    class="kpi-card full-height"
    :class="[tintClass, { 'kpi-card--clickable': to }]"
    v-bind="linkAttrs"
  >
    <q-card-section class="kpi-card__body">
      <div class="row items-center no-wrap q-mb-sm">
        <q-icon v-if="icon" :name="icon" size="22px" class="kpi-card__icon" :class="iconColorClass" />
        <span class="kpi-card__label text-caption text-weight-medium q-ml-sm">
          {{ label }}
        </span>
      </div>

      <div class="row items-end no-wrap q-gutter-x-sm">
        <div class="kpi-card__value" :class="{ 'kpi-card__value--text': typeof value === 'string' }">
          {{ displayValue }}
        </div>
        <div v-if="trend || trendLabel" class="kpi-card__trend" :class="trendColorClass">
          {{ trendArrow }}
          <span class="text-caption q-ml-xs">{{ trendLabel }}</span>
        </div>
      </div>
    </q-card-section>
  </q-card>
</template>

<script setup lang="ts">
import type { SignalColor } from '~/types/golden-data'

/**
 * Enhanced KPI card with icon, trend indicator, signal dot, and status tinting.
 *
 * Used on the dashboard to display key performance metrics.
 */

interface Props {
  value: string | number
  label: string
  icon?: string
  signalColor?: SignalColor
  trend?: 'up' | 'down' | 'stable'
  trendLabel?: string
  trendPositive?: 'up' | 'down'
  to?: string
}

const props = withDefaults(defineProps<Props>(), {
  icon: undefined,
  signalColor: undefined,
  trend: undefined,
  trendLabel: undefined,
  trendPositive: 'down',
  to: undefined,
})

const linkAttrs = computed(() => {
  if (!props.to) return {}
  return {
    clickable: true,
    onClick: () => navigateTo(props.to!),
    role: 'link',
    tabindex: 0,
  }
})

const displayValue = computed(() => {
  if (typeof props.value === 'number') {
    return props.value.toLocaleString()
  }
  return props.value
})

const trendArrow = computed(() => {
  switch (props.trend) {
    case 'up':
      return '↑'
    case 'down':
      return '↓'
    case 'stable':
      return '→'
    default:
      return ''
  }
})

const trendColorClass = computed(() => {
  if (!props.trend) return ''
  const isGood =
    (props.trend === 'down' && props.trendPositive === 'down') ||
    (props.trend === 'up' && props.trendPositive === 'up') ||
    props.trend === 'stable'
  return isGood ? 'text-positive' : 'text-negative'
})

const iconColorClass = computed(() => {
  if (props.signalColor === 'danger') return 'text-negative'
  if (props.signalColor === 'warning') return 'text-warning'
  if (props.signalColor === 'success') return 'text-positive'
  return 'text-primary'
})

const tintClass = computed(() => {
  if (props.signalColor === 'danger') return 'kpi-card--tint-danger'
  if (props.signalColor === 'warning') return 'kpi-card--tint-warning'
  if (typeof props.value === 'number' && props.value > 0 && props.label?.toLowerCase().includes('alarm')) {
    return 'kpi-card--tint-danger'
  }
  return ''
})
</script>

<style scoped lang="scss">
.kpi-card {
  transition:
    box-shadow 0.2s ease,
    background-color 0.2s ease,
    transform 0.2s ease;

  &:hover {
    box-shadow: 0 4px 16px rgba(0, 0, 0, 0.12);
  }

  &--clickable {
    cursor: pointer;

    &:hover {
      transform: translateY(-2px);
      box-shadow: 0 6px 20px rgba(0, 0, 0, 0.15);
    }

    &:active {
      transform: translateY(0);
    }
  }

  &__body {
    padding: 16px 20px;
  }

  &__label {
    color: var(--cd-muted);
    font-size: 12px;
    letter-spacing: 0.5px;
    text-transform: uppercase;
  }

  &__icon {
    opacity: 0.85;
  }

  &__value {
    font-size: 32px;
    font-weight: 700;
    line-height: 1.1;
    letter-spacing: -0.5px;
    color: var(--cd-surface-text);

    &--text {
      font-size: 16px;
      font-weight: 600;
      letter-spacing: 0;
      color: var(--cd-muted);
    }
  }

  &__trend {
    font-size: 16px;
    font-weight: 600;
    line-height: 1;
    padding-bottom: 4px;
  }

  &__signal-dot {
    width: 20px;
    height: 20px;
    border-radius: 50%;
    flex-shrink: 0;
    margin-right: 8px;

    &--danger {
      background-color: $color-danger;
      box-shadow: 0 0 8px rgba(var(--cd-danger-rgb), 0.5);
    }

    &--warning {
      background-color: $color-warning;
      box-shadow: 0 0 8px rgba(var(--cd-warning-rgb), 0.5);
    }

    &--success {
      background-color: $color-success;
      box-shadow: 0 0 8px rgba(var(--cd-success-rgb), 0.5);
    }

    &--info {
      background-color: var(--cd-info);
      box-shadow: 0 0 8px rgba(var(--cd-info-rgb), 0.5);
    }
  }

  &--tint-danger {
    background-color: rgba(var(--cd-danger-rgb), 0.06);
  }

  &--tint-warning {
    background-color: rgba(var(--cd-warning-rgb), 0.06);
  }
}

.body--dark {
  .kpi-card--tint-danger {
    background-color: rgba(var(--cd-danger-rgb), 0.1);
  }

  .kpi-card--tint-warning {
    background-color: rgba(var(--cd-warning-rgb), 0.1);
  }
}
</style>
