<template>
  <span v-if="factor" class="provenance-tag" :class="tagClass" :data-test="`provenance-${factor.source}`">
    {{ label }}
  </span>
  <span v-else class="provenance-tag provenance-tag--none" data-test="provenance-none">no profile</span>
</template>

<script setup lang="ts">
import type { EffectiveFactor } from '~/types/api'

/**
 * Renders where an effective detector factor came from.
 *
 * The Rhythm Review surface must never leave an operator guessing
 * whether a threshold is their own tuning or the shipped default: a
 * correction that looks like a no-op because the value already equals
 * the default reads very differently once provenance is visible.
 */
const props = defineProps<{
  /** The effective factor, or null when the series carries no profile. */
  factor: EffectiveFactor | null | undefined
}>()

const label = computed<string>(() => (props.factor?.source === 'override' ? 'override' : 'global default'))

const tagClass = computed<string>(() =>
  props.factor?.source === 'override' ? 'provenance-tag--override' : 'provenance-tag--global',
)
</script>

<style scoped>
.provenance-tag {
  font-size: 10px;
  padding: 2px 5px;
  border-radius: 3px;
  margin-left: 6px;
  white-space: nowrap;
}

.provenance-tag--override {
  color: #ffd180;
  background: rgba(255, 193, 7, 0.12);
}

.provenance-tag--global {
  color: #9fb3bd;
  background: rgba(144, 164, 174, 0.12);
}

.provenance-tag--none {
  color: #9fb3bd;
  background: transparent;
  font-style: italic;
}
</style>
