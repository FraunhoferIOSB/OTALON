<template>
  <q-item dense class="detail-row">
    <q-item-section>
      <q-item-label caption>{{ label }}</q-item-label>
      <q-item-label :class="{ 'text-mono': mono }">
        {{ value || '—' }}
      </q-item-label>
    </q-item-section>
  </q-item>
</template>

<script setup lang="ts">
/**
 * Helper component used inside the device detail panel to render a single
 * label/value pair with consistent typography across all rows.
 */
defineProps<{
  label: string
  value: string | null | undefined
  mono?: boolean
}>()
</script>

<style scoped lang="scss">
.detail-row {
  padding-left: 0;
  padding-right: 0;
}

.text-mono {
  font-family: $font-family-mono;
  font-size: 0.9rem;
}
</style>
