<template>
  <q-table
    flat
    bordered
    dense
    :rows="rows"
    :columns="columns"
    :row-key="rowKey"
    :rows-per-page-options="[rowsPerPage, 25, 50, 0]"
    :pagination="{ rowsPerPage }"
    class="data-table"
  >
    <template v-for="(_, name) in $slots" #[name]="slotData">
      <slot :name="name" v-bind="slotData ?? {}" />
    </template>
  </q-table>
</template>

<script setup lang="ts">
import type { QTableColumn } from 'quasar'

/**
 * Reusable data table component wrapping Quasar's q-table.
 *
 * Supports slot pass-through for custom cell rendering.
 */
defineProps<{
  rows: Record<string, unknown>[]
  columns: QTableColumn[]
  rowKey: string
  rowsPerPage?: number
}>()
</script>

<style scoped lang="scss">
.data-table {
  :deep(thead th) {
    font-weight: 600;
    background-color: var(--cd-surface);
  }

  :deep(tbody tr:nth-child(even)) {
    background-color: var(--cd-surface);
  }
}
</style>
