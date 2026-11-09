<template>
  <q-table
    v-model:pagination="pagination"
    flat
    bordered
    dense
    :rows="sortedGroups"
    :columns="columns"
    :visible-columns="visibleColumns"
    row-key="id"
    :rows-per-page-options="[0, 10, 25, 50, 100]"
    no-data-label="No anomaly groups found"
    no-results-label="No matching anomaly groups"
    class="alarm-group-table"
    :table-row-class-fn="rowClassFn"
    @row-click="onRowClick"
  >
    <template #no-data="{ message }">
      <div class="full-width column items-center q-pa-xl text-grey">
        <q-icon name="search_off" size="48px" class="q-mb-sm" />
        <div class="text-subtitle1">{{ message }}</div>
      </div>
    </template>

    <template #body-cell-primary_type="slotProps">
      <q-td :props="slotProps">
        <template v-if="Array.isArray(slotProps.row.primary_type)">
          <q-chip
            v-for="pt in slotProps.row.primary_type"
            :key="pt"
            :color="mitreChipColor(pt)"
            text-color="white"
            class="q-mr-xs primary-type-chip"
          >
            {{ pt }}
          </q-chip>
        </template>
        <q-chip v-else :color="mitreChipColor(slotProps.row.primary_type)" text-color="white" class="primary-type-chip">
          {{ slotProps.row.primary_type }}
        </q-chip>
      </q-td>
    </template>

    <template #body-cell-is_active="slotProps">
      <q-td :props="slotProps">
        <q-badge
          :color="slotProps.row.is_active ? 'negative' : 'grey-6'"
          :label="slotProps.row.is_active ? 'Active' : 'Closed'"
        />
      </q-td>
    </template>

    <template #body-cell-confirmed="slotProps">
      <q-td :props="slotProps">
        <q-badge
          :color="slotProps.row.confirmed ? 'primary' : 'grey-6'"
          :label="slotProps.row.confirmed ? 'Confirmed' : 'Unconfirmed'"
        />
      </q-td>
    </template>
  </q-table>
</template>

<script setup lang="ts">
import type { QTableColumn } from 'quasar'
import type { AnomalyGroupItem } from '~/types/api'
import { mitreChipColor } from '~/utils/mitre-colors'
import { formatDateTime, formatRelativeTime, parseApiTimestamp } from '~/utils/format'

/**
 * Alarm group master table for anomaly group data.
 *
 * Displays primary type as MITRE chip, a relative Age column, start/end time,
 * active/confirmed badges, connection count, and type count. Sorted by
 * start_timestamp descending. Emits 'select' on row click to trigger the
 * detail dialog.
 */

interface Props {
  groups: AnomalyGroupItem[]
  visibleColumns?: string[]
  rowsPerPage?: number
  selectedGroupId?: string | null
}

interface Emits {
  (e: 'select', group: AnomalyGroupItem): void
}

const props = withDefaults(defineProps<Props>(), {
  rowsPerPage: 0,
  selectedGroupId: null,
})
const emit = defineEmits<Emits>()

const sortedGroups = computed(() =>
  [...props.groups].sort((a, b) => new Date(b.start_timestamp).getTime() - new Date(a.start_timestamp).getTime()),
)

const pagination = ref({
  page: 1,
  rowsPerPage: props.rowsPerPage,
  sortBy: 'start_timestamp',
  descending: true,
})

watch(
  () => props.rowsPerPage,
  (newValue) => {
    pagination.value.rowsPerPage = newValue
  },
)

/**
 * Format primary_type for sorting (join arrays for backward compatibility).
 */
function formatPrimaryType(val: string | string[]): string {
  return Array.isArray(val) ? val.join(', ') : val
}

/**
 * Compare two ``start_timestamp`` ISO strings chronologically.
 *
 * The relative ``Age`` column formats its value via {@link formatRelativeTime}
 * ("Xm ago"), so a naive (lexicographic) sort would order "2h ago" before
 * "30m ago". Sorting on the parsed instant keeps newest/oldest correct.
 */
function compareTimestamps(a: unknown, b: unknown): number {
  return parseApiTimestamp(String(a)).getTime() - parseApiTimestamp(String(b)).getTime()
}

const columns: QTableColumn[] = [
  {
    name: 'primary_type',
    label: 'Prediction',
    field: 'primary_type',
    align: 'left',
    sortable: true,
    format: (val: string | string[]) => formatPrimaryType(val),
  },
  {
    name: 'relative',
    label: 'Age',
    field: 'start_timestamp',
    align: 'left',
    sortable: true,
    sort: compareTimestamps,
    format: (val: string) => formatRelativeTime(val),
  },
  {
    name: 'start_timestamp',
    label: 'Start Time',
    field: 'start_timestamp',
    align: 'left',
    sortable: true,
    format: (val: string) => formatDateTime(val),
  },
  {
    name: 'end_timestamp',
    label: 'End Time',
    field: 'end_timestamp',
    align: 'left',
    sortable: true,
    format: (val: string) => formatDateTime(val),
  },
  {
    name: 'is_active',
    label: 'Active',
    field: 'is_active',
    align: 'center',
    sortable: true,
  },
  {
    name: 'confirmed',
    label: 'Confirmed',
    field: 'confirmed',
    align: 'center',
    sortable: true,
  },
  {
    name: 'connections',
    label: 'Connections',
    field: (row: AnomalyGroupItem) => row.series_ids.length,
    align: 'center',
    sortable: true,
  },
  {
    name: 'types',
    label: 'Types',
    field: (row: AnomalyGroupItem) => Object.keys(row.anomaly_type_stats).length,
    align: 'center',
    sortable: true,
  },
]

/**
 * Return CSS class for each table row based on selection state.
 *
 * Real QTable and the test stub both support `table-row-class-fn`.
 */
function rowClassFn(row: AnomalyGroupItem): string {
  return row.id === props.selectedGroupId ? 'row-selected' : ''
}

/**
 * Handle row click to select the alarm group.
 */
function onRowClick(_evt: Event, row: AnomalyGroupItem): void {
  emit('select', row)
}
</script>

<style scoped lang="scss">
.alarm-group-table {
  :deep(.q-table__top) {
    padding: 8px 16px;
  }

  :deep(thead th) {
    font-weight: 700;
    font-size: 12px;
    letter-spacing: 0.5px;
  }

  :deep(.q-table tbody tr) {
    cursor: pointer;
    transition: background-color 0.15s ease;
  }

  :deep(.q-table tbody tr:hover) {
    background-color: rgba(var(--cd-primary-rgb), 0.08) !important;
  }

  :deep(.q-table tbody tr.row-selected) {
    background-color: rgba(var(--cd-primary-rgb), 0.18) !important;
    outline: 1px solid rgba(var(--cd-primary-rgb), 0.35);
    outline-offset: -1px;
  }

  /*
   * Primary-type chips: inherit the page font-size + scale the chip
   * height with it. ``--page-font-size`` is the inline CSS variable
   * set on ``<q-page>`` by the alarms-page wrapper, so list and
   * detail share one source of truth. We target ``.q-chip.primary-type-chip``
   * so the rule has enough specificity to win over Quasar's defaults.
   */
  :deep(.q-chip.primary-type-chip) {
    font-size: var(--page-font-size, 13px);
    height: calc(var(--page-font-size, 13px) + 14px);
    padding: 0 8px;
    line-height: 1;
  }
}
</style>
