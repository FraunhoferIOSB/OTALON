<template>
  <div class="mac-selector">
    <div class="filter-row row q-gutter-sm q-mb-sm">
      <q-input v-model="filterText" dense outlined placeholder="Search Name / IP / MAC…" clearable class="col">
        <template #prepend>
          <q-icon name="search" size="18px" />
        </template>
      </q-input>
      <q-toggle
        :model-value="showSilentProfiled"
        dense
        color="amber-8"
        label="SILENT"
        @update:model-value="emit('update:showSilentProfiled', $event)"
      />
      <q-badge v-if="silentProfiledCount > 0" color="amber-8" :label="silentProfiledCount" />
    </div>

    <q-table
      v-model:selected="selectedRows"
      flat
      bordered
      dense
      virtual-scroll
      :virtual-scroll-sticky-size-start="28"
      :rows="filteredMacs"
      :columns="columns"
      row-key="mac"
      :rows-per-page-options="[0]"
      :pagination="pagination"
      hide-pagination
      selection="single"
      no-data-label="No MAC addresses available"
      no-results-label="No matching MAC addresses"
      class="selector-table"
      :table-row-class-fn="(row) => (row.presence === 'silent' ? 'silent-profiled-row' : '')"
      @row-click="onRowClick"
    >
      <template #no-data="{ message }">
        <div class="full-width column items-center q-pa-xl text-grey">
          <q-icon :name="DOMAIN_ICONS.assets" size="48px" class="q-mb-sm" />
          <div class="text-subtitle1">{{ message }}</div>
        </div>
      </template>

      <template #body-cell-state="props">
        <q-td :props="props" class="cell-state">
          <q-icon
            :name="props.row.presence === 'silent' ? 'notifications_paused' : 'circle'"
            size="10px"
            :color="props.row.presence === 'silent' ? 'amber-8' : props.row.state === 'anomaly' ? 'red' : 'green'"
          />
        </q-td>
      </template>

      <template #body-cell-name="props">
        <q-td :props="props">
          <span class="asset-name" :class="props.row.name ? '' : 'text-grey-6'">
            {{ props.row.name || '—' }}
          </span>
          <q-tooltip v-if="props.row.name">{{ props.row.name }}</q-tooltip>
        </q-td>
      </template>

      <template #body-cell-ip="props">
        <q-td :props="props">
          <span class="text-mono" :class="props.row.ip ? '' : 'text-grey-6'">
            {{ props.row.ip || '—' }}
          </span>
        </q-td>
      </template>

      <template #body-cell-mac="props">
        <q-td :props="props">
          <span class="text-mono">{{ props.row.mac }}</span>
        </q-td>
      </template>
    </q-table>
  </div>
</template>

<script setup lang="ts">
import type { QTableColumn } from 'quasar'
import type { MacSourceItem } from '~/stores/macSourcesStore'
import { DOMAIN_ICONS } from '~/composables/useNavigation'

interface Props {
  macs: MacSourceItem[]
  initialMac?: string
  visibleColumns?: string[]
  showSilentProfiled?: boolean
  silentProfiledCount?: number
}

const props = withDefaults(defineProps<Props>(), {
  initialMac: '',
  visibleColumns: () => ['state', 'name', 'ip', 'mac'],
  showSilentProfiled: false,
  silentProfiledCount: 0,
})

const emit = defineEmits<{
  select: [mac: MacSourceItem | null]
  'update:showSilentProfiled': [value: boolean]
}>()

const filterText = ref('')
const selectedRows = ref<MacSourceItem[]>([])

const pagination = ref({
  rowsPerPage: 0,
  page: 1,
})

const baseColumns: QTableColumn[] = [
  {
    name: 'state',
    label: '',
    field: 'state',
    align: 'center',
    style: 'width: 30px',
    headerStyle: 'width: 30px',
    sortable: true,
  },
  {
    name: 'name',
    label: 'Name',
    field: 'name',
    align: 'left',
    sortable: true,
    style: 'width: clamp(140px, 28cqw, 300px)',
    headerStyle: 'width: clamp(140px, 28cqw, 300px)',
  },
  {
    name: 'ip',
    label: 'IP',
    field: 'ip',
    align: 'left',
    sortable: true,
  },
  {
    name: 'mac',
    label: 'MAC',
    field: 'mac',
    align: 'left',
    sortable: true,
  },
]

const columns = computed<QTableColumn[]>(() => {
  const visible = new Set(props.visibleColumns)
  return baseColumns.filter((c) => visible.has(c.name))
})

const filteredMacs = computed<MacSourceItem[]>(() => {
  const result = props.macs
  const text = (filterText.value || '').toLowerCase()
  if (!text) return result
  return result.filter(
    (m) =>
      m.mac.toLowerCase().includes(text) ||
      (m.name && m.name.toLowerCase().includes(text)) ||
      (m.ip && m.ip.toLowerCase().includes(text)),
  )
})

function onRowClick(_event: Event, row: MacSourceItem): void {
  selectedRows.value = [row]
  emit('select', row)
}

function autoSelectFirst(): void {
  if (selectedRows.value.length > 0) return
  if (props.macs.length === 0) return

  if (props.initialMac) {
    const match = props.macs.find((m) => m.mac.toLowerCase() === props.initialMac.toLowerCase())
    if (match) {
      selectedRows.value = [match]
      emit('select', match)
      return
    }
  }

  selectedRows.value = [props.macs[0]]
  emit('select', props.macs[0])
}

watch(
  () => props.macs,
  (newMacs) => {
    if (selectedRows.value.length > 0) {
      const currentMac = selectedRows.value[0].mac
      const freshMatch = newMacs.find((m) => m.mac === currentMac)
      if (freshMatch) {
        selectedRows.value = [freshMatch]
      } else {
        selectedRows.value = []
      }
      return
    }
    autoSelectFirst()
  },
)

onMounted(() => {
  autoSelectFirst()
})
</script>

<style scoped lang="scss">
.mac-selector {
  height: 100%;
  display: flex;
  flex-direction: column;
}

.filter-row {
  flex-shrink: 0;
}

.selector-table {
  flex: 1;
  overflow: auto;
  container-type: inline-size;

  :deep(table) {
    table-layout: fixed;
    width: 100%;
  }

  .asset-name {
    display: block;
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .text-mono {
    font-family: $font-family-mono;
    font-size: $font-size-sm;
  }

  :deep(thead th) {
    font-weight: 600;
    background-color: var(--cd-surface);
    position: sticky;
    top: 0;
    z-index: 1;
  }

  :deep(tbody tr) {
    cursor: pointer;
    transition: background-color 0.15s ease;

    &:hover {
      background-color: var(--cd-surface);
    }
  }

  :deep(tbody tr.selected) {
    background-color: rgba(var(--cd-primary-rgb), 0.12) !important;
  }

  :deep(th:first-child),
  :deep(td:first-child) {
    display: none;
  }
}
</style>
