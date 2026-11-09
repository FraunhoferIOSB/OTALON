<template>
  <div class="proto-selector">
    <div class="filter-row row q-gutter-sm q-mb-sm">
      <q-input v-model="filterText" dense outlined placeholder="Search protocol…" clearable class="col">
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
      :rows="filteredProtos"
      :columns="visibleColumns"
      row-key="id"
      :rows-per-page-options="[0]"
      :pagination="pagination"
      hide-pagination
      selection="single"
      no-data-label="No protocols available"
      no-results-label="No matching protocols"
      class="selector-table"
      :table-row-class-fn="(row) => (row.presence === 'silent' ? 'silent-profiled-row' : '')"
      @row-click="onRowClick"
    >
      <template #no-data="{ message }">
        <div class="full-width column items-center q-pa-xl text-grey">
          <q-icon :name="DOMAIN_ICONS.protocols" size="48px" class="q-mb-sm" />
          <div class="text-subtitle1">{{ message }}</div>
        </div>
      </template>

      <template #body-cell-state="cellProps">
        <q-td :props="cellProps">
          <q-icon
            :name="cellProps.row.presence === 'silent' ? 'notifications_paused' : 'circle'"
            size="10px"
            :color="
              cellProps.row.presence === 'silent' ? 'amber-8' : cellProps.row.state === 'anomaly' ? 'red' : 'green'
            "
          />
        </q-td>
      </template>

      <template #body-cell-protocol="cellProps">
        <q-td :props="cellProps">
          <span class="text-weight-medium asset-name">{{ shortProtocolName(cellProps.row.protocol) }}</span>
          <q-tooltip>{{ cellProps.row.protocol || cellProps.row.id }}</q-tooltip>
        </q-td>
      </template>

      <template #body-cell-id="cellProps">
        <q-td :props="cellProps">
          <span class="text-mono text-caption text-grey-7">{{ cellProps.row.id }}</span>
        </q-td>
      </template>
    </q-table>
  </div>
</template>

<script setup lang="ts">
import type { QTableColumn } from 'quasar'
import type { ProtoSourceItem } from '~/stores/protoSourcesStore'
import { DOMAIN_ICONS } from '~/composables/useNavigation'

interface Props {
  protos: (ProtoSourceItem & { state?: string })[]
  initialProtoId?: string
  showIdColumn?: boolean
  showSilentProfiled?: boolean
  silentProfiledCount?: number
}

const props = withDefaults(defineProps<Props>(), {
  initialProtoId: '',
  showIdColumn: false,
  showSilentProfiled: false,
  silentProfiledCount: 0,
})

const emit = defineEmits<{
  select: [proto: ProtoSourceItem | null]
  'update:showSilentProfiled': [value: boolean]
}>()

const filterText = ref('')
const selectedRows = ref<(ProtoSourceItem & { state?: string })[]>([])

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
    name: 'protocol',
    label: 'Protocol',
    field: 'protocol',
    align: 'left',
    sortable: true,
    style: 'width: clamp(140px, 32cqw, 360px)',
    headerStyle: 'width: clamp(140px, 32cqw, 360px)',
  },
  {
    name: 'id',
    label: 'ID',
    field: 'id',
    align: 'left',
    sortable: true,
  },
]

const visibleColumns = computed<QTableColumn[]>(() => {
  if (!props.showIdColumn) {
    return baseColumns.filter((c) => c.name !== 'id')
  }
  return baseColumns
})

const filteredProtos = computed<(ProtoSourceItem & { state?: string })[]>(() => {
  const result = props.protos
  const text = (filterText.value || '').toLowerCase()
  if (!text) return result
  return result.filter(
    (p) => (p.protocol && p.protocol.toLowerCase().includes(text)) || p.id.toLowerCase().includes(text),
  )
})

/**
 * Build a display-name map over ALL protocols in the table that shows the
 * shortest unambiguous suffix per protocol stack.
 *
 * Default is the top (last) segment only, e.g. ``PROFINET_RT_IO``. When two
 * or more stacks would collapse to the same suffix (e.g.
 * ``Ethernet:VLAN:PROFINET_RT:PROFINET_RT_IO`` vs
 * ``Ethernet:PROFINET_RT:PROFINET_RT_IO`` → both ``PROFINET_RT_IO``), each
 * colliding stack grows by one more leading segment until the displayed
 * names are unique (``VLAN:PROFINET_RT:PROFINET_RT_IO`` vs
 * ``PROFINET_RT:PROFINET_RT_IO``).
 */
const protocolDisplayMap = computed<Map<string, string>>(() => {
  const stacks = props.protos.map((p) => p.protocol || p.id).filter((s): s is string => !!s)
  const unique = Array.from(new Set(stacks))
  const result = new Map<string, string>()
  const parts = new Map<string, string[]>()
  const depth = new Map<string, number>()

  for (const s of unique) {
    parts.set(s, s.split(':'))
    depth.set(s, 1)
  }

  const suffix = (s: string): string => {
    const segs = parts.get(s)!
    return segs.slice(Math.max(0, segs.length - depth.get(s)!)).join(':')
  }

  let changed = true
  while (changed) {
    changed = false
    const byDisplay = new Map<string, string[]>()
    for (const s of unique) {
      const d = suffix(s)
      const arr = byDisplay.get(d)
      if (arr) arr.push(s)
      else byDisplay.set(d, [s])
    }
    for (const [, group] of byDisplay) {
      if (group.length < 2) continue
      for (const s of group) {
        if (depth.get(s)! < parts.get(s)!.length) {
          depth.set(s, depth.get(s)! + 1)
          changed = true
        }
      }
    }
  }

  for (const s of unique) result.set(s, suffix(s))
  return result
})

function shortProtocolName(protocol: string | null): string {
  if (!protocol) return ''
  return protocolDisplayMap.value.get(protocol) ?? protocol.split(':').pop() ?? protocol
}

function onRowClick(_event: Event, row: ProtoSourceItem & { state?: string }): void {
  selectedRows.value = [row]
  emit('select', row)
}

function autoSelectFirst(): void {
  if (selectedRows.value.length > 0) return
  if (props.protos.length === 0) return

  if (props.initialProtoId) {
    const match = props.protos.find((p) => p.id === props.initialProtoId || p.protocol === props.initialProtoId)
    if (match) {
      selectedRows.value = [match]
      emit('select', match)
      return
    }
  }

  selectedRows.value = [props.protos[0]]
  emit('select', props.protos[0])
}

watch(
  () => props.protos,
  (newProtos) => {
    if (selectedRows.value.length > 0) {
      const currentId = selectedRows.value[0].id
      const freshMatch = newProtos.find((p) => p.id === currentId)
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
.proto-selector {
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
