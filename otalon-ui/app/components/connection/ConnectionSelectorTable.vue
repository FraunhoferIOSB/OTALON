<template>
  <div class="connection-selector">
    <div class="filter-row row q-gutter-sm q-mb-sm">
      <q-input v-model="filterSource" dense outlined placeholder="Source" clearable class="col">
        <template #prepend>
          <q-icon name="search" size="18px" />
        </template>
      </q-input>
      <q-input v-model="filterDest" dense outlined placeholder="Destination" clearable class="col">
        <template #prepend>
          <q-icon name="search" size="18px" />
        </template>
      </q-input>
      <q-input v-model="filterProtocol" dense outlined placeholder="Protocol" clearable class="col">
        <template #prepend>
          <q-icon name="filter_list" size="18px" />
        </template>
      </q-input>

      <!-- The toggle is wrapped in a focusable span so the explanation is
           keyboard reachable, matching the RHYTHM lane's tooltip pattern. -->
      <span class="silent-toggle-wrap row items-center no-wrap" tabindex="0" :aria-label="silentToggleAriaLabel">
        <q-toggle
          :model-value="showSilentProfiled"
          dense
          size="sm"
          color="amber-8"
          data-testid="silent-profiled-toggle"
          @update:model-value="emit('update:showSilentProfiled', $event)"
        />
        <span class="text-caption text-muted silent-toggle-label">SILENT</span>
        <q-badge
          v-if="silentProfiledCount > 0"
          color="amber-8"
          text-color="white"
          :label="silentProfiledCount"
          class="q-ml-xs"
          data-testid="silent-profiled-count"
        />
        <q-tooltip anchor="bottom middle" self="top middle" :offset="[0, 6]" max-width="360px">
          <div class="text-weight-bold q-mb-xs">Profiled but silent</div>
          <div>
            Connections with a learned cadence profile that sent nothing in the current time window. They are absent from
            live traffic, so they only appear here when this is on — that is exactly the state the absence detector
            reports. Silent rows are marked SILENT and can be selected to open their CADENCE lane.
          </div>
        </q-tooltip>
      </span>
    </div>

    <q-table
      v-model:selected="selectedRows"
      flat
      bordered
      dense
      virtual-scroll
      :virtual-scroll-sticky-size-start="28"
      :rows="filteredConnections"
      :columns="visibleColumns"
      row-key="uci"
      :rows-per-page-options="[0]"
      :pagination="pagination"
      hide-pagination
      selection="single"
      no-data-label="No connections available"
      no-results-label="No matching connections"
      class="selector-table"
      :table-row-class-fn="rowClass"
      @row-click="onRowClick"
    >
      <template #no-data="{ message }">
        <div class="full-width column items-center q-pa-xl text-grey">
          <q-icon :name="DOMAIN_ICONS.connections" size="48px" class="q-mb-sm" />
          <div class="text-subtitle1">{{ message }}</div>
        </div>
      </template>

      <template #body-cell-state="props">
        <q-td :props="props">
          <q-icon
            v-if="props.row.presence === 'silent'"
            name="notifications_paused"
            size="14px"
            color="amber-8"
            :tabindex="0"
            aria-label="Profiled but silent — no traffic in this window"
            data-testid="silent-row-marker"
          >
            <q-tooltip anchor="bottom start" self="top start" :offset="[0, 6]" max-width="320px">
              <div class="text-weight-bold q-mb-xs">Profiled but silent</div>
              <div>
                This connection has a learned cadence profile but sent nothing in the current time window. Select it to
                open its CADENCE lane and see whether the silence has already passed the absence deadline.
              </div>
            </q-tooltip>
          </q-icon>
          <q-icon
            v-else-if="props.row.state === 'anomaly'"
            name="circle"
            size="10px"
            color="red"
            data-testid="connection-status-anomaly"
          />
          <q-icon
            v-else-if="props.row.profiled === false"
            name="circle"
            size="10px"
            color="yellow-8"
            aria-label="No detection profile — not monitored"
            data-testid="connection-status-no-profile"
          >
            <q-tooltip>No detection profile — not monitored</q-tooltip>
          </q-icon>
          <q-icon
            v-else
            name="circle"
            size="10px"
            color="green"
            data-testid="connection-status-ok"
          />
        </q-td>
      </template>

      <template #body-cell-source="props">
        <q-td :props="props">
          <span class="text-mono asset-name">{{ resolveLabelFor(props.row, 'source') }}</span>
          <q-tooltip>
            <div>{{ resolveLabelFor(props.row, 'source') }}</div>
            <div v-if="resolveLabelFor(props.row, 'source') !== props.row.source">
              {{ props.row.sourceIp || '—' }} / {{ props.row.sourceMac || '—' }}
            </div>
          </q-tooltip>
        </q-td>
      </template>

      <template #body-cell-destination="props">
        <q-td :props="props">
          <span class="text-mono asset-name">{{ resolveLabelFor(props.row, 'destination') }}</span>
          <q-tooltip>
            <div>{{ resolveLabelFor(props.row, 'destination') }}</div>
            <div v-if="resolveLabelFor(props.row, 'destination') !== props.row.destination">
              {{ props.row.destIp || '—' }} / {{ props.row.destMac || '—' }}
            </div>
          </q-tooltip>
        </q-td>
      </template>

      <template #body-cell-protocol="props">
        <q-td :props="props">
          <q-badge
            :color="protocolColor(props.row.protocol)"
            :label="props.row.protocol"
            outline
            class="text-weight-medium protocol-badge"
          >
            <q-tooltip v-if="props.row.protocol.length > 16">
              {{ props.row.protocol }}
            </q-tooltip>
          </q-badge>
        </q-td>
      </template>

      <template #body-cell-port="props">
        <q-td :props="props">
          <q-badge
            v-if="props.row.isWildcard"
            color="amber-8"
            text-color="white"
            :label="`${props.row.collapsed_port_count ?? props.row.memberCount} ports`"
            class="text-weight-medium"
          />
          <span v-if="props.row.isWildcard && props.row.ruleTrained === false" class="q-ml-xs">
            <q-badge
            v-if="props.row.isWildcard && props.row.ruleTrained === false"
            color="warning"
            outline
            label="Rule not trained yet"
            class="text-weight-medium"
            />
            <q-tooltip>
              Port-collapse rule for this connection group hasn't been computed by the periodic training job yet. Ports
              are shown ungrouped-by-literal-value until the next training cycle.
            </q-tooltip>
          </span>
          <span v-if="!props.row.isWildcard && props.row.port" class="text-mono">
            {{ props.row.port }}
          </span>
        </q-td>
      </template>
    </q-table>
  </div>
</template>

<script setup lang="ts">
import type { QTableColumn } from 'quasar'
import { DOMAIN_ICONS } from '~/composables/useNavigation'
import type { Connection } from '~/types/golden-data'

/**
 * Connection selector table with filters and single-row selection.
 *
 * Displays connections from golden data with state indicators, source/dest
 * addresses, and protocol badges. Supports client-side filtering.
 */

interface Props {
  connections: Connection[]
  initialUci?: string
  initialDeviceFilter?: string
  showPortColumn?: boolean
  showSilentProfiled?: boolean
  silentProfiledCount?: number
  resolveLabel?: (ip: string | null, mac: string | null) => string
}

const props = withDefaults(defineProps<Props>(), {
  initialUci: '',
  initialDeviceFilter: '',
  showPortColumn: true,
  showSilentProfiled: false,
  silentProfiledCount: 0,
  resolveLabel: undefined,
})

const emit = defineEmits<{
  select: [connection: Connection | null]
  'update:showSilentProfiled': [value: boolean]
}>()

const silentToggleAriaLabel = computed(
  () =>
    `Show profiled but silent connections (${props.silentProfiledCount} available). ` +
    'These have a learned cadence profile but no traffic in the current time window.',
)

/**
 * Tag silent rows so they read differently from live traffic.
 *
 * @param row - The connection rendered in this table row.
 * @returns The extra CSS class for the row, empty for live rows.
 */
function rowClass(row: Connection): string {
  return row.presence === 'silent' ? 'silent-profiled-row' : ''
}

const filterSource = ref('')
const filterDest = ref('')
const filterProtocol = ref('')
const selectedRows = ref<Connection[]>([])

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
    name: 'source',
    label: 'Source',
    field: 'source',
    align: 'left',
    sortable: true,
    style: 'width: clamp(140px, 22cqw, 300px)',
    headerStyle: 'width: clamp(140px, 22cqw, 300px)',
  },
  {
    name: 'destination',
    label: 'Destination',
    field: 'destination',
    align: 'left',
    sortable: true,
    style: 'width: clamp(140px, 22cqw, 300px)',
    headerStyle: 'width: clamp(140px, 22cqw, 300px)',
  },
  {
    name: 'protocol',
    label: 'Protocol',
    field: 'protocol',
    align: 'left',
    sortable: true,
    style: 'width: clamp(100px, 20cqw, 220px)',
    headerStyle: 'width: clamp(100px, 20cqw, 220px)',
  },
  {
    name: 'port',
    label: 'Port',
    field: 'port',
    align: 'center',
    sortable: true,
    style: 'width: 100px',
    headerStyle: 'width: 100px',
  },
]

const visibleColumns = computed<QTableColumn[]>(() => {
  if (!props.showPortColumn) {
    return baseColumns.filter((c) => c.name !== 'port')
  }
  return baseColumns
})

function resolveLabelFor(row: Connection, endpoint: 'source' | 'destination'): string {
  if (!props.resolveLabel) {
    return endpoint === 'source' ? row.source : row.destination
  }
  if (endpoint === 'source') {
    return props.resolveLabel(row.sourceIp, row.sourceMac) || row.source
  }
  return props.resolveLabel(row.destIp, row.destMac) || row.destination
}

const filteredConnections = computed<Connection[]>(() => {
  let result = props.connections
  const src = (filterSource.value || '').toLowerCase()
  const dst = (filterDest.value || '').toLowerCase()
  const proto = (filterProtocol.value || '').toLowerCase()

  if (src) {
    result = result.filter((c) => {
      const label = resolveLabelFor(c, 'source').toLowerCase()
      return (
        label.includes(src) ||
        (c.sourceIp ?? '').toLowerCase().includes(src) ||
        (c.sourceMac ?? '').toLowerCase().includes(src)
      )
    })
  }
  if (dst) {
    result = result.filter((c) => {
      const label = resolveLabelFor(c, 'destination').toLowerCase()
      return (
        label.includes(dst) ||
        (c.destIp ?? '').toLowerCase().includes(dst) ||
        (c.destMac ?? '').toLowerCase().includes(dst)
      )
    })
  }
  if (proto) {
    result = result.filter((c) => c.protocol.toLowerCase().includes(proto) || (c.port && c.port.includes(proto)))
  }
  return result
})

function protocolColor(protocol: string): string {
  const p = protocol.split(':')[0].trim()
  if (p.includes('PROFINET')) return 'teal'
  if (p.includes('OPC_UA') || p.includes('OPC UA')) return 'blue'
  if (p.includes('LLDP')) return 'purple'
  if (p.includes('mDNS')) return 'orange'
  if (p.includes('Modbus')) return 'cyan'
  if (p.includes('ARP')) return 'grey-7'
  if (p.includes('TCP')) return 'indigo'
  if (p.includes('UDP')) return 'deep-purple'
  if (p.includes('ICMP')) return 'brown'
  return 'grey'
}

function onRowClick(_event: Event, row: Connection): void {
  selectedRows.value = [row]
  emit('select', row)
}

/**
 * Auto-select a connection when the list first becomes available.
 *
 * Handles the race between component mount and the async fetch in the
 * parent: if `connections` is still empty at mount time, this watcher
 * fires as soon as the first batch arrives and selects either the
 * URL-requested UCI or the first row.
 */
function autoSelectFirst(): void {
  if (selectedRows.value.length > 0) return
  if (props.connections.length === 0) return

  if (props.initialUci) {
    const match = props.connections.find((c) => c.uci === props.initialUci)
    if (match) {
      selectedRows.value = [match]
      emit('select', match)
      return
    }
  }

  // Never auto-select a silent row: the default landing state should be a
  // connection that is actually sending. Silent rows are opened deliberately.
  const firstLive = props.connections.find((c) => c.presence !== 'silent')
  if (!firstLive) return
  selectedRows.value = [firstLive]
  emit('select', firstLive)
}

watch(
  () => props.connections,
  (newConnections) => {
    if (selectedRows.value.length > 0) {
      const currentUci = selectedRows.value[0].uci
      const freshMatch = newConnections.find((c) => c.uci === currentUci)
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
  if (props.initialDeviceFilter) {
    filterSource.value = props.initialDeviceFilter
  }
  autoSelectFirst()
})
</script>

<style scoped lang="scss">
.connection-selector {
  height: 100%;
  display: flex;
  flex-direction: column;
}

.filter-row {
  flex-shrink: 0;
}

.silent-toggle-wrap {
  padding: 0 4px;
  border-radius: $border-radius-md;

  &:focus-visible {
    outline: 2px solid var(--q-primary);
    outline-offset: 2px;
  }
}

.silent-toggle-label {
  font-weight: 700;
  font-size: 11px;
  letter-spacing: 0.8px;
  white-space: nowrap;
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

  /* Silent profiled rows must never read as live traffic: a left amber rule
     plus a dimmed body keeps the distinction legible at a glance without
     adding a column. */
  :deep(tbody tr.silent-profiled-row) {
    box-shadow: inset 3px 0 0 0 var(--q-amber-8, #ff8f00);

    td {
      opacity: 0.72;
      font-style: italic;
    }

    &.selected td {
      opacity: 1;
    }
  }

  :deep(th:first-child),
  :deep(td:first-child) {
    display: none;
  }

  .protocol-badge {
    min-width: 0;
    max-width: 100%;
    text-align: center;
    display: inline-block;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    vertical-align: middle;
  }
}
</style>
