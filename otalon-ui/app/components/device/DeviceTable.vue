<template>
  <q-table
    v-model:selected="selectedModel"
    :pagination="pagination"
    flat
    bordered
    dense
    virtual-scroll
    :virtual-scroll-sticky-size-start="28"
    :rows="rows"
    :columns="columns"
    :visible-columns="effectiveVisibleColumns"
    row-key="id"
    :selection="selection"
    :filter="filter"
    :filter-method="filterMethod"
    :rows-per-page-options="[0]"
    hide-pagination
    no-data-label="No assets found"
    no-results-label="No assets match the current filter"
    binary-state-sort
    :row-class="rowClass"
    class="device-table"
    @row-click="onRowClick"
  >
    <template #no-data="{ message }">
      <div class="full-width column items-center q-pa-xl text-grey">
        <q-icon name="devices_other" size="48px" class="q-mb-sm" />
        <div class="text-subtitle1">{{ message }}</div>
      </div>
    </template>

    <template #body-cell-hostname="slotProps">
      <q-td :props="slotProps">
        <span v-if="slotProps.row.hostname" class="text-mono">{{ slotProps.row.hostname }}</span>
       </q-td>
    </template>

    <template #body-cell-device_type="slotProps">
      <q-td :props="slotProps">
        <q-chip
          dense
          square
          :color="typeChipColor(slotProps.row.device_type || '')"
          text-color="white"
          :icon="typeChipIcon(slotProps.row.device_type || '')"
          class="device-type-chip"
        >
          {{ slotProps.row.device_type || 'Unknown' }}
        </q-chip>
      </q-td>
    </template>

    <template #body-cell-article_number="slotProps">
      <q-td :props="slotProps">
        <span v-if="slotProps.row.article_number" class="text-mono">
          {{ slotProps.row.article_number }}
        </span>
        <span v-else class="text-grey-6">—</span>
      </q-td>
    </template>

    <template #body-cell-product_name="slotProps">
      <q-td :props="slotProps">
        <span v-if="slotProps.row.product_name">{{ slotProps.row.product_name }}</span>
        <span v-else class="text-grey-6">—</span>
      </q-td>
    </template>

    <template #body-cell-vendor="slotProps">
      <q-td :props="slotProps">
        <div class="text-weight-medium">{{ slotProps.row.vendor || '—' }}</div>
        <div v-if="slotProps.row.device_family" class="text-caption text-muted">
          {{ slotProps.row.device_family }}
        </div>
      </q-td>
    </template>

    <template #body-cell-ip="slotProps">
      <q-td :props="slotProps">
        <span v-if="slotProps.row._primaryIp" class="text-mono">
          {{ slotProps.row._primaryIp }}
        </span>
        <span v-else class="text-grey-6">—</span>
      </q-td>
    </template>

    <template #body-cell-mac="slotProps">
      <q-td :props="slotProps">
        <span v-if="slotProps.row._primaryMac" class="text-mono">
          {{ slotProps.row._primaryMac }}
        </span>
        <span v-else class="text-grey-6">—</span>
      </q-td>
    </template>

    <template #body-cell-firmware_version="slotProps">
      <q-td :props="slotProps">
        <div class="row items-center q-gutter-xs no-wrap">
          <span :class="slotProps.row.firmware_version ? 'text-mono' : 'text-grey-6'">
            {{ slotProps.row.firmware_version || '—' }}
          </span>
          <q-icon v-if="slotProps.row.update_available" name="system_update" color="warning" size="16px">
            <q-tooltip>Firmware update available</q-tooltip>
          </q-icon>
        </div>
      </q-td>
    </template>

    <template #body-cell-lookup_eligible="slotProps">
      <q-td :props="slotProps">
        <q-badge
          v-if="slotProps.row._lookupEligible"
          color="positive"
          class="q-px-sm lookup-badge"
          data-testid="device-eligible-badge"
        >
          <q-icon name="check_circle" size="14px" class="q-mr-xs" />
          Eligible
        </q-badge>
        <div v-else class="row items-center q-gutter-xs no-wrap">
          <q-badge color="warning" class="q-px-sm lookup-badge" data-testid="device-ineligible-badge">
            <q-icon name="warning" size="14px" class="q-mr-xs" />
            Incomplete
          </q-badge>
          <q-icon name="info" size="16px" color="grey-6" data-testid="device-ineligible-info">
            <q-tooltip>
              Missing identity fields:
              <ul class="q-ma-none q-pl-md">
                <li v-for="f in slotProps.row._missingFields" :key="f">{{ f }}</li>
              </ul>
            </q-tooltip>
          </q-icon>
        </div>
      </q-td>
    </template>

    <template #body-cell-vulnerabilities="slotProps">
      <q-td :props="slotProps" @click.stop>
        <q-badge
          v-if="vulnCount(slotProps.row) > 0"
          :color="vulnColor(slotProps.row)"
          :label="vulnCount(slotProps.row)"
          class="q-px-sm cursor-pointer"
        >
          <q-menu anchor="bottom middle" self="top middle">
            <q-list dense bordered class="vuln-menu">
              <q-item-label header class="text-weight-bold">
                {{ vulnCount(slotProps.row) }} CVE{{ vulnCount(slotProps.row) === 1 ? '' : 's' }} for
                {{ slotProps.row.device_family || 'this device' }}
              </q-item-label>
              <q-separator />
              <q-item
                v-for="v in slotProps.row.vulnerabilities || []"
                :key="cveKey(v)"
                clickable
                tag="a"
                :href="cveUrl(v)"
                target="_blank"
                rel="noopener noreferrer"
              >
                <q-item-section avatar>
                  <q-badge :color="cveSeverityColor(v.severity)" :label="(v.cvss_score ?? 0).toFixed(1)" />
                </q-item-section>
                <q-item-section>
                  <q-item-label class="text-mono">{{ cveKey(v) }}</q-item-label>
                  <q-item-label caption lines="2">
                    {{ v.summary || v.description || '' }}
                  </q-item-label>
                  <q-item-label v-if="v.fixed_in" caption>
                    <q-icon name="build" size="14px" class="q-mr-xs" />
                    Fixed in {{ v.fixed_in }}
                  </q-item-label>
                </q-item-section>
                <q-item-section side>
                  <q-icon name="open_in_new" size="16px" color="grey-6" />
                </q-item-section>
              </q-item>
            </q-list>
          </q-menu>
        </q-badge>
        <span v-else class="text-grey-6">0</span>
      </q-td>
    </template>

    <template #body-cell-last_scan_at="slotProps">
      <q-td :props="slotProps">
        <span v-if="slotProps.row.last_scan_at">
          {{ formatRelativeTime(slotProps.row.last_scan_at) }}
        </span>
        <span v-else class="text-grey-6">never</span>
      </q-td>
    </template>

    <template #body-cell-status="slotProps">
      <q-td :props="slotProps">
        <q-badge v-if="slotProps.row._outsideTimeWindow" color="grey-6" class="q-px-sm" title="Not seen in the selected time window">
          Not in window
        </q-badge>
        <q-badge
          v-else-if="slotProps.row.last_scan_at && isRecent(slotProps.row.last_scan_at)"
          color="positive"
          class="q-px-sm"
        >
          Online
        </q-badge>
        <span v-else-if="slotProps.row.last_scan_at" class="text-caption text-grey-6">
          Last seen {{ formatRelativeTime(slotProps.row.last_scan_at) }}
        </span>
        <span v-else class="text-caption text-grey-6">Unknown</span>
        <span v-if="slotProps.row._outsideTimeWindow && slotProps.row.last_scan_at" class="text-caption text-grey-6">
          — last seen {{ formatRelativeTime(slotProps.row.last_scan_at) }}
        </span>
      </q-td>
    </template>

    <template #body-cell-actions="slotProps">
      <q-td :props="slotProps" @click.stop>
        <q-btn
          dense
          flat
          round
          color="primary"
          icon="play_arrow"
          size="sm"
          aria-label="Scan this device"
          data-testid="device-table-row-scan-btn"
          @click.stop="onScanRow(slotProps.row)"
        >
          <q-tooltip>Scan this device</q-tooltip>
        </q-btn>
        <q-btn
          v-if="isLookupEligible(slotProps.row)"
          dense
          flat
          round
          color="secondary"
          icon="search"
          size="sm"
          aria-label="CVE lookup"
          data-testid="device-table-row-cve-lookup-btn"
          @click.stop="onCveLookupRow(slotProps.row)"
        >
          <q-tooltip>Lookup CVEs for this asset</q-tooltip>
        </q-btn>
      </q-td>
    </template>
  </q-table>
</template>

<script setup lang="ts">
import type { QTableColumn } from 'quasar'
import type { DeviceItem, DeviceVulnerabilityItem } from '~/types/api'
import { formatRelativeTime, isRecent } from '~/utils/format'
import { isLookupEligible } from '~/utils/device'
import { severityColor } from '~/utils/severity'

interface DeviceTableRow extends DeviceItem {
  _primaryIp: string
  _primaryMac: string
  _vulnCount: number
  _lookupEligible: boolean
  _missingFields: string[]
}

interface Props {
  devices: DeviceItem[]
  filter?: string
  visibleColumns?: string[]
  rowsPerPage?: number
  /**
   * When ``'multiple'``, the table renders selection checkboxes on each row
   * (Decision 3 — Quasar native multi-select). The parent owns the
   * selection via ``v-model:selected``.
   */
  selection?: 'multiple' | 'single' | 'none'
  /** Two-way binding for ``q-table`` selection. */
  selected?: DeviceItem[]
}

interface Emits {
  (e: 'select' | 'scan-row' | 'cve-lookup', device: DeviceItem): void
  (e: 'update:selected', value: DeviceItem[]): void
}

const props = withDefaults(defineProps<Props>(), {
  filter: '',
  visibleColumns: () => [
    'status',
    'hostname',
    'device_type',
    'vendor',
    'ip',
    'mac',
    'article_number',
    'firmware_version',
    'vulnerabilities',
    'last_scan_at',
  ],
  rowsPerPage: 25,
  selection: 'none',
  selected: () => [],
})
const emit = defineEmits<Emits>()

const selectedModel = computed<DeviceItem[]>({
  get: () => props.selected,
  set: (value) => emit('update:selected', value),
})

/**
 * Always include the ``actions`` column whenever the parent has not opted
 * it out by explicitly listing visible columns without ``actions``. We
 * append it so it is the last column.
 */
const effectiveVisibleColumns = computed<string[]>(() => {
  const base = props.visibleColumns ?? []
  if (base.includes('actions')) return base
  return [...base, 'actions']
})

function onScanRow(device: DeviceItem): void {
  emit('scan-row', device)
}

function onCveLookupRow(device: DeviceItem): void {
  emit('cve-lookup', device)
}

/**
 * Annotate each device with derived fields used for table display + sorting.
 *
 * The primary IP/MAC come from the first network interface so the table can
 * show a single representative address even when multiple interfaces exist.
 */
const rows = computed<DeviceTableRow[]>(() =>
  props.devices.map((device) => {
    const firstIface = device.interfaces[0] ?? null
    const vulnCount = Array.isArray(device.vulnerabilities) ? device.vulnerabilities.length : 0
    const missingFields: string[] = []
    if (!device.vendor || device.vendor.trim().length === 0) missingFields.push('vendor')
    if (!device.product_name || device.product_name.trim().length === 0) missingFields.push('product_name')
    if (!device.firmware_version || device.firmware_version.trim().length === 0) missingFields.push('firmware_version')
    return {
      ...device,
      _primaryIp: firstIface?.ipv4_address ?? firstIface?.ipv6_address ?? '',
      _primaryMac: firstIface?.mac_address ?? '',
      _vulnCount: vulnCount,
      _lookupEligible: missingFields.length === 0,
      _missingFields: missingFields,
    }
  }),
)

/**
 * Per-row CSS classes.
 *
 * Devices outside the selected time window stay listed but are dimmed, so
 * the inventory remains complete while recency is still visible
 * (audit UI-04).
 *
 * @param row - The device row being rendered.
 * @returns Space-separated class list for the row.
 */
function rowClass(row: DeviceTableRow): string {
  return row._outsideTimeWindow ? 'device-table-row device-table-row--stale' : 'device-table-row'
}

const pagination = ref({
  page: 1,
  rowsPerPage: 0,
  sortBy: 'vendor',
  descending: false,
})

/**
 * Case-insensitive substring filter that searches across vendor, family, type,
 * role, IP and MAC columns.
 */
function filterMethod(rs: DeviceTableRow[], term: string): DeviceTableRow[] {
  if (!term) return rs
  const needle = term.toLowerCase().trim()
  if (!needle) return rs
  return rs.filter((r) => {
    const haystack = [
      r.vendor,
      r.device_family,
      r.device_type,
      r.hostname,
      r.device_role,
      r.firmware_version,
      r.description,
      r._primaryIp,
      r._primaryMac,
    ]
      .filter((v): v is string => typeof v === 'string' && v.length > 0)
      .join(' ')
      .toLowerCase()
    return haystack.includes(needle)
  })
}

/**
 * Pick a Quasar color name for the device-type chip so the table mirrors
 * the topology graph palette (PLC=blue, IPC=purple, IO=orange, Switch=teal).
 *
 * Driven by product_name or a normalized role, not the raw DB device_type.
 */
function typeChipColor(label: string): string {
  const t = label.toLowerCase()
  if (!t) return 'grey-6'
  if (t === 'unknown') return 'grey-6'
  if (t.includes('plc') || t.includes('pac') || t.includes('controller')) return 'blue-6'
  if (t.includes('ipc') || t.includes('workstation') || t.includes('hmi')) return 'purple-6'
  if (t === 'io' || t.includes('field i/o') || t.includes('field io') || t.includes('ied')) return 'orange-7'
  if (t.includes('switch') || t.includes('router')) return 'teal-6'
  if (t.includes('firewall') || t.includes('vpn')) return 'red-6'
  if (t === 'other') return 'blue-grey-7'
  return 'blue-grey-6'
}

/**
 * Material-icon glyph that visually reinforces the device-type chip text.
 */
function typeChipIcon(label: string): string {
  const t = label.toLowerCase()
  if (t.includes('plc') || t.includes('pac') || t.includes('controller')) return 'memory'
  if (t.includes('ipc') || t.includes('workstation') || t.includes('server') || t.includes('hmi')) return 'computer'
  if (t === 'io' || t.includes('field i/o') || t.includes('field io') || t.includes('ied')) return 'settings_input_component'
  if (t.includes('switch') || t.includes('router') || t.includes('gateway')) return 'hub'
  if (t.includes('firewall') || t.includes('vpn')) return 'security'
  if (t === 'unknown' || t === 'other') return 'device_unknown'
  return 'device_hub'
}

function vulnCount(row: DeviceTableRow): number {
  return row._vulnCount
}

/**
 * Map the highest severity present in the vulnerabilities column to a
 * Quasar palette entry so the badge color matches the threat level.
 */
function vulnColor(row: DeviceTableRow): string {
  const vulns = row.vulnerabilities ?? []
  let worst: 'low' | 'medium' | 'high' | 'critical' = 'low'
  for (const v of vulns) {
    const sev = String(v.severity || '').toLowerCase()
    if (sev === 'critical') worst = 'critical'
    else if (sev === 'high' && worst !== 'critical') worst = 'high'
    else if (sev === 'medium' && worst !== 'critical' && worst !== 'high') worst = 'medium'
  }
  return severityColor(worst)
}

/**
 * Return the canonical CVE identifier from a vulnerability record,
 * preferring ``cve`` over ``id`` so older entries keep working.
 */
function cveKey(v: DeviceVulnerabilityItem | Record<string, unknown>): string {
  return String((v as Record<string, unknown>).vuln_id ?? (v as Record<string, unknown>).cve ?? '?')
}

/**
 * Build the NVD detail URL for a CVE entry. Falls back to a search
 * URL when no canonical ``url`` is stored.
 */
function cveUrl(v: DeviceVulnerabilityItem | Record<string, unknown>): string {
  const url = (v as Record<string, unknown>).url
  if (typeof url === 'string' && url.length > 0) return url
  const key = cveKey(v)
  return key !== '?' ? `https://nvd.nist.gov/vuln/detail/${key}` : 'https://nvd.nist.gov/'
}

/**
 * Per-CVE severity color used in the menu list (independent of the
 * row-level "worst severity" badge color).
 */
function cveSeverityColor(severity: unknown): string {
  return severityColor(String(severity || ''))
}

const columns: QTableColumn<DeviceTableRow>[] = [
  {
    name: 'status',
    label: 'Status',
    field: 'last_scan_at',
    align: 'center',
    sortable: true,
  },
  {
    name: 'hostname',
    label: 'Hostname',
    field: 'hostname',
    align: 'left',
    sortable: true,
  },
  {
    name: 'device_type',
    label: 'Type',
    field: 'device_type',
    align: 'left',
    sortable: true,
  },
  {
    name: 'vendor',
    label: 'Vendor / Family',
    field: 'vendor',
    align: 'left',
    sortable: true,
  },
  {
    name: 'ip',
    label: 'IP Address',
    field: '_primaryIp',
    align: 'left',
    sortable: true,
  },
  {
    name: 'mac',
    label: 'MAC Address',
    field: '_primaryMac',
    align: 'left',
    sortable: true,
  },
  {
    name: 'article_number',
    label: 'Article',
    field: 'article_number',
    align: 'left',
    sortable: true,
  },
  {
    name: 'product_name',
    label: 'Product',
    field: 'product_name',
    align: 'left',
    sortable: true,
  },
  {
    name: 'firmware_version',
    label: 'Firmware',
    field: 'firmware_version',
    align: 'left',
    sortable: true,
  },
  {
    name: 'lookup_eligible',
    label: 'Lookup',
    field: '_lookupEligible',
    align: 'left',
    sortable: true,
  },
  {
    name: 'vulnerabilities',
    label: 'CVEs',
    field: '_vulnCount',
    align: 'center',
    sortable: true,
  },
  {
    name: 'last_scan_at',
    label: 'Last Scan',
    field: 'last_scan_at',
    align: 'left',
    sortable: true,
  },
  {
    name: 'actions',
    label: 'Actions',
    field: () => '',
    align: 'center',
    sortable: false,
  },
]

function onRowClick(_evt: Event, row: DeviceTableRow): void {
  emit('select', row)
}
</script>

<style scoped lang="scss">
// Devices not seen in the selected time window remain listed but recede
// visually (audit UI-04). Opacity only — never `display: none`, so the row
// stays selectable and searchable.
:deep(.device-table-row--stale) {
  opacity: 0.55;
}

.device-table {
  :deep(.q-table__top) {
    padding: 8px 16px;
  }

  :deep(thead th) {
    font-weight: 700;
    font-size: 12px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    position: sticky;
    top: 0;
    z-index: 1;
    background-color: var(--cd-surface);
  }

  :deep(.q-table tbody tr) {
    cursor: pointer;
    transition: background-color 0.15s ease;
  }

  :deep(.q-table tbody tr:hover) {
    background-color: rgba(var(--cd-primary-rgb), 0.08) !important;
  }
}

.text-mono {
  font-family: $font-family-mono;
  font-size: 0.85rem;
}

/*
 * Type-chip — inherit the table body font-size instead of Quasar's
 * built-in 12 px ``size="sm"`` default. Without this the chip looked
 * noticeably smaller than the rest of the row text. The explicit
 * height keeps the chip compact and aligned with the dense table row.
 */
.device-table :deep(.q-chip.device-type-chip) {
  font-size: inherit;
  height: 24px;
  padding: 0 8px;
  line-height: 1;
}

/* CVE popup menu — wider than the badge anchor so descriptions wrap nicely. */
.vuln-menu {
  min-width: 420px;
  max-width: 520px;
  max-height: 360px;
  overflow-y: auto;
  scrollbar-width: thin;
}

.vuln-menu :deep(.q-item) {
  padding: 8px 12px;
}

.vuln-menu :deep(.q-item__label--caption) {
  white-space: normal;
}

.lookup-badge {
  min-width: 100px;
  display: inline-flex;
  justify-content: center;
  align-items: center;
}
</style>
