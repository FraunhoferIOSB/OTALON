<template>
  <q-page
    role="main"
    class="time-toolbar-page"
    :class="[`assets-density-${displaySettings.density}`]"
    :style="`--page-font-size: ${displaySettings.fontSize}px`"
  >
    <SharedTimeToolbarRow toolbar-class="col" @update="onTimeUpdate">
      <q-btn
        color="primary"
        icon="play_arrow"
        :label="devicesStore.devices.length > 0 ? 'Scan all' : 'Subnet scan'"
        dense
        no-caps
        data-testid="devices-page-scan-all-btn"
        @click="openScanModal(devicesStore.devices)"
      >
        <q-tooltip>
          {{
            devicesStore.devices.length > 0
              ? 'Run a scan against all loaded devices'
              : 'Run a subnet-wide scan to discover assets'
          }}
        </q-tooltip>
      </q-btn>
      <q-btn
        color="secondary"
        icon="history"
        label="Recent Scans"
        outline
        dense
        no-caps
        data-testid="devices-page-recent-scans-btn"
        @click="recentScansOpen = true"
      >
        <q-tooltip>View recent scan history</q-tooltip>
      </q-btn>
      <q-btn
        v-if="selectedDevices.length > 0"
        color="secondary"
        icon="play_arrow"
        :label="`Scan selected (${selectedDevices.length})`"
        dense
        no-caps
        data-testid="devices-page-scan-selected-btn"
        @click="openScanModal(selectedDevices)"
      >
        <q-tooltip>Run a scan against the selected devices</q-tooltip>
      </q-btn>
      <q-btn flat dense round icon="tune" aria-label="Display settings" @click="dialogOpen = true">
        <q-tooltip>Display Settings</q-tooltip>
      </q-btn>
    </SharedTimeToolbarRow>

    <div class="devices-page">
      <SharedErrorBanner :message="devicesStore.error" @retry="reload()" @dismiss="devicesStore.error = null" />

      <q-inner-loading :showing="devicesStore.isLoading && devicesStore.devices.length === 0" label="Loading assets…" />

      <div class="row items-center q-gutter-sm q-mb-md" data-testid="devices-toolbar">
        <q-badge class="kpi-badge kpi-badge--neutral" role="none">
          <q-icon :name="DOMAIN_ICONS.assets" size="14px" color="primary" class="q-mr-xs" />
          Total Devices: {{ devicesStore.total }}
        </q-badge>
        <q-badge class="kpi-badge kpi-badge--neutral" role="none">
          <q-icon name="check_circle" size="14px" color="positive" class="q-mr-xs" />
          Online: {{ devicesStore.onlineCount }}
        </q-badge>
        <q-badge
          class="kpi-badge"
          :class="filterMode === 'updates' ? 'kpi-badge--selected' : 'kpi-badge--neutral'"
          style="cursor: pointer"
          role="none"
          @click="toggleFilterMode('updates')"
        >
          <q-icon name="system_update" size="14px" color="warning" class="q-mr-xs" />
          Updates Available: {{ devicesStore.updatesAvailableCount }}
        </q-badge>
        <q-badge
          class="kpi-badge"
          :class="filterMode === 'vulnerable' ? 'kpi-badge--selected' : 'kpi-badge--neutral'"
          style="cursor: pointer"
          role="none"
          @click="toggleFilterMode('vulnerable')"
        >
          <q-icon name="bug_report" size="14px" color="negative" class="q-mr-xs" />
          Vulnerabilities: {{ devicesStore.vulnerabilityCount }}
        </q-badge>
        <q-badge
          class="kpi-badge"
          :class="filterMode === 'lookup_eligible' ? 'kpi-badge--selected' : 'kpi-badge--neutral'"
          style="cursor: pointer"
          role="none"
          @click="toggleFilterMode('lookup_eligible')"
        >
          <q-icon name="search" size="14px" color="positive" class="q-mr-xs" />
          Lookup Eligible: {{ lookupEligibleCount }}
        </q-badge>
        <q-badge
          v-if="filterMode !== 'all' || vendorFilter !== 'All vendors'"
          class="kpi-badge kpi-badge--neutral"
          style="cursor: pointer"
          @click="clearFilters()"
        >
          <q-icon name="filter_alt_off" size="14px" class="q-mr-xs" />
          Clear Filter
        </q-badge>
      </div>

      <q-card flat bordered class="filter-card q-mb-md">
        <q-card-section class="q-py-sm">
          <div class="row q-col-gutter-sm items-center">
            <div class="col-md-6 col-sm-12 col-xs-12">
              <q-input
                v-model="searchTerm"
                outlined
                dense
                clearable
                placeholder="Search vendor, type, IP, MAC…"
                aria-label="Search assets by vendor, type, IP, MAC"
                debounce="200"
              >
                <template #prepend>
                  <q-icon name="search" />
                </template>
              </q-input>
            </div>
            <div class="col-md-4 col-sm-8 col-xs-12">
              <q-select
                v-model="vendorFilter"
                :options="['All vendors', ...devicesStore.vendorOptions]"
                outlined
                dense
                emit-value
                map-options
                label="Vendor"
              />
            </div>
            <div class="col-md-2 col-sm-4 col-xs-12 text-right">
              <q-btn
                flat
                dense
                no-caps
                color="primary"
                icon="refresh"
                label="Refresh"
                :loading="devicesStore.isLoading"
                @click="reload()"
              />
            </div>
          </div>
        </q-card-section>
      </q-card>

      <q-toolbar
        v-if="selectedDevices.length > 0"
        class="bulk-select-toolbar q-mb-md rounded-borders"
        data-testid="devices-bulk-toolbar"
      >
        <q-icon name="check_box" color="primary" class="q-mr-sm" />
        <q-toolbar-title class="text-body2 text-weight-medium"> {{ selectedDevices.length }} selected </q-toolbar-title>
        <q-space />
        <q-btn
          flat
          no-caps
          dense
          color="grey-8"
          icon="clear"
          label="Clear selection"
          class="q-mr-sm"
          data-testid="devices-bulk-clear-btn"
          @click="devicesStore.clearSelection()"
        />
        <q-btn
          color="negative"
          icon="delete"
          label="Delete"
          no-caps
          dense
          :loading="bulkDeleting"
          data-testid="devices-bulk-delete-btn"
          @click="onBulkDelete"
        />
      </q-toolbar>

      <q-banner v-if="staleDeviceCount > 0" dense class="bg-grey-3 text-dark q-mb-sm">
        <template #avatar>
          <q-icon name="history" />
        </template>
        {{ staleDeviceCount }} of {{ timeFilteredDevices.length }} assets were not seen in the selected time window.
        They stay listed and are dimmed.
      </q-banner>

      <DeviceTable
        v-model:selected="selectedDevices"
        :devices="timeFilteredDevices"
        :filter="searchTerm"
        :visible-columns="effectiveColumns"
        :rows-per-page="displaySettings.rowsPerPage"
        selection="multiple"
        class="device-table-flex"
        @select="onSelectDevice"
        @scan-row="onScanRow"
        @cve-lookup="(d) => runLookupForDevice(d.id)"
      />

      <div v-if="devicesStore.hasMoreDevices" class="row justify-center q-my-md">
        <q-btn
          outline
          no-caps
          color="primary"
          icon="expand_more"
          :label="`Load more assets (${devicesStore.devices.length} of ${devicesStore.total})`"
          :loading="devicesStore.isLoadingMore"
          data-testid="devices-load-more-btn"
          @click="devicesStore.loadMoreDevices()"
        />
      </div>
    </div>

    <ScanRunModal
      v-model="scanModalOpen"
      :target-devices="scanModalTargets"
      :replay-scan-id="scanModalReplayId"
      :has-profinet-in-subnet="scanModalHasProfinet"
      @started="onScanStarted"
      @finished="onScanFinished"
    />

    <q-dialog v-model="detailDialogOpen" position="right" full-height seamless>
      <q-card class="device-detail-dialog">
        <DeviceDetailPanel
          :device="selectedDevice"
          @close="detailDialogOpen = false"
          @scan="onDetailScan"
          @removed="onDetailRemoved"
          @cve-lookup="runLookupForDevice"
          @identity-updated="onDetailIdentityUpdated"
          @observations="deviceObservations = $event"
        />
      </q-card>
    </q-dialog>

    <CveLookupDialog
      v-model="cveDialogOpen"
      :initial-device-id="cveDialogInitialDeviceId"
      :initial-job-id="cveDialogInitialJobId"
    />

    <q-dialog v-model="recentScansOpen" full-width position="top">
      <q-card class="recent-scans-modal" data-testid="recent-scans-modal">
        <ScanRecentPanel inline @select="onSelectRecentScan" />
      </q-card>
    </q-dialog>

    <SharedDisplaySettingsDialog
      v-model="displaySettings"
      v-model:open="dialogOpen"
      :table-columns="togglableColumns"
      @reset="resetSettings"
      @commit="persistSettings"
    />
  </q-page>
</template>

<script setup lang="ts">
import { useQuasar } from 'quasar'
import { DOMAIN_ICONS } from '~/composables/useNavigation'

import ScanRunModal from '~/components/scan/ScanRunModal.vue'
import ScanRecentPanel from '~/components/scan/ScanRecentPanel.vue'
import CveLookupDialog from '~/components/CveLookupDialog.vue'
import { useApi } from '~/composables/useApi'
import { useSse } from '~/composables/useSse'
import { useJobNotificationsStore } from '~/stores/jobNotificationsStore'
import type { ScanItem } from '~/types/scans'
import type { DeviceItem, ServiceObservationItem, TopologyGraphResponse } from '~/types/api'
import { isLookupEligible } from '~/utils/device'
import type { ColumnDefinition } from '~/components/shared/DisplaySettingsDialog.vue'
import { provideChatContext } from '~/composables/useChatContext'
import { buildAssetsContribution } from '~/utils/chatContext'

definePageMeta({
  title: 'Asset List',
})

const devicesStore = useDevicesStore()
const appStore = useAppStore()
const jobStore = useJobNotificationsStore()
const route = useRoute()
const $q = useQuasar()
const api = useApi()

type FilterMode = 'all' | 'updates' | 'vulnerable' | 'lookup_eligible'

const togglableColumns: ColumnDefinition[] = [
  { value: 'status', label: 'Status' },
  { value: 'device_type', label: 'Type' },
  { value: 'vendor', label: 'Vendor / Family' },
  { value: 'ip', label: 'IP Address' },
  { value: 'mac', label: 'MAC Address' },
  { value: 'article_number', label: 'Article' },
  { value: 'product_name', label: 'Product' },
  { value: 'firmware_version', label: 'Firmware' },
  { value: 'lookup_eligible', label: 'Lookup' },
  { value: 'vulnerabilities', label: 'CVEs' },
  { value: 'last_scan_at', label: 'Last Scan' },
]

const {
  settings: displaySettings,
  dialogOpen,
  persist: persistSettings,
  reset: resetSettings,
} = useDisplaySettings({
  storageKey: 'assets:displaySettings',
  columnDefaults: {
    status: true,
    device_type: true,
    vendor: true,
    ip: true,
    mac: true,
    article_number: true,
    product_name: true,
    firmware_version: true,
    lookup_eligible: true,
    vulnerabilities: true,
    last_scan_at: true,
  },
  defaultFontSize: 13,
  defaultRowsPerPage: 25,
})

/**
 * Resolve the column subset that the table should render based on the
 * user's toggle selections.  The hostname column is always visible.
 */
const effectiveColumns = computed<string[]>(() => {
  const visible: string[] = ['hostname']
  for (const col of togglableColumns) {
    if (displaySettings.value.visibleColumns[col.value]) {
      visible.push(col.value)
    }
  }
  return visible
})

const filterMode = ref<FilterMode>('all')
const searchTerm = ref('')
const vendorFilter = ref<string>('All vendors')
/**
 * Current time window for the device list filter.
 *
 * Stored as a reactive ref and updated alongside every data fetch so
 * that the filter range always matches the queried window. A plain
 * `computed` over `freshApiTimeParams()` would cache the value because
 * `new Date()` is not a reactive dependency — in LIVE mode the window
 * would freeze and devices would fall out of the filtered list until
 * it goes completely empty (UI-121).
 */
const timeRange = ref(appStore.freshApiTimeParams())

/**
 * Re-read the time window from the store (which always returns a fresh
 * wall-clock snapshot in LIVE mode) and publish it to the reactive ref.
 *
 * Call this at every fetch/refresh point so the filter never uses a
 * stale `new Date()` captured at mount time.
 *
 * @returns The applied `{ start, stop }` window as ISO 8601 UTC strings.
 */
function applyTimeWindow(): { start: string; stop: string } {
  const params = appStore.freshApiTimeParams()
  timeRange.value = params
  return params
}

const selectedDevice = ref<DeviceItem | null>(null)
const detailDialogOpen = ref(false)
const deviceObservations = ref<ServiceObservationItem[]>([])

/**
 * Two-way wrapper around ``devicesStore.selectedIds`` shaped as
 * ``DeviceItem[]`` for Quasar's ``q-table v-model:selected`` contract.
 * The store remains the single source of truth — the wrapper just
 * resolves ids back to row objects on read and pushes ids back on
 * write.
 */
const selectedDevices = computed<DeviceItem[]>({
  get: () => {
    const idSet = new Set(devicesStore.selectedIds)
    return devicesStore.devices.filter((d) => idSet.has(d.id))
  },
  set: (rows) => {
    devicesStore.setSelection(rows.map((d) => d.id))
  },
})

const bulkDeleting = ref(false)

const scanModalOpen = ref(false)
const scanModalTargets = ref<DeviceItem[]>([])
const scanModalReplayId = ref<string | null>(null)
const scanModalHasProfinet = ref(false)

const recentScansOpen = ref(false)

const cveDialogOpen = computed({
  get: () => appStore.cveLookupDialogOpen,
  set: (v: boolean) => {
    if (v) {
      appStore.openCveLookupDialog()
    } else {
      appStore.closeCveLookupDialog()
    }
  },
})
const cveDialogInitialDeviceId = ref<number | undefined>(undefined)
const cveDialogInitialJobId = computed(() => appStore.cveLookupDialogJobId ?? undefined)

/**
 * Derive a ``/24`` CIDR from a dotted-quad IPv4 address.
 *
 * @param ipv4 - An IPv4 address (e.g. ``"192.168.0.42"``) or null.
 * @returns The enclosing ``/24`` CIDR (``"192.168.0.0/24"``) or null when
 *   the input is not a well-formed dotted quad.
 */
function ipv4ToSlash24(ipv4: string | null | undefined): string | null {
  if (!ipv4) return null
  const octets = ipv4.split('.')
  if (octets.length !== 4) return null
  if (!octets.every((o) => /^\d+$/.test(o) && Number(o) >= 0 && Number(o) <= 255)) {
    return null
  }
  return `${octets[0]}.${octets[1]}.${octets[2]}.0/24`
}

/**
 * Determine a target subnet (CIDR) for the scan-all PROFINET probe.
 *
 * UI-016 Cause 1: passive-seeded L2 devices carry no explicit
 * ``interfaces[0].subnet`` (the passive source records ``with_subnet=0``),
 * so a strict ``subnet``-only read returns null and the PROFINET probe is
 * skipped — leaving the recommendation stuck on ``arp_scan``. Fall back to a
 * ``/24`` derived from any interface IPv4 so the probe is still issued; the
 * backend's L2 PROFINET signal is subnet-agnostic and will surface even when
 * the CIDR is only approximate.
 *
 * @param devices - The scan-all target devices.
 * @returns The first usable CIDR, or null when no interface yields one.
 */
function extractSubnet(devices: DeviceItem[]): string | null {
  for (const d of devices) {
    const subnet = d.interfaces?.[0]?.subnet
    if (subnet) return subnet
  }
  for (const d of devices) {
    for (const iface of d.interfaces ?? []) {
      const derived = ipv4ToSlash24(iface.ipv4_address)
      if (derived) return derived
    }
  }
  return null
}

async function openScanModal(targets: DeviceItem[]): Promise<void> {
  scanModalReplayId.value = null
  scanModalTargets.value = targets
  scanModalHasProfinet.value = false

  const subnet = extractSubnet(targets)
  if (subnet && targets.length > 1) {
    try {
      const res = await api.get<{ subnet: string; protocols: string[]; seen: boolean }>(
        `/api/v1/topology/subnet-protocols?subnet=${encodeURIComponent(subnet)}`,
      )
      scanModalHasProfinet.value =
        res.seen && res.protocols.some((p) => p.toLowerCase().includes('profinet') || p.toLowerCase() === 'pn')
    } catch {
      scanModalHasProfinet.value = false
    }
  }

  scanModalOpen.value = true
}

function onScanRow(device: DeviceItem): void {
  openScanModal([device])
}

function runLookupForDevice(deviceId: number): void {
  cveDialogInitialDeviceId.value = deviceId
  cveDialogOpen.value = true
}

function onDetailScan(device: DeviceItem): void {
  detailDialogOpen.value = false
  openScanModal([device])
}

function onDetailRemoved(deviceId: number): void {
  // Optimistically drop the row so the inventory reflects the operator's
  // intent immediately. The next ``fetchDevices`` will reconcile if the
  // upstream is eventually-consistent.
  devicesStore.devices = devicesStore.devices.filter((d) => d.id !== deviceId)
  devicesStore.setSelection(devicesStore.selectedIds.filter((id) => id !== deviceId))
  detailDialogOpen.value = false
}

/**
 * SCAN-023: the detail panel mutated a device's identity fields in place
 * (manual override). Sync the matching store row so the inventory table,
 * the vendor filter and the lookup-eligible KPI re-render off the new
 * values without a full refetch.
 */
function onDetailIdentityUpdated(device: DeviceItem): void {
  const idx = devicesStore.devices.findIndex((d) => d.id === device.id)
  if (idx !== -1) {
    devicesStore.devices[idx] = { ...devicesStore.devices[idx], ...device }
  }
}

/**
 * Confirm-dialog + bulk DELETE /api/v1/devices.
 *
 * Mirrors the single-delete UX on the detail panel: ask the operator
 * to confirm, then call the store action. On success, surface a
 * Quasar notify with ``"X deleted, Y not found"`` (the ``not found``
 * tail is omitted when empty so the happy path stays compact). On
 * any error the selection is preserved so the operator can retry.
 */
function onBulkDelete(): void {
  const count = selectedDevices.value.length
  if (count === 0) return
  $q.dialog({
    title: 'Delete devices',
    message: `Delete ${count} device${count === 1 ? '' : 's'}? This cannot be undone.`,
    ok: { label: 'Delete', color: 'negative', noCaps: true },
    cancel: { label: 'Cancel', flat: true, noCaps: true },
    persistent: true,
  }).onOk(() => {
    void performBulkDelete()
  })
}

async function performBulkDelete(): Promise<void> {
  bulkDeleting.value = true
  try {
    const res = await devicesStore.bulkDeleteSelected()
    const msg =
      res.not_found.length > 0
        ? `${res.deleted.length} deleted, ${res.not_found.length} not found`
        : `${res.deleted.length} deleted`
    $q.notify({
      type: 'positive',
      message: msg,
      timeout: 3000,
    })
  } catch (err: unknown) {
    const e = err as { status?: number; message?: string; detail?: unknown }
    const detailStr = typeof e.detail === 'string' && e.detail.length > 0 ? e.detail : (e.message ?? 'Unknown error')
    $q.notify({
      type: 'warning',
      message: `Bulk delete failed (${e.status ?? 0}): ${detailStr}`,
      timeout: 5000,
    })
  } finally {
    bulkDeleting.value = false
  }
}

function onScanStarted(scanId: string): void {
  $q.notify({
    type: 'positive',
    message: `Scan started (${scanId})`,
    timeout: 3000,
  })
}

/**
 * Refresh the device list and, when the detail panel is open, rebind
 * ``selectedDevice`` to the newly fetched row so in-place updates render
 * without a close/reopen cycle.
 */
async function refreshDevices(): Promise<void> {
  applyTimeWindow()
  await devicesStore.fetchDevices()
  if (detailDialogOpen.value && selectedDevice.value) {
    const updated = devicesStore.devices.find((d) => d.id === selectedDevice.value!.id) ?? null
    if (updated) {
      selectedDevice.value = updated
    }
  }
}

async function onScanFinished(scanId: string, status: 'completed' | 'failed' | 'cancelled'): Promise<void> {
  // F-OE6: on successful scan, refetch the devices list so newly
  // discovered or updated assets appear immediately without a manual
  // page reload. Failed or cancelled scans skip the refetch — nothing new landed.
  if (status === 'completed') {
    // P8 UI-170: the scan service commits the fresh `last_scan_at` timestamps
    // asynchronously, so a refresh fired the instant the job flips to
    // `completed` can read the pre-commit rows and briefly mark the just-scanned
    // assets "Not in window" until a manual Refresh. Wait for the commit, then
    // refresh; a single delayed retry covers a slow commit.
    await new Promise((resolve) => setTimeout(resolve, 1500))
    void refreshDevices()
    window.setTimeout(() => void refreshDevices(), 4000)
  }
}

function onSelectRecentScan(scan: ScanItem): void {
  appStore.openScanDetailModal(scan.scan_id)
}

/* G3-F2: auto-refresh on job-completion events (scan + CVE lookup). */
const handledJobIdsForRefresh = new Set<string>()

watch(
  () => jobStore.pending,
  (list) => {
    for (const n of list) {
      if (n.status === 'completed' && !handledJobIdsForRefresh.has(n.id)) {
        handledJobIdsForRefresh.add(n.id)
        void refreshDevices()
      }
    }
  },
  { deep: true },
)

/* G3-F2: auto-refresh on topology changes (passive seeder / other source). */
let lastTopologyNodeCount = 0
useSse('topology', {
  enabled: computed(() => appStore.liveMode),
  onEvent: (_topic, data) => {
    const graph = data as TopologyGraphResponse
    const nodeCount = graph?.meta?.node_count ?? graph?.nodes?.length ?? 0
    if (nodeCount !== lastTopologyNodeCount) {
      lastTopologyNodeCount = nodeCount
      void refreshDevices()
    }
  },
})

const lookupEligibleCount = computed<number>(() => {
  return devicesStore.devices.filter((d) => isLookupEligible(d)).length
})

const filteredDevices = computed<DeviceItem[]>(() => {
  return devicesStore.devices.filter((d) => {
    if (filterMode.value === 'updates' && !d.update_available) return false
    if (filterMode.value === 'vulnerable') {
      const vulns = d.vulnerabilities
      if (!Array.isArray(vulns) || vulns.length === 0) return false
    }
    if (filterMode.value === 'lookup_eligible' && !isLookupEligible(d)) return false
    if (vendorFilter.value && vendorFilter.value !== 'All vendors' && d.vendor !== vendorFilter.value) {
      return false
    }
    return true
  })
})

function latestDeviceTimestamp(device: DeviceItem): number | null {
  const timestamps = [device.last_scan_at, ...device.interfaces.map((iface) => iface.last_scan_at)]
    .filter((timestamp): timestamp is string => Boolean(timestamp))
    .map((timestamp) => new Date(timestamp).getTime())
    .filter((timestamp) => Number.isFinite(timestamp))
  return timestamps.length > 0 ? Math.max(...timestamps) : null
}

/**
 * Devices annotated with whether they were seen inside the selected window.
 *
 * The time window used to REMOVE devices outside it. On an asset inventory
 * that is actively misleading: a device absent from the list reads as "we do
 * not know about this device", when the truth is only "not seen in this
 * window". Devices are therefore always listed and merely marked stale, so
 * the inventory stays complete while the recency signal is preserved
 * (audit UI-04).
 */
const timeFilteredDevices = computed<DeviceItem[]>(() => {
  const start = new Date(timeRange.value.start).getTime()
  const stop = new Date(timeRange.value.stop).getTime()
  return filteredDevices.value.map((device) => {
    const timestamp = latestDeviceTimestamp(device)
    const inWindow = timestamp !== null && timestamp >= start && timestamp <= stop
    return { ...device, _outsideTimeWindow: !inWindow }
  })
})

/** Number of listed devices not seen within the selected time window. */
const staleDeviceCount = computed<number>(
  () => timeFilteredDevices.value.filter((device) => device._outsideTimeWindow).length,
)

function onTimeUpdate(): void {
  void reload()
}

function toggleFilterMode(mode: FilterMode): void {
  filterMode.value = filterMode.value === mode ? 'all' : mode
}

function clearFilters(): void {
  filterMode.value = 'all'
  vendorFilter.value = 'All vendors'
  searchTerm.value = ''
}

function onSelectDevice(device: DeviceItem): void {
  selectedDevice.value = device
  detailDialogOpen.value = true
}

async function reload(): Promise<void> {
  applyTimeWindow()
  await devicesStore.fetchDevices()
}

/**
 * After the inventory loads, honor an optional ``?device=<id>`` query
 * parameter so the Topology page can deep-link into the matching row.
 */
function applyDeepLink(): void {
  const deviceParam = route.query.device
  if (!deviceParam) return
  const targetId = Number(Array.isArray(deviceParam) ? deviceParam[0] : deviceParam)
  if (!Number.isFinite(targetId)) return
  const match = devicesStore.devices.find((d) => d.id === targetId)
  if (match) {
    selectedDevice.value = match
    detailDialogOpen.value = true
  }
}

onMounted(async () => {
  await reload()
  applyDeepLink()
})

watch(
  () => route.query.device,
  () => applyDeepLink(),
)

watch(
  displaySettings,
  () => {
    persistSettings()
  },
  { deep: true },
)

/* Re-fetch with a fresh window when the operator changes the live interval. */
watch(
  () => appStore.liveIntervalSeconds,
  () => {
    if (!appStore.liveMode) return
    void reload()
  },
)

provideChatContext(() => {
  const notes: string[] = []
  if (devicesStore.error) notes.push(`Error loading assets: ${devicesStore.error}`)
  if (filterMode.value === 'vulnerable' && devicesStore.vulnerabilityCount === 0) {
    notes.push('Filtered for vulnerable assets but none of the loaded devices carry CVEs.')
  }

  const contrib = buildAssetsContribution({
    devices: filteredDevices.value,
    selectedDevice: selectedDevice.value,
    detailOpen: detailDialogOpen.value,
    observations: deviceObservations.value,
    filters: {
      kpiFilter: filterMode.value,
      vendor: vendorFilter.value === 'All vendors' ? null : vendorFilter.value,
      searchTerm: searchTerm.value || null,
    },
    totalDevices: devicesStore.total,
    onlineCount: devicesStore.total,
    updatesAvailableCount: devicesStore.updatesAvailableCount,
    vulnerabilityCount: devicesStore.vulnerabilityCount,
    vendorOptions: devicesStore.vendorOptions,
  })

  if (notes.length > 0) contrib.notes = notes
  return contrib
})
</script>

<style scoped lang="scss">
.devices-page {
  position: relative;
  display: flex;
  flex-direction: column;
  padding: 0;
  height: calc(100dvh - var(--cd-header-height, 51px));
  overflow: hidden;
}

.device-table-flex {
  flex: 1;
  min-height: 0;
  overflow: hidden;
}

.kpi-badge {
  padding: 6px 12px;
  font-size: 13px;
  font-weight: 600;
  border-radius: 4px;
}

.kpi-badge--neutral {
  background-color: var(--cd-surface);
  color: var(--cd-surface-text);
  border: 1px solid var(--cd-border);
}

.kpi-badge--selected {
  background-color: rgba(var(--cd-primary-rgb), 0.15);
  color: var(--q-primary);
  outline: 1.5px solid var(--q-primary);
}

.body--dark .kpi-badge--selected {
  background-color: rgba(var(--cd-primary-rgb), 0.3);
}

.filter-card {
  background-color: var(--cd-surface);
  border-color: var(--cd-border);
}

.bulk-select-toolbar {
  background-color: rgba(var(--cd-primary-rgb), 0.08);
  border: 1px solid rgba(var(--cd-primary-rgb), 0.3);
  min-height: 44px;
  padding: 0 12px;
}

.body--dark .bulk-select-toolbar {
  background-color: rgba(var(--cd-primary-rgb), 0.18);
}

.device-detail-dialog {
  background-color: var(--cd-surface);
  min-width: 400px;
  max-width: 600px;
  width: 520px;
  margin-top: 50px;
  height: calc(100dvh - var(--cd-header-height, 51px)) !important;
  max-height: calc(100dvh - var(--cd-header-height, 51px)) !important;
  border-radius: 0;
}

/* Density + font-size apply to the table only so the toolbar stays readable. */
.assets-density-compact :deep(.device-table thead th),
.assets-density-compact :deep(.device-table tbody td) {
  padding-top: 2px !important;
  padding-bottom: 2px !important;
}

.assets-density-comfortable :deep(.device-table thead th),
.assets-density-comfortable :deep(.device-table tbody td) {
  padding-top: 12px !important;
  padding-bottom: 12px !important;
}

.q-page :deep(.device-table thead th),
.q-page :deep(.device-table tbody td),
.q-page :deep(.device-table .q-chip),
.q-page :deep(.device-table .q-badge) {
  font-size: var(--page-font-size);
}

.recent-scans-modal {
  max-width: 900px;
  width: 90vw;
  margin-top: 50px;
}
</style>
