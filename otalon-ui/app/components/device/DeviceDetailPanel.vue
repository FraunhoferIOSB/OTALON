<template>
  <div v-if="device" class="device-detail-panel">
    <q-card-section class="row items-center q-pb-none">
      <q-icon :name="typeIcon" :color="device.update_available ? 'warning' : 'primary'" size="md" class="q-mr-sm" />
      <div>
        <div class="text-h6">{{ titleLabel }}</div>
        <div class="text-caption text-muted">
          {{ device.vendor || 'Unknown vendor' }} · {{ device.device_family || 'Unknown family' }}
        </div>
      </div>
      <q-space />
    </q-card-section>

    <q-separator class="q-my-sm" />

    <q-card-actions align="left" class="q-px-md q-pb-sm q-gutter-sm device-detail-actions">
      <q-btn
        dense
        no-caps
        color="primary"
        :icon="DOMAIN_ICONS.assets"
        label="MAC Timeseries"
        data-testid="device-detail-mac-timeseries-btn"
        :disable="removing || !primaryMac"
        @click="onMacTimeseries"
      >
        <q-tooltip>View MAC traffic timeseries for this device</q-tooltip>
      </q-btn>
      <q-btn
        dense
        no-caps
        color="primary"
        icon="play_arrow"
        label="Scan this device"
        data-testid="device-detail-scan-btn"
        :disable="removing"
        @click="onScan"
      />
      <q-btn
        v-if="lookupEligible"
        dense
        no-caps
        color="secondary"
        icon="search"
        label="CVE Lookup"
        data-testid="device-detail-cve-lookup-btn"
        :disable="removing"
        @click="onCveLookup"
      />
      <q-space />
      <q-btn
        dense
        flat
        no-caps
        color="negative"
        icon="delete"
        label="Remove device"
        data-testid="device-detail-remove-btn"
        :loading="removing"
        @click="onRemove"
      />
      <q-btn
        icon="close"
        flat
        round
        dense
        aria-label="Close detail panel"
        data-testid="device-detail-close-btn"
        @click="$emit('close')"
      />
    </q-card-actions>

    <q-separator class="q-my-sm" />

    <q-card-section class="q-pt-sm">
      <div class="row q-col-gutter-sm">
        <q-badge :color="device.update_available ? 'warning' : 'positive'" class="q-py-xs q-px-sm">
          <q-icon :name="device.update_available ? 'system_update' : 'check_circle'" size="14px" class="q-mr-xs" />
          {{ device.update_available ? 'Update Available' : 'Up to Date' }}
        </q-badge>
        <q-badge v-if="vulnerabilities.length > 0" :color="severityColor" class="q-py-xs q-px-sm">
          <q-icon name="bug_report" size="14px" class="q-mr-xs" />
          {{ vulnerabilities.length }} CVE{{ vulnerabilities.length === 1 ? '' : 's' }}
        </q-badge>
        <q-badge color="info" class="q-py-xs q-px-sm">
          <q-icon name="settings_ethernet" size="14px" class="q-mr-xs" />
          {{ device.interfaces.length }} interface{{ device.interfaces.length === 1 ? '' : 's' }}
        </q-badge>
      </div>
    </q-card-section>

    <q-separator />

    <q-card-section class="q-pt-md" data-testid="device-detail-asset-section">
      <div class="row items-center q-mb-sm">
        <div class="text-overline text-muted">Asset Identity</div>
        <q-space />
        <q-chip
          v-if="lookupEligible"
          dense
          square
          size="sm"
          icon="check_circle"
          class="identity-eligible-chip"
          data-testid="device-detail-lookup-eligible"
        >
          Lookup eligible
        </q-chip>
        <q-chip
          v-else
          dense
          square
          size="sm"
          icon="info"
          class="identity-incomplete-chip"
          data-testid="device-detail-lookup-incomplete"
        >
          Identity incomplete
        </q-chip>
      </div>
      <div class="asset-details-grid">
        <div class="asset-details-label">Hostname</div>
        <div
          class="asset-details-value"
          :class="device.hostname ? 'text-mono' : 'text-grey-6'"
          data-testid="asset-hostname"
        >
          {{ device.hostname || '—' }}
        </div>
        <template v-for="field in assetFields" :key="field.key">
          <div class="asset-details-label">
            {{ field.label }}
            <q-icon
              v-if="field.locked"
              name="lock"
              size="13px"
              class="identity-manual-icon"
              :data-testid="`asset-${field.key}-manual`"
            >
              <q-tooltip>Operator-set (manual) — protected from scan overwrite</q-tooltip>
            </q-icon>
          </div>
          <div
            class="asset-details-value identity-editable"
            :class="field.value ? 'text-mono' : 'text-grey-6'"
            :data-testid="field.testid"
          >
            <span class="identity-value-text">{{ field.value || '—' }}</span>
            <q-icon name="edit" size="14px" class="identity-edit-icon" />
            <q-popup-edit
              v-slot="scope"
              :model-value="field.value ?? ''"
              buttons
              label-set="Save"
              label-cancel="Cancel"
              :title="`Set ${field.label}`"
              :data-testid="`asset-${field.key}-edit`"
               @save="(val: string | null) => onIdentitySave(field.key, val)"
            >
               <q-select
                 v-if="field.key === 'device_type'"
                 v-model="scope.value"
                 :options="deviceTypeOptions"
                 dense
                 autofocus
                 emit-value
                 map-options
                 :data-testid="`asset-${field.key}-select`"
               />
               <q-input
                 v-else
                 v-model="scope.value"
                 dense
                 autofocus
                 counter
                 :data-testid="`asset-${field.key}-input`"
                 @keyup.enter="scope.set"
               />
            </q-popup-edit>
          </div>
        </template>
      </div>
    </q-card-section>

    <q-separator />

    <q-card-section class="q-pt-md">
      <div class="text-overline text-muted q-mb-sm">Observed Services ({{ portObservations.length }})</div>
      <q-inner-loading
        :showing="observationsLoading && portObservations.length === 0"
        label="Loading observations…"
        size="sm"
      />
      <div v-if="!observationsLoading && portObservations.length === 0" class="text-grey-6">
        No service observations recorded.
      </div>
      <div v-if="portObservations.length > 0" class="observed-services-list">
        <div v-for="obs in portObservations" :key="obs.id" class="observed-service-row">
          <div class="observed-service-chip">
            <q-chip dense square size="sm" color="blue-grey-6" text-color="white">
              {{ obs.port }}/{{ obs.transport }}
            </q-chip>
          </div>
          <div class="observed-service-details">
            <div class="row items-center no-wrap">
              <span v-if="obs.service_name" class="q-mr-sm">{{ obs.service_name }}</span>
              <q-badge v-if="obs.product" color="grey-7" size="sm">
                {{ obs.product }}<span v-if="obs.version"> {{ obs.version }}</span>
              </q-badge>
            </div>
            <div v-if="obs.extra_info" class="text-mono text-caption">
              {{ obs.extra_info }}
            </div>
            <div class="text-caption text-grey-6">
              {{ obs.ip_address }} · first seen {{ formatDateTime(obs.first_seen_at) }}
            </div>
          </div>
        </div>
      </div>
    </q-card-section>

    <q-separator />

    <q-card-section class="q-pt-md" data-testid="device-detail-opcua-section">
      <div class="text-overline text-muted q-mb-sm">OPC-UA Endpoints ({{ opcuaObservations.length }})</div>
      <div v-if="opcuaObservations.length === 0" class="text-grey-6">No OPC-UA observations recorded.</div>
      <q-list v-else separator dense>
        <q-item v-for="obs in opcuaObservations" :key="obs.id" class="q-py-sm">
          <q-item-section avatar>
            <q-chip dense square size="sm" color="indigo-6" text-color="white">
              {{ obs.port }}/{{ obs.transport }}
            </q-chip>
          </q-item-section>
          <q-item-section>
            <q-item-label class="row items-center no-wrap">
              <span v-if="obs.service_name" class="q-mr-sm">{{ obs.service_name }}</span>
              <q-badge v-if="obs.product" color="grey-7" size="sm">
                {{ obs.product }}
              </q-badge>
            </q-item-label>
            <OpcUaEndpointList
              v-if="extractEndpointsFromJsonString(obs.extra_info).length > 0"
              :endpoints="extractEndpointsFromJsonString(obs.extra_info)"
              class="q-my-xs"
            />
            <q-item-label v-else-if="obs.extra_info" caption class="text-mono">
              {{ obs.extra_info }}
            </q-item-label>
            <q-item-label caption class="text-grey-6">
              {{ obs.ip_address }} · first seen {{ formatDateTime(obs.first_seen_at) }}
            </q-item-label>
          </q-item-section>
        </q-item>
      </q-list>
    </q-card-section>

    <q-separator v-if="vulnerabilities.length > 0" />

    <q-card-section v-if="vulnerabilities.length > 0" class="q-pt-md">
      <div class="text-overline text-muted q-mb-sm">Vulnerabilities ({{ vulnerabilities.length }})</div>
      <q-list separator dense>
        <q-item v-for="vuln in sortedVulnerabilities" :key="cveKey(vuln)" class="q-py-sm">
          <q-item-section avatar>
            <q-badge :color="severityColorFor(vuln.severity)" class="severity-badge">
              {{
                vuln.cvss_score != null
                  ? `${vuln.cvss_score.toFixed(1)} · ${vuln.severity || 'n/a'}`
                  : vuln.severity || 'n/a'
              }}
            </q-badge>
          </q-item-section>
          <q-item-section>
            <q-item-label class="text-mono text-weight-medium row items-center no-wrap">
              <a
                :href="cveUrl(vuln)"
                target="_blank"
                rel="noopener noreferrer"
                style="color: inherit; text-decoration: none"
              >
                <span>{{ cveKey(vuln) }}</span>
                <q-icon name="open_in_new" size="14px" color="grey-6" class="q-ml-xs" />
              </a>
            </q-item-label>
            <q-item-label caption lines="3">
              {{ vuln.summary || vuln.description || 'No summary available.' }}
            </q-item-label>
            <q-item-label v-if="vuln.fixed_in" caption class="text-positive">
              <q-icon name="build" size="14px" class="q-mr-xs" />
              Fixed in {{ vuln.fixed_in }}
            </q-item-label>
          </q-item-section>
          <q-item-section side>
            <div class="row items-center q-gutter-xs no-wrap">
              <q-select
                :model-value="vuln.status || 'active'"
                :options="statusOptions"
                dense
                outlined
                style="min-width: 140px"
                emit-value
                map-options
                data-testid="device-detail-vuln-status-select"
                @update:model-value="(val) => onVulnStatusChange(vuln, val as string)"
              />
              <q-icon
                v-if="
                  (vuln as DeviceVulnerabilityItem)._status_changed_by &&
                  (vuln as DeviceVulnerabilityItem)._status_changed_by !== 'auto'
                "
                name="lock"
                size="16px"
                color="grey-7"
                data-testid="device-detail-vuln-locked"
              >
                <q-tooltip>Operator-locked ({{ (vuln as DeviceVulnerabilityItem)._status_changed_by }})</q-tooltip>
              </q-icon>
            </div>
          </q-item-section>
        </q-item>
      </q-list>
    </q-card-section>

    <q-separator />

    <q-card-section class="q-pt-md text-caption text-muted">
      Last scan: {{ device.last_scan_at ? formatDateTime(device.last_scan_at) : '—' }}
      <br />
      Created: {{ device.created_at ? formatDateTime(device.created_at) : '—' }}
      <br />
      Updated: {{ device.updated_at ? formatDateTime(device.updated_at) : '—' }}
    </q-card-section>
  </div>
</template>

<script setup lang="ts">
import { DOMAIN_ICONS } from '~/composables/useNavigation'
import { useQuasar } from 'quasar'
import { computed, ref, watch } from 'vue'

import OpcUaEndpointList from '~/components/scan/OpcUaEndpointList.vue'
import { useApi, type ApiError } from '~/composables/useApi'
import type {
  DeviceIdentityPatchResponse,
  DeviceItem,
  DeviceObservationsResponse,
  DeviceVulnerabilityItem,
  ServiceObservationItem,
} from '~/types/api'
import { extractEndpointsFromJsonString } from '~/utils/opcua'
import { formatDateTime } from '~/utils/format'
import { isLookupEligible } from '~/utils/device'

interface Props {
  device: DeviceItem | null
}

const emit = defineEmits<{
  (e: 'close'): void
  (e: 'scan' | 'identity-updated', device: DeviceItem): void
  (e: 'removed' | 'cve-lookup', deviceId: number): void
  (e: 'observations', observations: ServiceObservationItem[]): void
}>()

const props = defineProps<Props>()

const $q = useQuasar()
const api = useApi()
const removing = ref(false)

const observations = ref<ServiceObservationItem[]>([])
const observationsLoading = ref(false)

/**
 * Group observations into port-scan (non-opcua) and opcua buckets.
 */
const portObservations = computed<ServiceObservationItem[]>(() =>
  observations.value.filter((o) => o.protocol !== 'opcua'),
)

const opcuaObservations = computed<ServiceObservationItem[]>(() =>
  observations.value.filter((o) => o.protocol === 'opcua'),
)

/**
 * Load fresh observations whenever the displayed device changes.
 */
async function loadObservations(deviceId: number): Promise<void> {
  observationsLoading.value = true
  try {
    const res = await api.get<DeviceObservationsResponse>(`/api/v1/devices/${deviceId}/observations`)
    observations.value = res.observations ?? []
    emit('observations', observations.value)
  } catch (err) {
    const apiErr = err as ApiError
    console.error(`[DeviceDetailPanel] observations failed (${apiErr.status}):`, apiErr.message)
    observations.value = []
    emit('observations', observations.value)
  } finally {
    observationsLoading.value = false
  }
}

watch(
  () => props.device,
  (device) => {
    observations.value = []
    emit('observations', observations.value)
    if (device) {
      void loadObservations(device.id)
    }
  },
  { immediate: true },
)

/**
 * Open the run-modal pre-targeted at the currently displayed device.
 * The parent page hosts the modal and listens to this emit.
 */
function onScan(): void {
  if (props.device) emit('scan', props.device)
}

/**
 * Request a per-device CVE lookup. The parent page owns the dialog
 * and will open CveLookupDialog with this device's id.
 */
function onCveLookup(): void {
  if (props.device) emit('cve-lookup', props.device.id)
}

/**
 * Confirm-dialog + DELETE /api/v1/devices/{id} (Decision 4).
 *
 * Observations and scan history are retained server-side; only the device
 * row is removed from the inventory. On 2xx the panel emits ``removed``
 * upward so the parent page can drop the row optimistically; on any non-2xx
 * the upstream ``detail`` is surfaced as a Quasar notify and the panel
 * stays open.
 */
function onRemove(): void {
  const device = props.device
  if (!device) return
  const label = device.device_family || device.device_type || device.vendor || `Device ${device.id}`
  $q.dialog({
    title: 'Remove device',
    message: `Permanently remove ${label}? Observations and scan history will be retained but the device will no longer appear in the inventory or topology.`,
    ok: { label: 'Remove', color: 'negative', noCaps: true },
    cancel: { label: 'Cancel', flat: true, noCaps: true },
    persistent: true,
  }).onOk(() => {
    void performRemoval(device)
  })
}

/**
 * Issue the DELETE request and dispatch UX side effects. Pure function in
 * terms of UI state — the parent owns the actual store mutation.
 */
async function performRemoval(device: DeviceItem): Promise<void> {
  removing.value = true
  try {
    await api.del<unknown>(`/api/v1/devices/${device.id}`)
    $q.notify({
      type: 'positive',
      message: `Device ${device.id} removed`,
      timeout: 3000,
    })
    emit('removed', device.id)
    emit('close')
  } catch (err) {
    const apiErr = err as ApiError
    const detail = apiErr.detail && apiErr.detail.trim() !== '' ? apiErr.detail : apiErr.message
    $q.notify({
      type: 'warning',
      message: `Device removal failed (${apiErr.status}): ${detail}`,
      timeout: 5000,
    })
  } finally {
    removing.value = false
  }
}

const titleLabel = computed(() => {
  if (!props.device) return 'Device Details'
  return (
    props.device.device_family ||
    props.device.device_type ||
    props.device.hostname ||
    props.device.vendor ||
    `Device ${props.device.id}`
  )
})

/**
 * SCAN-023: the eight operator-lockable identity fields. The key MUST
 * match the `manual_identity_fields` marker names emitted by
 * otalon-scan so the per-field lock icon and the PATCH body line up.
 */
type IdentityFieldKey =
  | 'vendor'
  | 'device_family'
  | 'device_type'
  | 'article_number'
  | 'firmware_version'
  | 'product_name'
  | 'hw_version'
  | 'sw_version'

interface IdentityFieldRow {
  key: IdentityFieldKey
  label: string
  value: string | null
  testid: string
  locked: boolean
}

const MITRE_DEVICE_TYPES = [
  'Application Server',
  'Control Server',
  'Data Gateway',
  'Data Historian',
  'DCS Controller',
  'Field I/O',
  'Firewall',
  'HMI',
  'IED',
  'Jump Host',
  'PAC',
  'PLC',
  'RTU',
  'Routers',
  'Safety Controller',
  'Switch',
  'VPN Server',
  'Workstation',
  'Other',
] as const

const deviceTypeOptions = [
  { label: 'Unknown', value: null },
  ...MITRE_DEVICE_TYPES.map((value) => ({ label: value, value })),
]

/**
 * Asset identity rows rendered (and inline-editable) in the detail panel.
 * Covers the SCAN-018 SNMP-enrichment fields plus vendor / family / type
 * / article / firmware. Each row carries its `locked` flag derived from
 * the device's `manual_identity_fields` so a manually-set value shows the
 * operator "manual" marker. Per operator decision D4 these appear only
 * here, never as device-table columns.
 */
const assetFields = computed<IdentityFieldRow[]>(() => {
  const d = props.device
  if (!d) return []
  const locked = new Set<string>(d.manual_identity_fields ?? [])
  const row = (key: IdentityFieldKey, label: string): IdentityFieldRow => ({
    key,
    label,
    value: d[key],
    testid: `asset-${key.replace(/_/g, '-')}`,
    locked: locked.has(key),
  })
  return [
    row('vendor', 'Vendor'),
    row('device_family', 'Family'),
    row('device_type', 'Type'),
    row('article_number', 'Article'),
    row('product_name', 'Product Name'),
    row('firmware_version', 'Firmware'),
    row('hw_version', 'HW Version'),
    row('sw_version', 'SW Version'),
  ]
})

/**
 * Live lookup-eligibility indicator. Recomputes off `props.device`, so a
 * successful manual identity set (which mutates the device fields in
 * place) re-evaluates it immediately (SCAN-023 acceptance).
 */
const lookupEligible = computed<boolean>(() => (props.device ? isLookupEligible(props.device) : false))

/**
 * Persist an inline identity edit via `PATCH /api/v1/devices/{id}`
 * (SCAN-023). The supplied value is written AND locked against
 * scan-overwrite. On success the device's identity fields and lock set
 * are mutated in place (so the table, the per-field marker and the
 * eligibility chip all re-render) and `identity-updated` is emitted.
 */
async function onIdentitySave(key: IdentityFieldKey, rawValue: string | null): Promise<void> {
  const device = props.device
  if (!device) return
  const nextValue = key === 'device_type' ? rawValue : rawValue?.trim() || null
  try {
    const res = await api.patch<DeviceIdentityPatchResponse>(`/api/v1/devices/${device.id}`, {
      [key]: nextValue,
    })
    device.vendor = res.vendor
    device.device_family = res.device_family
    device.device_type = res.device_type
    device.article_number = res.article_number
    device.firmware_version = res.firmware_version
    device.product_name = res.product_name
    device.hw_version = res.hw_version
    device.sw_version = res.sw_version
    device.manual_identity_fields = res.manual_identity_fields
    emit('identity-updated', device)
    $q.notify({
      type: 'positive',
      message: `${key.replace(/_/g, ' ')} set (manual)`,
      timeout: 3000,
    })
  } catch (err: unknown) {
    const apiErr = err as ApiError
    const detail = apiErr.detail && apiErr.detail.trim() !== '' ? apiErr.detail : apiErr.message
    $q.notify({
      type: 'warning',
      message: `Identity update failed (${apiErr.status}): ${detail}`,
      timeout: 5000,
    })
  }
}

const typeIcon = computed(() => {
  const t = (props.device?.device_type ?? '').toLowerCase()
  if (t.includes('plc')) return 'memory'
  if (t.includes('ipc')) return 'computer'
  if (t.includes('io')) return 'settings_input_component'
  if (t.includes('switch')) return 'hub'
  return 'device_hub'
})

const SEVERITY_RANK: Record<string, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
}

const vulnerabilities = computed<DeviceVulnerabilityItem[]>(() => {
  const v = props.device?.vulnerabilities
  return Array.isArray(v) ? v : []
})

const sortedVulnerabilities = computed<DeviceVulnerabilityItem[]>(() => {
  const list = [...vulnerabilities.value]
  list.sort((a, b) => {
    const ra = SEVERITY_RANK[(a.severity || '').toLowerCase()] ?? 0
    const rb = SEVERITY_RANK[(b.severity || '').toLowerCase()] ?? 0
    return rb - ra
  })
  return list
})

const primaryMac = computed<string | null>(() => {
  return props.device?.interfaces?.[0]?.mac_address ?? null
})

function onMacTimeseries(): void {
  const mac = primaryMac.value
  if (!mac) return
  navigateTo({ path: '/mac-timeseries', query: { mac } })
}

function severityColorFor(severity: string | undefined): string {
  switch ((severity || '').toLowerCase()) {
    case 'critical':
      return 'negative'
    case 'high':
      return 'orange-9'
    case 'medium':
      return 'warning'
    case 'low':
      return 'blue-grey-6'
    default:
      return 'grey-6'
  }
}

/**
 * Return the canonical CVE identifier from a vulnerability record,
 * preferring ``cve`` over ``id`` so older legacy entries keep working.
 */
function cveKey(v: DeviceVulnerabilityItem): string {
  return String(v.vuln_id ?? v.cve ?? '?')
}

/**
 * Build the NVD detail URL for a CVE entry. Falls back to NVD search
 * when no canonical ``url`` was stored.
 */
function cveUrl(v: DeviceVulnerabilityItem): string {
  if (typeof v.url === 'string' && v.url.length > 0) return v.url
  const key = cveKey(v)
  return key !== '?' ? `https://nvd.nist.gov/vuln/detail/${key}` : 'https://nvd.nist.gov/'
}

const severityColor = computed(() => {
  const ranks = { critical: 4, high: 3, medium: 2, low: 1 }
  let best = 0
  let bestSeverity = 'low'
  for (const v of vulnerabilities.value) {
    const sev = (v.severity || '').toLowerCase()
    const rank = ranks[sev as keyof typeof ranks] ?? 0
    if (rank > best) {
      best = rank
      bestSeverity = sev
    }
  }
  return severityColorFor(bestSeverity)
})

const statusOptions = [
  { label: 'Active', value: 'active' },
  { label: 'Mitigated', value: 'mitigated' },
  { label: 'False Positive', value: 'false_positive' },
  { label: 'Resolved', value: 'resolved' },
]

async function onVulnStatusChange(vuln: DeviceVulnerabilityItem, newStatus: string): Promise<void> {
  // ``device_topology_view`` exposes the observation primary key as ``id``
  // since migration 0008; ``observation_id`` is only a legacy alias. Reading
  // the alias alone made every status change a silent no-op on current
  // payloads (audit UI-05).
  const observationId = vuln.id ?? vuln.observation_id
  if (!observationId) {
    $q.notify({
      type: 'warning',
      message: 'Status update failed: vulnerability has no observation id',
      timeout: 5000,
    })
    return
  }
  try {
    const res = await api.patch<{
      status: string
      status_changed_by: string | null
    }>(`/api/v1/vulnerabilities/${observationId}`, { status: newStatus, status_changed_by: 'operator' })
    vuln.status = res.status
    vuln._status_changed_by = res.status_changed_by
    $q.notify({
      type: 'positive',
      message: `${vuln.vuln_id ?? vuln.cve ?? '?'} set to ${res.status}`,
      timeout: 3000,
    })
  } catch (err: unknown) {
    const apiErr = err as ApiError
    $q.notify({
      type: 'warning',
      message: `Status update failed: ${apiErr.message ?? 'Unknown error'}`,
      timeout: 5000,
    })
  }
}
</script>

<style scoped lang="scss">
.device-detail-panel {
  height: 100%;
  overflow-y: auto;
}

.device-detail-actions {
  position: sticky;
  top: 0;
  z-index: 2;
  background: var(--cd-surface, #fff);
}

.text-mono {
  font-family: $font-family-mono;
  font-size: 0.85rem;
}

.asset-details-grid {
  display: grid;
  grid-template-columns: auto 1fr;
  gap: 6px 16px;
  align-items: baseline;
}

.asset-details-label {
  font-size: 0.8rem;
  color: var(--cd-muted);
}

.asset-details-value {
  word-break: break-all;
}

.identity-editable {
  display: flex;
  align-items: baseline;
  gap: 6px;
  cursor: pointer;
  border-radius: 4px;
  padding: 1px 4px;
  margin: -1px -4px;
  transition: background-color 0.15s ease;

  .identity-edit-icon {
    opacity: 0;
    color: var(--cd-muted);
    transition: opacity 0.15s ease;
  }

  &:hover {
    background-color: rgba(var(--cd-primary-rgb), 0.12);

    .identity-edit-icon {
      opacity: 1;
    }
  }
}

.identity-value-text {
  flex: 1 1 auto;
}

.identity-manual-icon {
  color: var(--cd-primary);
  margin-left: 4px;
  vertical-align: middle;
}

.identity-eligible-chip {
  background-color: rgba(var(--cd-success-rgb), 0.18);
  color: var(--cd-surface-text);
}

.identity-incomplete-chip {
  background-color: rgba(var(--cd-warning-rgb), 0.18);
  color: var(--cd-surface-text);
}

.observed-services-list {
  padding: 0 16px;
}

.observed-service-row {
  display: grid;
  grid-template-columns: 90px 1fr;
  gap: 8px 12px;
  align-items: start;
  padding: 8px 0;
}

.observed-service-row:not(:last-child) {
  border-bottom: 1px solid rgba(0, 0, 0, 0.12);
}

.observed-service-chip {
  display: flex;
  align-items: flex-start;
  justify-content: flex-start;
}

.observed-service-details {
  display: flex;
  flex-direction: column;
  gap: 2px;
}

.severity-badge {
  min-width: 105px;
  justify-content: center;
}
</style>
