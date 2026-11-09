<template>
  <q-page padding role="main">
    <SharedErrorBanner :message="store.error" @retry="reload()" @dismiss="store.error = null" />

    <q-banner class="under-construction-banner q-mb-md" rounded data-testid="vuln-under-construction">
      <template #avatar>
        <q-icon name="construction" color="warning" />
      </template>
      <div class="text-weight-medium">Under Construction</div>
      <div class="text-caption">
        This page is being redesigned (SUITE-013). For functional CVE work, use the Asset List page for now. Data shown
        here is provisional.
      </div>
    </q-banner>

    <h1 class="text-h6 q-mt-none q-mb-md">Vulnerabilities</h1>

    <div style="position: relative; min-height: 200px">
      <q-inner-loading :showing="store.isLoading && store.rows.length === 0" label="Loading vulnerabilities…" />

      <div class="row items-center q-gutter-sm q-mb-md">
        <q-badge class="kpi-badge kpi-badge--neutral" role="none">
          <q-icon name="bug_report" size="14px" color="negative" class="q-mr-xs" />
          Total CVEs: {{ store.totalCount }}
        </q-badge>
        <q-badge class="kpi-badge kpi-badge--neutral" role="none">
          <q-icon :name="DOMAIN_ICONS.assets" size="14px" color="primary" class="q-mr-xs" />
          Assets with CVEs:
          {{ store.devices.filter((d) => Array.isArray(d.vulnerabilities) && d.vulnerabilities.length > 0).length }}
        </q-badge>
        <q-space />
        <q-btn
          color="primary"
          icon="search"
          label="Lookup all"
          dense
          no-caps
          :loading="store.lookupLoading"
          :disable="true"
          data-testid="vuln-lookup-all-btn"
          @click="runLookupAll()"
        >
          <q-tooltip>CVE lookup is temporarily disabled while this page is under construction.</q-tooltip>
        </q-btn>
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
                placeholder="Search CVE, vendor, summary…"
                aria-label="Search vulnerabilities by CVE, vendor, or summary"
                debounce="200"
              >
                <template #prepend>
                  <q-icon name="search" />
                </template>
              </q-input>
            </div>
            <div class="col-md-4 col-sm-8 col-xs-12">
              <q-select
                v-model="severityFilter"
                :options="['All severities', 'critical', 'high', 'medium', 'low']"
                outlined
                dense
                label="Severity"
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
                :loading="store.isLoading"
                @click="reload()"
              />
            </div>
          </div>
        </q-card-section>
      </q-card>

      <q-table
        v-model:pagination="pagination"
        flat
        bordered
        dense
        :rows="filteredRows"
        :columns="columns"
        row-key="vulnId"
        :rows-per-page-options="[0, 10, 25, 50, 100]"
        no-data-label="No vulnerabilities found"
        no-results-label="No vulnerabilities match the current filter"
        binary-state-sort
        class="vuln-table"
      >
        <template #no-data="{ message }">
          <div class="full-width column items-center q-pa-xl text-grey">
            <q-icon name="shield" size="48px" class="q-mb-sm" />
            <div class="text-subtitle1">{{ message }}</div>
            <div class="text-caption q-mt-sm">Run a lookup to discover CVEs for eligible assets.</div>
          </div>
        </template>

        <template #body-cell-severity="slotProps">
          <q-td :props="slotProps">
            <q-badge
              :color="severityColor(slotProps.row.severity)"
              :label="slotProps.row.severity || 'n/a'"
              class="q-px-sm"
            />
          </q-td>
        </template>

        <template #body-cell-device="slotProps">
          <q-td :props="slotProps">
            <div class="text-weight-medium">{{ slotProps.row.deviceVendor || '—' }}</div>
            <div v-if="slotProps.row.deviceFamily" class="text-caption text-muted q-mt-xs">
              {{ slotProps.row.deviceFamily }}
            </div>
          </q-td>
        </template>

        <template #body-cell-summary="slotProps">
          <q-td :props="slotProps">
            <div class="ellipsis" style="max-width: 420px">{{ slotProps.row.summary || '—' }}</div>
          </q-td>
        </template>

        <template #body-cell-status="slotProps">
          <q-td :props="slotProps">
            <div class="row items-center q-gutter-xs no-wrap">
              <q-chip
                v-if="editingStatusRow !== slotProps.row.observationId"
                dense
                :color="statusChipColor(slotProps.row.status)"
                text-color="white"
                data-testid="vuln-status-chip"
              >
                {{ slotProps.row.status }}
              </q-chip>
              <q-select
                v-else
                :model-value="slotProps.row.status"
                :options="statusOptions"
                dense
                outlined
                style="min-width: 140px"
                emit-value
                map-options
                data-testid="vuln-status-select"
                @update:model-value="(val) => onStatusChange(slotProps.row, val as string)"
                @blur="editingStatusRow = null"
              />
              <q-icon
                v-if="slotProps.row.statusChangedBy && slotProps.row.statusChangedBy !== 'auto'"
                name="lock"
                size="18px"
                color="warning"
                data-testid="vuln-status-locked"
              >
                <q-tooltip>Operator-locked ({{ slotProps.row.statusChangedBy }})</q-tooltip>
              </q-icon>
            </div>
          </q-td>
        </template>

        <template #body-cell-actions="slotProps">
          <q-td :props="slotProps">
            <q-btn
              dense
              flat
              no-caps
              color="primary"
              icon="search"
              label="Lookup"
              size="sm"
              :disable="true"
              data-testid="vuln-row-lookup-btn"
              @click="runLookupForDevice(slotProps.row.deviceId)"
            >
              <q-tooltip>CVE lookup is temporarily disabled while this page is under construction.</q-tooltip>
            </q-btn>
          </q-td>
        </template>
      </q-table>
    </div>

    <CveLookupDialog
      v-model="cveDialogOpen"
      :initial-device-id="cveDialogInitialDeviceId"
      :initial-job-id="cveDialogInitialJobId"
    />
  </q-page>
</template>

<script setup lang="ts">
import { useQuasar } from 'quasar'
import { DOMAIN_ICONS } from '~/composables/useNavigation'
import type { QTableColumn } from 'quasar'

import type { ApiError } from '~/composables/useApi'
import type { VulnRow } from '~/stores/vulnerabilitiesStore'
import { severityColor } from '~/utils/severity'
import CveLookupDialog from '~/components/CveLookupDialog.vue'
import { provideChatContext, makeVisibleTable } from '~/composables/useChatContext'

definePageMeta({
  title: 'Vulnerabilities',
})

const store = useVulnerabilitiesStore()
const appStore = useAppStore()
const $q = useQuasar()

const searchTerm = ref('')
const severityFilter = ref<string>('All severities')
const editingStatusRow = ref<number | null>(null)
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

const statusOptions = [
  { label: 'Active', value: 'active' },
  { label: 'Mitigated', value: 'mitigated' },
  { label: 'False Positive', value: 'false_positive' },
  { label: 'Resolved', value: 'resolved' },
]

function severityWeight(severity: string | null): number {
  switch ((severity || '').toLowerCase()) {
    case 'critical':
      return 4
    case 'high':
      return 3
    case 'medium':
      return 2
    case 'low':
      return 1
    default:
      return 0
  }
}

const pagination = ref({
  page: 1,
  rowsPerPage: 25,
  sortBy: 'severity',
  descending: true,
})

const filteredRows = computed<VulnRow[]>(() => {
  let rows = store.rows
  const term = searchTerm.value.trim().toLowerCase()
  if (term) {
    rows = rows.filter((r) => {
      const hay = [r.vulnId, r.deviceVendor, r.deviceFamily, r.summary, r.severity]
        .filter((v): v is string => typeof v === 'string' && v.length > 0)
        .join(' ')
        .toLowerCase()
      return hay.includes(term)
    })
  }
  if (severityFilter.value && severityFilter.value !== 'All severities') {
    rows = rows.filter((r) => (r.severity ?? '').toLowerCase() === severityFilter.value.toLowerCase())
  }
  return rows
})

function statusChipColor(status: string | null): string {
  switch ((status || '').toLowerCase()) {
    case 'mitigated':
      return 'positive'
    case 'false_positive':
      return 'grey-7'
    case 'resolved':
      return 'blue-7'
    default:
      return 'negative'
  }
}

async function reload(): Promise<void> {
  await store.fetchDevices()
}

async function runLookupAll(): Promise<void> {
  cveDialogInitialDeviceId.value = undefined
  cveDialogOpen.value = true
}

async function runLookupForDevice(deviceId: number): Promise<void> {
  cveDialogInitialDeviceId.value = deviceId
  cveDialogOpen.value = true
}

async function onStatusChange(row: VulnRow, newStatus: string): Promise<void> {
  try {
    await store.patchVulnerability(row.observationId, { status: newStatus })
    editingStatusRow.value = null
    $q.notify({
      type: 'positive',
      message: `${row.vulnId} set to ${newStatus}`,
      timeout: 3000,
    })
  } catch (err: unknown) {
    const e = err as ApiError
    $q.notify({
      type: 'warning',
      message: `Status update failed: ${e.message ?? 'Unknown error'}`,
      timeout: 5000,
    })
  }
}

onMounted(async () => {
  await reload()
})

provideChatContext(() => {
  const rows = filteredRows.value.map((r) => ({
    vuln_id: r.vulnId,
    severity: r.severity ?? null,
    device_vendor: r.deviceVendor ?? null,
    device_family: r.deviceFamily ?? null,
    status: r.status,
  }))

  return {
    filters: {
      search_term: searchTerm.value || null,
      severity: severityFilter.value === 'All severities' ? null : severityFilter.value,
    },
    summary: {
      total_vulns: store.totalCount,
      filtered_count: filteredRows.value.length,
    },
    visible_data: [
      makeVisibleTable(
        'vulnerabilities_list',
        ['vuln_id', 'severity', 'device_vendor', 'device_family', 'status'],
        rows,
      ),
    ],
  }
})

const columns: QTableColumn<VulnRow>[] = [
  {
    name: 'vulnId',
    label: 'CVE',
    field: 'vulnId',
    align: 'left',
    sortable: true,
  },
  {
    name: 'severity',
    label: 'Severity',
    field: 'severity',
    align: 'left',
    sortable: true,
    sort: (a: string, b: string) => severityWeight(a) - severityWeight(b),
  },
  {
    name: 'device',
    label: 'Asset',
    field: (r) => r.deviceVendor || '',
    align: 'left',
    sortable: true,
  },
  {
    name: 'summary',
    label: 'Summary',
    field: 'summary',
    align: 'left',
    sortable: false,
  },
  {
    name: 'status',
    label: 'Status',
    field: 'status',
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
</script>

<style scoped lang="scss">
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

.filter-card {
  background-color: var(--cd-surface);
  border-color: var(--cd-border);
}

.vuln-table :deep(thead th) {
  font-weight: 700;
  font-size: 12px;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

.under-construction-banner {
  background-color: rgba(255, 193, 7, 0.12);
  border: 1px solid rgba(255, 193, 7, 0.4);
}
</style>
