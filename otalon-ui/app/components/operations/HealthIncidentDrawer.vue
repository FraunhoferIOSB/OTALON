<template>
  <q-dialog v-model="open" position="right">
    <q-card class="incident-drawer">
      <q-card-section class="row items-start no-wrap q-pb-sm">
        <div>
          <div class="text-overline">Operational health evidence</div>
          <div class="text-h6">{{ incident?.service ?? 'Health incident' }}</div>
          <div v-if="incident" class="text-caption incident-id">Incident {{ incident.id }}</div>
        </div>
        <q-space />
        <q-btn flat round dense icon="close" aria-label="Close incident preview" @click="open = false" />
      </q-card-section>
      <q-separator />
      <q-card-section v-if="incident" class="incident-body">
        <q-banner dense rounded :class="incident.status === 'active' ? 'incident-active' : 'incident-recovered'">
          <strong>{{ incident.status === 'active' ? 'Active' : 'Recovered recently' }}</strong>
          <div>{{ incident.cause }}</div>
        </q-banner>
        <div class="incident-facts q-mt-md">
          <div><span>Category</span><strong>{{ incident.category }}</strong></div>
          <div><span>Owning service</span><strong>{{ incident.owning_service || '—' }}</strong></div>
          <div><span>Probe target</span><strong>{{ incident.probe_target || incident.service }}</strong></div>
          <div><span>First seen</span><strong>{{ formatDate(incident.first_seen) }}</strong></div>
          <div><span>Last seen</span><strong>{{ formatDate(incident.last_seen) }}</strong></div>
          <div v-if="incident.recovered_at"><span>Recovered</span><strong>{{ formatDate(incident.recovered_at) }}</strong></div>
          <div><span>Probe evidence</span><strong>{{ incident.failure_count }} failures / {{ incident.sample_count }} samples</strong></div>
          <div><span>Worst latency</span><strong>{{ incident.worst_latency_ms }} ms / {{ incident.latency_budget_ms }} ms budget</strong></div>
        </div>
         <div class="text-subtitle2 q-mt-lg">Probe timeline <span class="text-caption text-muted">latest {{ incident.samples?.length ?? 0 }} of {{ incident.sample_count }} samples</span></div>
        <q-list dense separator class="q-mt-sm">
          <q-item v-for="sample in incident.samples ?? []" :key="`${sample.timestamp}-${sample.detail}`">
            <q-item-section>
              <q-item-label>{{ sample.running ? 'In budget' : 'Failed' }} · {{ sample.latency_ms }} ms</q-item-label>
              <q-item-label caption>{{ formatDate(sample.timestamp) }} · {{ sample.detail }}</q-item-label>
            </q-item-section>
          </q-item>
        </q-list>
      </q-card-section>
      <q-card-section v-else class="text-muted incident-body">No incident selected.</q-card-section>
      <q-separator />
      <q-card-actions align="right" class="incident-footer">
        <q-btn flat no-caps label="Close" @click="open = false" />
        <q-btn
          flat
          no-caps
          size="sm"
          color="grey-7"
          class="incident-secondary"
          label="Services & Logs"
          :disable="!incident"
          data-test="incident-services-logs"
          @click="openServices"
        >
          <q-tooltip>Secondary: process output is not probe history.</q-tooltip>
        </q-btn>
        <q-btn
          color="primary"
          no-caps
          label="Health evidence"
          :disable="!incident"
          data-test="incident-health-evidence"
          @click="openEvidence"
        />
      </q-card-actions>
    </q-card>
  </q-dialog>
</template>

<script setup lang="ts">
import type { HealthIncidentSummary } from '~/types/api'

const props = defineProps<{ modelValue: boolean; incident: HealthIncidentSummary | null }>()
const emit = defineEmits<{ 'update:modelValue': [value: boolean] }>()
const open = computed({ get: () => props.modelValue, set: (value) => emit('update:modelValue', value) })

function formatDate(value: string | number | null): string {
  if (value === null) return '—'
  const date = new Date(typeof value === 'number' ? value * 1000 : value)
  return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString()
}

function openEvidence(): void {
  if (!props.incident) return
  open.value = false
  void navigateTo(`/operations/system?tab=health&incident=${encodeURIComponent(props.incident.id)}`)
}

// Secondary destination: deep-link the System / Services tab to the owning
// service so the operator can inspect process output, while Health evidence
// remains the primary destination for probe history.
function openServices(): void {
  if (!props.incident) return
  open.value = false
  const query = new URLSearchParams({ tab: 'services' })
  if (props.incident.system_service_id) query.set('service', props.incident.system_service_id)
  void navigateTo(`/operations/system?${query.toString()}`)
}
</script>

<style scoped lang="scss">
.incident-drawer { width: min(520px, 100vw); max-width: 100vw; height: 100vh; display: flex; flex-direction: column; }
.incident-body { overflow-y: auto; flex: 1 1 auto; padding-bottom: 32px; }
.incident-footer { flex: 0 0 auto; }
.incident-secondary { font-weight: 400; opacity: 0.85; }
.incident-active { border: 1px solid rgba(var(--cd-danger-rgb), .45); background: rgba(var(--cd-danger-rgb), .1); }
.incident-recovered { border: 1px solid rgba(var(--cd-success-rgb), .45); background: rgba(var(--cd-success-rgb), .1); }
.incident-facts { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
.incident-facts div { display: flex; flex-direction: column; gap: 2px; }
.incident-facts span { color: var(--cd-muted); font-size: 12px; }
.incident-facts strong { font-size: 13px; font-weight: 500; }
.incident-id { overflow-wrap: anywhere; color: var(--cd-muted); }
</style>
