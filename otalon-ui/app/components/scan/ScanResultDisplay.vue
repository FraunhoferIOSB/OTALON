<template>
  <div class="scan-result-display">
    <div class="row items-center q-mb-sm">
      <q-badge color="primary" class="q-mr-sm">
        {{ moduleLabel }}
      </q-badge>
      <span class="text-caption text-muted"> {{ findingsCount }} finding{{ findingsCount === 1 ? '' : 's' }} </span>
      <q-space />
      <q-btn
        v-if="findings.length > 0"
        flat
        dense
        size="sm"
        :icon="resultsExpanded ? 'expand_less' : 'expand_more'"
        :label="resultsExpanded ? 'Collapse' : 'Expand'"
        data-testid="scan-result-toggle"
        @click="resultsExpanded = !resultsExpanded"
      />
      <span v-if="abortReason" class="text-caption text-negative q-ml-sm"> Aborted: {{ abortReason }} </span>
    </div>

    <div v-if="moduleSlug === 'port' && props.overrides?.port_range" class="row items-center q-mb-sm">
      <q-chip dense size="sm" color="grey-7" text-color="white" class="scan-result-display__chip">
        {{ props.overrides.port_range }}
      </q-chip>
      <span class="text-caption text-grey-6 q-ml-xs">Scanned range</span>
    </div>

    <div v-show="resultsExpanded" class="scan-result-display__scroll">
      <q-list v-if="findings.length > 0" bordered class="scan-result-display__list">
        <q-expansion-item
          v-for="(finding, idx) in findings"
          :key="idx"
          dense
          expand-icon="expand_more"
          expanded-icon="expand_less"
          class="scan-result-display__item"
        >
          <template #header>
            <q-item-section>
              <div class="row items-center full-width no-wrap">
                <span class="scan-result-display__ip text-mono">
                  {{ finding.ipv4 || finding.ipv6 || '—' }}
                </span>
                <div class="scan-result-display__fields row items-center q-gutter-x-sm">
                  <q-chip
                    v-for="(chip, cidx) in leadChips(finding)"
                    :key="cidx"
                    dense
                    :color="chip.color"
                    text-color="white"
                    class="scan-result-display__chip"
                  >
                    {{ chip.label }}
                  </q-chip>
                  <span v-if="leadMeta(finding)" class="text-caption text-grey-6 ellipsis">
                    {{ leadMeta(finding) }}
                  </span>
                </div>
              </div>
            </q-item-section>
          </template>

          <div class="scan-result-display__detail q-pa-sm">
            <div class="scan-result-display__kv">
              <template v-for="(kv, kidx) in detailKvs(finding)" :key="kidx">
                <span class="scan-result-display__k text-caption text-grey-6">{{ kv.key }}</span>
                <span class="scan-result-display__v text-mono text-caption">{{ kv.value }}</span>
              </template>
            </div>

            <!-- OPC-UA structured endpoints -->
            <div v-if="moduleSlug === 'opcua_discover' && opcuaEndpoints(finding).length > 0" class="q-mt-md">
              <div class="text-caption text-grey-6 q-mb-xs">Endpoints</div>
              <OpcUaEndpointList :endpoints="opcuaEndpoints(finding)" />
            </div>

            <!-- Port scan: detailed ports table -->
            <div v-if="moduleSlug === 'port' && detailedPorts(finding).length > 0" class="q-mt-md">
              <div class="text-caption text-grey-6 q-mb-xs">Port details</div>
              <table class="scan-result-display__port-table">
                <caption class="sr-only">
                  Port scan details
                </caption>
                <thead>
                  <tr>
                    <th class="text-left" scope="col">Port</th>
                    <th class="text-left" scope="col">Proto</th>
                    <th class="text-left" scope="col">State</th>
                    <th class="text-left" scope="col">Service</th>
                    <th class="text-left" scope="col">Product</th>
                  </tr>
                </thead>
                <tbody>
                  <tr v-for="(p, pidx) in detailedPorts(finding)" :key="pidx">
                    <td class="text-mono">{{ p.port }}</td>
                    <td>{{ p.proto }}</td>
                    <td>{{ p.state }}</td>
                    <td>{{ p.service }}</td>
                    <td>{{ p.product }}</td>
                  </tr>
                </tbody>
              </table>
            </div>

            <!-- Notes -->
            <div v-if="finding.notes" class="q-mt-md text-caption text-grey-6">
              {{ finding.notes }}
            </div>
          </div>
        </q-expansion-item>
      </q-list>

      <q-banner
        v-else
        rounded
        class="q-pa-sm"
        style="background: var(--cd-surface); border: 1px solid var(--cd-border); color: var(--cd-muted)"
      >
        No findings reported.
      </q-banner>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, ref } from 'vue'

import OpcUaEndpointList from '~/components/scan/OpcUaEndpointList.vue'
import { extractEndpointsFromExtra, type OpcUaEndpoint } from '~/utils/opcua'

interface PortItem {
  port: number
  proto: string
}

interface LeadChip {
  label: string
  color: string
}

interface FindingShape {
  ipv4?: string | null
  ipv6?: string | null
  mac?: string | null
  subnet?: string | null
  vendor?: string | null
  hostname?: string | null
  product_name?: string | null
  device_family?: string | null
  device_type?: string | null
  description?: string | null
  article_number?: string | null
  device_role?: string | null
  firmware_version?: string | null
  hw_version?: string | null
  sw_version?: string | null
  open_ports_summary?: Record<string, unknown> | null
  notes?: string | null
  extra?: Record<string, unknown> | null
}

interface ResultShape {
  module_name?: string | null
  findings?: FindingShape[] | null
  status?: string | null
  abort_reason?: string | null
}

const props = defineProps<{
  result: unknown
  overrides?: Record<string, unknown>
}>()

const resultsExpanded = ref(true)

const parsed = computed<ResultShape>(() => {
  if (!props.result || typeof props.result !== 'object') return {}
  return props.result as ResultShape
})

const moduleSlug = computed<string>(() => {
  const name = parsed.value.module_name ?? ''
  const leaf = String(name).split('/').pop() ?? String(name)
  return leaf.replace(/_scan$/, '')
})

const moduleLabel = computed<string>(() => {
  const slug = moduleSlug.value
  if (!slug) return 'Scan result'
  return slug.replace(/_/g, ' ')
})

const findings = computed<FindingShape[]>(() => {
  const list = parsed.value.findings
  return Array.isArray(list) ? list : []
})

const findingsCount = computed<number>(() => findings.value.length)

const abortReason = computed<string | null>(() => parsed.value.abort_reason ?? null)

function opcuaEndpoints(finding: FindingShape): OpcUaEndpoint[] {
  return extractEndpointsFromExtra(finding.extra)
}

function openPorts(finding: FindingShape): PortItem[] {
  const summary = finding.open_ports_summary
  if (!summary || typeof summary !== 'object') return []
  const open = (summary as Record<string, unknown>).open
  if (!Array.isArray(open)) return []
  return open
    .filter((p): p is Record<string, unknown> => p && typeof p === 'object')
    .map((p) => ({
      port: Number(p.port) || 0,
      proto: String(p.proto || 'tcp'),
    }))
    .filter((p) => p.port > 0)
}

function detailedPorts(finding: FindingShape): Array<{
  port: number
  proto: string
  state: string
  service: string
  product: string
}> {
  const extra = finding.extra
  if (!extra || typeof extra !== 'object') return []
  const raw = (extra as Record<string, unknown>).open_ports
  if (!Array.isArray(raw)) return []
  return raw
    .filter((p): p is Record<string, unknown> => p && typeof p === 'object')
    .map((p) => ({
      port: Number(p.port) || 0,
      proto: String(p.protocol || p.proto || 'tcp'),
      state: String(p.state || 'open'),
      service: String(p.service_name || p.service || ''),
      product: String(p.product || ''),
    }))
    .filter((p) => p.port > 0)
}

function leadChips(finding: FindingShape): LeadChip[] {
  const chips: LeadChip[] = []
  const slug = moduleSlug.value
  switch (slug) {
    case 'pn_discovery':
      if (finding.mac) chips.push({ label: finding.mac, color: 'grey-7' })
      if (finding.vendor) chips.push({ label: finding.vendor, color: 'cyan-8' })
      if (finding.hostname) chips.push({ label: finding.hostname, color: 'purple-8' })
      break
    case 'opcua_discover': {
      const eps = opcuaEndpoints(finding)
      for (const ep of eps) {
        if (ep.url) chips.push({ label: ep.url, color: 'cyan-8' })
        if (ep.securityMode) chips.push({ label: ep.securityMode, color: 'positive' })
        if (ep.securityLevel != null) chips.push({ label: `L${ep.securityLevel}`, color: 'purple-8' })
      }
      break
    }
    case 'snmp':
      if (finding.hostname) chips.push({ label: finding.hostname, color: 'cyan-8' })
      if (finding.vendor) chips.push({ label: finding.vendor, color: 'grey-7' })
      if (finding.product_name) chips.push({ label: finding.product_name, color: 'purple-8' })
      break
    case 'port':
      for (const p of openPorts(finding)) {
        chips.push({ label: `${p.port}/${p.proto}`, color: 'positive' })
      }
      if (finding.hostname) chips.push({ label: finding.hostname, color: 'cyan-8' })
      break
    case 'arp':
      if (finding.mac) chips.push({ label: finding.mac, color: 'grey-7' })
      if (finding.vendor) chips.push({ label: finding.vendor, color: 'cyan-8' })
      if (finding.hostname) chips.push({ label: finding.hostname, color: 'purple-8' })
      break
  }
  return chips
}

function leadMeta(finding: FindingShape): string {
  const slug = moduleSlug.value
  switch (slug) {
    case 'pn_discovery':
      return finding.product_name || finding.device_family || ''
    case 'opcua_discover': {
      const eps = opcuaEndpoints(finding)
      const ep = eps[0]
      return ep?.securityPolicy || ''
    }
    case 'snmp':
      return finding.sw_version || finding.hw_version || finding.firmware_version || ''
    case 'port':
      return finding.product_name || finding.device_family || ''
    case 'arp':
      return finding.product_name || ''
  }
  return ''
}

function detailKvs(finding: FindingShape): Array<{ key: string; value: string }> {
  const kvs: Array<{ key: string; value: string }> = []
  const add = (label: string, value: string | null | undefined) => {
    if (value) kvs.push({ key: label, value })
  }
  add('IPv4', finding.ipv4)
  add('IPv6', finding.ipv6)
  add('MAC', finding.mac)
  add('Subnet', finding.subnet)
  add('Vendor', finding.vendor)
  add('Hostname', finding.hostname)
  add('Product', finding.product_name)
  add('Device Family', finding.device_family)
  add('Device Type', finding.device_type)
  add('Description', finding.description)
  add('Article', finding.article_number)
  add('Device Role', finding.device_role)
  add('Firmware', finding.firmware_version)
  add('HW Version', finding.hw_version)
  add('SW Version', finding.sw_version)
  add('Notes', finding.notes)

  const eps = opcuaEndpoints(finding)
  for (const ep of eps) {
    add('Endpoint URL', ep.url)
    add('Application URI', ep.applicationUri)
    add('Application Name', ep.applicationName)
    add('Security Mode', ep.securityMode)
    add('Security Policy', ep.securityPolicy)
    add('Security Level', String(ep.securityLevel))
  }

  return kvs
}
</script>

<style scoped lang="scss">
.scan-result-display {
  scrollbar-width: thin;
}

.scan-result-display__scroll {
  max-height: 420px;
  overflow-y: auto;
  scrollbar-width: thin;
}

.scan-result-display__list {
  border-radius: 6px;
  overflow: hidden;
}

.scan-result-display__item {
  border-bottom: 1px solid var(--cd-border, rgba(0, 0, 0, 0.08));
}

.scan-result-display__item:last-child {
  border-bottom: none;
}

.scan-result-display__ip {
  font-size: 13.5px;
  font-weight: 600;
  min-width: 108px;
  flex-shrink: 0;
}

.scan-result-display__fields {
  flex: 1;
  flex-wrap: wrap;
  min-width: 0;
}

.scan-result-display__detail {
  border-top: 1px solid var(--cd-border, rgba(0, 0, 0, 0.08));
}

.scan-result-display__kv {
  display: grid;
  grid-template-columns: 140px 1fr;
  gap: 3px 14px;
  align-items: baseline;
}

.scan-result-display__k {
  font-size: 12px;
}

.scan-result-display__v {
  font-size: 12px;
  word-break: break-all;
}

.text-mono {
  font-family: $font-family-mono;
}

.sr-only {
  position: absolute;
  width: 1px;
  height: 1px;
  padding: 0;
  margin: -1px;
  overflow: hidden;
  clip: rect(0, 0, 0, 0);
  white-space: nowrap;
  border: 0;
}

.scan-result-display__port-table {
  font-size: 11px;

  th,
  td {
    padding: 3px 10px;
  }
}

.scan-result-display__chip {
  font-size: 0.875rem;
  line-height: 1.4;
  height: 26px;
  padding: 0 8px;
}
</style>
