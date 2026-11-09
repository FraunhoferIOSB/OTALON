<template>
  <div class="cve-result-display">
    <div class="row items-center q-mb-sm">
      <q-badge color="primary" class="q-mr-sm">CVE lookup</q-badge>
      <span class="text-caption text-muted">{{ cveCount }} CVE{{ cveCount === 1 ? '' : 's' }}</span>
      <q-space />
      <q-btn
        v-if="cveCards.length > 0"
        flat
        dense
        size="sm"
        :icon="expanded ? 'expand_less' : 'expand_more'"
        :label="expanded ? 'Collapse' : 'Expand'"
        data-testid="cve-result-toggle"
        @click="expanded = !expanded"
      />
      <span v-if="lookupError" class="text-caption text-negative q-ml-sm">Aborted: {{ lookupError }}</span>
    </div>

    <div v-show="expanded" class="cve-result-display__scroll">
      <q-list v-if="cveCards.length > 0" bordered class="cve-result-display__list">
        <q-expansion-item
          v-for="(card, idx) in cveCards"
          :key="`${card.deviceId}-${cveKey(card.cve)}-${idx}`"
          dense
          expand-icon="expand_more"
          expanded-icon="expand_less"
          class="cve-result-display__item"
        >
          <template #header>
            <q-item-section>
              <div class="row items-center full-width no-wrap">
                <span class="cve-result-display__cve-id text-mono">
                  {{ cveKey(card.cve) }}
                </span>
                <div class="cve-result-display__fields row items-center q-gutter-x-sm">
                  <q-chip
                    dense
                    :color="severityColor(card.cve.severity ?? null)"
                    text-color="white"
                    class="cve-result-display__chip"
                  >
                    {{ cvssLabel(card.cve) }}
                  </q-chip>
                  <span v-if="card.deviceProduct" class="text-caption text-grey-6 ellipsis">
                    {{ card.deviceProduct }}
                  </span>
                </div>
              </div>
            </q-item-section>
          </template>

          <div class="cve-result-display__detail q-pa-sm">
            <div class="cve-result-display__kv">
              <template v-for="(kv, kidx) in detailKvs(card.cve)" :key="kidx">
                <span class="cve-result-display__k text-caption text-grey-6">{{ kv.key }}</span>
                <span class="cve-result-display__v text-mono text-caption">{{ kv.value }}</span>
              </template>
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
        No CVEs found.
      </q-banner>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, ref } from 'vue'

import { severityColor } from '~/utils/severity'
import type { CveLookupItem, DeviceItem, DeviceVulnerabilityItem } from '~/types/api'

interface CveCard {
  deviceId: number
  deviceName: string
  deviceProduct: string
  cve: DeviceVulnerabilityItem
}

const props = defineProps<{
  lookup: CveLookupItem | null
  devices: DeviceItem[]
}>()

const expanded = ref(true)

const cveCount = computed<number>(() => cveCards.value.length)

const lookupError = computed<string | null>(() => props.lookup?.error ?? null)

const perAsset = computed<Array<{ device_id: number; cve_count?: number }>>(() => {
  const s = props.lookup?.summary
  if (!s || typeof s !== 'object') return []
  const list = (s as Record<string, unknown>).per_asset
  return Array.isArray(list) ? (list as Array<{ device_id: number; cve_count?: number }>) : []
})

const cveCards = computed<CveCard[]>(() => {
  const cards: CveCard[] = []
  const assets = perAsset.value

  if (assets.length === 0 && props.lookup?.device_id != null) {
    const dev = props.devices.find((d) => d.id === props.lookup?.device_id)
    if (dev) {
      for (const v of dev.vulnerabilities ?? []) {
        cards.push({
          deviceId: dev.id,
          deviceName: `${dev.vendor ?? ''} ${dev.device_family ?? ''}`.trim() || `Device ${dev.id}`,
          deviceProduct: dev.product_name ?? dev.device_family ?? dev.vendor ?? '',
          cve: v,
        })
      }
    }
    return cards
  }

  for (const a of assets) {
    const dev = props.devices.find((d) => d.id === a.device_id)
    if (!dev) continue
    for (const v of dev.vulnerabilities ?? []) {
      cards.push({
        deviceId: dev.id,
        deviceName: `${dev.vendor ?? ''} ${dev.device_family ?? ''}`.trim() || `Device ${dev.id}`,
        deviceProduct: dev.product_name ?? dev.device_family ?? dev.vendor ?? '',
        cve: v,
      })
    }
  }
  return cards
})

function cveKey(v: DeviceVulnerabilityItem): string {
  return String(v.vuln_id ?? v.cve ?? '?')
}

function cvssLabel(v: DeviceVulnerabilityItem): string {
  const score = v.cvss_score != null ? v.cvss_score.toFixed(1) : 'n/a'
  const sev = v.severity || 'n/a'
  return `${score} \u00b7 ${sev}`
}

function detailKvs(v: DeviceVulnerabilityItem): Array<{ key: string; value: string }> {
  const kvs: Array<{ key: string; value: string }> = []
  const add = (label: string, value: string | null | undefined) => {
    if (value) kvs.push({ key: label, value })
  }
  add('Summary', v.summary)
  add('Description', v.description)
  add('CVSS Score', v.cvss_score != null ? String(v.cvss_score) : null)
  add('Vector', v.vector)
  add('Published', v.published)
  add('Fixed in', v.fixed_in)
  if (v.references && v.references.length > 0) {
    add('References', v.references.join(', '))
  }
  return kvs
}
</script>

<style scoped lang="scss">
.cve-result-display {
  scrollbar-width: thin;
}

.cve-result-display__scroll {
  max-height: 420px;
  overflow-y: auto;
  scrollbar-width: thin;
}

.cve-result-display__list {
  border-radius: 6px;
  overflow: hidden;
}

.cve-result-display__item {
  border-bottom: 1px solid var(--cd-border, rgba(0, 0, 0, 0.08));
}

.cve-result-display__item:last-child {
  border-bottom: none;
}

.cve-result-display__cve-id {
  font-size: 13.5px;
  font-weight: 600;
  min-width: 140px;
  flex-shrink: 0;
}

.cve-result-display__fields {
  flex: 1;
  flex-wrap: wrap;
  min-width: 0;
}

.cve-result-display__detail {
  border-top: 1px solid var(--cd-border, rgba(0, 0, 0, 0.08));
}

.cve-result-display__kv {
  display: grid;
  grid-template-columns: 140px 1fr;
  gap: 3px 14px;
  align-items: baseline;
}

.cve-result-display__k {
  font-size: 12px;
}

.cve-result-display__v {
  font-size: 12px;
  word-break: break-all;
}

.text-mono {
  font-family: $font-family-mono;
}

.cve-result-display__chip {
  font-size: 0.875rem;
  line-height: 1.4;
  height: 26px;
  padding: 0 8px;
}
</style>
