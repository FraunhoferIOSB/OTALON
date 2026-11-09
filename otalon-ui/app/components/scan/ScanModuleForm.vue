<template>
  <div class="scan-module-form">
    <template v-if="moduleName === 'arp_scan'">
      <q-input
        :model-value="(values.target_subnet as string | undefined) ?? ''"
        label="Target subnet (CIDR)"
        dense
        outlined
        :disable="disable"
        :rules="[ruleRequired, ruleCidr]"
        hint="IPv4 or IPv6 CIDR, e.g. 192.168.0.0/24"
        class="q-mb-md"
        data-testid="scan-modal-field-target_subnet"
        @update:model-value="(v) => setField('target_subnet', v)"
      />
      <q-select
        :model-value="(values.network_interface as string | undefined) ?? null"
        :options="interfaceOptions"
        label="Network interface"
        dense
        outlined
        emit-value
        map-options
        clearable
        :disable="disable"
        class="q-mb-md"
        data-testid="scan-modal-field-network_interface"
        @update:model-value="(v) => setField('network_interface', v)"
      />
    </template>

    <template v-else-if="moduleName === 'pn_discovery'">
      <q-input
        :model-value="(values.target_mac as string | undefined) ?? ''"
        label="Target station MAC (optional)"
        dense
        outlined
        clearable
        :disable="disable"
        :rules="[ruleMac]"
        hint="Single PROFINET station MAC — filters the multicast DCP results to this device. Leave blank to discover all stations."
        class="q-mb-md"
        data-testid="scan-modal-field-target_mac"
        @update:model-value="(v) => setField('target_mac', v)"
      />
      <q-select
        :model-value="(values.network_interface as string | undefined) ?? null"
        :options="interfaceOptions"
        label="Network interface"
        dense
        outlined
        emit-value
        map-options
        clearable
        :disable="disable"
        class="q-mb-md"
        data-testid="scan-modal-field-network_interface"
        @update:model-value="(v) => setField('network_interface', v)"
      />
    </template>

    <template v-else-if="moduleName === 'snmp_scan'">
      <q-input
        :model-value="(values.target_ip as string | undefined) ?? ''"
        label="Target IP"
        dense
        outlined
        :disable="disable"
        :rules="[ruleRequired, ruleIp]"
        hint="Single IPv4 or IPv6 address"
        class="q-mb-md"
        data-testid="scan-modal-field-target_ip"
        @update:model-value="(v) => setField('target_ip', v)"
      />
      <q-select
        :model-value="(values.network_interface as string | undefined) ?? null"
        :options="interfaceOptions"
        label="Network interface"
        dense
        outlined
        emit-value
        map-options
        clearable
        :disable="disable"
        class="q-mb-md"
        data-testid="scan-modal-field-network_interface"
        @update:model-value="(v) => setField('network_interface', v)"
      />
    </template>

    <template v-else-if="moduleName === 'opcua_discover'">
      <q-input
        :model-value="(values.target_ip as string | undefined) ?? ''"
        label="Target IP"
        dense
        outlined
        :disable="disable"
        :rules="[ruleRequired, ruleIp]"
        hint="Single IPv4 or IPv6 address"
        class="q-mb-md"
        data-testid="scan-modal-field-target_ip"
        @update:model-value="(v) => setField('target_ip', v)"
      />
      <q-input
        :model-value="targetPortText"
        label="Target port"
        dense
        outlined
        type="number"
        :disable="disable"
        :rules="[rulePortOptional]"
        hint="TCP port 1–65535 (optional; module default applies when blank)"
        class="q-mb-md"
        data-testid="scan-modal-field-target_port"
        @update:model-value="(v) => setPortField('target_port', v)"
      />
      <q-select
        :model-value="(values.network_interface as string | undefined) ?? null"
        :options="interfaceOptions"
        label="Network interface"
        dense
        outlined
        emit-value
        map-options
        clearable
        :disable="disable"
        class="q-mb-md"
        data-testid="scan-modal-field-network_interface"
        @update:model-value="(v) => setField('network_interface', v)"
      />
    </template>

    <template v-else-if="moduleName === 'port_scan'">
      <q-input
        :model-value="(values.target_ip as string | undefined) ?? ''"
        label="Target IP"
        dense
        outlined
        :disable="disable"
        :rules="[ruleRequired, ruleIp]"
        hint="Single IPv4 or IPv6 address"
        class="q-mb-md"
        data-testid="scan-modal-field-target_ip"
        @update:model-value="(v) => setField('target_ip', v)"
      />
      <q-input
        :model-value="(values.port_range as string | undefined) ?? ''"
        :label="portRangeLabel"
        dense
        outlined
        :disable="disable"
        :rules="[ruleRequired, rulePortRange]"
        :hint="portRangeHint"
        class="q-mb-md"
        data-testid="scan-modal-field-port_range"
        @update:model-value="(v) => setField('port_range', v)"
      />
      <q-select
        :model-value="(values.timing_template as string | undefined) ?? null"
        :options="timingTemplateOptions"
        label="Timing template"
        dense
        outlined
        emit-value
        map-options
        clearable
        :disable="disable"
        class="q-mb-md"
        data-testid="scan-modal-field-timing_template"
        @update:model-value="(v) => setField('timing_template', v)"
      />
      <q-select
        :model-value="(values.network_interface as string | undefined) ?? null"
        :options="interfaceOptions"
        label="Network interface"
        dense
        outlined
        emit-value
        map-options
        clearable
        :disable="disable"
        class="q-mb-md"
        data-testid="scan-modal-field-network_interface"
        @update:model-value="(v) => setField('network_interface', v)"
      />
    </template>

    <template v-else>
      <q-banner
        rounded
        class="q-mb-md"
        style="background: var(--cd-surface); border: 1px solid var(--cd-border); color: var(--cd-surface-text)"
      >
        No structured form is available for module
        <code>{{ moduleName }}</code
        >. Switch to <strong>Advanced (JSON)</strong> mode to provide a config.
      </q-banner>
    </template>
  </div>
</template>

<script setup lang="ts">
import { computed, watch } from 'vue'

import { PORT_SCAN_OT_PRESET_RANGE } from '~/utils/scanDefaults'

/**
 * On fetch failure the caller supplies an empty list so the operator must
 * enter the interface manually instead of picking from plausible-but-fake
 * defaults.
 */

/**
 * nmap timing-template selectors (T0…T5) as accepted by the backend
 * ``port_scan`` override schema. The dropdown value is the bare digit so
 * the JSON payload matches the Pydantic validator exactly.
 */
const TIMING_TEMPLATES: { label: string; value: string }[] = [
  { label: 'T0 — paranoid', value: '0' },
  { label: 'T1 — sneaky', value: '1' },
  { label: 'T2 — polite', value: '2' },
  { label: 'T3 — normal', value: '3' },
  { label: 'T4 — aggressive', value: '4' },
  { label: 'T5 — insane', value: '5' },
]

/** IPv4 dotted-quad regex used for inline form validation. */
const IPV4_RE =
  /^(25[0-5]|2[0-4]\d|[01]?\d?\d)\.(25[0-5]|2[0-4]\d|[01]?\d?\d)\.(25[0-5]|2[0-4]\d|[01]?\d?\d)\.(25[0-5]|2[0-4]\d|[01]?\d?\d)$/

/** Permissive IPv6 regex — accepts ``::`` shortened forms. */
const IPV6_RE =
  /^(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|::1|::)$/

/** IPv4 CIDR regex (mask 0–32). */
const IPV4_CIDR_RE =
  /^(25[0-5]|2[0-4]\d|[01]?\d?\d)\.(25[0-5]|2[0-4]\d|[01]?\d?\d)\.(25[0-5]|2[0-4]\d|[01]?\d?\d)\.(25[0-5]|2[0-4]\d|[01]?\d?\d)\/(3[0-2]|[12]?\d)$/

/** IPv6 CIDR regex (mask 0–128) — pairs with the permissive v6 regex. */
const IPV6_CIDR_RE = /^(([0-9a-fA-F]{1,4}:){0,7}[0-9a-fA-F:]+)\/(1[01]\d|12[0-8]|\d?\d)$/

/** nmap-style port-range grammar, mirroring the backend validator. */
const PORT_RANGE_RE = /^\d+(-\d+)?(,\d+(-\d+)?)*$/

/**
 * MAC-address grammar mirroring the backend ``canonicalise`` input forms:
 * colon / dash / dot separated, or bare 12-hex. Case-insensitive.
 */
const MAC_RE =
  /^(?:[0-9a-fA-F]{2}([:-])[0-9a-fA-F]{2}(?:\1[0-9a-fA-F]{2}){4}|[0-9a-fA-F]{4}(?:\.[0-9a-fA-F]{4}){2}|[0-9a-fA-F]{12})$/

type FieldValue = string | number | null | undefined
type Overrides = Record<string, unknown>

interface Props {
  /** Module identifier; drives which field set is rendered. */
  moduleName: string | null
  /** Current overrides JSON the parent owns. */
  modelValue: Overrides
  /** Disable all inputs while a request is in flight. */
  disable?: boolean
  /** Live interface names from the backend (defaults to a hardcoded fallback). */
  interfaceOptions?: string[]
}

const props = withDefaults(defineProps<Props>(), {
  disable: false,
  interfaceOptions: undefined,
})

const emit = defineEmits<{
  (e: 'update:modelValue', overrides: Overrides): void
  (e: 'update:valid', valid: boolean): void
}>()

const values = computed<Overrides>(() => props.modelValue ?? {})

const interfaceOptions = computed(() => {
  const source = props.interfaceOptions ?? []
  return source.map((n) => ({ label: n, value: n }))
})

const timingTemplateOptions = computed(() => TIMING_TEMPLATES)

const targetPortText = computed<string>(() => {
  const v = values.value.target_port
  if (typeof v === 'number') return String(v)
  if (typeof v === 'string') return v
  return ''
})

const portRangeLabel = computed<string>(() => {
  if (values.value.port_range === PORT_SCAN_OT_PRESET_RANGE) return 'Port range (OT preset)'
  return 'Port range'
})

const portRangeHint = computed<string>(() => {
  if (values.value.port_range === PORT_SCAN_OT_PRESET_RANGE) return 'OT preset applied — editable'
  return 'nmap-style, e.g. 22,80,443 or 1-1024 or 22,1000-2000'
})

/**
 * Apply a single-field patch onto the current overrides record and emit
 * the new object. Empty strings and ``null`` cause the key to be removed
 * so the backend treats the field as "unset" (its module config applies).
 */
function setField(key: string, value: FieldValue): void {
  if (value === null || value === undefined || value === '') {
    const next: Overrides = Object.fromEntries(Object.entries(values.value).filter(([k]) => k !== key))
    emit('update:modelValue', next)
    return
  }
  emit('update:modelValue', { ...values.value, [key]: value })
}

/**
 * Coerce the ``target_port`` text input to a number on emit so the JSON
 * payload matches the Pydantic ``int`` field type. Empty input removes
 * the key entirely (module default applies).
 */
function setPortField(key: string, value: FieldValue): void {
  if (value === null || value === undefined || value === '') {
    const next: Overrides = Object.fromEntries(Object.entries(values.value).filter(([k]) => k !== key))
    emit('update:modelValue', next)
    return
  }
  const num = Number(value)
  const next: Overrides = { ...values.value }
  next[key] = Number.isFinite(num) ? num : value
  emit('update:modelValue', next)
}

/**
 * Quasar rule helpers. Each returns ``true`` on pass, or a string error
 * message on fail. They are stateless and safe to share across fields.
 */
function ruleRequired(v: unknown): true | string {
  if (v === null || v === undefined) return 'Required'
  if (typeof v === 'string' && v.trim() === '') return 'Required'
  return true
}

function ruleIp(v: unknown): true | string {
  if (typeof v !== 'string' || v === '') return true
  return IPV4_RE.test(v) || IPV6_RE.test(v) || 'Invalid IP address'
}

function ruleCidr(v: unknown): true | string {
  if (typeof v !== 'string' || v === '') return true
  return IPV4_CIDR_RE.test(v) || IPV6_CIDR_RE.test(v) || 'Invalid CIDR subnet'
}

function rulePortRange(v: unknown): true | string {
  if (typeof v !== 'string' || v === '') return true
  if (!PORT_RANGE_RE.test(v)) return 'Invalid port-range expression'
  for (const token of v.split(',')) {
    if (token.includes('-')) {
      const [lo, hi] = token.split('-', 2).map((n) => Number(n))
      if (!Number.isFinite(lo) || !Number.isFinite(hi)) return 'Invalid port number'
      if ((lo as number) < 1 || (hi as number) > 65535) return 'Ports must be in 1–65535'
      if ((lo as number) > (hi as number)) return 'Descending range not allowed'
    } else {
      const n = Number(token)
      if (!Number.isFinite(n)) return 'Invalid port number'
      if (n < 1 || n > 65535) return 'Ports must be in 1–65535'
    }
  }
  return true
}

function ruleMac(v: unknown): true | string {
  if (typeof v !== 'string' || v === '') return true
  return MAC_RE.test(v) || 'Invalid MAC address'
}

function rulePortOptional(v: unknown): true | string {
  if (v === null || v === undefined || v === '') return true
  const n = Number(v)
  if (!Number.isFinite(n)) return 'Invalid port number'
  if (n < 1 || n > 65535) return 'Port must be in 1–65535'
  return true
}

/**
 * Recompute and emit overall form validity whenever the bound overrides
 * change. The parent disables the submit button while ``valid`` is false.
 */
function isValid(): boolean {
  const v = values.value
  switch (props.moduleName) {
    case 'arp_scan':
      return ruleRequired(v.target_subnet) === true && ruleCidr(v.target_subnet) === true
    case 'pn_discovery':
      return ruleMac(v.target_mac as FieldValue) === true
    case 'snmp_scan':
      return ruleRequired(v.target_ip) === true && ruleIp(v.target_ip) === true
    case 'opcua_discover':
      return (
        ruleRequired(v.target_ip) === true &&
        ruleIp(v.target_ip) === true &&
        rulePortOptional(v.target_port as FieldValue) === true
      )
    case 'port_scan':
      return (
        ruleRequired(v.target_ip) === true &&
        ruleIp(v.target_ip) === true &&
        ruleRequired(v.port_range) === true &&
        rulePortRange(v.port_range) === true
      )
    default:
      return false
  }
}

watch(
  () => [props.moduleName, props.modelValue] as const,
  () => {
    emit('update:valid', isValid())
  },
  { immediate: true, deep: true },
)
</script>
