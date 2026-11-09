<template>
  <q-dialog
    v-model="show"
    :persistent="isRunning"
    role="dialog"
    aria-modal="true"
    aria-labelledby="scan-run-modal-title"
  >
    <q-card class="scan-run-modal__card">
      <!-- STICKY HEADER -->
      <q-card-section class="scan-run-modal__header row items-center q-pb-none">
        <div id="scan-run-modal-title" class="text-h6 row items-center">
          <q-spinner v-if="isRunning" color="primary" size="24px" class="q-mr-sm" />
          <q-icon
            v-else-if="terminalStatus === 'completed'"
            name="check_circle"
            color="positive"
            size="24px"
            class="q-mr-sm"
          />
          <q-icon v-else-if="terminalStatus === 'failed'" name="error" color="negative" size="24px" class="q-mr-sm" />
          <q-icon v-else name="play_arrow" color="primary" size="24px" class="q-mr-sm" />
          {{ replayMode ? 'Scan stream' : 'Run scan' }}
        </div>
        <q-space />
        <q-btn
          v-if="!replayMode && terminalStatus !== null"
          color="secondary"
          icon="refresh"
          label="New scan"
          class="q-mr-sm"
          data-testid="scan-modal-reset-btn"
          @click="resetScan"
        />
        <q-btn icon="close" flat round dense aria-label="Close scan dialog" :disable="locked" @click="onClose" />
      </q-card-section>

      <!-- RECOMMENDATION BANNER -->
      <q-card-section v-if="!replayMode && showRecommendationBanner" class="q-pt-sm q-pb-none">
        <q-banner
          rounded
          class="q-pa-sm"
          style="
            background: rgba(var(--cd-positive-rgb), 0.12);
            border: 1px solid var(--cd-positive);
            color: var(--cd-positive);
          "
          data-testid="scan-modal-recommendation-banner"
        >
          <template #avatar>
            <q-icon name="check_circle" color="positive" />
          </template>
          <div class="row items-center">
            <div>
              <strong>{{ recommendationText }}</strong>
              <div class="text-caption text-green-8">{{ recommendationWhy }}</div>
            </div>
            <q-space />
            <q-btn
              flat
              dense
              size="sm"
              label="Dismiss"
              style="color: var(--cd-positive)"
              data-testid="scan-modal-dismiss-reco"
              @click="dismissRecommendation"
            />
          </div>
        </q-banner>
      </q-card-section>

      <!-- BODY -->
      <q-card-section class="scan-run-modal__body">
        <!-- MAIN CONFIG (collapsible) -->
        <div v-if="!replayMode" class="scan-run-modal__config">
          <!-- Compact summary line when scan is active and collapsed -->
          <div
            v-if="scanId !== null && !configExpanded"
            class="scan-run-modal__config-summary row items-center q-pa-xs cursor-pointer"
            @click="configExpanded = true"
          >
            <q-badge color="primary">{{ selectedModule }}</q-badge>
            <span class="q-ml-sm text-caption text-muted">{{ configSummaryText }}</span>
            <q-space />
            <q-icon name="expand_more" size="16px" color="grey-6" />
          </div>

          <!-- Full config pane -->
          <div v-else class="scan-run-modal__config-full">
            <div class="row" style="min-height: 320px">
              <!-- Left rail: module list -->
              <div class="col-3" style="border-right: 1px solid rgba(0, 0, 0, 0.08)">
                <div class="q-pr-md">
                  <div
                    class="text-caption text-muted text-uppercase q-mb-xs"
                    style="font-size: 10px; letter-spacing: 0.5px"
                  >
                    Module
                  </div>
                  <q-list dense separator role="listbox">
                    <q-item
                      v-for="mod in moduleOptions"
                      :key="mod.value"
                      clickable
                      role="option"
                      :aria-selected="selectedModule === mod.value"
                      :class="selectedModule === mod.value ? 'bg-primary text-white' : ''"
                      data-testid="scan-modal-module-rail-item"
                      @click="selectModule(mod.value)"
                    >
                      <q-item-section>
                        <q-item-label class="text-body2">
                          {{ mod.label }}
                          <q-icon
                            v-if="mod.value === recommendedModule"
                            name="check_circle"
                            size="14px"
                            color="positive"
                            class="q-ml-xs"
                          />
                        </q-item-label>
                      </q-item-section>
                    </q-item>
                  </q-list>

                  <q-banner
                    v-if="contextText"
                    rounded
                    class="q-mt-md text-caption text-muted"
                    style="font-size: 11px; background: rgba(0, 0, 0, 0.03)"
                  >
                    {{ contextText }}
                  </q-banner>
                </div>
              </div>

              <!-- Right pane: live config -->
              <div class="col-9 q-pl-md">
                <!-- Form / JSON toggle -->
                <q-btn-toggle
                  v-if="!replayMode"
                  v-model="viewMode"
                  dense
                  outline
                  class="q-mb-sm"
                  :options="[
                    { label: 'Form', value: 'form' },
                    { label: 'JSON', value: 'json' },
                  ]"
                  data-testid="scan-modal-view-toggle"
                />

                <!-- Target summary -->
                <div
                  v-if="targetDevices && targetDevices.length > 0"
                  class="row items-center q-mb-sm q-pa-xs"
                  style="background: var(--cd-surface); border: 1px solid var(--cd-border); border-radius: 6px"
                >
                  <q-icon name="devices" size="18px" class="q-mr-sm text-primary" />
                  <span class="text-body2">
                    {{ targetDevices.length }} device{{ targetDevices.length === 1 ? '' : 's' }}
                  </span>
                  <span v-if="targetSummary" class="text-caption text-muted q-ml-xs"> — {{ targetSummary }} </span>
                </div>

                <!-- Scope display -->
                <q-banner
                  v-if="scopeDisplay"
                  rounded
                  class="q-mb-sm text-caption"
                  :class="scopeError ? 'bg-negative text-white' : 'bg-primary text-white'"
                  style="opacity: 0.9"
                >
                  <template #avatar>
                    <q-icon :name="scopeError ? 'error' : 'location_on'" />
                  </template>
                  <strong>Scope:</strong> {{ scopeDisplay }}
                </q-banner>

                <!-- Active-scan safety note -->
                <q-banner
                  v-if="selectedModule === 'port_scan' || selectedModule === 'arp_scan'"
                  rounded
                  class="q-mb-sm text-caption"
                  style="
                    background: rgba(var(--cd-warning-rgb), 0.12);
                    border: 1px solid var(--cd-warning);
                    color: var(--cd-warning);
                  "
                >
                  <template #avatar>
                    <q-icon name="warning" color="warning" />
                  </template>
                  Active scan — may affect fragile ICS/OT devices. Verify scope and interface before starting.
                </q-banner>

                <!-- Interface warning -->
                <q-banner
                  v-if="interfaceLoadError"
                  rounded
                  class="q-mb-sm text-caption"
                  style="
                    background: rgba(var(--cd-warning-rgb), 0.12);
                    border: 1px solid var(--cd-warning);
                    color: var(--cd-warning);
                  "
                >
                  {{ interfaceLoadError }}
                </q-banner>

                <!-- Form view -->
                <div v-if="viewMode === 'form'">
                  <ScanModuleForm
                    :module-name="selectedModule"
                    :model-value="formOverrides"
                    :disable="locked"
                    :interface-options="interfaceNames"
                    @update:model-value="onFormUpdate"
                    @update:valid="onFormValidUpdate"
                  />

                  <!-- Auth / Security disclosure -->
                  <q-expansion-item
                    v-if="moduleSchema"
                    v-model="advancedExpanded"
                    label="Authentication &amp; Security"
                    header-class="text-caption"
                    dense
                  >
                    <div class="q-pa-sm">
                      <div
                        v-if="moduleSchema.requires_auth"
                        class="q-pa-sm"
                        style="border: 1px dashed rgba(0, 0, 0, 0.2); border-radius: 6px; opacity: 0.7"
                        data-testid="scan-modal-auth-placeholder"
                      >
                        <div class="row items-center q-mb-xs">
                          <q-icon name="lock" size="16px" class="q-mr-sm" />
                          <span class="text-caption">Credentials / Certificates</span>
                          <q-space />
                          <q-badge color="warning" text-color="dark" label="Credential auth coming soon" />
                        </div>
                        <div class="row q-col-gutter-sm">
                          <div class="col-6">
                            <q-input label="Community / Username" dense outlined disable class="q-mb-xs" />
                          </div>
                          <div class="col-6">
                            <q-input label="Password / Key" dense outlined disable type="password" class="q-mb-xs" />
                          </div>
                        </div>
                      </div>
                      <div v-else class="text-caption text-muted q-pa-sm" data-testid="scan-modal-auth-none">
                        Anonymous / no certificate required for this module.
                      </div>
                    </div>
                  </q-expansion-item>
                </div>

                <!-- JSON view -->
                <div v-else>
                  <q-input
                    v-model="configText"
                    label="Config (JSON)"
                    dense
                    outlined
                    type="textarea"
                    autogrow
                    :input-style="{ fontFamily: 'monospace', fontSize: '12px' }"
                    :disable="locked"
                    :error="jsonParseError !== null || jsonSchemaError !== null"
                    :error-message="jsonParseError ?? jsonSchemaError ?? ''"
                    class="q-mb-sm"
                    data-testid="scan-modal-config-text"
                  />

                  <!-- Schema chips -->
                  <div v-if="moduleSchema" class="q-mb-sm">
                    <div class="text-caption text-muted q-mb-xs">Accepted keys:</div>
                    <q-chip
                      v-for="keyItem in moduleSchema.accepted_keys"
                      :key="keyItem.key"
                      dense
                      size="sm"
                      color="primary"
                      text-color="white"
                      class="q-mr-xs q-mb-xs"
                    >
                      {{ keyItem.key }}
                      <q-tooltip>{{ keyItem.type }}<span v-if="keyItem.required"> · required</span></q-tooltip>
                    </q-chip>
                    <div v-if="unknownJsonKeys.length > 0" class="q-mt-xs text-caption" style="color: #c10015">
                      Unknown keys: {{ unknownJsonKeys.join(', ') }} — not accepted by schema.
                    </div>
                    <div v-if="scan003Keys.length > 0" class="q-mt-xs text-caption" style="color: #d29922">
                      Not yet configurable: {{ scan003Keys.join(', ') }}.
                    </div>
                  </div>

                  <!-- Auth note in JSON mode -->
                  <div v-if="moduleSchema && moduleSchema.requires_auth" class="text-caption text-muted q-mt-sm">
                    Authentication required — not yet configurable.
                  </div>
                </div>
              </div>
            </div>

            <div v-if="scanId !== null" class="row justify-end q-mt-xs">
              <q-btn flat dense size="sm" label="Collapse config" @click="configExpanded = false" />
            </div>
          </div>
        </div>

        <!-- Upstream error -->
        <q-banner
          v-if="upstreamError"
          rounded
          class="q-mt-sm"
          style="
            background: rgba(var(--cd-negative-rgb), 0.12);
            border: 1px solid var(--cd-negative);
            color: var(--cd-negative);
          "
          data-testid="scan-modal-upstream-error"
        >
          <template #avatar>
            <q-icon name="error" color="negative" />
          </template>
          {{ upstreamError }}
        </q-banner>

        <!-- SCAN PREFERENCES ACCORDION -->
        <q-expansion-item
          v-if="!replayMode"
          v-model="prefsExpanded"
          label="Scan preferences"
          dense
          class="scan-run-modal__prefs"
        >
          <div class="q-pa-sm">
            <q-list dense>
              <q-item tag="label">
                <q-item-section side>
                  <q-toggle v-model="prefs.showRecommendations" />
                </q-item-section>
                <q-item-section>
                  <q-item-label>Show recommendations</q-item-label>
                  <q-item-label caption>Auto-suggest a module</q-item-label>
                </q-item-section>
              </q-item>
              <q-item tag="label">
                <q-item-section side>
                  <q-toggle v-model="prefs.alwaysJson" />
                </q-item-section>
                <q-item-section>
                  <q-item-label>Always start in JSON mode</q-item-label>
                  <q-item-label caption>Skip the form pane</q-item-label>
                </q-item-section>
              </q-item>
              <q-item tag="label">
                <q-item-section side>
                  <q-toggle v-model="prefs.expandAdvanced" />
                </q-item-section>
                <q-item-section>
                  <q-item-label>Expand Advanced by default</q-item-label>
                  <q-item-label caption>Auth &amp; schema panels open</q-item-label>
                </q-item-section>
              </q-item>
            </q-list>
          </div>
        </q-expansion-item>

        <!-- PROGRESS AREA -->
        <div v-if="scanId !== null" class="scan-run-modal__progress q-pa-sm">
          <div class="row items-center no-wrap">
            <q-spinner v-if="isRunning" color="primary" size="22px" />
            <q-icon v-else-if="terminalStatus === 'completed'" name="check_circle" color="positive" size="22px" />
            <q-icon v-else-if="terminalStatus === 'failed'" name="error" color="negative" size="22px" />
            <q-icon v-else name="stop_circle" color="warning" size="22px" />
            <span class="q-ml-sm text-weight-medium" data-testid="scan-modal-status-badge">
              {{ statusLabel }}
            </span>
            <q-space />
            <span v-if="isRunning" class="text-mono text-amber q-mr-md">{{ elapsedFormatted }}</span>
          </div>
          <div class="row items-center q-mt-xs">
            <span class="text-mono text-positive">{{ liveCountText }}</span>
            <q-space />
            <q-btn
              v-if="isRunning && !replayMode"
              color="negative"
              icon="stop"
              label="Stop"
              size="sm"
              :loading="stopping"
              :disable="stopping"
              :data-disabled="stopping ? 'true' : 'false'"
              data-testid="scan-modal-stop-btn"
              @click="stopScan"
            />
          </div>
          <div v-if="lastFindingText" class="scan-run-modal__last-finding text-caption text-grey-6 ellipsis">
            ↳ {{ lastFindingText }}
          </div>
        </div>

        <!-- DEBUG / EVENT LOG ACCORDION -->
        <q-expansion-item
          v-if="scanId !== null"
          v-model="debugExpanded"
          label="Details / Raw events"
          dense
          class="scan-run-modal__debug"
        >
          <q-list dense bordered class="event-log">
            <q-item
              v-for="(event, idx) in events"
              :key="idx"
              class="q-py-xs event-log__item"
              :class="eventClass(event.type)"
            >
              <q-item-section avatar>
                <q-badge :color="eventBadgeColor(event.type)" :label="event.type" />
              </q-item-section>
              <q-item-section>
                <span class="text-mono event-log__data">{{ summariseData(event.data) }}</span>
              </q-item-section>
            </q-item>
            <q-item v-if="events.length === 0">
              <q-item-section class="text-muted text-caption"> Waiting for events… </q-item-section>
            </q-item>
          </q-list>
        </q-expansion-item>

        <!-- RESULTS (scrollable) -->
        <div v-if="terminalResult !== null" class="scan-run-modal__results">
          <ScanResultDisplay
            :result="terminalResult"
            :overrides="lastSentOverrides"
            data-testid="scan-modal-result-display"
          />
        </div>
      </q-card-section>

      <q-separator />

      <!-- FOOTER -->
      <q-card-section class="q-py-sm">
        <div class="text-caption text-muted" data-testid="scan-modal-upstream-line">Scan engine: OTALON-SCAN</div>
      </q-card-section>

      <!-- ACTIONS -->
      <q-card-actions align="right" class="q-pa-md">
        <q-btn flat label="Close" :disable="locked" @click="onClose" />
        <q-btn
          v-if="!replayMode && scanId === null"
          color="primary"
          icon="play_arrow"
          label="Start scan"
          :loading="starting"
          :disable="startDisabled"
          :data-disabled="startDisabled ? 'true' : 'false'"
          data-testid="scan-modal-start-btn"
          @click="onStart"
        />
      </q-card-actions>
    </q-card>
  </q-dialog>
</template>

<script setup lang="ts">
import { computed, onUnmounted, ref, watch } from 'vue'

import ScanModuleForm from '~/components/scan/ScanModuleForm.vue'
import ScanResultDisplay from '~/components/scan/ScanResultDisplay.vue'
import { useApi, type ApiError } from '~/composables/useApi'
import { useJobStream } from '~/composables/useJobStream'
import { useJobNotificationsStore } from '~/stores/jobNotificationsStore'
import { useScanConfig } from '~/composables/useScanConfig'
import { useScanPrefs } from '~/composables/useScanPrefs'
import type { DeviceItem } from '~/types/api'
import type {
  ModuleSchema,
  ScanModulesResponse,
  ScanItem,
  ScanStartRequest,
  ScanStartResponse,
  ScanInterface,
} from '~/types/scans'
import { formatApiError as formatApiErrorUtil } from '~/utils/apiError'
import { computeScanHeuristic, primaryIpOf } from '~/utils/scanHeuristic'
import { PORT_SCAN_OT_PRESET_RANGE } from '~/utils/scanDefaults'

/**
 * Per-module default override objects for the structured form.
 */
const MODULE_DEFAULT_OVERRIDES: Record<string, Record<string, unknown>> = {
  arp_scan: {},
  port_scan: { target_ip: '192.168.0.1', port_range: PORT_SCAN_OT_PRESET_RANGE, timing_template: '3' },
  snmp_scan: { target_ip: '192.168.0.1' },
  opcua_discover: { target_ip: '192.168.0.1', target_port: 4840 },
  pn_discovery: {},
}

/**
 * Subnet-wide scan modules eligible in multi-target / "scan all" mode.
 */
const SUBNET_SCAN_MODULES = new Set<string>(['arp_scan', 'pn_discovery'])

/**
 * Keys known to be valid module config parameters that are NOT yet in the
 * caller-overridable schema. They are flagged amber in JSON mode.
 * ( SCAN-003 will expand the schema to include these. )
 */
const SCAN_003_KEYS: Record<string, string[]> = {
  port_scan: ['udp_scan', 'service_version_info', 'host_timeout_ms'],
  snmp_scan: ['communities', 'retry_attempts'],
  arp_scan: [],
  opcua_discover: [],
  pn_discovery: [],
}

/**
 * Modules that accept a single target IP.
 */
const TARGET_IP_MODULES = new Set<string>(['port_scan', 'snmp_scan', 'opcua_discover'])

/**
 * Derive a /24 CIDR from a dotted-quad IPv4 address.
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
 * Derive the target subnet for arp_scan from a list of devices.
 * Prefers explicit interface.subnet, then falls back to /24 from ipv4.
 */
function deriveSubnetFromDevices(devices: DeviceItem[] | null | undefined): string | null {
  if (!devices || devices.length === 0) return null
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

/**
 * Resolve the single device's MAC address: prefer the canonical
 * ``primary_mac`` identity, fall back to the first interface MAC.
 */
function deviceMac(device: DeviceItem | null | undefined): string | null {
  if (!device) return null
  if (device.primary_mac) return device.primary_mac
  for (const iface of device.interfaces ?? []) {
    if (iface.mac_address) return iface.mac_address
  }
  return null
}

/**
 * Derive per-module override defaults from target devices.
 *
 * P8 Welle E (F-11) — single-asset targeting: when the modal was opened
 * from exactly one asset ("Scan this device"), pre-fill the scan
 * parameters to that one device instead of the broad subnet/multicast
 * defaults:
 *  - arp_scan: the device IPv4 as a ``/32`` CIDR (single-host nmap sweep),
 *    not the enclosing ``/24``.
 *  - pn_discovery: the device MAC as ``target_mac`` so the PROFINET DCP
 *    results are filtered to that one station (the Identify itself stays
 *    multicast — see backend rationale).
 * Multi-target / "Scan all" keeps the subnet (arp) and unfiltered
 * multicast (pn) behaviour.
 */
function devicePrefillFor(
  moduleName: string | null,
  devices: DeviceItem[] | null | undefined,
): Record<string, unknown> {
  if (!moduleName) return {}
  const result: Record<string, unknown> = {}
  const single = devices && devices.length === 1 ? devices[0] : null

  if (moduleName === 'arp_scan') {
    if (single) {
      const ip = primaryIpOf(single)
      if (ip) {
        result.target_subnet = `${ip}/32`
        return result
      }
    }
    const subnet = deriveSubnetFromDevices(devices)
    if (subnet) result.target_subnet = subnet
  } else if (moduleName === 'pn_discovery') {
    if (single) {
      const mac = deviceMac(single)
      if (mac) result.target_mac = mac
    }
  } else if (TARGET_IP_MODULES.has(moduleName)) {
    if (!single) return {}
    const ip = primaryIpOf(single)
    if (ip) result.target_ip = ip
  }
  return result
}

interface Props {
  modelValue: boolean
  presetModule?: string | null
  targetDevices?: DeviceItem[] | null
  replayScanId?: string | null
  hasProfinetInSubnet?: boolean
}

const props = withDefaults(defineProps<Props>(), {
  presetModule: null,
  targetDevices: () => [],
  replayScanId: null,
  hasProfinetInSubnet: false,
})

const emit = defineEmits<{
  (e: 'update:modelValue', value: boolean): void
  (e: 'started', scanId: string): void
  (e: 'finished', scanId: string, status: 'completed' | 'failed' | 'cancelled'): void
}>()

const api = useApi()
const { fetchInterfaces, fetchModuleSchema } = useScanConfig()
const { prefs } = useScanPrefs()

const show = computed({
  get: () => props.modelValue,
  set: (v: boolean) => emit('update:modelValue', v),
})

const replayMode = computed(() => props.replayScanId !== null)

const loadingModules = ref(false)
const modules = ref<string[]>([])
const selectedModule = ref<string | null>(props.presetModule ?? null)
const viewMode = ref<'form' | 'json'>('form')

const configExpanded = ref(true)
const debugExpanded = ref(false)
const prefsExpanded = ref(false)

const scanStartTime = ref<number | null>(null)
const timerNow = ref(Date.now())
let timerInterval: ReturnType<typeof setInterval> | null = null

// L-01 safety net: backstop poller that resolves the modal from the persisted
// scan record if the SSE stream never delivers a terminal frame.
const TERMINAL_POLL_INTERVAL_MS = 4000
let terminalWatchdog: ReturnType<typeof setInterval> | null = null

defineExpose({ viewMode })
const formOverrides = ref<Record<string, unknown>>(defaultOverridesFor(props.presetModule))
const formValid = ref(false)
const configText = ref<string>(defaultConfigFor(props.presetModule))
const jsonParseError = ref<string | null>(null)
const starting = ref(false)
const stopping = ref(false)
const upstreamError = ref<string | null>(null)
const jobStore = useJobNotificationsStore()
const scanId = ref<string | null>(props.replayScanId)
const terminalStatus = ref<'completed' | 'failed' | 'cancelled' | null>(null)
const terminalResult = ref<unknown>(null)
const lastSentOverrides = ref<Record<string, unknown>>({})

const interfaces = ref<ScanInterface[]>([])
const interfaceLoadError = ref<string | null>(null)
const moduleSchema = ref<ModuleSchema | null>(null)
const recommendationDismissed = ref(false)
const advancedExpanded = ref(false)

const recommendedModule = ref<string | null>(null)
const recommendationWhy = ref('')

// UI-016 Cause 1: the module the heuristic auto-applied (vs. one the operator
// picked).  A reactive re-run may upgrade the auto-selection (e.g. a late
// PROFINET signal flips ``arp_scan`` → ``pn_discovery``) but must never
// override a module the operator chose by hand.
const autoSelectedModule = ref<string | null>(null)

const isSubnetMode = computed(() => (props.targetDevices?.length ?? 0) !== 1)

const moduleOptions = computed(() => {
  const all = modules.value.map((m) => ({ label: m, value: m }))
  if (isSubnetMode.value) {
    return all.filter((m) => SUBNET_SCAN_MODULES.has(m.value))
  }
  return all
})

const showRecommendationBanner = computed(
  () =>
    prefs.value.showRecommendations &&
    !replayMode.value &&
    !recommendationDismissed.value &&
    recommendedModule.value !== null &&
    recommendedModule.value === selectedModule.value,
)

const recommendationText = computed(() => {
  const mod = recommendedModule.value
  if (!mod) return ''
  return `${mod} recommended`
})

const contextText = computed(() => {
  if (recommendedModule.value && selectedModule.value === recommendedModule.value) {
    return recommendationWhy.value
      ? `Recommended because ${recommendationWhy.value}. Active scan runs over the selected interface.`
      : ''
  }
  return ''
})

const targetSummary = computed<string>(() => {
  const list = props.targetDevices ?? []
  if (list.length === 0) return ''
  const labels = list.slice(0, 5).map((d) => d.device_family || d.device_type || d.vendor || `Device ${d.id}`)
  if (list.length > 5) labels.push(`+${list.length - 5} more`)
  return labels.join(', ')
})

const scopeDisplay = computed<string | null>(() => {
  const mod = selectedModule.value
  if (!mod) return null
  if (mod === 'arp_scan') {
    const subnet =
      (formOverrides.value.target_subnet ?? configText.value.includes('target_subnet'))
        ? (formOverrides.value.target_subnet as string | undefined)
        : undefined
    if (subnet) return subnet.endsWith('/32') ? `Host ${subnet.replace('/32', '')}` : `Subnet ${subnet}`
    return 'Subnet not determined — check device interfaces'
  }
  if (TARGET_IP_MODULES.has(mod)) {
    const ip = formOverrides.value.target_ip as string | undefined
    if (ip) return `Target IP ${ip}`
    return 'Target IP not set'
  }
  if (mod === 'pn_discovery') {
    const targetMac = formOverrides.value.target_mac as string | undefined
    const iface = formOverrides.value.network_interface as string | undefined
    if (targetMac) {
      return iface ? `PROFINET DCP on ${iface} — station ${targetMac}` : `PROFINET DCP — station ${targetMac}`
    }
    return iface ? `PROFINET DCP on ${iface}` : 'PROFINET DCP on selected interface'
  }
  return null
})

const scopeError = computed<string | null>(() => {
  const mod = selectedModule.value
  if (!mod) return null
  if (mod === 'arp_scan' && !formOverrides.value.target_subnet) {
    return 'arp_scan requires a target subnet. Add interface/subnet data to at least one device.'
  }
  if (TARGET_IP_MODULES.has(mod) && !formOverrides.value.target_ip) {
    return `${mod} requires a target IP. Select exactly one device with an IPv4 interface.`
  }
  return null
})

const locked = computed(() => starting.value || stopping.value)

const startDisabled = computed(() => {
  if (loadingModules.value || selectedModule.value === null) return true
  if (scopeError.value) return true
  if (viewMode.value === 'json') {
    return jsonParseError.value !== null || jsonSchemaError.value !== null
  }
  return !formValid.value
})

const statusLabel = computed(() => {
  if (terminalStatus.value === 'completed') return 'Completed'
  if (terminalStatus.value === 'failed') return 'Failed'
  if (terminalStatus.value === 'cancelled') return 'Aborted'
  return 'Running'
})

const isRunning = computed(() => scanId.value !== null && terminalStatus.value === null)

const elapsedFormatted = computed(() => {
  if (scanStartTime.value === null) return '00:00.0'
  const ms = timerNow.value - scanStartTime.value
  const totalSeconds = Math.floor(ms / 1000)
  const minutes = Math.floor(totalSeconds / 60)
  const seconds = totalSeconds % 60
  const tenths = Math.floor((ms % 1000) / 100)
  return `${String(minutes).padStart(2, '0')}:${String(seconds).padStart(2, '0')}.${tenths}`
})

const liveCountText = computed(() => {
  if (terminalResult.value && typeof terminalResult.value === 'object') {
    const list = (terminalResult.value as Record<string, unknown>).findings
    if (Array.isArray(list)) {
      return `${list.length} device${list.length === 1 ? '' : 's'} found`
    }
  }
  const progressCount = events.value.filter((e) => e.type === 'progress').length
  if (progressCount > 0) {
    return `${progressCount} event${progressCount === 1 ? '' : 's'}`
  }
  return '0 devices found'
})

const lastFindingText = computed(() => {
  for (let i = events.value.length - 1; i >= 0; i--) {
    const ev = events.value[i]
    if (ev.type === 'progress' && ev.data !== null) {
      return summariseData(ev.data)
    }
  }
  return ''
})

const configSummaryText = computed(() => {
  const parts: string[] = []
  try {
    const cfg = JSON.parse(configText.value) as Record<string, unknown>
    if (cfg.target_subnet) {
      const sn = String(cfg.target_subnet)
      parts.push(sn.endsWith('/32') ? `Host ${sn.replace('/32', '')}` : `Subnet ${sn}`)
    } else if (cfg.target_ip) parts.push(`Target ${cfg.target_ip}`)
    else if (cfg.target_mac) parts.push(`Station ${cfg.target_mac}`)
    if (cfg.network_interface) parts.push(`Interface ${cfg.network_interface}`)
  } catch {
    // ignore parse errors
  }
  if (targetSummary.value) parts.push(targetSummary.value)
  return parts.join(' · ')
})

const streamUrl = computed<string | null>(() => (scanId.value ? `/api/v1/scans/${scanId.value}/events` : null))

const {
  events,
  status: streamStatus,
  close: closeJobStream,
} = useJobStream({
  url: streamUrl,
  onEvent: onStreamEvent,
})

const interfaceNames = computed<string[]>(() =>
  interfaces.value.length > 0 ? interfaces.value.filter((i) => i.role !== 'mirror').map((i) => i.name) : [],
)

const activeInterfaceDefault = computed<string | null>(() => {
  const declared = interfaces.value.find((i) => i.is_default === true)
  if (declared) return declared.name
  const active = interfaces.value.find((i) => i.role === 'active_scan')
  return active?.name ?? null
})

const acceptedKeyNames = computed<Set<string>>(() => {
  if (!moduleSchema.value) return new Set()
  return new Set(moduleSchema.value.accepted_keys.map((k) => k.key))
})

const unknownJsonKeys = computed<string[]>(() => {
  if (!moduleSchema.value) return []
  const parsed = parseJsonKeys(configText.value)
  return parsed.filter((k) => !acceptedKeyNames.value.has(k) && !scan003KeysSet.value.has(k))
})

const scan003Keys = computed<string[]>(() => {
  if (!moduleSchema.value) return []
  const parsed = parseJsonKeys(configText.value)
  return parsed.filter((k) => !acceptedKeyNames.value.has(k) && scan003KeysSet.value.has(k))
})

const scan003KeysSet = computed<Set<string>>(() => new Set(SCAN_003_KEYS[selectedModule.value ?? ''] ?? []))

const jsonSchemaError = computed<string | null>(() => {
  const unknown = unknownJsonKeys.value
  if (unknown.length > 0) {
    return `Key\`${unknown[0]}\` not accepted by schema`
  }
  return null
})

function parseJsonKeys(text: string): string[] {
  try {
    const obj = JSON.parse(text)
    if (obj && typeof obj === 'object' && !Array.isArray(obj)) {
      return Object.keys(obj)
    }
  } catch {
    // ignore parse errors — handled by jsonParseError
  }
  return []
}

watch(
  () => props.modelValue,
  (open) => {
    if (open) {
      void loadModules()
      void loadInterfaces()
      viewMode.value = prefs.value.alwaysJson ? 'json' : 'form'
      advancedExpanded.value = prefs.value.expandAdvanced
      recommendationDismissed.value = false
      configExpanded.value = true
      debugExpanded.value = false
      prefsExpanded.value = false
      if (!replayMode.value && props.replayScanId === null) {
        closeJobStream()
        upstreamError.value = null
        terminalStatus.value = null
        terminalResult.value = null
        events.value = []
        scanId.value = null
        selectedModule.value = props.presetModule ?? null
        autoSelectedModule.value = null
        starting.value = false
        stopping.value = false
        stopTimer()
        stopTerminalWatchdog()
        scanStartTime.value = null
      }
    }
  },
  { immediate: true },
)

watch(configText, (text) => {
  jsonParseError.value = parseConfigOrError(text)
})

watch(
  () => props.targetDevices,
  () => {
    if (replayMode.value) return
    if (!props.modelValue) return
    formOverrides.value = buildOverrides(selectedModule.value)
    configText.value = buildConfig(selectedModule.value)
    jsonParseError.value = null
  },
  { deep: true },
)

watch(selectedModule, (mod) => {
  if (mod) {
    void loadModuleSchemaFor(mod)
  }
})

watch(scanId, (id) => {
  if (id !== null) {
    configExpanded.value = false
    if (!replayMode.value) {
      startTimer()
      startTerminalWatchdog()
    }
  }
})

// UI-016 Cause 1: the PROFINET subnet signal is fetched asynchronously by the
// parent (devices.vue) and may arrive — or change — AFTER the modal has opened
// and modules have loaded.  Without this watcher ``applyHeuristic`` ran only
// once (on module load) against a stale ``hasProfinetInSubnet=false``, so a
// late-arriving PROFINET signal never upgraded the recommendation from
// ``arp_scan`` to ``pn_discovery``.  Re-run the heuristic reactively whenever
// the signal changes while the modal is open and modules are available.
watch(
  () => props.hasProfinetInSubnet,
  () => {
    if (!props.modelValue) return
    if (modules.value.length === 0) return
    applyHeuristic()
  },
)

function startTimer(): void {
  scanStartTime.value = Date.now()
  timerNow.value = Date.now()
  if (timerInterval) clearInterval(timerInterval)
  timerInterval = setInterval(() => {
    timerNow.value = Date.now()
  }, 100)
}

function stopTimer(): void {
  if (timerInterval) {
    clearInterval(timerInterval)
    timerInterval = null
  }
}

function selectModule(mod: string): void {
  selectedModule.value = mod
  autoSelectedModule.value = null
  formOverrides.value = buildOverrides(mod)
  resetConfigToDefault(mod)
}

function dismissRecommendation(): void {
  recommendationDismissed.value = true
}

function applyHeuristic(): void {
  if (!prefs.value.showRecommendations) {
    recommendedModule.value = null
    recommendationWhy.value = ''
    return
  }
  const result = computeScanHeuristic(props.targetDevices, props.hasProfinetInSubnet)
  recommendedModule.value = result.module
  recommendationWhy.value = result.reason
  // Only auto-apply when the recommended module is actually available.
  if (!modules.value.includes(result.module)) return
  // Apply the recommendation when nothing is selected yet, OR when the only
  // current selection is a prior auto-application (so a reactively-upgraded
  // recommendation flows through). A module the operator picked by hand —
  // tracked by ``autoSelectedModule`` being null — is left untouched.
  const selectionIsAuto = selectedModule.value !== null && selectedModule.value === autoSelectedModule.value
  if (modules.value.length > 0 && (!selectedModule.value || selectionIsAuto)) {
    selectedModule.value = result.module
    autoSelectedModule.value = result.module
    formOverrides.value = buildOverrides(result.module)
    configText.value = buildConfig(result.module)
  }
}

function defaultConfigFor(moduleName: string | null | undefined): string {
  if (!moduleName) return '{}'
  const base = MODULE_DEFAULT_OVERRIDES[moduleName] ?? {}
  const prefill = devicePrefillFor(moduleName ?? null, props.targetDevices)
  const merged = { ...base, ...prefill }
  if (Object.keys(merged).length === 0) return '{}'
  return JSON.stringify(merged, null, 2)
}

function defaultOverridesFor(moduleName: string | null | undefined): Record<string, unknown> {
  if (!moduleName) return {}
  const base = MODULE_DEFAULT_OVERRIDES[moduleName] ?? {}
  const prefill = devicePrefillFor(moduleName ?? null, props.targetDevices)
  return { ...base, ...prefill }
}

function buildOverrides(moduleName: string | null | undefined): Record<string, unknown> {
  const overrides = defaultOverridesFor(moduleName)
  const ifaceDefault = activeInterfaceDefault.value
  if (ifaceDefault && overrides.network_interface === undefined) {
    return { ...overrides, network_interface: ifaceDefault }
  }
  return overrides
}

function buildConfig(moduleName: string | null | undefined): string {
  const overrides = buildOverrides(moduleName)
  if (Object.keys(overrides).length === 0) return '{}'
  return JSON.stringify(overrides, null, 2)
}

function onFormUpdate(next: Record<string, unknown>): void {
  formOverrides.value = next
  configText.value = JSON.stringify(next, null, 2)
}

function onFormValidUpdate(valid: boolean): void {
  formValid.value = valid
}

function parseConfigOrError(text: string): string | null {
  if (text.trim() === '') return 'Config cannot be empty'
  try {
    JSON.parse(text)
    return null
  } catch (err) {
    return (err as Error).message
  }
}

async function loadModules(): Promise<void> {
  loadingModules.value = true
  try {
    const response = await api.get<ScanModulesResponse | string[]>('/api/v1/modules')
    const list = Array.isArray(response) ? response : (response.modules ?? [])
    modules.value = list
    applyHeuristic()
    if (selectedModule.value === null && list.length > 0) {
      const first = list[0] ?? null
      selectedModule.value = first
      configText.value = buildConfig(first)
      formOverrides.value = buildOverrides(first)
    }
    if (selectedModule.value) {
      await loadModuleSchemaFor(selectedModule.value)
    }
  } catch (err) {
    const apiErr = err as ApiError
    upstreamError.value = `Failed to load modules: ${apiErr.message}`
  } finally {
    loadingModules.value = false
  }
}

async function loadInterfaces(): Promise<void> {
  try {
    const list = await fetchInterfaces()
    interfaces.value = list
    interfaceLoadError.value = null
    // Re-seed defaults now that interfaces are known.
    if (selectedModule.value) {
      formOverrides.value = buildOverrides(selectedModule.value)
      configText.value = buildConfig(selectedModule.value)
    }
  } catch {
    interfaces.value = []
    interfaceLoadError.value = 'Live interfaces unavailable — enter the interface name manually (e.g. eth0).'
  }
}

async function loadModuleSchemaFor(name: string): Promise<void> {
  try {
    const schema = await fetchModuleSchema(name)
    moduleSchema.value = schema
  } catch {
    moduleSchema.value = null
  }
}

function resetConfigToDefault(newModule: string | null): void {
  configText.value = buildConfig(newModule)
  jsonParseError.value = null
}

async function onStart(): Promise<void> {
  upstreamError.value = null
  if (selectedModule.value === null) {
    upstreamError.value = 'No module selected'
    return
  }
  let overrides: Record<string, unknown>
  if (viewMode.value === 'json') {
    const parseErr = parseConfigOrError(configText.value)
    if (parseErr !== null) {
      jsonParseError.value = parseErr
      return
    }
    overrides = JSON.parse(configText.value) as Record<string, unknown>
  } else {
    if (!formValid.value) return
    overrides = { ...formOverrides.value }
  }

  lastSentOverrides.value = overrides

  starting.value = true
  try {
    const body: ScanStartRequest = {
      module_name: selectedModule.value,
      overrides,
    }
    const response = await api.post<ScanStartResponse>('/api/v1/scans', body)
    scanId.value = response.scan_id
    jobStore.watchScan(response.scan_id)
    emit('started', response.scan_id)
  } catch (err) {
    const apiErr = err as ApiError
    upstreamError.value = formatApiError(apiErr)
  } finally {
    starting.value = false
  }
}

async function stopScan(): Promise<void> {
  if (scanId.value === null) return
  stopping.value = true
  upstreamError.value = null
  try {
    await api.post(`/api/v1/scans/${scanId.value}/abort`)
    if (terminalStatus.value === null) {
      terminalStatus.value = 'cancelled'
      closeJobStream()
    }
    if (scanId.value !== null) {
      emit('finished', scanId.value, 'cancelled')
    }
  } catch (err) {
    const apiErr = err as ApiError
    upstreamError.value = formatApiErrorUtil(apiErr, 'Scan stop')
  } finally {
    stopping.value = false
  }
}

function formatApiError(err: ApiError): string {
  return formatApiErrorUtil(err, 'Scan start')
}

function onStreamEvent(type: string, data: unknown): void {
  if (type === 'result' || type === 'final') {
    if (terminalStatus.value !== null) return
    terminalResult.value = data
    const inferred = inferTerminalStatus(data)
    terminalStatus.value = inferred
    stopTimer()
    stopTerminalWatchdog()
    if (scanId.value !== null) {
      emit('finished', scanId.value, inferred)
    }
  } else if (type === 'status') {
    if (terminalStatus.value !== null) return
    const inferred = inferTerminalStatus(data)
    if (inferred !== 'completed') {
      terminalStatus.value = inferred
      stopTimer()
      stopTerminalWatchdog()
      if (scanId.value !== null) {
        emit('finished', scanId.value, inferred)
      }
    }
  } else if (type === 'error') {
    if (terminalStatus.value !== null) return
    terminalStatus.value = 'failed'
    stopTimer()
    stopTerminalWatchdog()
    if (scanId.value !== null) {
      emit('finished', scanId.value, 'failed')
    }
  }
}

function inferTerminalStatus(data: unknown): 'completed' | 'failed' | 'cancelled' {
  if (data && typeof data === 'object') {
    const obj = data as Record<string, unknown>
    const status = obj.status
    if (typeof status === 'string') {
      const lower = status.toLowerCase()
      if (lower === 'failed' || lower === 'error') return 'failed'
      if (lower === 'aborted' || lower === 'cancelled_partial') return 'cancelled'
    }
  }
  return 'completed'
}

/**
 * Map a persisted scan status string (from ``GET /api/v1/scans/{id}``) to a
 * terminal modal status, or ``null`` when the scan is still running.
 */
function persistedTerminalStatus(status: string | undefined): 'completed' | 'failed' | 'cancelled' | null {
  if (!status) return null
  const lower = status.toLowerCase()
  if (lower === 'running' || lower === 'pending' || lower === 'queued') return null
  if (lower === 'failed' || lower === 'error') return 'failed'
  if (lower === 'aborted' || lower === 'cancelled' || lower === 'cancelled_partial') return 'cancelled'
  // completed / completed_partial / anything else terminal → completed.
  return 'completed'
}

/**
 * L-01 safety net: resolve the modal from the persisted scan record so a
 * missed/late SSE ``result`` frame can never strand the modal in "Running".
 *
 * Polls ``GET /api/v1/scans/{id}`` and, when the row reports a terminal
 * ``status`` (or carries a ``finished_at``), transitions the modal exactly
 * like an in-stream terminal event would. No-op once a terminal status was
 * already resolved (the SSE stream usually wins the race).
 */
async function resolveFromPersistedScan(): Promise<void> {
  if (terminalStatus.value !== null) return
  const id = scanId.value
  if (id === null) return
  try {
    const record = await api.get<ScanItem>(`/api/v1/scans/${id}`)
    if (terminalStatus.value !== null) return
    const resolved = persistedTerminalStatus(record.status) ?? (record.finished_at ? 'completed' : null)
    if (resolved === null) return
    terminalStatus.value = resolved
    stopTimer()
    stopTerminalWatchdog()
    closeJobStream()
    emit('finished', id, resolved)
  } catch {
    // Transient poll failure — the watchdog will retry on its next tick.
  }
}

function startTerminalWatchdog(): void {
  stopTerminalWatchdog()
  // Backstop poll while the scan is running: even if the SSE stream stays
  // silent or drops, the persisted status resolves the modal within a few
  // seconds of the backend's ``finished_at``.
  terminalWatchdog = setInterval(() => {
    if (terminalStatus.value !== null || scanId.value === null) {
      stopTerminalWatchdog()
      return
    }
    void resolveFromPersistedScan()
  }, TERMINAL_POLL_INTERVAL_MS)
}

function stopTerminalWatchdog(): void {
  if (terminalWatchdog) {
    clearInterval(terminalWatchdog)
    terminalWatchdog = null
  }
}

// When the SSE stream errors out or closes without ever delivering a terminal
// frame, poll the persisted record immediately rather than waiting for the
// next watchdog tick.
watch(streamStatus, (next) => {
  if ((next === 'error' || next === 'closed') && scanId.value !== null && terminalStatus.value === null) {
    void resolveFromPersistedScan()
  }
})

onUnmounted(() => {
  stopTerminalWatchdog()
})

function eventBadgeColor(type: string): string {
  if (type === 'result' || type === 'final') return 'positive'
  if (type === 'error') return 'negative'
  if (type === 'progress') return 'primary'
  return 'grey-6'
}

function eventClass(type: string): string {
  if (type === 'result' || type === 'final') return 'event-log__item--ok'
  if (type === 'error') return 'event-log__item--err'
  return ''
}

function summariseData(data: unknown): string {
  try {
    const text = typeof data === 'string' ? data : JSON.stringify(data)
    if (text.length > 200) return `${text.slice(0, 197)}…`
    return text
  } catch {
    return String(data)
  }
}

function resetScan(): void {
  scanId.value = null
  terminalStatus.value = null
  terminalResult.value = null
  events.value = []
  upstreamError.value = null
  stopping.value = false
  stopTimer()
  stopTerminalWatchdog()
  scanStartTime.value = null
  configExpanded.value = true
  debugExpanded.value = false
  prefsExpanded.value = false
}

function onClose(): void {
  show.value = false
}
</script>

<style scoped lang="scss">
.scan-run-modal__card {
  width: 900px;
  min-width: 600px;
  max-width: 92vw;
  height: 80vh;
  min-height: 520px;
  max-height: 88vh;
  display: flex;
  flex-direction: column;
  resize: both;
  overflow: auto;
}

.scan-run-modal__header {
  flex-shrink: 0;
  position: sticky;
  top: 0;
  z-index: 10;
  background: inherit;
  border-bottom: 1px solid var(--cd-border, rgba(0, 0, 0, 0.08));
}

.scan-run-modal__body {
  flex: 1;
  overflow: hidden;
  display: flex;
  flex-direction: column;
  padding: 12px 18px;
}

.scan-run-modal__config-summary {
  background: rgba(0, 0, 0, 0.03);
  border: 1px solid var(--cd-border, rgba(0, 0, 0, 0.08));
  border-radius: 8px;
}

.scan-run-modal__progress {
  background: rgba(0, 0, 0, 0.03);
  border: 1px solid var(--cd-border, rgba(0, 0, 0, 0.08));
  border-radius: 8px;
  margin-top: 8px;
}

.scan-run-modal__last-finding {
  margin-top: 6px;
  font-size: 12px;
  font-family: $font-family-mono;
}

.scan-run-modal__results {
  flex: 1;
  overflow-y: auto;
  min-height: 0;
  margin-top: 8px;
}

.event-log {
  max-height: 200px;
  overflow-y: auto;
  scrollbar-width: thin;
}

.event-log__item {
  border-bottom: 1px solid var(--cd-border, rgba(0, 0, 0, 0.08));
}

.event-log__item--ok {
  background-color: rgba(33, 186, 69, 0.06);
}

.event-log__item--err {
  background-color: rgba(193, 0, 21, 0.08);
}

.event-log__data {
  font-size: 11px;
  word-break: break-all;
}

.text-mono {
  font-family: $font-family-mono;
}
</style>
