<template>
  <div class="configuration-page">
    <InsufficientPermissionsNotice :message="store.error || store.runtimeError" />
    <q-banner
      v-if="store.error && !isInsufficientPermissionsMessage(store.error)"
      class="q-mb-md"
      rounded
      dense
      type="warning"
      data-test="config-error"
    >
      {{ store.error }}
    </q-banner>

    <q-tabs v-model="tab" dense no-caps align="left" class="q-mb-md" active-color="primary" indicator-color="primary">
      <q-tab name="runtime" label="Runtime" />
      <q-tab name="boot" label="Boot & Environment" />
      <q-tab name="ai" label="AI Connection" />
      <q-tab v-if="!auth.user || auth.isAdmin" name="access" label="Access & Users" />
      <q-tab name="history" label="Change History" />
    </q-tabs>

    <q-tab-panels v-model="tab" animated>
      <!-- Runtime — live control plane, applies without a restart -->
      <q-tab-panel name="runtime" class="q-pa-none">
        <q-card flat bordered>
          <q-card-section>
            <div class="row items-center q-gutter-sm">
              <div class="text-subtitle1">Runtime Parameters</div>
              <CdStateBadge kind="ok" label="live" data-test="runtime-live" />
            </div>
            <p class="text-caption text-muted q-mb-none" data-test="runtime-no-restart-note">
              Runtime values apply within one poll cycle of the owning service — no restart is required. Values are
              validated by the server against the declared domain; every accepted write is audited.
            </p>

            <InsufficientPermissionsNotice :message="store.runtimeError" />
            <q-banner
              v-if="store.runtimeError && !isInsufficientPermissionsMessage(store.runtimeError)"
              dense
              rounded
              class="bg-red-1 text-red-9 q-mt-md"
              data-test="runtime-error"
            >
              {{ store.runtimeError }}
            </q-banner>

            <q-banner
              v-if="lastApply"
              dense
              rounded
              class="bg-green-1 text-green-9 q-mt-md"
              data-test="runtime-apply-result"
            >
              Applied <strong>{{ lastApply.changed_keys.join(', ') }}</strong
              >.
              <span data-test="runtime-apply-restart">{{
                lastApply.restart_required
                  ? 'A restart is required before this takes effect.'
                  : 'Applies within one poll cycle, no restart.'
              }}</span>
            </q-banner>

            <q-markup-table flat dense class="q-mt-md config-table">
              <thead>
                <tr>
                  <th class="text-left">Key</th>
                  <th class="text-left">Current</th>
                  <th class="text-left">Previous</th>
                  <th class="text-left">Last change</th>
                  <th class="text-left">Type · domain</th>
                  <th class="text-right">Edit</th>
                </tr>
              </thead>
              <tbody v-for="group in store.runtimeByService" :key="group.service">
                <tr class="runtime-service-row">
                  <td colspan="6" class="text-weight-medium" data-test="runtime-service">{{ group.service }}</td>
                </tr>
                <tr v-for="item in group.items" :key="`${item.service}:${item.key}`" data-test="runtime-row">
                  <td>
                    <div class="text-weight-medium" data-test="runtime-key">{{ item.key }}</div>
                    <div class="text-caption text-muted">{{ item.description }}</div>
                  </td>
                  <td class="cd-mono" data-test="runtime-value">{{ item.value }}</td>
                  <td class="cd-mono text-muted" data-test="runtime-value-prev">{{ item.value_prev ?? '—' }}</td>
                  <td class="text-caption" data-test="runtime-updated">
                    <span v-if="item.updated_at">
                      {{ formatTimestamp(item.updated_at) }} · {{ item.updated_by ?? 'unknown' }}
                    </span>
                    <span v-else class="text-muted" data-test="runtime-never-written">
                      never changed · boot-derived
                    </span>
                  </td>
                  <td class="text-caption" data-test="runtime-type">
                    {{ item.type }}<span v-if="item.domain"> · {{ item.domain }}</span>
                  </td>
                  <td class="text-right">
                    <q-btn
                      flat
                      dense
                      color="primary"
                      label="Edit"
                      data-test="runtime-edit"
                      :loading="store.runtimeSavingKey === `${item.service}:${item.key}`"
                      @click="openRuntimeDialog(item)"
                    />
                  </td>
                </tr>
              </tbody>
            </q-markup-table>

            <div v-if="!store.runtime.length" class="text-caption text-muted q-mt-md" data-test="runtime-empty">
              No runtime keys reported.
            </div>
          </q-card-section>
        </q-card>
      </q-tab-panel>

      <!-- Boot & Environment -->
      <q-tab-panel name="boot" class="q-pa-none">
        <q-card v-if="store.boot" flat bordered>
          <q-card-section>
            <div class="text-subtitle1">Boot &amp; Environment</div>
            <div class="text-caption text-muted">Values apply only when the affected services are recreated.</div>
            <q-markup-table flat dense class="q-mt-md config-table">
              <thead>
                <tr>
                  <th class="text-left">Key</th>
                  <th class="text-left">Value</th>
                  <th class="text-left">Affected services</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="key in [...store.boot.editable_keys, ...(store.boot.readonly_keys ?? [])]" :key="key">
                  <td class="text-weight-medium">
                    {{ key }}
                    <span v-if="store.isSensitiveKey(key)" class="text-caption text-muted q-ml-sm">write-only</span>
                    <span
                      v-else-if="(store.boot.readonly_keys ?? []).includes(key)"
                      class="text-caption text-muted q-ml-sm"
                      >derived · read-only</span
                    >
                  </td>
                  <td>
                    <span v-if="store.isSensitiveKey(key)" class="text-muted" data-test="boot-sensitive-value">
                      •••••••• (hidden)
                    </span>
                    <span v-else>{{
                      (store.boot.readonly_keys ?? []).includes(key) ? 'derived · hidden' : store.boot.env[key]
                    }}</span>
                  </td>
                  <td class="text-caption">{{ (store.boot.affected_services[key] || []).join(', ') || '—' }}</td>
                </tr>
              </tbody>
            </q-markup-table>
            <q-btn
              class="q-mt-md"
              color="primary"
              label="Change a boot value"
              data-test="boot-open"
              :disable="!store.editableBootKeys.length"
              @click="openBootDialog"
            />
            <div class="text-caption text-muted q-mt-sm">
              Changes route through the server-side operator proxy and require a reason plus a typed restart
              confirmation. Sensitive values are write-only and never shown.
            </div>
          </q-card-section>
        </q-card>
      </q-tab-panel>

      <!-- AI Connection -->
      <q-tab-panel name="ai" class="q-pa-none">
        <q-card flat bordered>
          <q-card-section>
            <div class="row items-center q-gutter-sm">
              <div class="text-subtitle1">AI Connection</div>
              <CdStateBadge :kind="aiStateKind" :label="aiStateLabel" data-test="ai-state" />
            </div>
            <q-banner
              v-if="store.aiModelsError && !store.aiModels.length"
              dense
              rounded
              class="bg-orange-1 text-orange-9 q-mb-sm"
              data-test="ai-models-unavailable"
            >
              {{ store.aiModelsError }} — pick a model from the list once the proxy is reachable, or use the explicit
              free-text fallback.
            </q-banner>
            <q-banner
              v-if="store.lastAISave"
              dense
              rounded
              class="q-mb-sm"
              :class="store.lastAISave.applied ? 'bg-green-1 text-green-9' : 'bg-orange-1 text-orange-9'"
              data-test="ai-save-result"
            >
              {{ store.lastAISave.message }}
            </q-banner>
            <q-banner
              v-if="driftVisible"
              dense
              rounded
              class="bg-orange-1 text-orange-9 q-mb-sm"
              data-test="ai-drift"
            >
              Model drift: saved chat model <strong>{{ store.ai?.chat_model ?? '' }}</strong> vs active
              <strong>{{ store.aiDrift?.active_chat_model ?? 'unknown' }}</strong>
              · saved job model <strong>{{ store.ai?.job_model ?? '' }}</strong> vs active
              <strong>{{ store.aiDrift?.active_job_model ?? 'unknown' }}</strong>
              — the running otalon-ai does not serve the saved models yet. Saving again pushes live; otherwise recreate
              otalon-ai to apply the saved configuration.
            </q-banner>
            <div class="row q-col-gutter-md">
              <div class="col-12 col-md-3">
                <q-input v-model="aiForm.endpoint" label="Endpoint" outlined dense data-test="ai-endpoint" />
              </div>
              <div class="col-12 col-md-3">
                <q-select
                  v-if="!chatCustom"
                  v-model="aiForm.chat_model"
                  :options="chatModelOptions"
                  label="Chat model"
                  outlined
                  dense
                  emit-value
                  map-options
                  data-test="ai-chat"
                />
                <q-input v-else v-model="aiForm.chat_model" label="Chat model" outlined dense data-test="ai-chat" />
                <q-toggle
                  v-model="chatCustom"
                  dense
                  label="Use a model not in the list"
                  data-test="ai-chat-custom-toggle"
                />
                <div
                  v-if="chatCustom"
                  class="text-caption text-negative q-mt-xs"
                  data-test="ai-chat-unverified-warning"
                >
                  Warning: this model is not verified against the proxy and may be rejected or unavailable.
                </div>
              </div>
              <div class="col-12 col-md-3">
                <q-select
                  v-if="!jobCustom"
                  v-model="aiForm.job_model"
                  :options="jobModelOptions"
                  label="Job model"
                  outlined
                  dense
                  emit-value
                  map-options
                  data-test="ai-job"
                />
                <q-input v-else v-model="aiForm.job_model" label="Job model" outlined dense data-test="ai-job" />
                <q-toggle
                  v-model="jobCustom"
                  dense
                  label="Use a model not in the list"
                  data-test="ai-job-custom-toggle"
                />
                <div
                  v-if="jobCustom"
                  class="text-caption text-negative q-mt-xs"
                  data-test="ai-job-unverified-warning"
                >
                  Warning: this model is not verified against the proxy and may be rejected or unavailable.
                </div>
              </div>
              <div class="col-12 col-md-3">
                <q-input
                  v-model.number="aiForm.context_window"
                  type="number"
                  label="Context size (tokens)"
                  hint="Chat context window, 4096 to 1000000"
                  outlined
                  dense
                  data-test="ai-context-window"
                />
              </div>
            </div>
            <q-btn
              class="q-mt-md"
              color="primary"
              label="Save AI connection"
              data-test="ai-save"
              :loading="store.saving"
              @click="openAIDialog"
            />
            <q-separator class="q-my-md" />
            <div class="row items-center q-gutter-sm">
              <span class="text-weight-medium">API key</span>
              <CdStateBadge
                :kind="store.ai?.key_configured ? 'muted' : 'warn'"
                :label="store.ai?.key_configured ? 'configured · write-only' : 'not configured'"
                data-test="ai-key-state"
              />
              <q-btn flat dense color="primary" label="Replace key" data-test="ai-key-replace" @click="openKeyDialog" />
            </div>
            <q-btn
              class="q-mt-md"
              color="secondary"
              label="Test connection"
              data-test="ai-test"
              :disable="!store.aiTestable"
              :loading="testing"
              @click="testAI"
            />
            <div v-if="!store.aiTestable" class="text-caption text-muted q-mt-xs">
              Test is available once an endpoint and a key are configured.
            </div>
            <q-banner
              v-if="testResult"
              dense
              class="q-mt-sm"
              :class="testResult.success ? 'bg-positive text-white' : 'bg-negative text-white'"
              data-test="ai-test-result"
              >{{
                testResult.success ? 'AI connection succeeded.' : `AI connection failed: ${testResult.state}`
              }}</q-banner
            >
          </q-card-section>
        </q-card>
      </q-tab-panel>

      <q-tab-panel v-if="auth.isAdmin" name="access" class="q-pa-none">
        <AccessUsersPanel />
      </q-tab-panel>
      <q-tab-panel v-else-if="!auth.user" name="access" class="q-pa-none">
        <q-card flat bordered>
          <q-card-section>
            <div class="text-subtitle1">Access &amp; Users</div>
            <div
              v-for="section in ['Accounts', 'Roles', 'Sessions', 'Credentials', 'Recovery']"
              :key="section"
              class="row items-center justify-between q-py-sm"
              data-test="access-section"
            >
              <span>{{ section }}</span
              ><span class="text-caption text-muted">future contract · SUITE-016</span>
            </div>
          </q-card-section>
        </q-card>
      </q-tab-panel>

      <!-- Change History -->
      <q-tab-panel name="history" class="q-pa-none">
        <q-card flat bordered>
          <q-card-section>
            <div class="text-subtitle1">Change History</div>
            <q-list separator class="q-mt-sm">
              <q-item v-for="entry in store.history" :key="entry.id" data-test="history-entry">
                <q-item-section>
                  <q-item-label>{{ entry.action }} · {{ entry.target }}</q-item-label>
                  <q-item-label caption>{{ entry.at }} · {{ entry.actor }} · {{ entry.reason }}</q-item-label>
                </q-item-section>
                <q-item-section side>
                  <q-btn
                    flat
                    dense
                    color="primary"
                    label="Rollback"
                    data-test="history-rollback"
                    :disable="true"
                    @click="openRollbackDialog(entry)"
                  />
                </q-item-section>
              </q-item>
              <q-item v-if="!store.history.length">
                <q-item-section class="text-muted">No configuration audit entries.</q-item-section>
              </q-item>
            </q-list>
          </q-card-section>
        </q-card>
      </q-tab-panel>
    </q-tab-panels>

    <!-- Runtime single-key edit — type-appropriate control, no restart -->
    <q-dialog v-model="runtimeDialog">
      <q-card style="min-width: 380px; max-width: 90vw">
        <q-card-section class="text-subtitle1">
          Change <span class="cd-mono">{{ runtimeTarget?.key }}</span>
        </q-card-section>
        <q-card-section class="q-gutter-md">
          <div class="text-caption text-muted" data-test="runtime-dialog-description">
            {{ runtimeTarget?.description }}
          </div>

          <template v-if="runtimeTarget?.type === 'list'">
            <div class="text-caption text-muted" data-test="runtime-list-caption">
              Series Blacklist — one pattern per line: IP, MAC (wildcards allowed), protocol tag, or UCI with `*`
              fields.
            </div>
            <div
              v-for="(entry, index) in runtimeList"
              :key="`runtime-list-${index}`"
              class="row items-center q-gutter-sm"
              :data-test="`runtime-list-row-${index}`"
            >
              <q-input
                v-model="runtimeList[index]"
                :placeholder="RUNTIME_LIST_PLACEHOLDERS[index % RUNTIME_LIST_PLACEHOLDERS.length]"
                class="col"
                outlined
                dense
                data-test="runtime-list-input"
              />
              <q-btn
                flat
                dense
                color="negative"
                icon="delete"
                label="Remove entry"
                data-test="runtime-list-remove"
                @click="removeRuntimeListEntry(index)"
              />
            </div>
            <q-btn
              flat
              dense
              color="primary"
              icon="add"
              label="Add entry"
              data-test="runtime-list-add"
              @click="runtimeList.push('')"
            />
            <div class="text-caption text-muted" data-test="runtime-list-preview">
              Will be saved as <span class="cd-mono">{{ runtimeListPreview }}</span>
            </div>
          </template>
          <q-toggle
            v-else-if="runtimeTarget?.type === 'bool'"
            v-model="runtimeBool"
            :label="runtimeBool ? 'true' : 'false'"
            data-test="runtime-bool-input"
          />
          <q-input
            v-else
            v-model="runtimeValue"
            type="number"
            :step="runtimeTarget?.type === 'float' ? 'any' : '1'"
            :label="`New value (${runtimeTarget?.type})`"
            outlined
            dense
            data-test="runtime-value-input"
          />

          <div v-if="runtimeTarget?.domain" class="text-caption text-muted" data-test="runtime-domain-hint">
            Allowed domain: <span class="cd-mono">{{ runtimeTarget.domain }}</span> — enforced by the server.
          </div>
          <div v-if="runtimeDomainWarning" class="text-caption text-negative" data-test="runtime-domain-warning">
            {{ runtimeDomainWarning }}
          </div>

          <q-input
            v-model="runtimeReason"
            label="Reason (optional, audited)"
            outlined
            dense
            data-test="runtime-reason-input"
          />

          <q-banner dense rounded class="bg-blue-1 text-blue-9" data-test="runtime-dialog-no-restart">
            Applies within one poll cycle — <strong>no restart</strong> of {{ runtimeTarget?.service }} is required.
          </q-banner>

          <InsufficientPermissionsNotice :message="store.runtimeError" />
          <q-banner
            v-if="store.runtimeError && !isInsufficientPermissionsMessage(store.runtimeError)"
            dense
            rounded
            class="bg-red-1 text-red-9"
            data-test="runtime-dialog-error"
          >
            {{ store.runtimeError }}
          </q-banner>
        </q-card-section>
        <q-card-actions align="right">
          <q-btn flat label="Cancel" data-test="runtime-cancel" @click="runtimeDialog = false" />
          <q-btn
            color="primary"
            label="Apply"
            data-test="runtime-apply"
            :loading="Boolean(store.runtimeSavingKey)"
            @click="confirmRuntime"
          />
        </q-card-actions>
      </q-card>
    </q-dialog>

    <!-- Boot change + restart-impact + typed confirmation -->
    <q-dialog v-model="bootDialog" persistent>
      <q-card style="min-width: 360px; max-width: 90vw">
        <q-card-section class="text-subtitle1">Change a boot value</q-card-section>
        <q-card-section class="q-gutter-md">
          <q-select
            v-model="bootKey"
            :options="store.editableBootKeys"
            label="Key"
            outlined
            dense
            data-test="boot-key-select"
            @update:model-value="onBootKeyChange"
          />
          <q-input v-model="bootValue" label="New value" outlined dense data-test="boot-value-input" />
          <q-input v-model="bootReason" label="Reason (audited)" outlined dense data-test="boot-reason-input" />
          <q-banner dense class="bg-orange-1 text-orange-9" data-test="boot-impact">
            Restart impact: recreates
            <strong>{{ bootAffected.join(', ') || 'no services' }}</strong>
            with a brief downtime for those services while they restart.
          </q-banner>
          <q-input
            v-model="bootConfirm"
            :label="`Type ${CONFIRM_APPLY} to confirm`"
            outlined
            dense
            data-test="boot-confirm-input"
          />
        </q-card-section>
        <q-card-actions align="right">
          <q-btn flat label="Cancel" @click="bootDialog = false" />
          <q-btn
            color="primary"
            label="Apply & recreate"
            data-test="boot-apply"
            :disable="true"
            :loading="store.saving"
            @click="confirmBoot"
          />
        </q-card-actions>
      </q-card>
    </q-dialog>

    <!-- AI save + recreate notice -->
    <q-dialog v-model="aiDialog" persistent>
      <q-card style="min-width: 360px; max-width: 90vw">
        <q-card-section class="text-subtitle1">Save AI connection</q-card-section>
        <q-card-section class="q-gutter-md">
          <q-banner dense class="bg-blue-1 text-blue-9" data-test="ai-save-dialog-live-hint">
            Saving writes the configuration and pushes it to the running otalon-ai. If the live push fails, the saved
            values apply on the next recreate of otalon-ai.
          </q-banner>
          <q-input v-model="aiReason" label="Reason (optional, audited)" outlined dense data-test="ai-reason-input" />
        </q-card-section>
        <q-card-actions align="right">
          <q-btn flat label="Cancel" @click="aiDialog = false" />
          <q-btn
            color="primary"
            label="Save"
            data-test="ai-save-confirm"
            :loading="store.saving"
            @click="confirmAI"
          />
        </q-card-actions>
      </q-card>
    </q-dialog>

    <!-- Write-only AI key replace -->
    <q-dialog v-model="keyDialog" persistent>
      <q-card style="min-width: 360px; max-width: 90vw">
        <q-card-section class="text-subtitle1">Replace AI key</q-card-section>
        <q-card-section class="q-gutter-md">
          <q-input
            v-model="keyValue"
            type="password"
            label="New key (write-only)"
            outlined
            dense
            data-test="ai-key-input"
          />
          <q-input v-model="keyReason" label="Reason (audited)" outlined dense data-test="ai-key-reason" />
          <div class="text-caption text-muted">The stored key is never shown; this replaces it in full.</div>
        </q-card-section>
        <q-card-actions align="right">
          <q-btn flat label="Cancel" @click="keyDialog = false" />
          <q-btn
            color="primary"
            label="Replace"
            data-test="ai-key-confirm"
            :disable="true"
            :loading="store.saving"
            @click="confirmKey"
          />
        </q-card-actions>
      </q-card>
    </q-dialog>

    <!-- Rollback + typed confirmation -->
    <q-dialog v-model="rollbackDialog" persistent>
      <q-card style="min-width: 360px; max-width: 90vw">
        <q-card-section class="text-subtitle1">Confirm rollback</q-card-section>
        <q-card-section class="q-gutter-md">
          <div>
            Re-apply the prior value for <strong>{{ rollbackTarget }}</strong> and append a new audit row?
          </div>
          <q-input v-model="rollbackReason" label="Reason (audited)" outlined dense data-test="rollback-reason-input" />
          <q-input
            v-model="rollbackConfirm"
            :label="`Type ${CONFIRM_ROLLBACK} to confirm`"
            outlined
            dense
            data-test="rollback-confirm-input"
          />
        </q-card-section>
        <q-card-actions align="right">
          <q-btn flat label="Cancel" @click="rollbackDialog = false" />
          <q-btn
            color="primary"
            label="Roll back"
            data-test="rollback-apply"
            :disable="true"
            :loading="store.saving"
            @click="confirmRollback"
          />
        </q-card-actions>
      </q-card>
    </q-dialog>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { Notify } from 'quasar'
import { useConfigurationStore, type ConfigHistoryItem } from '~/stores/configurationStore'
import type { RuntimeConfigItem } from '~/types/api'
import { usePolling } from '~/composables/usePolling'
import { OPERATIONS_HEAVY_POLL_INTERVAL_MS, useOperationsRefresh } from '~/composables/useOperationsRefresh'
import CdStateBadge from '~/components/operations/StateBadge.vue'
import AccessUsersPanel from '~/components/identity/AccessUsersPanel.vue'
import InsufficientPermissionsNotice from '~/components/shared/InsufficientPermissionsNotice.vue'
import { useAuthStore } from '~/stores/authStore'
import { isInsufficientPermissionsMessage } from '~/utils/permissions'

definePageMeta({ title: 'Operations / Configuration' })

const CONFIRM_APPLY = 'APPLY'
const CONFIRM_ROLLBACK = 'ROLLBACK'

const store = useConfigurationStore()
const auth = useAuthStore()
const route = useRoute()
const operationsRefresh = useOperationsRefresh()
const tab = ref(route.query.tab === 'access' && auth.isAdmin ? 'access' : 'runtime')

const aiStateLabel = computed(() => store.ai?.state ?? 'not-configured')
const aiStateKind = computed<'ok' | 'warn' | 'err' | 'muted' | 'info'>(() => {
  if (store.ai?.state === 'failed') return 'err'
  if (store.ai?.state === 'ready') return 'ok'
  if (store.ai?.state === 'testing') return 'info'
  return 'muted'
})

// ---- Runtime edit dialog ----
const runtimeDialog = ref(false)
const runtimeTarget = ref<RuntimeConfigItem | null>(null)
const runtimeValue = ref('')
const runtimeBool = ref(false)
const runtimeList = ref<string[]>([])
const runtimeReason = ref('')

/**
 * Placeholders naming the accepted series-blacklist entry forms, rotating
 * per row so each form is discoverable while editing.
 */
const RUNTIME_LIST_PLACEHOLDERS = [
  '192.168.0.1',
  '33:33:*',
  'IPv6',
  'Ethernet:ARP',
  '50:61:d6:00:ba:b2/*/*/IPv4/192.168.0.51',
]

/** Metadata of the most recent accepted runtime write, if any. */
const lastApply = computed(() => store.lastRuntimeApply)

/**
 * Render an ISO timestamp in the operator's local time.
 *
 * @param iso - ISO-8601 timestamp from the API.
 * @returns Localized date and time, or the raw value when unparseable.
 */
function formatTimestamp(iso: string): string {
  const parsed = new Date(iso)
  return Number.isNaN(parsed.getTime()) ? iso : parsed.toLocaleString()
}

/** The value that would be submitted, normalized to the API's string form. */
const runtimeSubmitValue = computed(() => {
  const target = runtimeTarget.value
  if (target?.type === 'bool') return String(runtimeBool.value)
  if (target?.type === 'list' || runtimeTarget.value?.type === 'list') return runtimeListJson.value
  return runtimeValue.value.trim()
})

/**
 * Trimmed, non-empty entries of the list editor.
 *
 * Empty and whitespace-only entries are dropped on submit rather than
 * rejected, so clearing a row is a valid way to remove it.
 */
const runtimeListEntries = computed<string[]>(() =>
  runtimeList.value.map((entry) => entry.trim()).filter((entry) => entry !== ''),
)

/** Canonical JSON serialization the server persists for the list value. */
const runtimeListJson = computed(() => JSON.stringify(runtimeListEntries.value))

/** Live preview of the JSON array the Apply button would send. */
const runtimeListPreview = computed(() => runtimeListJson.value)

function removeRuntimeListEntry(index: number): void {
  runtimeList.value.splice(index, 1)
}

function parseRuntimeList(value: string): string[] {
  try {
    const parsed: unknown = JSON.parse(value)
    if (!Array.isArray(parsed)) return [...value]
    const entries = parsed.filter((entry): entry is string => typeof entry === 'string')
    return entries.length === parsed.length ? entries : [...value]
  } catch {
    return [...value]
  }
}

/**
 * Client-side domain hint for numeric keys.
 *
 * Parses the inclusive/exclusive interval notation the registry emits
 * (for example `[10, 3600]` or `(0, 0.5]`) purely to warn early. The server
 * remains the authority and its rejection message is shown verbatim.
 */
const runtimeDomainWarning = computed<string | null>(() => {
  const target = runtimeTarget.value
  if (!target || target.type === 'bool' || !target.domain) return null
  const raw = runtimeSubmitValue.value
  if (raw === '') return null
  const parsed = Number(raw)
  if (Number.isNaN(parsed)) return `Enter a valid ${target.type}.`
  if (target.type === 'int' && !Number.isInteger(parsed)) return 'Enter a whole number.'
  const match = target.domain.match(/^([[(])\s*(-?[\d.]+)\s*,\s*(-?[\d.]+)\s*([\])])$/)
  if (!match) return null
  const [, lowBracket, lowRaw, highRaw, highBracket] = match
  const low = Number(lowRaw)
  const high = Number(highRaw)
  const lowOk = lowBracket === '[' ? parsed >= low : parsed > low
  const highOk = highBracket === ']' ? parsed <= high : parsed < high
  return lowOk && highOk ? null : `Outside the allowed domain ${target.domain}.`
})

function openRuntimeDialog(item: RuntimeConfigItem): void {
  store.runtimeError = ''
  store.lastRuntimeApply = null
  runtimeTarget.value = item
  runtimeReason.value = ''
  if (item.type === 'bool') {
    runtimeBool.value = item.value === 'true'
    runtimeValue.value = ''
  } else if (item.type === 'list') {
    runtimeList.value = parseRuntimeList(item.value)
    runtimeValue.value = ''
  } else {
    runtimeValue.value = item.value
  }
  runtimeDialog.value = true
}

async function confirmRuntime(): Promise<void> {
  const target = runtimeTarget.value
  if (!target) return
  const reason = runtimeReason.value.trim()
  try {
    const result = await store.saveRuntime({
      service: target.service,
      key: target.key,
      value: runtimeSubmitValue.value,
      ...(reason ? { reason } : {}),
    })
    runtimeDialog.value = false
    Notify.create({
      type: 'positive',
      message: result.restart_required
        ? `Applied ${result.changed_keys.join(', ')} — restart required`
        : `Applied ${result.changed_keys.join(', ')} — active within one poll cycle`,
    })
  } catch {
    // server message surfaced verbatim via store.runtimeError in the dialog
  }
}

// ---- Boot change dialog ----
const bootDialog = ref(false)
const bootKey = ref<string | null>(null)
const bootValue = ref('')
const bootReason = ref('')
const bootConfirm = ref('')
const bootAffected = computed(() => (bootKey.value ? (store.boot?.affected_services[bootKey.value] ?? []) : []))
const bootReady = computed(
  () => Boolean(bootKey.value) && bootReason.value.trim().length >= 3 && bootConfirm.value === CONFIRM_APPLY,
)

/** Load the currently selected key's saved value into the New value field. */
function loadBootValueForKey(key: string | null): void {
  bootValue.value = key && !store.isSensitiveKey(key) ? (store.boot?.env[key] ?? '') : ''
}

/** Keep New value in sync with the selected key so a switch never sends a stale value. */
function onBootKeyChange(key: string | null): void {
  loadBootValueForKey(key)
}

function openBootDialog(): void {
  bootKey.value = store.editableBootKeys[0] ?? null
  loadBootValueForKey(bootKey.value)
  bootReason.value = ''
  bootConfirm.value = ''
  bootDialog.value = true
}

async function confirmBoot(): Promise<void> {
  if (!bootReady.value || !bootKey.value) return
  try {
    await store.saveBoot({ key: bootKey.value, value: bootValue.value, reason: bootReason.value.trim() })
    bootDialog.value = false
    Notify.create({ type: 'positive', message: 'Boot configuration applied' })
  } catch {
    // error surfaced via store.error banner
  }
}

// ---- AI save dialog ----
const aiForm = reactive({ provider: '', endpoint: '', chat_model: '', job_model: '', context_window: 128000 })
const aiDialog = ref(false)
const aiReason = ref('')
const chatCustom = ref(false)
const jobCustom = ref(false)

/**
 * Selectable options for one model field: the proxy list plus a saved
 * model that is not offered (kept selectable so the current value stays
 * visible instead of silently changing meaning).
 */
/**
 * Selectable options for one model field: the proxy list plus a saved
 * model that is not offered (kept selectable so the current value stays
 * visible instead of silently changing meaning).
 */
function modelOptions(current: string): { label: string; value: string }[] {
  const values = new Set(store.aiModels)
  if (current) values.add(current)
  return [...values].map((value) => ({ label: value, value }))
}

const chatModelOptions = computed(() => modelOptions(aiForm.chat_model))
const jobModelOptions = computed(() => modelOptions(aiForm.job_model))

/**
 * Free-text fallback starts armed exactly when the saved model is not in
 * the proxy list — the operator keeps an unlisted value only explicitly.
 */
function syncCustomFlags(): void {
  chatCustom.value = Boolean(aiForm.chat_model) && !store.aiModels.includes(aiForm.chat_model)
  jobCustom.value = Boolean(aiForm.job_model) && !store.aiModels.includes(aiForm.job_model)
}

/** True when a drift indicator must be rendered (ui--ai-connection spec). */
const driftVisible = computed(() => store.aiDrift?.drift === true)

function syncAIForm(): void {
  // AI-045: provider is fixed to the only supported value; the field was not used by any logic.
  aiForm.provider = 'litellm'
  aiForm.endpoint = store.ai?.endpoint ?? ''
  aiForm.chat_model = store.ai?.chat_model ?? ''
  aiForm.job_model = store.ai?.job_model ?? ''
  aiForm.context_window = store.ai?.context_window ?? 128000
  syncCustomFlags()
}

function openAIDialog(): void {
  aiReason.value = ''
  aiDialog.value = true
}

async function confirmAI(): Promise<void> {
  const allowUnlisted =
    (chatCustom.value && Boolean(aiForm.chat_model)) || (jobCustom.value && Boolean(aiForm.job_model))
  try {
    const notice = await store.updateAI({
      provider: aiForm.provider,
      endpoint: aiForm.endpoint,
      chat_model: aiForm.chat_model,
      job_model: aiForm.job_model,
      context_window: Number(aiForm.context_window),
      reason: aiReason.value.trim(),
      ...(allowUnlisted ? { allow_unlisted_model: true } : {}),
    })
    aiDialog.value = false
    Notify.create({ type: notice.applied ? 'positive' : 'warning', message: notice.message })
  } catch {
    // error surfaced via store.error banner
  }
}

// ---- AI key replace dialog ----
const keyDialog = ref(false)
const keyValue = ref('')
const keyReason = ref('')

function openKeyDialog(): void {
  keyValue.value = ''
  keyReason.value = ''
  keyDialog.value = true
}

async function confirmKey(): Promise<void> {
  if (!keyValue.value || !keyReason.value.trim()) return
  try {
    await store.replaceAIKey(keyValue.value, keyReason.value.trim())
    keyValue.value = ''
    keyDialog.value = false
    Notify.create({ type: 'positive', message: 'AI key replaced — recreate otalon-ai to apply' })
  } catch {
    // error surfaced via store.error banner
  }
}

const testing = ref(false)
const testResult = ref<{ success: boolean; state: string } | null>(null)
async function testAI(): Promise<void> {
  testing.value = true
  try {
    const result = await store.testAI()
    testResult.value = result
    Notify.create({
      type: result.success ? 'positive' : 'negative',
      message: result.success ? 'AI connection ready' : 'AI connection failed',
    })
  } finally {
    testing.value = false
  }
}

// ---- Rollback dialog ----
const rollbackDialog = ref(false)
const rollbackEntryId = ref<number | null>(null)
const rollbackTarget = ref('')
const rollbackReason = ref('')
const rollbackConfirm = ref('')
const rollbackReady = computed(
  () =>
    rollbackEntryId.value !== null &&
    rollbackReason.value.trim().length >= 3 &&
    rollbackConfirm.value === CONFIRM_ROLLBACK,
)

function openRollbackDialog(entry: ConfigHistoryItem): void {
  if (!entry.rollback_eligible) return
  rollbackEntryId.value = entry.id
  rollbackTarget.value = entry.target
  rollbackReason.value = ''
  rollbackConfirm.value = ''
  rollbackDialog.value = true
}

async function confirmRollback(): Promise<void> {
  if (!rollbackReady.value || rollbackEntryId.value === null) return
  try {
    await store.rollback(rollbackEntryId.value, rollbackReason.value.trim())
    rollbackDialog.value = false
    Notify.create({ type: 'positive', message: 'Rollback applied' })
  } catch {
    // error surfaced via store.error banner
  }
}

onMounted(async () => {
  operationsRefresh.register(
    () => store.fetchAll(),
    () => store.loading,
  )
  await operationsRefresh.refresh()
  syncAIForm()
  await store.fetchAIModels()
  syncCustomFlags()
})

onUnmounted(operationsRefresh.unregister)

usePolling(operationsRefresh.refresh, OPERATIONS_HEAVY_POLL_INTERVAL_MS)
</script>

<style scoped>
.configuration-page {
  min-width: 0;
}
.config-table {
  max-width: 100%;
  overflow-x: auto;
}
.cd-mono {
  font-family: monospace;
}
.runtime-service-row td {
  background: rgba(127, 127, 127, 0.08);
  font-size: 12px;
  letter-spacing: 0.4px;
  text-transform: uppercase;
}
</style>
