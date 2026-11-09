<template>
  <div class="system-page">
    <q-banner dense class="bg-grey-2 text-grey-8 q-mb-md" data-test="operations-admin-boundary">
      Reset, Restore, and Service Action require an active admin product session and backend authorization.
    </q-banner>
    <InsufficientPermissionsNotice :message="store.error || store.actionError" />
    <q-banner v-if="store.error && !isInsufficientPermissionsMessage(store.error)" class="bg-negative text-white q-mb-md" role="alert">{{ store.error }}</q-banner>
    <q-banner v-if="store.actionError && !isInsufficientPermissionsMessage(store.actionError)" class="bg-negative text-white q-mb-md" role="alert">{{
      store.actionError
    }}</q-banner>

    <q-tabs v-model="tab" dense align="left" no-caps class="q-mb-md" active-color="primary" indicator-color="primary">
      <q-tab name="services" label="Services & Logs" />
      <q-tab name="storage" label="Storage & Retention" />
      <q-tab name="backup" label="Backup & Update" />
      <q-tab name="health" label="Health Check & Support" />
      <q-tab name="reset" label="Data Reset & Cleanup" />
    </q-tabs>

    <q-tab-panels v-model="tab" animated>
      <q-tab-panel name="services" class="q-pa-none">
        <q-card flat bordered>
          <q-card-section class="row items-center"
            ><span class="text-subtitle1">Services</span><q-space /><span class="text-caption text-muted"
              >Lifecycle actions are audited jobs.</span
            ></q-card-section
          >
          <q-separator />
          <q-markup-table v-if="store.services.length" flat dense class="system-services-table">
            <thead>
              <tr>
                <th class="text-left">Service</th>
                <th class="text-left">Health</th>
                <th class="text-left">Port</th>
                <th class="text-left">Detail</th>
                <th class="text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="service in store.services" :key="service.name">
                <td class="text-weight-medium">{{ service.name }}</td>
                <td>
                  <CdStateBadge
                    :kind="serviceBadgeKind(service.status)"
                    :label="service.status"
                    :icon="serviceBadgeIcon(service.status)"
                  />
                </td>
                <td>{{ service.ports || '—' }}</td>
                <td class="text-caption">{{ service.image || '—' }}</td>
                <td class="text-right">
                  <q-btn flat dense label="Logs" @click="showLogs(service.name)" /><q-btn-dropdown
                    v-if="!isCore(service)"
                    flat
                    dense
                    label="Actions"
                    :disable="!auth.isAdmin"
                    :data-test="`service-actions-${service.name}`"
                  >
                    <q-list dense>
                      <q-item
                        v-for="action in actionsFor(service)"
                        :key="action"
                        v-close-popup
                        clickable
                        @click="openServiceConfirm(service.name, action)"
                        ><q-item-section>{{ actionLabel(action) }}</q-item-section></q-item
                      >
                    </q-list>
                  </q-btn-dropdown>
                  <div v-if="!auth.isAdmin && !isCore(service)" class="text-caption text-muted">
                    Admin session required
                  </div>
                </td>
              </tr>
            </tbody>
          </q-markup-table>
          <q-card-section v-if="!store.services.length && !store.isLoading" class="text-muted"
            >No service data is available.</q-card-section
          >
          <q-card-section v-if="selectedLog" data-test="log-viewer"
            ><div class="text-subtitle2">Logs: {{ selectedLog }}</div>
            <pre class="log-viewer">{{ store.logs[selectedLog] || 'No log output returned.' }}</pre>
          </q-card-section>
        </q-card>
      </q-tab-panel>

      <q-tab-panel name="storage" class="q-pa-none">
        <q-card v-if="store.storage" flat bordered
          ><q-card-section
            ><div class="text-subtitle1">Host Disk</div>
            <div v-for="(mount, path) in store.storage.host.mounts" :key="path" class="q-mb-sm">
              <div class="text-weight-medium">{{ path }}</div>
              <div v-if="mount.purpose" class="text-caption text-muted">{{ mount.purpose }}</div>
              <div>
                {{ decimalGb(mount.used_gb) }} GB used · {{ decimalGb(mount.free_gb) }} GB free of
                {{ decimalGb(mount.total_gb) }} GB ({{ mount.used_pct }}%)
              </div>
              <q-linear-progress class="q-mt-xs" :value="mount.used_pct / 100" /></div></q-card-section
          ><q-separator /><q-card-section
            ><div class="text-subtitle1">PCAP Ringbuffer</div>
            <div>
              {{ decimalGb(store.storage.ringbuffer.size_gb) }} / {{ decimalGb(store.storage.ringbuffer.cap_gb) }} GB,
              {{ store.storage.ringbuffer.files }} / {{ store.storage.ringbuffer.file_cap }} files
            </div>
            <div class="text-caption text-muted">Only configured ringbuffer caps are shown.</div></q-card-section
          ><q-separator /><q-card-section
            ><div class="text-subtitle1">Disk Use Contributors</div>
            <q-markup-table flat dense
              ><thead>
                <tr>
                  <th class="text-left">Store</th>
                  <th class="text-right">Size</th>
                  <th class="text-left">Note</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="item in store.storage.contributors" :key="item.name">
                  <td>{{ item.name }}</td>
                  <td class="text-right">{{ decimalGb(item.size_gb) }} GB</td>
                  <td>{{ item.note }}</td>
                </tr>
                <tr>
                  <td><strong>Unattributed</strong></td>
                  <td class="text-right">{{ decimalGb(store.storage.unattributed_gb) }} GB</td>
                  <td>Remaining host usage</td>
                </tr>
              </tbody></q-markup-table
            ></q-card-section
          ></q-card
        >
        <q-card v-else flat bordered
          ><q-card-section class="text-muted">Storage data is unavailable.</q-card-section></q-card
        >
      </q-tab-panel>

      <q-tab-panel name="backup" class="q-pa-none"
        ><div class="row q-col-gutter-md">
          <div class="col-12 col-md-7">
            <q-card flat bordered
              ><q-card-section
                ><div class="text-subtitle1">Backup & Restore</div>
                <div v-if="store.backups">
                  Last backup: {{ store.backups.created_at }} ({{ store.backups.stale ? 'stale' : 'fresh' }})
                </div>
                <div v-else class="text-muted">No verified backup is recorded.</div>
                <q-select
                  v-model="store.selectedArtifactId"
                  :options="artifactOptions"
                  emit-value
                  map-options
                  label="Backup artifact"
                  outlined
                  dense
                  class="q-mt-md"
                  clearable
                />
                <q-option-group v-model="backupScope" :options="backupOptions" type="checkbox" class="q-mt-md" /><q-btn
                  color="primary"
                  label="Run backup"
                  class="q-mt-md"
                  disable
                  data-test="backend-pending-mutation"
                  @click="runBackup"
                /><q-btn
                  outline
                  color="primary"
                  label="Restore"
                  class="q-mt-md q-ml-sm"
                  data-test="restore-open"
                  :disable="!auth.isAdmin"
                  @click="restoreOpen = true"
                />
                <div class="text-caption text-muted q-mt-sm" data-test="restore-note">
                  <span v-if="auth.isAdmin">Admin session enables compatibility checks and live confirmation.</span>
                  <span v-else>Preview only. An active admin session is required.</span>
                  Production has no live restore executor; authorized live attempts return 503.
                </div></q-card-section
              ><q-card-section v-if="backupAck" class="text-positive" data-test="backup-ack"
                >Backup {{ backupAck.job.display_id }} completed. <a href="/operations/jobs">View job</a>. Checksum:
                {{ backupAck.manifest.sha256 }}</q-card-section
              ></q-card
            >
          </div>
          <div class="col-12 col-md-5">
            <q-card flat bordered
              ><q-card-section
                ><div class="text-subtitle1">Version & Update</div>
                <div v-if="store.version">Suite {{ store.version.suite.version }}</div>
                <div v-if="store.version" class="text-caption">Build {{ store.version.suite.build_ref }}</div>
                <q-list v-if="store.version" dense class="q-mt-sm"
                  ><q-item v-for="component in store.version.components" :key="component.name"
                    ><q-item-section>{{ component.name }}</q-item-section
                    ><q-item-section side>{{ component.version }} · {{ component.build_ref }}</q-item-section></q-item
                  ></q-list
                >
                <div v-else class="text-muted">Version data is unavailable.</div>
                <div class="text-caption q-mt-sm">
                  Update checks are manual only and do not call home automatically.
                </div>
                <q-btn
                  outline
                  color="primary"
                  label="Check for updates"
                  class="q-mt-md"
                  disable
                  data-test="backend-pending-mutation"
                  @click="store.checkUpdates()"
                />
                <div v-if="store.update" class="q-mt-sm">
                  Registry contacted: {{ store.update.registry_contacted ? 'yes' : 'no' }}
                </div></q-card-section
              ></q-card
            >
          </div>
        </div></q-tab-panel
      >

      <q-tab-panel name="health" class="q-pa-none"
        ><div class="row q-col-gutter-md">
          <div class="col-12 col-md-7">
            <q-card flat bordered class="q-mb-md">
              <q-card-section class="row items-center q-gutter-sm">
                <div class="text-subtitle1">Health incident history</div>
                <q-space />
                <q-select
                  v-model="incidentStatus"
                  :options="incidentStatusOptions"
                  emit-value
                  map-options
                  multiple
                  outlined
                  dense
                  options-dense
                  label="State"
                  style="min-width: 190px"
                />
                <q-select
                  v-model="incidentService"
                  :options="incidentServices"
                  outlined
                  dense
                  options-dense
                  clearable
                  label="Service"
                  style="min-width: 170px"
                />
              </q-card-section>
              <q-separator />
              <q-list v-if="filteredIncidents.length" separator>
                <template v-for="incident in filteredIncidents" :key="incident.id">
                  <q-item
                    clickable
                    :active="route.query.incident === incident.id"
                    active-class="incident-selected"
                    :class="{ 'incident-row--selected': route.query.incident === incident.id }"
                    :aria-expanded="route.query.incident === incident.id"
                    :aria-controls="
                      route.query.incident === incident.id ? `health-incident-detail-${incident.id}` : undefined
                    "
                    @click="selectIncident(incident.id)"
                  >
                    <q-item-section>
                      <q-item-label>{{ incident.service }} · {{ incident.category }}</q-item-label>
                      <q-item-label caption
                        >{{ incident.status === 'active' ? 'Active' : 'Recovered' }} ·
                        {{ incident.cause }}</q-item-label
                      >
                    </q-item-section>
                    <q-item-section side class="row items-center q-gutter-xs">
                      <q-badge :color="incident.acknowledged ? 'grey' : 'warning'">{{
                        incident.acknowledged ? 'Acknowledged' : 'Unacknowledged'
                      }}</q-badge>
                      <q-btn
                        v-if="!incident.acknowledged"
                        flat
                        dense
                        no-caps
                        label="Acknowledge"
                        :loading="incidentsStore.isAcknowledging(incident.id)"
                        :disable="incidentsStore.isAcknowledging(incident.id)"
                        :aria-busy="incidentsStore.isAcknowledging(incident.id)"
                        :aria-label="`Acknowledge health incident for ${incident.service}`"
                        :data-test="`acknowledge-${incident.id}`"
                        @click.stop="acknowledgeIncident(incident.id)"
                      />
                      <span>{{ formatIncidentDate(incident.last_seen) }}</span>
                    </q-item-section>
                  </q-item>
                  <q-card
                    v-if="route.query.incident === incident.id && incidentsStore.isDetailLoading"
                    :id="`health-incident-detail-${incident.id}`"
                    flat
                    bordered
                    class="q-ma-sm"
                    data-test="health-incident-loading"
                  >
                    <q-card-section class="row items-center q-gutter-sm"
                      ><q-spinner color="primary" /><span>Loading health evidence...</span></q-card-section
                    >
                  </q-card>
                  <q-card
                    v-else-if="route.query.incident === incident.id && incidentsStore.selected"
                    :id="`health-incident-detail-${incident.id}`"
                    flat
                    bordered
                    class="q-ma-sm"
                    data-test="health-incident-detail"
                  >
                    <q-card-section class="row items-center"
                      ><div>
                        <div class="text-subtitle1">Health evidence</div>
                        <div class="text-caption text-muted">{{ incidentsStore.selected.cause }}</div>
                      </div>
                      <q-space /><q-btn
                        flat
                        round
                        dense
                        icon="close"
                        aria-label="Close health evidence"
                        @click="closeIncident"
                    /></q-card-section>
                    <q-separator />
                    <q-list dense data-test="health-incident-evidence">
                      <q-item
                        ><q-item-section>Incident ID</q-item-section
                        ><q-item-section side
                          ><span class="incident-id" data-test="health-incident-id">{{
                            incidentsStore.selected.id
                          }}</span></q-item-section
                        ></q-item
                      >
                      <q-item
                        ><q-item-section>State</q-item-section
                        ><q-item-section side
                          >{{ incidentsStore.selected.status === 'active' ? 'Active' : 'Recovered' }} ·
                          {{ incidentsStore.selected.acknowledged ? 'Acknowledged' : 'Unacknowledged' }}</q-item-section
                        ></q-item
                      >
                      <q-item
                        ><q-item-section>First seen</q-item-section
                        ><q-item-section side>{{
                          formatIncidentDate(incidentsStore.selected.first_seen)
                        }}</q-item-section></q-item
                      >
                      <q-item
                        ><q-item-section>Last seen</q-item-section
                        ><q-item-section side>{{
                          formatIncidentDate(incidentsStore.selected.last_seen)
                        }}</q-item-section></q-item
                      >
                      <q-item v-if="incidentsStore.selected.recovered_at"
                        ><q-item-section>Recovered</q-item-section
                        ><q-item-section side>{{
                          formatIncidentDate(incidentsStore.selected.recovered_at)
                        }}</q-item-section></q-item
                      >
                      <q-item
                        ><q-item-section>Samples</q-item-section
                        ><q-item-section side
                          >{{ incidentsStore.selected.failure_count }} failures /
                          {{ incidentsStore.selected.sample_count }} total</q-item-section
                        ></q-item
                      >
                      <q-item
                        ><q-item-section>Latency</q-item-section
                        ><q-item-section side
                          >{{ incidentsStore.selected.worst_latency_ms }} ms worst /
                          {{ incidentsStore.selected.latency_budget_ms }} ms budget</q-item-section
                        ></q-item
                      >
                    </q-list>
                    <q-card-section>
                      <div class="text-subtitle2">
                        Timeline
                        <span class="text-caption text-muted"
                          >latest {{ incidentsStore.selected.samples?.length ?? 0 }} of
                          {{ incidentsStore.selected.sample_count }} samples</span
                        >
                      </div>
                      <q-list dense separator data-test="health-incident-excerpt">
                        <q-item
                          v-for="sample in incidentsStore.selected.samples ?? []"
                          :key="`${sample.timestamp}-${sample.detail}`"
                        >
                          <q-item-section>
                            <q-item-label
                              >{{ sample.running ? 'In budget' : 'Failed' }} · {{ sample.latency_ms }} ms</q-item-label
                            >
                            <q-item-label caption>{{ sample.detail }}</q-item-label>
                          </q-item-section>
                        </q-item>
                      </q-list>
                    </q-card-section>
                  </q-card>
                </template>
              </q-list>
              <q-banner
                v-if="incidentsStore.acknowledgeError"
                dense
                class="bg-negative text-white"
                role="alert"
                data-test="acknowledge-error"
              >
                {{ incidentsStore.acknowledgeError }}
              </q-banner>
              <q-card-section v-else-if="!filteredIncidents.length" class="text-muted"
                >No incidents match selected filters.</q-card-section
              >
              <q-card-section class="text-caption text-muted"
                >Operational evidence retained up to {{ incidentsStore.retention.max_incidents }} incidents /
                {{ incidentsStore.retention.max_days }} days. Not immutable Change Audit.</q-card-section
              >
            </q-card>
          </div>
          <div class="col-12 col-md-5">
            <q-card flat bordered class="q-mb-md"
              ><q-card-section
                ><div class="text-subtitle1">System Health Check</div>
                <div class="text-caption text-muted">Read-only pipeline self-test.</div>
                <q-btn
                  color="primary"
                  label="Run health check"
                  class="q-mt-md"
                  @click="store.runHealthCheck()"
                /><q-list v-if="store.health" separator class="q-mt-md"
                  ><q-item v-for="finding in store.health.findings" :key="finding.name"
                    ><q-item-section
                      ><q-item-label class="row items-center q-gutter-sm"
                        ><span>{{ finding.name }}</span
                        ><CdStateBadge :kind="findingKind(finding.status)" :label="finding.status" /></q-item-label
                      ><q-item-label caption
                        >{{ finding.detail
                        }}<span v-if="finding.remediation">. {{ finding.remediation }}</span></q-item-label
                      ></q-item-section
                    ></q-item
                  ></q-list
                >
                <div v-else class="text-caption text-muted q-mt-md">
                  No health check has run in this session.
                </div></q-card-section
              ></q-card
            >
            <q-card flat bordered
              ><q-card-section
                ><div class="text-subtitle1">Support Bundle</div>
                <div class="text-caption text-muted">
                  Preview privacy boundaries before creating a local, never-uploaded archive.
                </div>
                <q-btn
                  outline
                  color="primary"
                  label="Preview support bundle"
                  class="q-mt-md"
                  @click="previewSupport"
                /><q-btn
                  v-if="store.support"
                  outline
                  color="primary"
                  label="Create local bundle"
                  class="q-mt-md q-ml-sm"
                  disable
                  data-test="backend-pending-mutation"
                  @click="createSupport"
                />
                <div v-if="store.support" class="q-mt-md">
                  <div><strong>Privacy:</strong> {{ store.support.privacy_scope }}</div>
                  <div><strong>Included:</strong> {{ store.support.included.join(', ') }}</div>
                  <div><strong>Excluded:</strong> {{ store.support.excluded.join(', ') }}</div>
                  <div><strong>Redacted:</strong> {{ store.support.redacted.join(', ') }}</div>
                  <div v-if="supportAck" class="text-positive q-mt-sm" data-test="support-ack">
                    Created {{ supportAck.path }} ({{ supportAck.sha256 }})
                  </div>
                </div></q-card-section
              ></q-card
            >
          </div>
        </div></q-tab-panel
      >

      <q-tab-panel name="reset" class="q-pa-none"
        ><q-card flat bordered class="reset-card"
          ><q-card-section
            ><div class="text-subtitle1">Data Reset & Cleanup</div>
            <div class="text-caption text-muted">
              Named domain actions only. Each requires a reason and exact typed confirmation.
            </div></q-card-section
          ><q-separator /><q-list separator
            ><q-item v-for="item in resetOptions" :key="item.scope"
              ><q-item-section
                ><q-item-label>{{ item.label }}</q-item-label
                ><q-item-label caption>{{ item.description }}</q-item-label></q-item-section
              ><q-item-section side
                ><q-btn
                  outline
                  color="primary"
                  label="Review"
                  data-test="reset-review"
                  @click="previewPostgres(item.scope)" /></q-item-section></q-item></q-list
          ><q-banner class="q-ma-md bg-grey-2 text-dark" data-test="factory-coming-later">
            <strong>Factory reset</strong> — Coming later. This operation is not available from this interface. </q-banner
          ><q-btn
            outline
            color="primary"
            label="Preview InfluxDB timeseries"
            class="q-ma-md"
            data-test="reset-influx-preview"
            @click="previewInflux"
          />
          <div v-if="resetPreview" class="q-ma-md text-caption" data-test="reset-preview">
            <div>Target: {{ resetPreview.target }}</div>
            <div>Scope: {{ resetPreview.scope }}</div>
            <div v-if="resetPreview.tables">Tables: {{ (resetPreview.tables as string[]).join(', ') || 'none' }}</div>
            <div v-if="resetPreview.measurements">
              Measurements: {{ (resetPreview.measurements as string[]).join(', ') || 'none' }}
            </div>
            <div>Executed: {{ resetPreview.executed ? 'yes' : 'no' }}</div>
            <div class="text-muted">Read-only impact preview. No reset is executed from this control.</div>
            <q-btn
              v-if="previewResetScope"
              outline
              color="negative"
              label="Continue to confirmation"
              class="q-mt-md"
              data-test="reset-confirm-open"
              @click="openResetConfirm"
            />
          </div>
          <q-banner v-if="staleBackup" class="q-ma-md bg-warning text-dark" data-test="factory-backup-prereq"
            >Factory reset requires a recent verified FULL backup ({{ FULL_BACKUP_SCOPE.join(', ') }}). The backend
            returns 409 until that prerequisite is met.</q-banner
          ><q-banner v-if="resetResult" class="q-ma-md bg-grey-2 text-dark" data-test="reset-result">
            Reset result: executed={{ resetResult.executed ? 'yes' : 'no' }}; scope={{ resetResult.scope }}; tables={{
              resetResult.tables.join(', ') || 'none'
            }}.
          </q-banner></q-card
        ></q-tab-panel
      >
    </q-tab-panels>

    <q-dialog v-model="confirmOpen"
      ><q-card style="min-width: min(420px, 90vw)"
        ><q-card-section
          ><div class="text-subtitle1">Confirm {{ pendingAction || pendingReset }}</div>
          <div v-if="pendingReset" class="q-mt-sm">
            Scope: {{ pendingReset }}. Recovery requires a verified backup and audit record.
          </div>
          <div v-if="!auth.isAdmin" class="text-warning q-mt-sm" data-test="mutation-admin-required">
            Active admin session required. This control is preview-only for operator and viewer sessions.
          </div>
          <q-input
            v-if="pendingReset"
            v-model="reason"
            label="Reason (required)"
            type="textarea"
            outlined
            class="q-mt-md" /><q-input
            v-model="phrase"
            outlined
            class="q-mt-md"
            :label="`Type ${requiredPhrase}`"
            autocomplete="off" /></q-card-section
        ><q-card-actions align="right"
          ><q-btn flat label="Cancel" @click="closeConfirm" /><q-btn
            v-if="pendingReset"
            color="negative"
            label="Confirm"
            :disable="!auth.isAdmin || !resetConfirmReady"
            data-test="mutation-confirm-submit"
            @click="confirmAction" /><q-btn
            v-else
            color="negative"
            label="Confirm"
            :disable="!auth.isAdmin || !serviceConfirmReady"
            data-test="mutation-confirm-submit"
            @click="confirmAction" /></q-card-actions></q-card
    ></q-dialog>
    <q-dialog v-model="restoreOpen"
      ><q-card style="min-width: min(420px, 90vw)"
        ><q-card-section
          ><div class="text-subtitle1">Restore pre-check</div>
          <div class="text-caption">
            Compatibility is checked first. A database restore requires typed confirmation and never runs without it.
          </div>
          <q-btn
            outline
            label="Run compatibility pre-check"
            class="q-mt-md"
            data-test="restore-precheck"
            :disable="!auth.isAdmin"
            @click="runRestorePrecheck" />
          <div v-if="restoreResult" class="q-mt-md" data-test="restore-precheck-result">
            <div>Backup available: {{ restoreResult.backup_available ? 'yes' : 'no' }}</div>
            <div>Compatible: {{ restoreResult.compatible ? 'yes' : 'no' }}</div>
            <div v-if="restoreResult.backup_stale" class="text-warning">Latest verified backup is stale.</div>
            <div class="text-caption text-muted">
              Production has no live restore executor; API errors remain visible.
            </div>
          </div>
          <q-input
            v-if="restoreResult?.compatible"
            v-model="phrase"
            outlined
            label="Type RESTORE DATABASE"
            class="q-mt-md" /></q-card-section
        ><q-card-actions align="right"
          ><q-btn v-close-popup flat label="Cancel" /><q-btn
            color="primary"
            label="Confirm Restore"
            :disable="!restoreConfirmReady"
            data-test="restore-confirm-submit"
            @click="runRestore" /></q-card-actions></q-card
    ></q-dialog>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, watch } from 'vue'
import {
  useSystemStore,
  type ResetScope,
  type RestorePrecheck,
  type ServiceAction,
  type SystemService,
} from '~/stores/systemStore'
import CdStateBadge from '~/components/operations/StateBadge.vue'
import InsufficientPermissionsNotice from '~/components/shared/InsufficientPermissionsNotice.vue'
import { usePolling } from '~/composables/usePolling'
import { OPERATIONS_HEAVY_POLL_INTERVAL_MS, useOperationsRefresh } from '~/composables/useOperationsRefresh'
import { useHealthIncidentsStore, type HealthIncidentStatusFilter } from '~/stores/healthIncidentsStore'
import { useAuthStore } from '~/stores/authStore'
import { isInsufficientPermissionsMessage } from '~/utils/permissions'

definePageMeta({ title: 'Operations / System' })
const store = useSystemStore()
const auth = useAuthStore()
const incidentsStore = useHealthIncidentsStore()
const operationsRefresh = useOperationsRefresh()
const route = useRoute()
const tab = ref(
  typeof route.query.tab === 'string' && ['services', 'storage', 'backup', 'health', 'reset'].includes(route.query.tab)
    ? route.query.tab
    : 'services',
)
const incidentStatus = ref<HealthIncidentStatusFilter[]>(['active', 'recovered'])
const incidentService = ref<string | null>(null)
const incidentStatusOptions = [
  { label: 'Active', value: 'active' },
  { label: 'Recovered', value: 'recovered' },
]
const filteredIncidents = computed(() =>
  incidentsStore.history.filter((incident) => {
    const statusMatches = incidentStatus.value.includes(incident.status)
    return statusMatches && (!incidentService.value || incident.service === incidentService.value)
  }),
)
const incidentServices = computed(() => [...new Set(incidentsStore.history.map((incident) => incident.service))])

function closeIncident(): void {
  incidentsStore.clearSelection()
  const query = { ...route.query }
  delete query.incident
  void navigateTo({ path: route.path, query })
}

async function selectIncident(id: string): Promise<void> {
  await navigateTo({ path: route.path, query: { ...route.query, tab: 'health', incident: id } })
}

async function acknowledgeIncident(id: string): Promise<void> {
  await incidentsStore.acknowledge(id)
}

watch(
  () => [route.query.tab, route.query.incident] as const,
  async ([routeTab, value]) => {
    const activeTab = typeof routeTab === 'string' ? routeTab : 'services'
    tab.value = ['services', 'storage', 'backup', 'health', 'reset'].includes(activeTab) ? activeTab : 'services'
    if (tab.value !== 'health' || typeof value !== 'string' || !value) {
      incidentsStore.clearSelection()
      return
    }
    await incidentsStore.select(value)
  },
  { immediate: true },
)
const selectedLog = ref<string | null>(null)
const backupScope = ref(['config'])
const backupAck = ref<Awaited<ReturnType<typeof store.runBackup>>>(null)
const supportAck = ref<Awaited<ReturnType<typeof store.createSupportBundle>>>(null)
const restoreResult = ref<RestorePrecheck | null>(null)
const resetResult = ref<Awaited<ReturnType<typeof store.reset>>>(null)
const resetPreview = ref<Record<string, unknown> | null>(null)
const previewResetScope = ref<ResetScope | null>(null)
const backupOptions = [
  { label: 'Configuration', value: 'config' },
  { label: 'PostgreSQL (runtime source required)', value: 'postgresql' },
  { label: 'Models and bounds (runtime source required)', value: 'models' },
  { label: 'PCAP Baselines', value: 'baselines' },
  { label: 'PCAP archive', value: 'pcap_archive' },
]
const restoreOpen = ref(false)
const confirmOpen = ref(false)
const pendingAction = ref<ServiceAction | null>(null)
const pendingService = ref<string | null>(null)
const pendingReset = ref<ResetScope | null>(null)
const reason = ref('')
const phrase = ref('')
const resetOptions: Array<{ scope: ResetScope; label: string; description: string }> = [
  {
    scope: 'anomaly-history',
    label: 'Clear Anomalies & Alarms',
    description: 'Remove stored anomaly and alarm records (PostgreSQL anomalies + alarms tables).',
  },
  {
    scope: 'trained-bounds',
    label: 'Drop Bounds',
    description: 'Remove trained bounds and require retraining.',
  },
  {
    scope: 'detection-results',
    label: 'Clear Anomaly Records',
    description:
      'Remove stored anomaly records (PostgreSQL anomalies table) only. Does not touch alarms or InfluxDB time-series.',
  },
]
const FULL_BACKUP_SCOPE = ['config', 'postgresql', 'models', 'baselines', 'pcap_archive']
const staleBackup = computed(() => {
  const backup = store.backups
  if (!backup || !backup.verified || backup.stale) return true
  const scope = new Set(backup.scope ?? [])
  return !FULL_BACKUP_SCOPE.every((entry) => scope.has(entry))
})
const artifactOptions = computed(() =>
  store.backupCatalog.map((item) => ({
    label: `${item.artifact_name} · ${item.scope.join(', ')} · ${item.verified ? 'verified' : 'unverified'} · ${item.archive_bytes} bytes`,
    value: item.artifact_id,
  })),
)
const requiredPhrase = computed(() =>
  pendingReset.value
    ? `RESET ${pendingReset.value.toUpperCase()}`
    : `CONFIRM ${(pendingAction.value ?? '').toUpperCase()} ${pendingService.value ?? ''}`,
)
const resetConfirmReady = computed(() => reason.value.trim().length > 0 && phrase.value === requiredPhrase.value)
const restoreConfirmReady = computed(
  () => auth.isAdmin && restoreResult.value?.compatible === true && phrase.value === 'RESTORE DATABASE',
)
const serviceConfirmReady = computed(
  () => auth.isAdmin && phrase.value === requiredPhrase.value && Boolean(pendingService.value && pendingAction.value),
)
const isCore = (service: SystemService): boolean =>
  service.core_db === true || service.coreDb === true || ['postgres', 'influxdb3'].includes(service.name)
const actionsFor = (service: SystemService): ServiceAction[] =>
  service.status.toLowerCase().includes('stop') ? ['up', 'restart'] : ['restart', 'stop']
const actionLabel = (action: ServiceAction): string =>
  action === 'up' ? 'Start' : action[0].toUpperCase() + action.slice(1)
async function showLogs(name: string): Promise<void> {
  if (!store.services.some((service) => service.name === name)) return
  selectedLog.value = name
  await store.fetchLogs(name)
}
function formatIncidentDate(value: string): string {
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString()
}
function openServiceConfirm(name: string, action: ServiceAction): void {
  pendingService.value = name
  pendingAction.value = action
  pendingReset.value = null
  phrase.value = ''
  confirmOpen.value = true
}
function closeConfirm(): void {
  confirmOpen.value = false
  pendingAction.value = null
  pendingService.value = null
  pendingReset.value = null
}
function openResetConfirm(): void {
  if (!previewResetScope.value) return
  pendingReset.value = previewResetScope.value
  pendingAction.value = null
  pendingService.value = null
  reason.value = ''
  phrase.value = ''
  confirmOpen.value = true
}
async function confirmAction(): Promise<void> {
  if (pendingReset.value) {
    resetResult.value = await store.reset(pendingReset.value, reason.value.trim(), phrase.value, auth.isAdmin)
  } else if (pendingService.value && pendingAction.value)
    await store.serviceAction(pendingService.value, pendingAction.value, phrase.value)
  closeConfirm()
}
async function runBackup(): Promise<void> {
  backupAck.value = await store.runBackup(backupScope.value)
}
async function runRestore(): Promise<void> {
  await store.restore(['postgresql'], phrase.value, true)
  restoreOpen.value = false
  phrase.value = ''
}
async function runRestorePrecheck(): Promise<void> {
  restoreResult.value = await store.restore(['postgresql'])
}
async function createSupport(): Promise<void> {
  supportAck.value = await store.createSupportBundle()
}
async function previewSupport(): Promise<void> {
  await store.loadSupportPreview()
}
onMounted(() => {
  const service = typeof route.query.service === 'string' ? route.query.service : null
  operationsRefresh.register(
    () => store.load(),
    () => store.isLoading,
  )
  void (async () => {
    await operationsRefresh.refresh()
    if (tab.value === 'services' && service) await applyServiceDeepLink(service)
  })()
  void incidentsStore.fetchHistory()
})

async function applyServiceDeepLink(serviceId: string): Promise<void> {
  await nextTick()
  await showLogs(serviceId)
}

watch(
  () => route.query.service,
  (service) => {
    if (tab.value === 'services' && typeof service === 'string') void applyServiceDeepLink(service)
  },
)

watch(incidentStatus, (statuses) => {
  void incidentsStore.fetchHistory(statuses.length === 1 ? statuses[0] : undefined)
})

onUnmounted(operationsRefresh.unregister)

usePolling(operationsRefresh.refresh, OPERATIONS_HEAVY_POLL_INTERVAL_MS)

function decimalGb(value: number): string {
  return typeof value === 'number' && Number.isFinite(value) ? value.toFixed(2) : '—'
}
function findingKind(status: string): 'ok' | 'warn' | 'err' | 'muted' | 'info' {
  return status === 'pass' ? 'ok' : status === 'fail' ? 'err' : status === 'warn' ? 'warn' : 'muted'
}
function serviceBadgeKind(status: string): 'ok' | 'warn' | 'err' | 'muted' | 'info' {
  const normalized = status.toLowerCase()
  if (normalized.includes('error') || normalized.includes('fail')) return 'err'
  if (normalized.includes('warn') || normalized.includes('degrad')) return 'warn'
  if (normalized.includes('run') || normalized.includes('up') || normalized.includes('healthy')) return 'ok'
  if (normalized.includes('start') || normalized.includes('init')) return 'info'
  return 'muted'
}
function serviceBadgeIcon(status: string): string {
  return serviceBadgeKind(status) === 'err' ? 'error' : serviceBadgeKind(status) === 'warn' ? 'warning' : 'check_circle'
}
async function previewPostgres(scope: ResetScope): Promise<void> {
  previewResetScope.value = scope
  resetPreview.value = await store.previewPostgresqlReset(scope)
}
async function previewInflux(): Promise<void> {
  previewResetScope.value = null
  resetPreview.value = await store.previewInfluxReset('timeseries')
}
</script>

<style scoped lang="scss">
.system-page {
  width: 100%;
}
.log-viewer {
  max-height: 280px;
  overflow: auto;
  white-space: pre-wrap;
  background: var(--cd-surface);
  padding: 12px;
}
.reset-card {
  border-color: rgba(var(--cd-danger-rgb), 0.35);
}
.incident-id {
  font-family: var(--cd-font-mono, monospace);
  font-size: 0.8rem;
  word-break: break-all;
}
.incident-row--selected {
  background: rgba(var(--cd-primary-rgb), 0.08);
}
</style>
