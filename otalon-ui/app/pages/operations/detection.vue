<template>
  <div class="cd-detection-page">
    <InsufficientPermissionsNotice :message="store.error" />
    <q-banner
      v-if="store.error && !isInsufficientPermissionsMessage(store.error)"
      rounded
      class="bg-negative text-white q-mb-md"
      >{{ store.error }}</q-banner
    >
    <div class="detection-command-bar" data-test="detection-command-bar">
      <q-tabs v-model="tab" dense no-caps align="left" active-color="primary" indicator-color="primary">
        <q-tab name="readiness" label="Readiness" />
        <q-tab name="training" label="Training" />
        <q-tab name="bounds" label="Bound Review" />
        <q-tab name="rhythm" label="Cadence Review" data-test="tab-rhythm" />
      </q-tabs>
      <q-space />
      <div v-if="tab === 'training'" class="training-actions" data-test="training-command-bar">
        <ContextHelp
          label="About single-flight training behavior"
          text="Only one training request may run at a time. A second start is blocked until the active job reaches a terminal phase."
        />
        <q-btn
          v-if="store.trainingBusy || store.trainingError"
          flat
          dense
          no-caps
          to="/operations/jobs"
          label="Jobs &amp; History"
        />
      </div>
      <q-btn
        v-if="tab === 'bounds' || tab === 'rhythm'"
        flat
        dense
        no-caps
        icon="tune"
        label="Display Settings"
        aria-label="Display Settings"
        data-test="display-settings"
        @click="displaySettingsOpen = true"
      />
    </div>
    <q-tab-panels v-model="tab" animated>
      <!-- Readiness -->
      <q-tab-panel name="readiness" class="q-pa-none">
        <div class="row q-col-gutter-md">
          <div v-for="item in store.modules" :key="item.module" class="col-12 col-md-4">
            <q-card flat bordered class="full-height">
              <q-card-section class="row items-center">
                <span class="text-subtitle1 text-weight-bold">{{ friendlyModuleLabel(item.module) }}</span>
                <q-icon
                  name="info"
                  size="18px"
                  tabindex="0"
                  class="q-ml-xs text-grey-5"
                  :aria-label="`About ${friendlyModuleLabel(item.module)}`"
                >
                  <q-tooltip>{{ moduleHelp(item.module) }}</q-tooltip>
                </q-icon>
                <span class="text-caption text-muted q-ml-sm">{{ item.module }}</span>
                <q-space />
                <CdStateBadge :kind="stateKind(item.state)" :label="friendlyReadinessLabel(item.state)" />
                <q-icon
                  name="info"
                  size="18px"
                  tabindex="0"
                  class="q-ml-xs text-grey-5"
                  :aria-label="`About the ${friendlyReadinessLabel(item.state)} readiness state`"
                >
                  <q-tooltip>{{ readinessHelp(item.state) }}</q-tooltip>
                </q-icon>
              </q-card-section>
              <q-separator />
              <q-card-section class="stats">
                <span>Module</span><b>{{ item.detection_mode }}</b> <span>Bounds</span
                ><b :data-test="`bounds-gate-state-${item.module}`"
                  >{{ item.bounds_series_count }} ·
                  {{ gateStateLabel(item.module, 'bounds_enabled', item.bounds_state) }}</b
                >
                <span>NoBounds Series/UCI</span><b>{{ item.no_bounds_series_count ?? item.no_bounds_count }}</b>
                <span v-if="item.no_bounds_event_count !== undefined">Raw NoBounds events</span
                ><b v-if="item.no_bounds_event_count !== undefined">{{ item.no_bounds_event_count }}</b>
                <span>Cadence profiles</span>
                ><b :data-test="`frequency-gate-state-${item.module}`"
                  >{{ item.frequency_profile_count }} ·
                  {{ gateStateLabel(item.module, 'frequency_enabled', item.frequency_state) }}</b
                >
                <span>Last training</span><b>{{ formatDate(item.last_training) }}</b>
                <span v-if="item.classification_state">Classification</span
                ><b v-if="item.classification_state" :data-test="`classification-gate-state-${item.module}`">{{
                  item.classification_state
                }}</b>
              </q-card-section>
              <q-card-actions>
                <q-btn
                  v-if="noBoundsSeries(item)"
                  unelevated
                  no-caps
                  color="primary"
                  :label="`Review NoBounds Series (${noBoundsSeries(item)})`"
                  @click="openNoBounds(item.module)"
                >
                  <q-tooltip v-if="item.no_bounds_event_count !== undefined">
                    {{ noBoundsSeries(item) }} unique Series/UCI affected across {{ item.no_bounds_event_count }} raw
                    NoBounds events.
                  </q-tooltip>
                </q-btn>
                <q-btn
                  unelevated
                  color="secondary"
                  no-caps
                  :label="'Change detection modes'"
                  :loading="pendingGateModule === item.module"
                  :disable="runtimeGatePending"
                  :data-test="`change-detection-gates-${item.module}`"
                  @click="openModeDialog(item.module)"
                />
                <span
                  v-if="pendingGateModule === item.module"
                  class="text-caption text-info q-ml-sm"
                  data-test="gate-pending-card"
                >
                  Waiting for next detection poll
                </span>
              </q-card-actions>
            </q-card>
          </div>
        </div>
        <q-card flat bordered class="q-mt-md">
          <q-card-section class="text-subtitle1">Classifier artifacts</q-card-section>
          <q-markup-table flat dense>
            <thead>
              <tr>
                <th class="text-left">Artifact</th>
                <th class="text-left">Status</th>
                <th class="text-left">Training window</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="artifact in store.artifacts" :key="artifact.artifact">
                <td>{{ artifact.artifact }}</td>
                <td>{{ artifact.status }}</td>
                <td>{{ String(artifact.train_window ?? artifact.training_window ?? 'Not recorded') }}</td>
              </tr>
              <tr v-if="!store.artifacts.length">
                <td colspan="3">No classifier artifacts found.</td>
              </tr>
            </tbody>
          </q-markup-table>
        </q-card>
      </q-tab-panel>

      <!-- Training -->
      <q-tab-panel name="training" class="q-pa-none">
        <q-banner v-if="store.trainingBusy" dense rounded class="bg-info text-white q-mb-md">
          Detection stays online while the active training job runs. Progress is reported by truthful phase, never a
          percentage.
        </q-banner>
        <q-banner
          v-else-if="store.trainingError && !store.retrainCooldownActive"
          dense
          rounded
          class="bg-negative text-white q-mb-md"
          data-test="training-error-banner"
        >
          The last training run failed: {{ store.trainingError }}
          <template #action>
            <q-btn flat dense no-caps to="/operations/jobs" label="Jobs &amp; History" />
          </template>
        </q-banner>
        <q-banner
          v-if="store.retrainCooldownActive"
          dense
          rounded
          class="bg-warning text-dark q-mb-md"
          data-test="training-cooldown-banner"
        >
          Cooldown aktiv, wieder verfügbar in {{ cooldownMinutes }} min.
        </q-banner>
        <div class="training-console-frame">
          <div class="training-grid" data-test="training-grid">
            <q-card flat bordered class="training-panel">
              <q-card-section class="training-panel__header">
                <q-icon name="monitor_heart" color="primary" size="18px" aria-hidden="true" />
                <span class="training-panel__title">Bounds &amp; Cadence Training</span>
                <ContextHelp
                  label="About bounds and cadence training"
                  text="Selected windows read historical timeseries observations from InfluxDB. Bounds learn per-feature lower and upper normal envelopes. Cadence profiles learn normal recurrence and timing per series. Detection remains online and publication is atomic."
                  size="17px"
                />
                <q-space />
                <span class="training-panel__descriptor">per-series bounds + cadence profiles</span>
              </q-card-section>
              <q-card-section class="training-panel__body">
                <div class="training-section-heading">
                  <span>Windows</span>
                  <span class="training-section-heading__copy">Europe/Berlin · atomic union · gaps excluded</span>
                  <ContextHelp
                    label="About atomic interval union and gap exclusion"
                    text="All selected windows become one atomic job over their union. Time gaps between disjoint windows are excluded from training."
                  />
                  <ContextHelp
                    data-test="training-timezone-help"
                    label="About window time zone and UTC submission"
                    text="These datetime controls display and accept Europe/Berlin wall-clock time. The request converts each window to UTC before it is submitted, so the job runs against UTC instants regardless of daylight saving."
                  />
                </div>
                <div class="training-window-status" data-test="bounds-training-status">
                  <template
                    v-if="
                      store.trainingBusy &&
                      store.boundsTrainingStatus?.windowStart &&
                      store.boundsTrainingStatus?.windowStop
                    "
                  >
                    Training now: {{ formatTrainingWindow(store.boundsTrainingStatus) }}
                  </template>
                  <template
                    v-else-if="
                      store.lastBoundsTraining &&
                      store.lastBoundsTraining.windowStart &&
                      store.lastBoundsTraining.windowStop
                    "
                  >
                    <div class="training-window-list">
                      <div class="training-window-list__label">Last trained:</div>
                      <div
                        v-for="(win, index) in trainedWindows(store.lastBoundsTraining)"
                        :key="`bounds-last-${index}`"
                        class="training-window-list__row"
                      >
                        <span class="training-window-list__time"
                          >{{ formatDate(win[0]) }} → {{ formatDate(win[1]) }}</span
                        >
                        <q-btn
                          flat
                          round
                          dense
                          icon="add_circle_outline"
                          size="sm"
                          color="primary"
                          :aria-label="`Reuse bounds window ${index + 1}`"
                          data-test="reuse-bounds-window"
                          @click="reuseWindow('bounds', win)"
                        >
                          <q-tooltip>Add this window to the training list</q-tooltip>
                        </q-btn>
                      </div>
                    </div>
                  </template>
                  <span v-else>No training run yet</span>
                </div>
                <div class="interval-stack">
                  <div v-for="(interval, index) in boundsIntervals" :key="`bounds-${index}`" class="interval-entry">
                    <div class="interval-row">
                      <q-input
                        v-model="interval.start"
                        type="datetime-local"
                        outlined
                        dense
                        hide-bottom-space
                        :aria-label="`Bounds window ${index + 1} start (Europe/Berlin)`"
                        class="interval-row__input"
                      />
                      <span class="interval-arrow" aria-hidden="true">→</span>
                      <q-input
                        v-model="interval.end"
                        type="datetime-local"
                        outlined
                        dense
                        hide-bottom-space
                        :aria-label="`Bounds window ${index + 1} end (Europe/Berlin)`"
                        class="interval-row__input"
                      />
                      <span class="interval-duration">{{ intervalDuration(interval) }}</span>
                      <q-btn
                        flat
                        round
                        dense
                        icon="remove_circle_outline"
                        :disable="boundsIntervals.length === 1"
                        :aria-label="`Remove bounds window ${index + 1}`"
                        @click="boundsIntervals.splice(index, 1)"
                      >
                        <q-tooltip v-if="boundsIntervals.length === 1">At least one window is required.</q-tooltip>
                      </q-btn>
                    </div>
                  </div>
                </div>
                <q-btn
                  flat
                  dense
                  no-caps
                  icon="add"
                  label="Add window"
                  class="training-add-window"
                  @click="addInterval(boundsIntervals)"
                />
              </q-card-section>
              <q-card-section class="training-panel__footer" data-test="training-panel-footer">
                <div
                  class="interval-summary"
                  :class="`interval-summary--${intervalSummary(boundsIntervals).state}`"
                  data-test="bounds-interval-summary"
                >
                  <b>{{ intervalSummary(boundsIntervals).count }}</b>
                  {{ intervalSummary(boundsIntervals).count === 1 ? 'window' : 'windows' }} ·
                  <template v-if="intervalSummary(boundsIntervals).state === 'complete'">
                    union <b>{{ intervalSummary(boundsIntervals).unionMinutes }} min</b>
                  </template>
                  <template v-else-if="intervalSummary(boundsIntervals).state === 'incomplete'"> incomplete </template>
                  <template v-else-if="intervalSummary(boundsIntervals).state === 'duplicate'">
                    duplicate window
                  </template>
                  <template v-else> start must be before end </template>
                </div>
                <q-space />
                <q-btn
                  color="primary"
                  no-caps
                  label="Start training"
                  :disable="store.trainingBusy || store.retrainCooldownActive || !intervalsValid(boundsIntervals)"
                  data-test="start-bounds-training"
                  @click="startTraining"
                />
              </q-card-section>
            </q-card>
            <q-card flat bordered class="training-panel">
              <q-card-section class="training-panel__header">
                <q-icon name="memory" color="primary" size="18px" aria-hidden="true" />
                <span class="training-panel__title">ML / Classifier Training</span>
                <ContextHelp
                  label="About ML classifier training"
                  text="Historical observations in selected windows are matched against ground-truth label events to train the attack classifier. This does not change Bounds or Cadence profiles. Only one training job runs at a time."
                  size="17px"
                />
                <q-space />
                <span class="training-panel__descriptor">attack classifier from MITRE labels</span>
              </q-card-section>
              <q-card-section class="training-panel__body">
                <div class="training-section-heading">
                  <span>Windows</span>
                  <span class="training-section-heading__copy">Europe/Berlin · atomic union · gaps excluded</span>
                  <ContextHelp
                    label="About classifier interval union and gap exclusion"
                    text="Intervals are sent separately inside one atomic classifier job. Gaps remain untrained; they are not filled in by the UI."
                  />
                  <ContextHelp
                    data-test="classifier-timezone-help"
                    label="About window time zone and UTC submission"
                    text="These datetime controls display and accept Europe/Berlin wall-clock time. The request converts each window to UTC before it is submitted, so the job runs against UTC instants regardless of daylight saving."
                  />
                </div>
                <div class="training-window-status" data-test="classifier-training-status">
                  <template
                    v-if="
                      store.trainingBusy &&
                      store.classifierTrainingStatus?.windowStart &&
                      store.classifierTrainingStatus?.windowStop
                    "
                  >
                    Training now: {{ formatTrainingWindow(store.classifierTrainingStatus) }}
                  </template>
                  <template
                    v-else-if="
                      store.lastClassifierTraining &&
                      store.lastClassifierTraining.windowStart &&
                      store.lastClassifierTraining.windowStop
                    "
                  >
                    <div class="training-window-list">
                      <div class="training-window-list__label">Last trained:</div>
                      <div
                        v-for="(win, index) in trainedWindows(store.lastClassifierTraining)"
                        :key="`ml-last-${index}`"
                        class="training-window-list__row"
                      >
                        <span class="training-window-list__time"
                          >{{ formatDate(win[0]) }} → {{ formatDate(win[1]) }}</span
                        >
                        <q-btn
                          flat
                          round
                          dense
                          icon="add_circle_outline"
                          size="sm"
                          color="primary"
                          :aria-label="`Reuse classifier window ${index + 1}`"
                          data-test="reuse-classifier-window"
                          @click="reuseWindow('ml', win)"
                        >
                          <q-tooltip>Add this window to the training list</q-tooltip>
                        </q-btn>
                      </div>
                    </div>
                  </template>
                  <span v-else>No training run yet</span>
                </div>
                <div class="interval-stack">
                  <div
                    v-for="(interval, index) in classifierIntervals"
                    :key="`classifier-${index}`"
                    class="interval-entry"
                  >
                    <div class="interval-row">
                      <q-input
                        v-model="interval.start"
                        type="datetime-local"
                        outlined
                        dense
                        hide-bottom-space
                        :aria-label="`Classifier window ${index + 1} start (Europe/Berlin)`"
                        class="interval-row__input"
                      />
                      <span class="interval-arrow" aria-hidden="true">→</span>
                      <q-input
                        v-model="interval.end"
                        type="datetime-local"
                        outlined
                        dense
                        hide-bottom-space
                        :aria-label="`Classifier window ${index + 1} end (Europe/Berlin)`"
                        class="interval-row__input"
                      />
                      <span class="interval-duration">{{ intervalDuration(interval) }}</span>
                      <q-btn
                        flat
                        round
                        dense
                        icon="remove_circle_outline"
                        :disable="classifierIntervals.length === 1"
                        :aria-label="`Remove classifier window ${index + 1}`"
                        @click="classifierIntervals.splice(index, 1)"
                      >
                        <q-tooltip v-if="classifierIntervals.length === 1">At least one window is required.</q-tooltip>
                      </q-btn>
                    </div>
                  </div>
                </div>
                <q-btn
                  flat
                  dense
                  no-caps
                  icon="add"
                  label="Add window"
                  class="training-add-window"
                  @click="addInterval(classifierIntervals)"
                />
                <div class="training-section-heading training-section-heading--source">
                  <span>Label source</span>
                  <ContextHelp
                    label="About classifier label source"
                    text="MITRE ground-truth JSON maps historical observations to attack labels. Each entry requires module_name, start_time, and end_time; optional target and source fields refine matching. Select a validated Shared Models file or upload a JSON file."
                  />
                </div>
                <q-select
                  v-model="mitreFile"
                  :options="labelSourceOptions"
                  emit-value
                  map-options
                  outlined
                  dense
                  hide-bottom-space
                  label="Validated Shared Models source"
                  aria-label="MITRE label source"
                  class="label-source-input"
                  data-test="label-source-select"
                />
                <input
                  ref="labelSourceInput"
                  type="file"
                  accept="application/json,.json"
                  class="label-source-file"
                  data-test="label-source-file"
                  @change="onLabelSourceSelected"
                />
                <q-btn
                  outline
                  dense
                  no-caps
                  icon="upload_file"
                  label="Upload JSON"
                  data-test="upload-label-source"
                  @click="openLabelSourcePicker"
                />
                <div v-if="labelSourceError" class="text-negative text-caption" data-test="label-source-error">
                  {{ labelSourceError }}
                </div>
                <div v-if="store.labelSourceWarning" class="text-muted text-caption" data-test="label-source-warning">
                  {{ store.labelSourceWarning }}
                </div>
              </q-card-section>
              <q-card-section class="training-panel__footer" data-test="training-panel-footer">
                <div
                  class="interval-summary"
                  :class="`interval-summary--${intervalSummary(classifierIntervals).state}`"
                  data-test="classifier-interval-summary"
                >
                  <b>{{ intervalSummary(classifierIntervals).count }}</b>
                  {{ intervalSummary(classifierIntervals).count === 1 ? 'window' : 'windows' }} ·
                  <template v-if="intervalSummary(classifierIntervals).state === 'complete'">
                    union <b>{{ intervalSummary(classifierIntervals).unionMinutes }} min</b>
                  </template>
                  <template v-else-if="intervalSummary(classifierIntervals).state === 'incomplete'">
                    incomplete
                  </template>
                  <template v-else-if="intervalSummary(classifierIntervals).state === 'duplicate'">
                    duplicate window
                  </template>
                  <template v-else> start must be before end </template>
                </div>
                <q-space />
                <q-btn
                  color="primary"
                  no-caps
                  label="Start classifier training"
                  :disable="
                    store.trainingBusy ||
                    store.retrainCooldownActive ||
                    !intervalsValid(classifierIntervals) ||
                    !mitreFile.trim()
                  "
                  data-test="start-classifier-training"
                  @click="startClassifier"
                />
              </q-card-section>
            </q-card>
          </div>
          <q-card flat bordered class="baseline-panel" data-test="baseline-panel">
            <q-card-section class="training-panel__header">
              <q-icon name="inventory_2" color="primary" size="18px" aria-hidden="true" />
              <span class="training-panel__title">PCAP Baselines</span>
              <ContextHelp
                label="About PCAP baselines"
                text="PCAP baselines are curated quiet-traffic references for comparing training evidence. Exactly one may be active, and the active baseline cannot be deleted."
                size="17px"
              />
              <q-space />
              <span class="training-panel__descriptor">quiet-traffic references · one active</span>
            </q-card-section>
            <q-card-section class="baseline-panel__body">
              <div v-if="store.baselines.length" class="baseline-grid" data-test="baseline-grid">
                <article
                  v-for="baseline in store.baselines"
                  :key="String(baseline.id)"
                  class="baseline-item"
                  data-test="baseline-item"
                >
                  <div class="baseline-item__content">
                    <strong>{{ String(baseline.name) }}</strong>
                    <span>{{ String(baseline.start_ts) }} → {{ String(baseline.end_ts) }}</span>
                    <span>{{ baselineDetail(baseline) }}</span>
                  </div>
                  <CdStateBadge
                    :kind="baseline.is_active ? 'ok' : 'muted'"
                    :label="baseline.is_active ? 'Active' : 'Inactive'"
                  />
                  <ContextHelp
                    v-if="!baseline.is_active"
                    :label="`Activate baseline ${String(baseline.name)} unavailable`"
                    text="Activation is unavailable because no supported backend mutation exists."
                  >
                    <q-btn
                      flat
                      dense
                      no-caps
                      label="Activate"
                      disable
                      tabindex="-1"
                      data-test="backend-pending-mutation"
                    />
                  </ContextHelp>
                  <ContextHelp
                    :label="`Delete baseline ${String(baseline.name)} unavailable`"
                    :text="
                      baseline.is_active
                        ? 'The active baseline cannot be deleted.'
                        : 'Deletion is unavailable because no supported backend mutation exists.'
                    "
                  >
                    <q-btn
                      flat
                      dense
                      no-caps
                      label="Delete"
                      disable
                      tabindex="-1"
                      data-test="backend-pending-mutation"
                    />
                  </ContextHelp>
                </article>
              </div>
              <div v-else class="baseline-empty">No baselines available.</div>
              <div class="baseline-create-row" data-test="baseline-create-row">
                <q-input
                  v-model="newBaseline.name"
                  outlined
                  dense
                  hide-bottom-space
                  aria-label="Baseline name"
                  placeholder="Name"
                />
                <q-input
                  v-model="newBaseline.start"
                  type="datetime-local"
                  outlined
                  dense
                  hide-bottom-space
                  aria-label="Baseline start (Europe/Berlin)"
                />
                <q-input
                  v-model="newBaseline.end"
                  type="datetime-local"
                  outlined
                  dense
                  hide-bottom-space
                  aria-label="Baseline end (Europe/Berlin)"
                />
                <ContextHelp
                  label="Create baseline unavailable"
                  text="Creation is unavailable because no supported backend mutation exists."
                >
                  <q-btn
                    outline
                    dense
                    no-caps
                    label="Create"
                    disable
                    tabindex="-1"
                    data-test="backend-pending-mutation"
                    @click="createBaseline"
                  />
                </ContextHelp>
              </div>
            </q-card-section>
          </q-card>
        </div>
      </q-tab-panel>

      <!-- Bound Review -->
      <q-tab-panel name="bounds" class="q-pa-none">
        <div v-if="cardMode !== 'hidden'" class="bound-cards" :class="`mode-${cardMode}`">
          <q-card v-if="cardMode === 'full'" flat bordered class="bound-card total"
            ><q-card-section
              ><div class="text-caption">Active series in interval</div>
              <div class="bound-number">{{ statusCounts.total }}</div>
              <div class="text-caption text-muted">status computed against this set</div></q-card-section
            ></q-card
          >
          <template v-if="cardMode === 'full'">
            <q-card
              v-for="item in statusCardItems"
              :key="item.state"
              flat
              bordered
              class="bound-card"
              :class="item.className"
              :data-test="`status-card-${item.state}`"
              clickable
              @click="toggleStatus(item.state)"
            >
              <q-card-section
                ><div class="text-caption">
                  {{ item.label }}
                  <q-badge v-if="activeStates.has(item.state)" outline color="primary" label="filter on" />
                </div>
                <div class="bound-number">{{ statusCounts[item.state] }}</div>
                <div class="text-caption text-muted">{{ item.description }}</div></q-card-section
              >
            </q-card>
          </template>
          <div v-if="cardMode === 'compact'" class="bound-summary-strip" data-test="compact-summary-strip">
            <span class="bound-summary-total">{{ statusCounts.total }} active series</span>
            <button
              v-for="item in statusCardItems"
              :key="item.state"
              type="button"
              class="bound-summary-chip"
              :class="{ 'bound-summary-chip--active': activeStates.has(item.state) }"
              :aria-pressed="activeStates.has(item.state)"
              @click="toggleStatus(item.state)"
            >
              <span>{{ item.label }}</span
              ><b>{{ statusCounts[item.state] }}</b>
            </button>
          </div>
        </div>
        <div class="row q-col-gutter-sm q-mb-md">
          <q-select
            v-model="boundModule"
            :options="moduleOptions"
            emit-value
            map-options
            outlined
            dense
            label="Module"
            class="col-12 col-md-3 bound-filter-field"
            data-test="bound-module"
          />
          <q-select
            v-model="boundStateSelection"
            :options="stateFilterOptions"
            multiple
            use-chips
            outlined
            dense
            label="State"
            class="col-12 col-md-3"
            data-test="bound-state"
            :class="['bound-filter-field', 'bound-filter-field--state']"
          />
          <q-select
            v-model="range"
            :options="['1h', '6h', '24h', '7d', 'All', 'custom']"
            outlined
            dense
            label="Time range"
            class="col-12 col-md-2 bound-filter-field"
            data-test="bound-range"
          />
          <q-input
            v-model="search"
            outlined
            dense
            label="Search series"
            class="col-12 col-md-4 bound-filter-field"
            data-test="bound-search"
          />
        </div>
        <div v-if="range === 'custom'" class="row q-col-gutter-sm q-mb-md items-center">
          <q-input
            v-model="customFrom"
            type="datetime-local"
            outlined
            dense
            label="From (Europe/Berlin)"
            class="col-12 col-md-3 bound-filter-field"
            data-test="bound-from"
          />
          <q-input
            v-model="customTo"
            type="datetime-local"
            outlined
            dense
            label="To (Europe/Berlin, exclusive)"
            class="col-12 col-md-3"
            data-test="bound-to"
          />
          <div class="text-caption text-muted col-12 col-md-5">
            Events are filtered strictly on [from, to); an event exactly at "To" is excluded. Sent to the API as UTC.
          </div>
        </div>
        <q-table
          flat
          bordered
          :rows="boundRows"
          :columns="boundColumns"
          row-key="rowKey"
          :dense="density === 'dense'"
          :loading="store.loading"
          :pagination="boundPagination"
          :rows-per-page-options="[0]"
          binary-state-sort
          data-test="bound-review-table"
          @row-click="(_evt: unknown, row: BoundReviewItem) => openBound(row)"
        >
          <template #body-cell-module="props"
            ><q-td :props="props" data-test="bound-module-cell">
              <span class="module-friendly">{{ friendlyModuleLabel(props.row.module) }}</span>
              <div v-if="density !== 'dense'" class="text-caption text-muted">{{ props.row.module }}</div></q-td
            ></template
          >
          <template #body-cell-state="props">
            <q-td :props="props">
              <CdStateBadge :kind="stateBadgeKind(props.row.state)" :label="props.row.state" />
            </q-td>
          </template>
          <template #body-cell-series_id="props"
            ><q-td :props="props"
              ><div class="series-id" :title="props.row.series_id">
                {{ props.row.series_display ?? props.row.series_id }}
              </div>
              <div
                v-if="props.row.series_display && props.row.series_display !== props.row.series_id"
                class="text-caption text-muted"
              >
                {{ props.row.series_id }}
              </div>
              <div v-if="density !== 'dense'" class="text-caption text-muted">
                {{ props.row.affected_features?.length ?? 0 }} affected features
              </div></q-td
            ></template
          >
          <template #body-cell-last_event="props"
            ><q-td :props="props"
              >{{ formatDate(props.row.last_event) }}
              <div v-if="density !== 'dense'" class="text-caption text-muted">
                {{ eventCount(props.row) }} event(s) in interval
              </div></q-td
            ></template
          >
          <template #no-data
            ><div class="q-pa-xl text-center text-muted">
              {{
                activeStates.size === 0
                  ? 'No states selected. Select a State to show matching series.'
                  : 'No series match filters. Enable OK or widen interval to inspect more data.'
              }}
            </div></template
          >
        </q-table>
        <q-drawer
          v-model="boundDialog"
          side="right"
          overlay
          bordered
          :width="640"
          :breakpoint="700"
          class="bound-drawer"
        >
          <div class="drawer-shell">
            <div class="drawer-head">
              <div class="row items-center no-wrap drawer-head-line">
                <CdStateBadge :kind="stateBadgeKind(selectedBound?.state ?? '')" :label="selectedBound?.state ?? ''" />
                <span class="series-id drawer-series" :title="selectedBound?.series_id">{{
                  selectedBound?.series_display ?? selectedBound?.series_id
                }}</span>
                <q-btn flat round icon="close" aria-label="Close drawer" @click="boundDialog = false" />
              </div>
            </div>
            <q-tabs v-model="drawerTab" dense no-caps align="justify" active-color="primary" indicator-color="primary"
              ><q-tab name="overview" label="Overview" /><q-tab name="features" label="Features & Chart" /><q-tab
                name="correct"
                label="Correct"
            /></q-tabs>
            <q-separator />
            <div
              class="drawer-scroll"
              :class="{ 'drawer-scroll--flush': drawerTab === 'overview' }"
              data-test="bound-drawer-body"
            >
              <div v-if="drawerTab === 'overview'" class="overview-pane" data-test="overview-pane">
                <ContextHelp
                  class="q-mb-sm"
                  data-test="overview-help"
                  label="About this Bound Review state"
                  :text="overviewText"
                />
                <div class="drawer-kv overview-pane__kpis">
                  <div class="drawer-kpi-tile">
                    <span>Status priority</span><b>{{ selectedBound?.state }}</b>
                  </div>
                  <div class="drawer-kpi-tile">
                    <span>Events in interval</span><b>{{ selectedBound ? eventCount(selectedBound) : 0 }}</b>
                  </div>
                  <div class="drawer-kpi-tile">
                    <span>Affected features</span><b>{{ selectedBound?.affected_features?.length ?? 0 }}</b>
                  </div>
                  <div class="drawer-kpi-tile">
                    <span>Last trained</span><b>{{ formatDate(selectedBound?.last_trained_at ?? null) }}</b>
                  </div>
                </div>
                <div class="text-overline overview-pane__label">Event timeline</div>
                <ul class="timeline-list" data-test="overview-timeline">
                  <li
                    v-for="(event, index) in timelineEvents"
                    :key="`${event.ts}-${index}`"
                    class="timeline-row"
                    data-test="timeline-row"
                  >
                    <span class="timeline-row__ts">{{ formatDate(event.ts) }}</span>
                    <CdStateBadge :kind="stateBadgeKind(event.type)" :label="event.type" />
                    <span v-if="event.features.length" class="timeline-row__feat" :title="event.features.join(', ')">{{
                      event.features.join(', ')
                    }}</span>
                    <span v-else class="timeline-row__feat text-muted">no per-feature detail recorded</span>
                  </li>
                  <li v-if="!timelineEvents.length" class="timeline-row text-muted">No events in selected interval.</li>
                </ul>
              </div>
              <div v-else-if="drawerTab === 'features'">
                <div class="q-mb-sm">
                  <ContextHelp
                    data-test="features-help"
                    label="About Features & Chart"
                    text="Affected features and current bounds. Select a feature to inspect live interval values. NoBounds rows show values only; they do not fabricate bounds or violations."
                  />
                </div>
                <q-markup-table flat bordered dense
                  ><thead>
                    <tr>
                      <th class="text-left">Feature</th>
                      <th>Lower</th>
                      <th>Upper</th>
                      <th>Violations</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr
                      v-for="feature in detailFeatures"
                      :key="feature"
                      :class="{ 'feature-selected': selectedFeature === feature }"
                      @click="selectFeature(feature)"
                    >
                      <td>{{ feature }}</td>
                      <td>{{ boundValue(feature, 'lower') }}</td>
                      <td>{{ boundValue(feature, 'upper') }}</td>
                      <td>{{ selectedHasBounds ? featureViolationCount(feature) : 'No bound violations' }}</td>
                    </tr>
                    <tr v-if="!detailFeatures.length">
                      <td colspan="4">No feature-level bound data returned.</td>
                    </tr>
                  </tbody></q-markup-table
                >
                <div class="text-overline q-mt-md">
                  Feature chart <span v-if="selectedFeature">· {{ selectedFeature }}</span>
                </div>
                <TimeseriesChart
                  :data="focusedPlotData"
                  :show-bounds="selectedHasBounds"
                  :show-violations="selectedHasBounds"
                  :height="220"
                  data-test="drawer-chart"
                />
                <div v-if="plotLoading" class="text-caption text-muted">Loading selected feature data…</div>
                <div v-else-if="!plotData.length" class="text-caption text-muted">
                  No chart data in strict selected interval.
                </div>
                <div v-else-if="chartFocused" class="text-caption text-muted" data-test="chart-focus-note">
                  Focused on the anomaly window with edge padding. Bucket min/max preserve extrema, so a red point can
                  appear even when the bucket mean is within bounds.
                </div>
              </div>
              <div v-else class="correct-editor" data-test="correct-editor">
                <!-- Action tiles: NoBounds Create/Train, Violation Expand/Replace -->
                <div class="correction-tiles" role="group" :aria-label="`${correctionAction} action`">
                  <template v-if="!selectedHasBounds">
                    <button
                      type="button"
                      class="correction-tile"
                      :class="{ 'correction-tile--active': createSubMode === 'create' }"
                      :aria-pressed="createSubMode === 'create'"
                      data-test="tile-create"
                      @click="createSubMode = 'create'"
                    >
                      <q-icon name="fact_check" size="20px" />
                      <span class="correction-tile__title">Create from reviewed values</span>
                      <span class="correction-tile__desc">Review a server proposal or enter values manually.</span>
                    </button>
                    <button
                      type="button"
                      class="correction-tile"
                      :class="{ 'correction-tile--active': createSubMode === 'train' }"
                      :aria-pressed="createSubMode === 'train'"
                      data-test="tile-train"
                      @click="onSelectTrainTile"
                    >
                      <q-icon name="school" size="20px" />
                      <span class="correction-tile__title">Train from history</span>
                      <span class="correction-tile__desc">Use selected historical windows in Training.</span>
                    </button>
                  </template>
                  <template v-else>
                    <button
                      type="button"
                      class="correction-tile"
                      :class="{ 'correction-tile--active': correctionMode === 'expand' }"
                      :aria-pressed="correctionMode === 'expand'"
                      data-test="tile-expand"
                      @click="correctionMode = 'expand'"
                    >
                      <q-icon name="unfold_more" size="20px" />
                      <span class="correction-tile__title">Expand</span>
                      <span class="correction-tile__desc">Widen only; retains the current envelope.</span>
                    </button>
                    <button
                      type="button"
                      class="correction-tile"
                      :class="{ 'correction-tile--active': correctionMode === 'replace' }"
                      :aria-pressed="correctionMode === 'replace'"
                      data-test="tile-replace"
                      @click="correctionMode = 'replace'"
                    >
                      <q-icon name="published_with_changes" size="20px" />
                      <span class="correction-tile__title">Replace</span>
                      <span class="correction-tile__desc">Advanced: overwrites the full envelope.</span>
                    </button>
                  </template>
                </div>

                <!-- Suggest / status / safety / Apply — above the feature grid -->
                <div class="correction-actionbar" data-test="correction-actionbar">
                  <q-btn
                    flat
                    dense
                    no-caps
                    color="primary"
                    icon="auto_awesome"
                    label="Suggest proposed bounds"
                    data-test="suggest-bounds"
                    :loading="suggestionLoading"
                    @click="suggestBounds"
                  />
                  <q-space />
                  <ContextHelp
                    class="correction-safety-help"
                    data-test="correction-safety-help"
                    label="Safe apply gates"
                    text="Apply is one action. Internally it runs a non-mutating server validation, then a stale-before comparison, then a canonical audited job and history mutation. Operator authorization and explicit error handling are enforced by the API."
                  >
                    <span class="correction-safety-dot" aria-hidden="true">●</span>
                  </ContextHelp>
                  <q-btn
                    color="primary"
                    no-caps
                    label="Apply"
                    data-test="apply-correction"
                    :data-can-apply="canApply"
                    :loading="applyLoading"
                    :disable="!canApply || previewLoading || applyLoading"
                    @click="applyCorrection"
                  />
                </div>
                <div
                  v-if="suggestionEvidence"
                  class="suggestion-provenance suggestion-provenance--success"
                  data-test="suggestion-provenance"
                >
                  <q-icon name="verified" color="primary" size="16px" />
                  <div>
                    <strong>Server proposal · {{ suggestionEvidence.status }}</strong>
                    <span>
                      {{ suggestionEvidence.evidenceCount }} numeric observations · strict window [{{
                        suggestionEvidence.windowFrom
                      }}, {{ suggestionEvidence.windowTo }})
                    </span>
                  </div>
                </div>
                <div v-if="suggestionMessage" class="text-caption text-muted q-mt-xs" data-test="suggestion-result">
                  {{ suggestionMessage }}
                </div>
                <div
                  v-if="proposedValidationError"
                  class="text-negative text-caption q-mt-xs"
                  data-test="proposed-error"
                  role="alert"
                >
                  {{ proposedValidationError }}
                </div>
                <q-banner v-if="previewError" dense class="bg-negative text-white q-mt-sm" data-test="preview-error">{{
                  previewError
                }}</q-banner>

                <!-- Dense aligned Feature | Current | Proposed lower | Proposed upper grid -->
                <div class="proposed-grid" data-test="proposed-editor">
                  <div class="proposed-grid__head" aria-hidden="true">
                    <span>Feature</span><span>Current</span><span>Proposed lower</span><span>Proposed upper</span>
                  </div>
                  <div
                    v-for="feature in proposedFeatures"
                    :key="feature"
                    class="proposed-grid__row"
                    data-test="correction-feature-row"
                  >
                    <span class="proposed-grid__name" :title="feature">{{ feature }}</span>
                    <span class="proposed-grid__current">
                      <template v-if="selectedHasBounds"
                        >[{{ currentBoundValue(feature, 'lower') }},
                        {{ currentBoundValue(feature, 'upper') }}]</template
                      >
                      <template v-else>none</template>
                    </span>
                    <q-input
                      v-model.number="proposed[feature].lower"
                      dense
                      outlined
                      type="number"
                      :aria-label="`${feature} proposed lower bound`"
                      :data-test="`proposed-lower-${feature}`"
                    />
                    <q-input
                      v-model.number="proposed[feature].upper"
                      dense
                      outlined
                      type="number"
                      :aria-label="`${feature} proposed upper bound`"
                      :data-test="`proposed-upper-${feature}`"
                    />
                  </div>
                  <div v-if="!proposedFeatures.length" class="text-muted proposed-grid__empty">
                    No feature bounds available to edit.
                  </div>
                </div>

                <q-input
                  v-model="reason"
                  outlined
                  dense
                  type="textarea"
                  autogrow
                  label="Reason (optional, audited)"
                  class="q-mt-sm"
                  data-test="correction-reason"
                />
              </div>
            </div>
          </div>
        </q-drawer>
      </q-tab-panel>

      <!-- Rhythm Review — mockup 004 "Bound Review Mirror" -->
      <q-tab-panel name="rhythm" class="q-pa-none">
        <q-banner v-if="rhythm.error" rounded class="bg-negative text-white q-mb-md" data-test="rhythm-error">{{
          rhythm.error
        }}</q-banner>
        <div
          v-if="cardMode !== 'hidden'"
          class="bound-cards rhythm-cards"
          :class="`mode-${cardMode}`"
          data-test="rhythm-cards"
        >
          <q-card v-if="cardMode === 'full'" flat bordered class="bound-card total">
            <q-card-section>
              <div class="text-caption">Active profiles in fleet</div>
              <div class="bound-number">{{ rhythm.profiles.length }}</div>
              <div class="text-caption text-muted">status computed against this set</div>
            </q-card-section>
          </q-card>
          <template v-if="cardMode === 'full'">
            <q-card
              v-for="item in rhythmStatusCardItems"
              :key="item.state"
              flat
              bordered
              class="bound-card"
              :class="item.className"
              :data-test="`rhythm-status-card-${item.state}`"
              clickable
              @click="toggleRhythmState(item.state)"
            >
              <q-card-section>
                <div class="text-caption">
                  {{ item.label }}
                  <q-badge v-if="rhythmStates.has(item.state)" outline color="primary" label="filter on" />
                </div>
                <div class="bound-number">{{ rhythmStateCount(item.state) }}</div>
                <div class="text-caption text-muted">{{ item.description }}</div>
              </q-card-section>
            </q-card>
          </template>
          <div v-if="cardMode === 'compact'" class="bound-summary-strip" data-test="rhythm-compact-summary-strip">
            <span class="bound-summary-total">{{ rhythm.profiles.length }} active profiles</span>
            <button
              v-for="item in rhythmStatusCardItems"
              :key="item.state"
              type="button"
              class="bound-summary-chip"
              :class="{ 'bound-summary-chip--active': rhythmStates.has(item.state) }"
              :aria-pressed="rhythmStates.has(item.state)"
              @click="toggleRhythmState(item.state)"
            >
              <span>{{ item.label }}</span
              ><b>{{ rhythmStateCount(item.state) }}</b>
            </button>
          </div>
        </div>
        <div class="row q-col-gutter-sm q-mb-md items-center rhythm-filters" data-test="rhythm-filters">
          <q-select
            v-model="rhythmModule"
            :options="moduleOptions"
            emit-value
            map-options
            outlined
            dense
            label="Module"
            class="col-12 col-md-2 bound-filter-field rhythm-module-select"
            data-test="rhythm-module"
          />
          <q-select
            v-model="rhythmStateSelection"
            :options="RHYTHM_STATES"
            multiple
            use-chips
            outlined
            dense
            label="State"
            class="col-12 col-md-4 bound-filter-field bound-filter-field--state rhythm-state-select"
            data-test="rhythm-state"
          />
          <q-select
            v-model="rhythmRange"
            :options="['1h', '6h', '24h', '7d', 'All', 'custom']"
            outlined
            dense
            label="Time range"
            class="col-12 col-md-2 bound-filter-field rhythm-range-select"
            data-test="rhythm-range"
          />
          <q-input
            v-model="rhythmSearch"
            outlined
            dense
            label="Search series / UCI"
            class="col-12 col-md-2 bound-filter-field"
            data-test="rhythm-search"
          />
          <div class="col-12 col-md-2 text-caption text-muted rhythm-counts" data-test="rhythm-counts">
            <b>{{ rhythm.profiledCount }}</b> / {{ rhythm.profiles.length }} profiles ·
            <b>{{ rhythm.overriddenProfiles.length }}</b> with overrides ·
            <span data-test="rhythm-role-placeholder">Role: ot-operator · may edit overrides</span>
          </div>
        </div>
        <div v-if="rhythmRange === 'custom'" class="row q-col-gutter-sm q-mb-md items-center">
          <q-input
            v-model="rhythmCustomFrom"
            type="datetime-local"
            outlined
            dense
            label="From (Europe/Berlin)"
            class="col-12 col-md-3 bound-filter-field"
            data-test="rhythm-from"
          />
          <q-input
            v-model="rhythmCustomTo"
            type="datetime-local"
            outlined
            dense
            label="To (Europe/Berlin, exclusive)"
            class="col-12 col-md-3 bound-filter-field"
            data-test="rhythm-to"
          />
          <div class="text-caption text-muted col-12 col-md-5">
            Profiles are filtered by last seen time; this does not change learned cadence values.
          </div>
        </div>
        <q-table
          flat
          bordered
          :rows="rhythmRows"
          :columns="rhythmColumns"
          :row-key="rhythmRowKey"
          :dense="density === 'dense'"
          :loading="rhythm.loading"
          :pagination="rhythmPagination"
          :rows-per-page-options="[0]"
          binary-state-sort
          data-test="rhythm-review-table"
          @row-click="(_evt: unknown, row: FrequencyProfileResponse) => openRhythm(row)"
        >
          <template #body-cell-module="props">
            <q-td :props="props" data-test="rhythm-module-cell">
              <span class="module-friendly">{{ friendlyModuleLabel(props.row.module) }}</span>
              <div v-if="density !== 'dense'" class="text-caption text-muted">{{ props.row.module }}</div>
            </q-td>
          </template>
          <template #body-cell-state="props">
            <q-td :props="props">
              <CdStateBadge
                :kind="rhythmStateKind(rhythmEffectiveState(props.row))"
                :label="rhythmEffectiveState(props.row)"
              />
            </q-td>
          </template>
          <template #body-cell-series_id="props">
            <q-td :props="props">
              <div class="series-id" :title="props.row.series_id">{{ props.row.series_display ?? props.row.series_id }}</div>
              <div v-if="density !== 'dense'" class="text-caption text-muted">
                {{ cadenceLabel(props.row) }}
              </div>
            </q-td>
          </template>
          <template #body-cell-event_count="props">
            <q-td :props="props" data-test="rhythm-event-count-cell">
              {{ rhythmEventCount(props.row) }}
            </q-td>
          </template>
          <template #body-cell-last_seen="props">
            <q-td :props="props">
              {{ formatDate(props.row.last_seen) }}
              <div v-if="density !== 'dense'" class="text-caption text-muted">
                {{ rhythmEventCount(props.row) }} event(s) in interval
              </div>
            </q-td>
          </template>
          <template #no-data>
            <div class="q-pa-xl text-center text-muted" data-test="rhythm-empty">
              {{
                rhythmStates.size === 0
                  ? 'No states selected. Select a state to show matching profiles.'
                  : 'No frequency profiles match the current filters.'
              }}
            </div>
          </template>
        </q-table>
        <div class="cd-hintbar text-caption text-muted q-mt-xs">
          <span>Click a series to open its review drawer.</span>
        </div>

        <q-drawer
          v-model="rhythmDrawer"
          side="right"
          overlay
          bordered
          :width="640"
          :breakpoint="700"
          class="bound-drawer rhythm-drawer"
          data-test="rhythm-drawer"
        >
          <div class="drawer-shell">
            <div class="drawer-head">
              <div class="row items-center no-wrap drawer-head-line">
                <CdStateBadge
                  :kind="rhythmStateKind(selectedRhythm ? rhythmEffectiveState(selectedRhythm) : '')"
                  :label="selectedRhythm ? rhythmEffectiveState(selectedRhythm) : ''"
                />
                <span class="series-id drawer-series" :title="selectedRhythm?.series_id">{{
                  selectedRhythm?.series_display ?? selectedRhythm?.series_id
                }}</span>
                <q-btn
                  flat
                  round
                  icon="close"
                  aria-label="Close drawer"
                  data-test="rhythm-drawer-close"
                  @click="rhythmDrawer = false"
                />
              </div>
            </div>
            <q-tabs
              v-model="rhythmTab"
              dense
              no-caps
              align="justify"
              active-color="primary"
              indicator-color="primary"
              data-test="rhythm-drawer-tabs"
            >
              <q-tab name="overview" label="Overview" data-test="rhythm-tab-overview" />
              <q-tab name="features" label="Features & Chart" data-test="rhythm-tab-features" />
              <q-tab name="correct" label="Correct" data-test="rhythm-tab-correct" />
            </q-tabs>
            <q-separator />
            <div class="drawer-scroll" data-test="rhythm-drawer-body">
              <!-- Overview -->
              <div v-if="rhythmTab === 'overview'" class="overview-pane" data-test="rhythm-overview-pane">
                <ContextHelp
                  class="q-mb-sm"
                  label="About this cadence state"
                  :text="rhythmOverviewText"
                  data-test="rhythm-overview-help"
                />
                <div class="drawer-kv overview-pane__kpis">
                  <div class="drawer-kpi-tile">
                    <span>Status priority</span><b>{{ selectedRhythm ? rhythmEffectiveState(selectedRhythm) : '—' }}</b>
                  </div>
                  <div class="drawer-kpi-tile">
                    <span>Cadence</span><b>{{ selectedRhythm ? cadenceLabel(selectedRhythm) : '—' }}</b>
                  </div>
                  <div class="drawer-kpi-tile" data-test="rhythm-kpi-absence-count">
                    <span>Absence events ({{ rhythmRangeLabel }})</span
                    ><b>{{ selectedRhythm?.recent_absence_count ?? 0 }}</b>
                  </div>
                  <div class="drawer-kpi-tile" data-test="rhythm-kpi-frequency-count">
                    <span>Cadence anomalies ({{ rhythmRangeLabel }})</span
                    ><b>{{ selectedRhythm?.recent_frequency_anomaly_count ?? 0 }}</b>
                  </div>
                  <div class="drawer-kpi-tile">
                    <span>Last seen</span><b>{{ formatDate(selectedRhythm?.last_seen ?? null) }}</b>
                  </div>
                  <div class="drawer-kpi-tile">
                    <span>Last trained</span><b>{{ formatDate(selectedRhythm?.trained_at ?? null) }}</b>
                  </div>
                </div>
                <div class="text-caption text-muted" data-test="rhythm-overview-counts">
                  {{ selectedRhythm?.recent_absence_count ?? 0 }} absence event(s) and
                  {{ selectedRhythm?.recent_frequency_anomaly_count ?? 0 }} cadence anomaly event(s) in the selected
                  {{ rhythmRangeLabel }} window. Live detector state is <b>{{ selectedRhythm?.state ?? '—' }}</b
                  >.
                </div>
                <div class="text-overline overview-pane__label">Absence deadline</div>
                <div class="text-caption" data-test="rhythm-overview-deadline">
                  <span class="mono">{{ formatDate(selectedRhythm?.absence_deadline ?? null) }}</span>
                  <span class="text-muted q-ml-sm">{{ selectedRhythm ? deadlineHint(selectedRhythm) : '' }}</span>
                </div>
                <div v-if="selectedRhythm?.active_anomaly_type" class="text-caption q-mt-sm" data-test="rhythm-active">
                  Open {{ selectedRhythm.active_anomaly_type }} since
                  {{ formatDate(selectedRhythm.active_anomaly_since) }}
                </div>
                <div class="text-overline overview-pane__label">Event timeline</div>
                <ul class="timeline-list" data-test="rhythm-overview-timeline">
                  <li
                    v-for="(event, index) in rhythm.events"
                    :key="`${event.start_ts}-${index}`"
                    class="timeline-row"
                    data-test="rhythm-timeline-row"
                  >
                    <span class="timeline-row__ts">{{ formatDate(event.start_ts) }}</span>
                    <CdStateBadge
                      :kind="rhythmStateKind(rhythmEventState(event.anomaly_type))"
                      :label="rhythmEventState(event.anomaly_type)"
                    />
                    <span class="timeline-row__feat">{{ eventDurationLabel(event) }}</span>
                  </li>
                  <li
                    v-if="!rhythm.events.length && !rhythm.eventsLoading"
                    class="timeline-row text-muted"
                    data-test="rhythm-timeline-empty"
                  >
                    No absence or cadence anomaly events in the selected {{ rhythmRangeLabel }} window.
                  </li>
                  <li v-if="rhythm.eventsTruncated" class="timeline-row text-muted" data-test="rhythm-timeline-capped">
                    Showing the newest {{ rhythm.events.length }} events; more exist in this window.
                  </li>
                </ul>
              </div>

              <!-- Features & Chart -->
              <div v-else-if="rhythmTab === 'features'" data-test="rhythm-features-pane">
                <ContextHelp
                  class="q-mb-sm"
                  label="About cadence and effective factors"
                  text="Cadence is learned by training and is read-only here. Only the two factor overrides are operator-editable."
                />
                <q-markup-table flat bordered dense>
                  <thead>
                    <tr>
                      <th class="text-left">Metric</th>
                      <th class="text-left">Current</th>
                      <th class="text-left">Provenance</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr>
                      <td>Cadence mean ± std</td>
                      <td class="mono">{{ selectedRhythm ? cadenceLabel(selectedRhythm) : '—' }}</td>
                      <td data-test="rhythm-cadence-provenance">learned profile</td>
                    </tr>
                    <tr>
                      <td>tolerance_factor</td>
                      <td class="mono">{{ factorLabel(selectedRhythm?.tolerance_factor ?? null) }}</td>
                      <td><CdProvenanceTag :factor="selectedRhythm?.tolerance_factor ?? null" /></td>
                    </tr>
                    <tr>
                      <td>absence_factor</td>
                      <td class="mono">{{ factorLabel(selectedRhythm?.absence_factor ?? null) }}</td>
                      <td><CdProvenanceTag :factor="selectedRhythm?.absence_factor ?? null" /></td>
                    </tr>
                  </tbody>
                </q-markup-table>
                <div class="text-overline q-mt-md">
                  Observed cadence <span v-if="rhythmPlotLabel">· {{ rhythmPlotLabel }}</span>
                </div>
                <TimeseriesChart
                  v-if="rhythmPlotData.length"
                  :data="rhythmPlotData"
                  :show-bounds="true"
                  :height="220"
                  data-test="rhythm-cadence-chart"
                />
                <div v-else-if="rhythmPlotLoading" class="rhythm-history-empty" role="status">
                  <q-spinner-dots size="28px" color="primary" />
                  <span>Loading observed cadence…</span>
                </div>
                <div v-else class="rhythm-history-empty" data-test="rhythm-cadence-empty-chart" role="status">
                  <q-icon name="show_chart" size="28px" />
                  <span v-if="rhythmPlotError">{{ rhythmPlotError }}</span>
                  <span v-else>No observed timeseries for this series in the selected window.</span>
                </div>
                <div class="text-caption text-muted" data-test="rhythm-chart-note">
                  Observed traffic for this series from
                  <span class="mono">/api/v1/anomalies/bounds</span>, the same source the Bound Review chart uses.
                  <template v-if="rhythmRange === 'All'">
                    The All range has no start instant, so the chart shows the last 24 h.
                  </template>
                  Learned cadence is {{ selectedRhythm ? cadenceLabel(selectedRhythm) : '—' }}.
                </div>
                <div class="text-overline q-mt-md">Correction history</div>
                <TimeseriesChart
                  v-if="rhythmHistoryChartData.length"
                  :data="rhythmHistoryChartData"
                  :height="180"
                  data-test="rhythm-drawer-chart"
                />
                <div v-else class="rhythm-history-empty" data-test="rhythm-history-empty-chart" role="status">
                  <q-icon name="history_toggle_off" size="28px" />
                  <span>No corrections recorded for this profile yet.</span>
                </div>
                <div class="text-overline q-mt-md">Detector threshold</div>
                <div class="text-caption text-muted" data-test="rhythm-threshold-note">
                  Cadence threshold = max(tolerance × std, 0.5 × mean). The 0.5 × mean floor stays in force; absence
                  is missing evidence, not a measured feature.
                </div>
              </div>

              <!-- Correct -->
              <div v-else-if="rhythmTab === 'correct'" class="correct-editor" data-test="rhythm-correct-editor">
                <div class="correction-actionbar" data-test="correction-actionbar">
                  <q-btn
                    flat
                    dense
                    no-caps
                    color="primary"
                    icon="auto_awesome"
                    label="Suggest proposed values"
                    data-test="rhythm-suggest"
                    :loading="rhythmSuggestLoading"
                    @click="requestRhythmSuggestion"
                  />
                  <q-space />
                  <ContextHelp
                    data-test="correction-safety-help"
                    label="Safe apply gates"
                    text="Apply validates the current profile, then atomically writes the audited override. A concurrent change makes the API answer 409 and nothing is written."
                  />

                  <q-btn
                    color="primary"
                    no-caps
                    label="Apply"
                    data-test="rhythm-apply"
                    :data-can-apply="canApplyRhythm"
                    :loading="rhythmApplyLoading"
                    :disable="!canApplyRhythm || rhythmApplyLoading"
                    @click="applyRhythm"
                  />
                </div>
                <div
                  v-if="rhythmSuggestion"
                  class="suggestion-provenance suggestion-provenance--success"
                  data-test="rhythm-suggestion-provenance"
                >
                  <q-icon name="verified" color="primary" size="16px" />
                  <div>
                    <strong>Server proposal · available · advisory only</strong>
                    <span>
                      {{ rhythmSuggestion.evidence.observations }} observations · strict window
                      {{ rhythmSuggestion.evidence.window_days }} d · {{ rhythmSuggestion.evidence.method }}
                    </span>
                  </div>
                </div>
                <div class="text-overline q-mt-md">Correction history</div>
                <ul class="timeline-list" data-test="rhythm-history-list">
                  <li
                    v-for="(record, index) in rhythm.history"
                    :key="`${record.changed_at}-${index}`"
                    class="timeline-row"
                    data-test="rhythm-history-row"
                  >
                    <span class="timeline-row__ts">{{ formatDate(record.changed_at) }} · {{ record.actor }}</span>
                    <span class="timeline-row__feat">
                      tolerance {{ record.old_tolerance ?? 'default' }} → {{ record.new_tolerance ?? 'default' }} ·
                      absence {{ record.old_absence ?? 'default' }} → {{ record.new_absence ?? 'default' }}
                    </span>
                    <span class="text-caption text-muted">{{ record.reason }}</span>
                  </li>
                  <li
                    v-if="!rhythm.history.length && !rhythm.historyLoading"
                    class="timeline-row text-muted"
                    data-test="rhythm-history-empty"
                  >
                    No override has ever been recorded for this series.
                  </li>
                </ul>
                <div class="text-caption text-muted q-mt-xs" data-test="rhythm-cadence-readonly">
                  Learned cadence {{ selectedRhythm ? cadenceLabel(selectedRhythm) : '—' }} is not editable here.
                  Correct a wrong cadence by retraining the profile.
                </div>
                <div class="text-overline q-mt-md">Feature · Current · Proposed</div>
                <div class="rhythm-form-grid" data-test="rhythm-form">
                  <div class="rhythm-form-head" aria-hidden="true">
                    <span>Feature</span>
                    <span>Current</span>
                    <span>Proposed</span>
                    <span />
                  </div>
                  <div class="rhythm-form-row">
                    <label for="rhythm-tolerance">tolerance_factor.override</label>
                    <span class="mono rhythm-current-value">{{
                      factorLabel(selectedRhythm?.tolerance_factor ?? null)
                    }}</span>
                    <q-input
                      id="rhythm-tolerance"
                      v-model="toleranceInput"
                      dense
                      outlined
                      type="number"
                      step="0.1"
                      placeholder="global default"
                      aria-label="tolerance_factor override"
                      data-test="rhythm-tolerance-input"
                      :class="{
                        'rhythm-proposed--changed': rhythmInputChanged(
                          toleranceInput,
                          selectedRhythm?.tolerance_factor ?? null,
                        ),
                      }"
                    />
                    <q-btn
                      flat
                      dense
                      no-caps
                      size="sm"
                      label="Restore default"
                      data-test="rhythm-tolerance-restore"
                      @click="toleranceInput = ''"
                    />
                  </div>
                  <div class="rhythm-form-row">
                    <label for="rhythm-absence">absence_factor.override</label>
                    <span class="mono rhythm-current-value">{{
                      factorLabel(selectedRhythm?.absence_factor ?? null)
                    }}</span>
                    <q-input
                      id="rhythm-absence"
                      v-model="absenceInput"
                      dense
                      outlined
                      type="number"
                      step="0.25"
                      placeholder="global default"
                      aria-label="absence_factor override"
                      data-test="rhythm-absence-input"
                      :class="{
                        'rhythm-proposed--changed': rhythmInputChanged(
                          absenceInput,
                          selectedRhythm?.absence_factor ?? null,
                        ),
                      }"
                    />
                    <q-btn
                      flat
                      dense
                      no-caps
                      size="sm"
                      label="Restore default"
                      data-test="rhythm-absence-restore"
                      @click="absenceInput = ''"
                    />
                  </div>
                </div>
                <div
                  v-if="rhythmValidationError"
                  class="text-negative text-caption q-mt-xs"
                  role="alert"
                  data-test="rhythm-validation-error"
                >
                  {{ rhythmValidationError }}
                </div>
                <q-input
                  v-model="rhythmReason"
                  outlined
                  dense
                  type="textarea"
                  autogrow
                  label="Reason (optional, audited)"
                  class="q-mt-sm"
                  data-test="rhythm-reason"
                />
                <q-banner
                  v-if="rhythmConflict"
                  dense
                  class="bg-negative text-white q-mt-sm"
                  data-test="rhythm-conflict"
                >
                  <b>409 · rejected as stale.</b> {{ rhythmConflict }} Nothing was written; your entered values are
                  kept.
                </q-banner>
                <q-banner
                  v-else-if="rhythmPreviewError"
                  dense
                  class="bg-negative text-white q-mt-sm"
                  data-test="rhythm-preview-error"
                  >{{ rhythmPreviewError }}</q-banner
                >
              </div>
            </div>
          </div>
        </q-drawer>
      </q-tab-panel>
    </q-tab-panels>
    <q-dialog v-model="modeDialog" persistent>
      <q-card
        v-if="selectedGateModule"
        class="detection-gates-dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby="detection-gates-title"
        data-test="detection-gates-dialog"
      >
        <q-card-section class="row items-center no-wrap detection-gates-dialog__head">
          <div id="detection-gates-title" class="text-h6">
            Detection modes: {{ friendlyModuleLabel(selectedGateModule) }}
          </div>
          <q-icon
            name="info"
            size="18px"
            tabindex="0"
            class="q-ml-xs"
            aria-label="About detection modes"
            data-test="detection-gates-help"
            color="grey-5"
          >
            <q-tooltip
              >These controls affect live bounds and classification. Cadence detection also governs absence
              monitoring: disabling it stops both.</q-tooltip
            >
          </q-icon>
        </q-card-section>
        <q-card-section class="q-gutter-sm">
          <q-toggle
            v-model="runtimeGates.draft.bounds_enabled"
            label="Bounds detection"
            :disable="runtimeGatePending"
            aria-label="Bounds detection"
            data-test="live-bounds-toggle"
          />
          <q-toggle
            v-model="runtimeGates.draft.classification_enabled"
            label="Classification"
            :disable="runtimeGatePending"
            aria-label="Classification"
            data-test="live-classification-toggle"
          />
          <q-toggle
            v-model="runtimeGates.draft.frequency_enabled"
            label="Cadence"
            aria-label="Cadence"
            data-test="live-frequency-toggle"
          />
          <q-input
            v-model="modeReason"
            outlined
            type="textarea"
            label="Reason (optional)"
            aria-label="Reason (optional)"
            :disable="runtimeGatePending"
            class="q-mt-md"
            data-test="live-gates-reason"
          />
          <div v-if="gateReasonError" class="text-negative text-caption" role="alert" data-test="gate-reason-error">
            {{ gateReasonError }}
          </div>
          <q-banner v-if="gateError" dense class="bg-negative text-white" role="alert" data-test="gate-error">
            {{ gateError }}
          </q-banner>
          <div v-if="gateStatus === 'waiting'" class="q-pa-sm bg-info text-white" data-test="gate-pending">
            Live gate change saved. Waiting for the next detection poll.
          </div>
          <div v-if="gateStatus === 'saved'" class="q-pa-sm bg-positive text-white" data-test="gate-confirmed">
            Live detection gates saved. Detector will consume change on next poll.
          </div>
        </q-card-section>
        <q-card-actions align="right">
          <q-btn
            color="secondary"
            unelevated
            no-caps
            label="Close"
            data-test="close-live-gates"
            @click="closeModeDialog"
          />
          <q-btn
            color="primary"
            no-caps
            label="Apply"
            :loading="runtimeGatePending"
            :disable="runtimeGatePending || !gateChanged"
            data-test="apply-live-gates"
            @click="submitModeChange"
          />
        </q-card-actions>
      </q-card>
    </q-dialog>
    <q-dialog v-model="displaySettingsOpen">
      <q-card class="display-settings-card">
        <q-card-section class="text-h6">Display Settings</q-card-section>
        <q-card-section class="q-gutter-md">
          <q-select
            v-model="density"
            :options="densityOptions"
            emit-value
            map-options
            outlined
            dense
            label="Table density"
          />
          <q-select
            v-model="cardMode"
            :options="cardModeOptions"
            emit-value
            map-options
            outlined
            dense
            label="Summary presentation"
          />
        </q-card-section>
        <q-card-actions align="right"><q-btn v-close-popup flat label="Close" /></q-card-actions>
      </q-card>
    </q-dialog>
  </div>
</template>

<script setup lang="ts">
import { useQuasar } from 'quasar'
import {
  friendlyModuleLabel,
  friendlyReadinessLabel,
  rangeToWindow,
  useDetectionStore,
  type BoundReviewItem,
  type BoundReviewTimelineEvent,
  type BoundsCorrectionPreview,
  type BoundsEnvelope,
  type BoundSuggestionResponse,
  type TimeRangeKey,
  type TimeseriesBoundPoint,
  type TrainingWindowStatus,
} from '~/stores/detectionStore'
import {
  RhythmCorrectionConflictError,
  useRhythmReviewStore,
  type RhythmModule,
  type RhythmModuleFilter,
} from '~/stores/rhythmReviewStore'
import type {
  EffectiveFactor,
  FrequencyEventRecord,
  FrequencyOverridePayload,
  FrequencyOverrideSuggestion,
  FrequencyProfileResponse,
} from '~/types/api'
import type { TimeseriesPoint } from '~/types/golden-data'
import CdStateBadge from '~/components/operations/StateBadge.vue'
import CdProvenanceTag from '~/components/operations/ProvenanceTag.vue'
import ContextHelp from '~/components/operations/ContextHelp.vue'
import TimeseriesChart from '~/components/shared/TimeseriesChart.vue'
import InsufficientPermissionsNotice from '~/components/shared/InsufficientPermissionsNotice.vue'
import { OPERATIONS_HEAVY_POLL_INTERVAL_MS, useOperationsRefresh } from '~/composables/useOperationsRefresh'
import { usePolling } from '~/composables/usePolling'
import {
  DETECTION_GATE_MODULES,
  useDetectionRuntimeGates,
  type DetectionGateModule,
  type DetectionGateState,
} from '~/composables/useDetectionRuntimeGates'
import { useConfigurationStore } from '~/stores/configurationStore'
import {
  intervalDurationMinutes,
  summarizeTrainingIntervals,
  type TrainingIntervalValue,
} from '~/utils/trainingIntervals'
import { frameChartPoints } from '~/utils/chartFraming'
import { isInsufficientPermissionsMessage } from '~/utils/permissions'

definePageMeta({ title: 'Operations / Detection & Training' })
const $q = useQuasar()
const store = useDetectionStore()
const configurationStore = useConfigurationStore()
const runtimeGates = useDetectionRuntimeGates({
  getRuntimeItems: () => configurationStore.runtime,
  saveRuntime: (request) => configurationStore.saveRuntimeJob(Array.isArray(request) ? request : [request]),
  refreshRuntime: () => configurationStore.fetchRuntimeStrict(),
  getRuntimeError: () => configurationStore.runtimeError,
  refreshReadiness: () => store.refreshReadiness(),
  getPollIntervalSeconds: () => store.livePollIntervalSeconds,
})
const cooldownMinutes = computed(() => Math.max(1, Math.ceil(store.retrainCooldownRemainingSeconds / 60)))
const operationsRefresh = useOperationsRefresh()
const tab = ref('readiness')
const modeDialog = ref(false)
const modeReason = ref('')
const selectedGateModule = ref<DetectionGateModule | null>(null)
const pendingGateModule = computed(() => (runtimeGates.pending.value ? selectedGateModule.value : null))
const runtimeGatePending = computed(() => runtimeGates.pending.value)
// `runtimeGates` is a plain object, so Vue does NOT unwrap the refs it
// carries inside the template: `runtimeGates.error` there is the Ref itself
// and therefore *always* truthy. That rendered the error banner
// unconditionally (empty, but present in the DOM) and made the Apply gating
// read a truthy object instead of the boolean. These computeds unwrap
// explicitly so every consumer sees the real value.
const gateError = computed(() => runtimeGates.error.value)
const gateReasonError = computed(() => runtimeGates.reasonError.value)
const gateStatus = computed(() => runtimeGates.status.value)
const gateChanged = computed(() => runtimeGates.changed.value)
const boundDialog = ref(false)
const selectedBound = ref<BoundReviewItem | null>(null)
const boundModule = ref<string | null>(null)
const range = ref<TimeRangeKey | 'custom'>('24h')
const search = ref('')
const reason = ref('')
const correctionMode = ref<'expand' | 'replace'>('expand')
const createSubMode = ref<'create' | 'train'>('create')
const drawerTab = ref<'overview' | 'features' | 'correct'>('overview')
const selectedFeature = ref<string | null>(null)
const preview = ref<BoundsCorrectionPreview | null>(null)
const previewLoading = ref(false)
const applyLoading = ref(false)
const previewError = ref<string | null>(null)
const proposed = ref<Record<string, { lower: number | null; upper: number | null }>>({})
const customFrom = ref('')
const customTo = ref('')
const density = ref<'standard' | 'dense'>('dense')
const cardMode = ref<'full' | 'compact' | 'hidden'>('full')
const displaySettingsOpen = ref(false)
const suggestionLoading = ref(false)
const suggestionMessage = ref('')
const suggestionEvidence = ref<{
  status: BoundSuggestionResponse['status']
  evidenceCount: number
  windowFrom: string
  windowTo: string
} | null>(null)
// `activeStates` is the single source of truth for Bound Review status
// filtering. Both the client-side table filter and the API `state` query
// derive from it, so the State combobox and the status cards can never
// contradict each other (B-F1).
const DEFAULT_ACTIVE_STATES = ['NoBounds', 'Violation'] as const
const stateFilterOptions: string[] = ['NoBounds', 'Violation', 'OK']
const activeStates = ref<Set<string>>(new Set(DEFAULT_ACTIVE_STATES))
const DEFAULT_LABEL_SOURCE = '/app/models/mitre_techniques_log.json'
const mitreFile = ref(DEFAULT_LABEL_SOURCE)
const labelSourceInput = ref<HTMLInputElement | null>(null)
const labelSourceError = ref('')
const boundsIntervals = reactive([{ start: '', end: '' }])
const classifierIntervals = reactive([{ start: '', end: '' }])
// Explicit {label,value} options so the Module filter reads All / Connections /
// Assets / Protocols while `boundModule` still stores the raw module value (or
// null for All). Raw strings under `emit-value map-options` show the raw value
// as the field text and are not valid readable map-options input (CAPTURE 32).
const moduleOptions: Array<{ label: string; value: string | null }> = [
  { label: 'All', value: null },
  { label: friendlyModuleLabel('conn'), value: 'conn' },
  { label: friendlyModuleLabel('mac_traffic'), value: 'mac_traffic' },
  { label: friendlyModuleLabel('proto_traffic'), value: 'proto_traffic' },
]
const plotData = ref<TimeseriesBoundPoint[]>([])
const plotLoading = ref(false)
// Deterministic event-focused chart framing. Independent of wall-clock time,
// so reopening the drawer or switching features yields the same X window for
// the same data (no sliding 24h axis). Points are sorted by time; the window
// spans all violating points plus a fixed proportional padding on each side,
// bounded to a maximum number of rendered points to stay performance-safe.
const CHART_MAX_POINTS = 240
const CHART_PAD_RATIO = 0.15

/**
 * Deterministically frame the sorted plot around the violating points with
 * fixed proportional edge padding. Returns the framed slice plus whether any
 * framing was applied. Pure: identical input yields an identical window, so
 * reopening the drawer or switching features never slides the axis.
 */
const framedChart = computed(() =>
  frameChartPoints(plotData.value, { maxPoints: CHART_MAX_POINTS, padRatio: CHART_PAD_RATIO }),
)
const focusedPlotData = computed<TimeseriesBoundPoint[]>(() => framedChart.value.points)
const chartFocused = computed<boolean>(() => framedChart.value.focused)
const newBaseline = reactive({ name: '', start: '', end: '' })
// Monotonic request sequences guard selection-scoped async work so a slow
// response for a previously selected row/feature/action never overwrites the
// data or loading/error state of the current selection (B-F3).
let plotSeq = 0
let suggestionSeq = 0
// Preview is a selection-and-action-scoped request: it must never resolve into
// the current selection if the operator switched row/action or closed the
// drawer while it was in flight, otherwise a stale before/after could be
// applied to a different bound (B3-F1). `previewSeq` drops stale success/error/
// finally paths on row/action/drawer changes; `proposedRev` additionally drops
// a preview whose proposed values were edited after the request started;
// `previewKey` records which (module|series|action) the resolved preview
// belongs to so apply can require an exact match, not mere truthiness.
let previewSeq = 0
let proposedRev = 0
const previewKey = ref<string | null>(null)
// Apply is a one-click operation (it computes its own server preview), so it is
// a selection-scoped async operation too. `applySeq` identifies the current
// apply operation; any row/action/drawer/proposed change invalidates it so a
// pending apply for A can never mutate once the operator moved to B. While the
// mutation request itself is in flight (`applyMutating`) the loading flag is
// kept so a second apply cannot run concurrently.
let applySeq = 0
let applyMutating = false
let applyStarting = false

function invalidateApply(): void {
  applySeq += 1
  if (!applyMutating) applyLoading.value = false
}

// ---------------------------------------------------------------------------
// UI-101 Rhythm Review — fleet table + 640px right-overlay drawer, mirroring
// the Bound Review structure and the approved mockup 004.
// ---------------------------------------------------------------------------
const rhythm = useRhythmReviewStore()
const rhythmModule = ref<RhythmModuleFilter>('conn')
const rhythmSearch = ref('')
const rhythmRange = ref<TimeRangeKey | 'custom'>('All')
const rhythmCustomFrom = ref('')
const rhythmCustomTo = ref('')
const rhythmDrawer = ref(false)
const selectedRhythm = ref<FrequencyProfileResponse | null>(null)
const rhythmTab = ref<'overview' | 'features' | 'correct'>('overview')
const toleranceInput = ref('')
const absenceInput = ref('')
const rhythmReason = ref('')
const rhythmPreviewError = ref<string | null>(null)
const rhythmApplyLoading = ref(false)
const rhythmConflict = ref<string | null>(null)
const rhythmSuggestion = ref<FrequencyOverrideSuggestion | null>(null)
const rhythmSuggestLoading = ref(false)

const RHYTHM_STATES = ['absence_active', 'frequency_anomaly', 'normal', 'no_last_seen', 'no_profile'] as const
/** `no_profile` is a first-class state, so it is shown by default like any other. */
const rhythmStates = ref<Set<string>>(new Set(RHYTHM_STATES))

const rhythmStateSelection = computed<string[]>({
  get: () => [...rhythmStates.value],
  set: (value) => {
    const selected = Array.isArray(value) ? value : value ? [value] : []
    rhythmStates.value = new Set(selected)
  },
})

const rhythmStatusCardItems = [
  { state: 'absence_active', label: 'Absence active', description: 'past absence deadline', className: 'vio' },
  {
    state: 'frequency_anomaly',
    label: 'Cadence anomaly',
    description: 'outside cadence threshold',
    className: 'vio',
  },
  { state: 'normal', label: 'Normal', description: 'within learned cadence', className: 'ok' },
  { state: 'no_last_seen', label: 'No last seen', description: 'profile not observed yet', className: 'nob' },
  { state: 'no_profile', label: 'No profile', description: 'cadence not trained', className: 'nob' },
] as const

function rhythmInputChanged(input: string, factor: { override?: number | null } | null): boolean {
  const current = factor?.override ?? null
  if (input.trim() === '') return current !== null
  const proposed = Number(input)
  return Number.isFinite(proposed) && proposed !== current
}

// ---------------------------------------------------------------------------
// Rhythm cadence chart.
//
// The Features & Chart pane used to plot ONLY `rhythm.history`, i.e. the
// operator correction audit. A series that was never manually corrected
// has an empty history, which is almost all of them — hence "not a single
// series shows a chart". Correction history is real data and stays, but as
// a secondary panel; the primary chart is the actual observed cadence.
//
// `mean_interarrival_time` is the metric the frequency profile is learned
// from, so it is the honest primary. It is a conn-only feature though
// (`ALL_FEATURES` vs `MAC_FEATURES`/`PROTO_FEATURES` in
// `otalon-api/src/domain/netcap/models.py`), and on some conn series
// Netcap++ emits it as a constant 0 while packet counts are real. The
// per-module fallback chain therefore ends at a packet/connection count,
// which is a genuine recurrence signal rather than a fabricated one.
// ---------------------------------------------------------------------------
const RHYTHM_CADENCE_METRICS: Record<string, string[]> = {
  conn: ['mean_interarrival_time', 'packet_count'],
  mac_traffic: ['out_total_packets', 'total_conn_count'],
  proto_traffic: ['proto_total_packets', 'proto_conn_count'],
}
const rhythmPlotData = ref<TimeseriesPoint[]>([])
const rhythmPlotMetric = ref<string | null>(null)
const rhythmPlotLoading = ref(false)
const rhythmPlotError = ref<string | null>(null)
let rhythmPlotSeq = 0

const RHYTHM_METRIC_LABELS: Record<string, string> = {
  mean_interarrival_time: 'Mean inter-arrival time (s)',
  packet_count: 'Packets per bucket',
  out_total_packets: 'Outbound packets',
  total_conn_count: 'Connections',
  proto_total_packets: 'Protocol packets',
  proto_conn_count: 'Protocol connections',
}

const rhythmPlotLabel = computed<string>(() =>
  rhythmPlotMetric.value ? (RHYTHM_METRIC_LABELS[rhythmPlotMetric.value] ?? rhythmPlotMetric.value) : '',
)

/**
 * Window the cadence chart is drawn over.
 *
 * The unbounded "All" range has no start instant to query InfluxDB with,
 * so the chart falls back to the last 24 h — stated in the pane rather
 * than silently implied.
 */
function rhythmChartWindow(): { start: string; stop: string } {
  const win = rhythmWindow()
  if (win.from && win.to) return { start: win.from, stop: win.to }
  return rangeToWindow('24h')
}

/**
 * Load the observed cadence timeseries for the selected series.
 *
 * Tries each candidate metric for the row's module in order and keeps the
 * first that returns a non-degenerate series (at least one point that is
 * not zero). An all-zero response is a real answer from the API but not a
 * usable rhythm chart, so it is passed over rather than rendered as a
 * flat line implying no traffic.
 */
async function refreshRhythmPlot(): Promise<void> {
  const current = selectedRhythm.value
  if (!current) return
  const seq = ++rhythmPlotSeq
  const metrics = RHYTHM_CADENCE_METRICS[current.module] ?? []
  rhythmPlotLoading.value = true
  rhythmPlotError.value = null
  try {
    const { start, stop } = rhythmChartWindow()
    for (const metric of metrics) {
      const data = await store.fetchSeriesTimeseries(current.module, current.series_id, metric, start, stop)
      if (seq !== rhythmPlotSeq) return
      if (data.some((point) => (point.value ?? 0) !== 0)) {
        rhythmPlotData.value = data
        rhythmPlotMetric.value = metric
        return
      }
    }
    if (seq !== rhythmPlotSeq) return
    rhythmPlotData.value = []
    rhythmPlotMetric.value = null
  } catch (error: unknown) {
    if (seq !== rhythmPlotSeq) return
    rhythmPlotData.value = []
    rhythmPlotMetric.value = null
    rhythmPlotError.value = error instanceof Error ? error.message : 'Cadence timeseries could not be loaded.'
  } finally {
    if (seq === rhythmPlotSeq) rhythmPlotLoading.value = false
  }
}

const rhythmHistoryChartData = computed<TimeseriesPoint[]>(() => {
  const records = rhythm.history
  return records.flatMap((record) => {
    const tolerance = record.new_tolerance ?? record.old_tolerance
    const absence = record.new_absence ?? record.old_absence
    if (tolerance === null && absence === null) return []
    return [
      {
        time: record.changed_at,
        value: tolerance ?? absence ?? 0,
        value_min: null,
        value_max: null,
        lower_bound: null,
        upper_bound: null,
        violation_low: false,
        violation_high: false,
      },
    ]
  })
})

let rhythmSuggestSeq = 0

const RHYTHM_STATE_ORDER: Record<string, number> = {
  absence_active: 0,
  frequency_anomaly: 1,
  no_last_seen: 2,
  no_profile: 3,
  normal: 4,
}

/**
 * Number of rhythm episodes in the selected window for one row.
 *
 * The Rhythm counterpart of Bound Review's `eventCount`, so the two
 * tables' "Events" columns mean the same thing: how many detector events
 * this series produced inside the interval being reviewed.
 */
function rhythmEventCount(profile: FrequencyProfileResponse): number {
  return (profile.recent_absence_count ?? 0) + (profile.recent_frequency_anomaly_count ?? 0)
}

// Mirrors `boundColumns`: Module · Series · State · Events · Last event.
// Feature-level detail (cadence mean ± std, both factors, the absence
// deadline) moved into the drawer, exactly as Bound Review keeps
// per-feature Lower/Upper/Violations out of its table. `module` stays a
// real column because the Module filter offers "All", so a row's module
// is not implied by the tab.
const rhythmColumns = [
  {
    name: 'module',
    label: 'Module',
    field: (row: FrequencyProfileResponse): string => friendlyModuleLabel(row.module),
    sortable: true,
  },
  { name: 'series_id', label: 'Series', field: 'series_id', sortable: true },
  {
    name: 'state',
    label: 'State',
    // Sorting follows the pill, so the column orders the way it reads.
    field: (row: FrequencyProfileResponse): string => rhythmEffectiveState(row),
    sortable: true,
    sort: (a: string, b: string): number => (RHYTHM_STATE_ORDER[a] ?? 9) - (RHYTHM_STATE_ORDER[b] ?? 9),
  },
  {
    name: 'event_count',
    label: 'Events',
    field: (row: FrequencyProfileResponse): number => rhythmEventCount(row),
    sortable: true,
  },
  {
    name: 'last_seen',
    label: 'Last seen',
    field: (row: FrequencyProfileResponse): string => row.last_seen ?? '',
    sortable: true,
  },
]
const rhythmPagination = { sortBy: 'state', descending: false, rowsPerPage: 0 }

// The state filter tests the EFFECTIVE state, not the raw `profile.state`
// column. Filtering on the raw state while the pill renders the windowed
// one made the two contradict each other: a row whose badge said
// `absence_active` disappeared when the operator unchecked `normal`,
// because its persisted live state had already reverted. What is filtered
// is now exactly what is displayed.
const rhythmRows = computed<FrequencyProfileResponse[]>(() => {
  const needle = rhythmSearch.value.trim().toLowerCase()
  const matchesSearchAndTime = (profile: FrequencyProfileResponse): boolean =>
    (needle === '' || profile.series_id.toLowerCase().includes(needle)) && rhythmTimeMatches(profile.last_seen)
  const filtered = rhythm.profiles.filter(
    (profile) => rhythmStates.value.has(rhythmEffectiveState(profile)) && matchesSearchAndTime(profile),
  )
  const selected = selectedRhythm.value
  if (
    rhythmDrawer.value &&
    selected &&
    matchesSearchAndTime(selected) &&
    !filtered.some((row) => rhythmRowKey(row) === rhythmRowKey(selected))
  ) {
    filtered.push(selected)
  }
  return filtered
})

function rhythmRowKey(profile: FrequencyProfileResponse): string {
  return `${profile.module}:${profile.series_id}`
}

/**
 * Effective factor the operator's current input would produce, before any
 * server round-trip. `''` means "no override" and therefore the global default.
 */
const rhythmPayload = computed<FrequencyOverridePayload>(() => {
  const payload: FrequencyOverridePayload = {}
  const current = selectedRhythm.value
  if (!current) return payload
  const tolerance = parseOverrideInput(toleranceInput.value)
  const absence = parseOverrideInput(absenceInput.value)
  if (tolerance !== (current.tolerance_factor?.override ?? null)) payload.tolerance_factor_override = tolerance
  if (absence !== (current.absence_factor?.override ?? null)) payload.absence_factor_override = absence
  return payload
})

const rhythmValidationError = computed<string | null>(() => {
  for (const [label, raw] of [
    ['tolerance_factor.override', toleranceInput.value],
    ['absence_factor.override', absenceInput.value],
  ] as const) {
    if (raw.trim() === '') continue
    const parsed = Number(raw)
    if (!Number.isFinite(parsed) || parsed <= 0)
      return `${label} must be a positive number, or empty to restore the default.`
  }
  if (selectedRhythm.value && !Object.keys(rhythmPayload.value).length)
    return 'Change at least one override before previewing.'
  return null
})

const canApplyRhythm = computed<boolean>(
  () => Boolean(selectedRhythm.value?.has_profile) && !rhythmValidationError.value,
)

const rhythmOverviewText = computed<string>(() => {
  const state = selectedRhythm.value?.state
  if (state === 'no_profile')
    return 'This series has no learned cadence yet. Train a profile before tuning its detector factors.'
  if (state === 'absence_active')
    return 'The detector currently reports this series as silent past its absence deadline. Widen absence_factor.override if the silence is expected.'
  if (state === 'frequency_anomaly')
    return 'The observed interval deviates beyond the tolerance threshold. Widen tolerance_factor.override if the jitter is expected.'
  if (state === 'no_last_seen') return 'A cadence is trained but the detector has not observed this series yet.'
  return 'This series matches its learned cadence. No correction is required.'
})

/**
 * Parse an override input field. An empty field is an explicit request to
 * restore the global default, which the API expresses as `null`.
 */
function parseOverrideInput(raw: string): number | null {
  if (raw.trim() === '') return null
  const parsed = Number(raw)
  return Number.isFinite(parsed) ? parsed : null
}

/**
 * Badge kind for one rhythm state.
 *
 * Both anomaly states map to `warn` on purpose. They are the two
 * conditions the operator triages, they share the `vio` status-card
 * colour in `rhythmStatusCardItems`, and `err` (red) would make the same
 * severity read differently in the pill than in the card counting it.
 * This is the Rhythm-only mapping; Bound Review keeps its own
 * `stateBadgeKind`, where `err` legitimately marks NoBounds.
 */
function rhythmStateKind(state: string): 'ok' | 'warn' | 'err' | 'muted' | 'info' {
  if (state === 'normal') return 'ok'
  if (state === 'frequency_anomaly') return 'warn'
  if (state === 'absence_active') return 'warn'
  if (state === 'no_last_seen') return 'info'
  return 'muted'
}

/**
 * The state the operator is actually shown for a row in the current window.
 *
 * `state` on the profile is the detector's *live* verdict: otalon-clas
 * clears it back to `normal` as soon as the series speaks again, so a
 * series that was silent 40 times today still reads `normal` right now.
 * Whenever a window is selected, the windowed episode counts are the
 * truthful answer to "what happened in this window", so they win.
 *
 * "All" is a window too — the unbounded one. It used to fall through to
 * the live `state`, which is why the table showed nothing but `normal`
 * in that range even for series with hundreds of persisted episodes;
 * the fleet request now omits `since` rather than skipping the counts,
 * so the same precedence holds without a special case.
 */
function rhythmEffectiveState(row: FrequencyProfileResponse): string {
  if ((row.recent_absence_count ?? 0) > 0) return 'absence_active'
  if ((row.recent_frequency_anomaly_count ?? 0) > 0) return 'frequency_anomaly'
  return row.state
}

/**
 * Count profiles whose *effective* state matches, matching what is shown.
 *
 * Counting the raw `state` here would make a status card report a
 * different number than the rows the same card filters to.
 */
function rhythmStateCount(state: string): number {
  return rhythm.profiles.filter((profile) => rhythmEffectiveState(profile) === state).length
}

function toggleRhythmState(state: string): void {
  const next = new Set(rhythmStates.value)
  if (next.has(state)) next.delete(state)
  else next.add(state)
  rhythmStates.value = next
}

function cadenceLabel(profile: FrequencyProfileResponse): string {
  if (!profile.has_profile || profile.mean_interval_seconds === null) return 'no profile'
  const mean = profile.mean_interval_seconds.toFixed(2)
  const std = (profile.std_interval_seconds ?? 0).toFixed(2)
  return `${mean} s ± ${std} s`
}

function factorLabel(factor: EffectiveFactor | null | undefined): string {
  if (!factor) return '—'
  return `× ${factor.value}`
}

/**
 * Map a persisted anomaly type onto the rhythm state that names it.
 *
 * The timeline reuses the table's state vocabulary and badge colours, so
 * an `AbsenceAnomaly` row reads as the same `absence_active` the pill
 * shows rather than introducing a second name for one condition.
 */
function rhythmEventState(anomalyType: string): string {
  if (anomalyType === 'AbsenceAnomaly') return 'absence_active'
  if (anomalyType === 'FrequencyAnomaly') return 'frequency_anomaly'
  return anomalyType
}

/**
 * Human-readable length of one persisted episode.
 *
 * A missing duration is reported as such; an episode with no persisted
 * end instant has no measured length and must not be shown as zero.
 */
function eventDurationLabel(event: FrequencyEventRecord): string {
  if (event.duration_seconds === null) return 'duration not recorded'
  return `${Math.round(event.duration_seconds)} s`
}

function deadlineHint(profile: FrequencyProfileResponse): string {
  if (!profile.has_profile) return 'no profile'
  if (profile.absence_deadline === null) return 'no deadline'
  const seconds = profile.seconds_until_deadline
  if (seconds === null) return ''
  return seconds < 0 ? `exceeded ${Math.round(-seconds)} s ago` : `in ${Math.round(seconds)} s`
}

async function openRhythm(row: FrequencyProfileResponse): Promise<void> {
  selectedRhythm.value = row
  rhythmDrawer.value = true
  const refreshed = await rhythm.refreshProfile(row.module as RhythmModule, row.series_id, rhythmFleetSince())
  if (refreshed && selectedRhythm.value && rhythmRowKey(selectedRhythm.value) === rhythmRowKey(row))
    selectedRhythm.value = refreshed
}

/**
 * Clear every correction-scoped piece of state.
 *
 * Called on row change, on drawer close, and by Discard, so an abandoned
 * correction can never be resurrected by a late response.
 */
function resetRhythmEdits(): void {
  rhythmPreviewError.value = null
  rhythmConflict.value = null

  rhythmSuggestion.value = null
  rhythmSuggestLoading.value = false
  rhythmReason.value = ''
  seedRhythmInputs(selectedRhythm.value)
}

function seedRhythmInputs(profile: FrequencyProfileResponse | null): void {
  toleranceInput.value = profile?.tolerance_factor?.override != null ? String(profile.tolerance_factor.override) : ''
  absenceInput.value = profile?.absence_factor?.override != null ? String(profile.absence_factor.override) : ''
}

async function requestRhythmSuggestion(): Promise<void> {
  const current = selectedRhythm.value
  if (!current) return
  const seq = ++rhythmSuggestSeq
  rhythmSuggestLoading.value = true
  try {
    const suggestion = await rhythm.suggestOverride(current.module as RhythmModule, current.series_id)
    if (seq !== rhythmSuggestSeq) return
    rhythmSuggestion.value = suggestion
    // Advisory only: the values are seeded into the editable fields, which
    // invalidates any resolved preview, so Apply still requires a fresh one.
    if (suggestion.tolerance_factor_suggested !== null)
      toleranceInput.value = String(suggestion.tolerance_factor_suggested)
    if (suggestion.absence_factor_suggested !== null) absenceInput.value = String(suggestion.absence_factor_suggested)
  } catch (error: unknown) {
    if (seq !== rhythmSuggestSeq) return
    rhythmSuggestion.value = null
    $q.notify({
      type: 'negative',
      message: error instanceof Error ? error.message : 'Cadence suggestion failed.',
    })
  } finally {
    if (seq === rhythmSuggestSeq) rhythmSuggestLoading.value = false
  }
}

async function applyRhythm(): Promise<void> {
  const current = selectedRhythm.value
  if (!current || !canApplyRhythm.value) return
  rhythmApplyLoading.value = true
  try {
    const preview = await rhythm.previewOverride(current.module as RhythmModule, current.series_id, rhythmPayload.value)
    const result = await rhythm.applyOverride(
      current.module as RhythmModule,
      current.series_id,
      rhythmPayload.value,
      preview.before_snapshot,
      rhythmReason.value.trim(),
    )
    $q.notify({
      type: 'positive',
      message: result.notified
        ? 'Correction applied, audited and notified to active detection.'
        : 'Correction applied and audited.',
    })
    const refreshed = await rhythm.refreshProfile(current.module as RhythmModule, current.series_id)
    if (refreshed) selectedRhythm.value = refreshed
    await rhythm.loadHistory(current.module as RhythmModule, current.series_id)
    resetRhythmEdits()
    rhythmTab.value = 'correct'
  } catch (error: unknown) {
    if (error instanceof RhythmCorrectionConflictError) {
      // Retain the operator's entered values; the atomic server guard rejected the write.
      rhythmConflict.value = error.message
      const refreshed = await rhythm.refreshProfile(current.module as RhythmModule, current.series_id)
      if (refreshed) selectedRhythm.value = refreshed
    } else {
      $q.notify({
        type: 'negative',
        message: error instanceof Error ? error.message : 'Correction failed.',
      })
    }
  } finally {
    rhythmApplyLoading.value = false
  }
}

watch(rhythmModule, (module) => {
  selectedRhythm.value = null
  rhythmDrawer.value = false
  void rhythm.loadFleet(module, rhythmFleetSince())
})

watch([rhythmRange, rhythmCustomFrom, rhythmCustomTo], () => {
  void rhythm.loadFleet(rhythmModule.value, rhythmFleetSince())
})

watch(selectedRhythm, (profile, previous) => {
  const sameRow = profile?.series_id === previous?.series_id && profile?.module === previous?.module
  if (sameRow) return
  rhythmTab.value = 'overview'
  resetRhythmEdits()
  rhythm.clearHistory()
  rhythm.clearEvents()
  // Invalidate any chart request belonging to the previous row so a slow
  // response can never paint into the newly selected series.
  rhythmPlotSeq += 1
  rhythmPlotData.value = []
  rhythmPlotMetric.value = null
  rhythmPlotError.value = null
  rhythmPlotLoading.value = false
  if (!profile) return
  void rhythm.loadHistory(profile.module as RhythmModule, profile.series_id)
  void rhythm.loadEvents(profile.module as RhythmModule, profile.series_id, rhythmFleetSince())
  void refreshRhythmPlot()
})

// A range change re-scopes both the episode timeline and the chart window
// for the row that is already open, so the drawer never keeps showing the
// previous range's evidence beside the new range's counts.
watch([rhythmRange, rhythmCustomFrom, rhythmCustomTo], () => {
  const profile = selectedRhythm.value
  if (!profile) return
  void rhythm.loadEvents(profile.module as RhythmModule, profile.series_id, rhythmFleetSince())
  void refreshRhythmPlot()
})

watch(rhythmDrawer, (open) => {
  // Closing via the button leaves `selectedRhythm` set, so the selection
  // watcher does not fire. Invalidate here too.
  if (!open) resetRhythmEdits()
})

usePolling(async () => {
  const profile = selectedRhythm.value
  if (!rhythmDrawer.value || !profile) return
  const refreshed = await rhythm.refreshProfile(profile.module as RhythmModule, profile.series_id)
  if (refreshed && selectedRhythm.value?.series_id === profile.series_id) selectedRhythm.value = refreshed
}, 5000)

watch([toleranceInput, absenceInput], () => {
  rhythmPreviewError.value = null
})

watch(tab, (value) => {
  if (value === 'rhythm' && !rhythm.profiles.length && !rhythm.loading)
    void rhythm.loadFleet(rhythmModule.value, rhythmFleetSince())
})

const STATE_ORDER: Record<string, number> = { NoBounds: 0, BoundViolation: 1, Violation: 1, OK: 2 }
const boundColumns = [
  {
    name: 'module',
    label: 'Module',
    // Sort by the friendly label (Assets/Connections/Protocols) so the column
    // orders the way it reads. The raw `module` stays the canonical value on
    // the row for requests, row identity and mutations (CAPTURE 32); only the
    // rendered cell (body-cell-module) and this sort key are friendly.
    field: (row: BoundReviewItem): string => friendlyModuleLabel(row.module),
    sortable: true,
  },
  { name: 'series_id', label: 'Series', field: 'series_id', sortable: true },
  {
    name: 'state',
    label: 'State',
    field: 'state',
    sortable: true,
    sort: (a: string, b: string): number => (STATE_ORDER[a] ?? 9) - (STATE_ORDER[b] ?? 9),
  },
  {
    name: 'violation_count',
    label: 'Events',
    field: (row: BoundReviewItem): number => eventCount(row),
    sortable: true,
  },
  {
    name: 'last_event',
    label: 'Last event',
    field: (row: BoundReviewItem): string => row.latest_event_ts ?? row.last_event ?? '',
    sortable: true,
  },
]
const boundPagination = { sortBy: 'state', descending: false, rowsPerPage: 0 }

const densityOptions = [
  { label: 'Standard', value: 'standard' },
  { label: 'Dense', value: 'dense' },
]
const cardModeOptions = [
  { label: 'Cards', value: 'full' },
  { label: 'Compact', value: 'compact' },
  { label: 'Hidden', value: 'hidden' },
]
const statusCardItems = [
  { state: 'NoBounds', label: 'NoBounds', description: 'series without trained bounds', className: 'nob' },
  { state: 'Violation', label: 'Violation', description: 'bounded events in interval', className: 'vio' },
  { state: 'OK', label: 'OK', description: 'hidden by default', className: 'ok' },
]

function rowKeyOf(item: BoundReviewItem): string {
  return `${item.module}:${item.series_id}:${item.feature}`
}

const statusCounts = computed(() => {
  const counts = { total: store.bounds.length, NoBounds: 0, Violation: 0, OK: 0 }
  for (const item of store.bounds) {
    const state = item.state === 'BoundViolation' ? 'Violation' : item.state
    if (state in counts) counts[state as keyof typeof counts] += 1
  }
  return counts
})

const boundRows = computed(() =>
  store.bounds
    .filter((item) => activeStates.value.has(item.state === 'BoundViolation' ? 'Violation' : item.state))
    .map((item) => ({ ...item, rowKey: rowKeyOf(item) })),
)

/**
 * The API `state` query derives from `activeStates`. A single selected state is
 * pushed to the server (mapping the UI `Violation` label onto canonical
 * `BoundViolation`); multiple selections fetch all rows and let the client
 * filter the union (B-F1).
 */
const apiBoundState = computed<string | null>(() => {
  if (activeStates.value.size !== 1) return null
  const only = [...activeStates.value][0] ?? null
  return only === 'Violation' ? 'BoundViolation' : only
})

/**
 * Two-way proxy backing the State multi-select. Empty selection is explicit and
 * leaves the table in a truthful no-state-selected state.
 */
const boundStateSelection = computed<string[]>({
  get: () => [...activeStates.value],
  set: (value) => {
    const selected = Array.isArray(value) ? value : value ? [value] : []
    activeStates.value = new Set(selected)
  },
})
const labelSourceOptions = computed(() =>
  (store.labelSources ?? []).map((source) => ({
    label: `${source.filename} (${source.label_count} labels)`,
    value: source.worker_path,
  })),
)
watch(
  labelSourceOptions,
  (options) => {
    if (!store.labelSourcesLoaded) return
    if (!options.length) {
      mitreFile.value = ''
      return
    }
    const preferred = options.find((option) => option.value === DEFAULT_LABEL_SOURCE)
    if (!options.some((option) => option.value === mitreFile.value))
      mitreFile.value = preferred?.value ?? options[0]!.value
  },
  { immediate: true },
)
const detailFeatures = computed(() => {
  // Feature list truth order: real affected features first, then the current
  // bound envelope keys, then the server-declared `available_features` module
  // contract. The last fallback is what makes a NoBounds row (no affected
  // features, empty envelope) still show its module's feature rows/charts
  // (CAPTURE 36); without it `detailFeatures` was empty and no chart appeared.
  if (selectedBound.value?.affected_features?.length) return selectedBound.value.affected_features
  const boundKeys = Object.keys(selectedBound.value?.current_bounds?.lower_bounds ?? {})
  if (boundKeys.length) return boundKeys
  return selectedBound.value?.available_features ?? []
})
const timelineEvents = computed<BoundReviewTimelineEvent[]>(() => {
  const events = selectedBound.value?.timeline_events
  if (events?.length) return events
  // Backward-compatible fallback: bare timestamps with no fabricated features.
  return (selectedBound.value?.timeline ?? []).map((ts) => ({
    ts,
    type: selectedBound.value?.latest_event_type ?? selectedBound.value?.state ?? 'event',
    features: [],
  }))
})
const selectedHasBounds = computed(
  () =>
    selectedBound.value?.has_bounds ?? Object.keys(selectedBound.value?.current_bounds?.lower_bounds ?? {}).length > 0,
)
const proposedFeatures = computed(() => Object.keys(proposed.value).sort())
const correctionAction = computed<'expand' | 'replace' | 'create'>(() =>
  selectedHasBounds.value ? correctionMode.value : 'create',
)
const proposedValidationError = computed<string | null>(() => {
  for (const feature of proposedFeatures.value) {
    const entry = proposed.value[feature]
    if (!entry) continue
    if (entry.lower === null || entry.upper === null || Number.isNaN(entry.lower) || Number.isNaN(entry.upper))
      return `Feature "${feature}" needs numeric lower and upper values.`
    if (entry.lower > entry.upper) return `Feature "${feature}": lower must not exceed upper.`
    if (correctionAction.value === 'expand') {
      const curLower = Number(selectedBound.value?.current_bounds?.lower_bounds?.[feature])
      const curUpper = Number(selectedBound.value?.current_bounds?.upper_bounds?.[feature])
      if (!Number.isNaN(curLower) && entry.lower > curLower)
        return `Expand cannot raise the lower bound of "${feature}" (would narrow).`
      if (!Number.isNaN(curUpper) && entry.upper < curUpper)
        return `Expand cannot lower the upper bound of "${feature}" (would narrow).`
    }
  }
  return null
})
const overviewText = computed(() => {
  if (!selectedBound.value) return ''
  if (selectedBound.value.state === 'NoBounds')
    return 'No bounds are available for this Series/UCI in the selected interval. Review timeline, then train or create bounds under Correct.'
  if (selectedBound.value.state === 'BoundViolation' || selectedBound.value.state === 'Violation')
    return `Bound violation detected. ${eventCount(selectedBound.value)} event(s) are inside strict interval; inspect affected features before correction.`
  return 'No bound event requires action in selected interval.'
})
const reasonValid = computed(() => true)
const canPreview = computed(() =>
  Boolean(selectedBound.value && proposedFeatures.value.length && reasonValid.value && !proposedValidationError.value),
)
function currentPreviewKey(): string | null {
  const bound = selectedBound.value
  if (!bound) return null
  // Immutable identity of the correction the operator currently sees: the row
  // (module + series) and the resolved action. A resolved preview is only
  // valid to apply while this key is unchanged (B3-F1).
  return `${bound.module}\u0000${bound.series_id}\u0000${correctionAction.value}`
}
const canApply = computed(() =>
  Boolean(
    canPreview.value &&
    reasonValid.value &&
    !proposedValidationError.value &&
    true,
  ),
)

function berlinLocalToUtc(local: string): string | undefined {
  if (!local) return undefined
  // A datetime-local value has no timezone; interpret it as Europe/Berlin wall
  // clock and convert to a UTC ISO instant for the API.
  const asUtc = new Date(`${local}:00Z`).getTime()
  const berlinOffsetMs = berlinOffsetMinutes(asUtc) * 60000
  return new Date(asUtc - berlinOffsetMs).toISOString()
}

function berlinOffsetMinutes(utcMillis: number): number {
  const date = new Date(utcMillis)
  const berlin = new Date(date.toLocaleString('en-US', { timeZone: 'Europe/Berlin' }))
  const utc = new Date(date.toLocaleString('en-US', { timeZone: 'UTC' }))
  return Math.round((berlin.getTime() - utc.getTime()) / 60000)
}

function spaceToIso(value: string): string {
  return new Date(value.replace(' ', 'T') + 'Z').toISOString()
}

function currentWindow(): { from?: string; to?: string } {
  if (range.value === 'custom') {
    return { from: berlinLocalToUtc(customFrom.value), to: berlinLocalToUtc(customTo.value) }
  }
  if (range.value === 'All') return {}
  const { start, stop } = rangeToWindow(range.value)
  return { from: spaceToIso(start), to: spaceToIso(stop) }
}

function rhythmWindow(): { from?: string; to?: string } {
  if (rhythmRange.value === 'custom') {
    return { from: berlinLocalToUtc(rhythmCustomFrom.value), to: berlinLocalToUtc(rhythmCustomTo.value) }
  }
  if (rhythmRange.value === 'All') return {}
  const { start, stop } = rangeToWindow(rhythmRange.value)
  return { from: spaceToIso(start), to: spaceToIso(stop) }
}

/**
 * Explicit unbounded lower bound for the "All" range.
 *
 * The profiles API counts recent absence/frequency episodes only for a
 * supplied `since`; omitting it returns zero counts, not all-time ones.
 * That is why "All" used to show nothing but `normal` even for series
 * with hundreds of persisted episodes — the live `state` column is a
 * *current* verdict that otalon-clas clears the moment the series
 * speaks again (`_resolve_state` in
 * `otalon-api/src/services/frequency_service.py`), so with no
 * counts there was no surviving evidence of anything but "fine right
 * now". The epoch is the honest lower bound of "all persisted history"
 * and needs no new API parameter.
 */
const RHYTHM_ALL_TIME_SINCE = '1970-01-01T00:00:00.000Z'

/**
 * Lower bound sent to the profiles API for the currently selected range.
 *
 * `undefined` only for a custom range whose "From" the operator has not
 * filled in yet, where there is genuinely no bound to send.
 */
function rhythmFleetSince(): string | undefined {
  if (rhythmRange.value === 'All') return RHYTHM_ALL_TIME_SINCE
  return rhythmWindow().from
}

const rhythmRangeLabel = computed(() => (rhythmRange.value === 'custom' ? 'custom range' : rhythmRange.value))

function rhythmTimeMatches(lastSeen: string | null): boolean {
  const window = rhythmWindow()
  if (!window.from && !window.to) return true
  if (!lastSeen) return false
  const timestamp = new Date(lastSeen).getTime()
  const from = window.from ? new Date(window.from).getTime() : Number.NEGATIVE_INFINITY
  const to = window.to ? new Date(window.to).getTime() : Number.POSITIVE_INFINITY
  return timestamp >= from && timestamp < to
}

function windowForChart(): { start: string; stop: string } {
  const win = currentWindow()
  if (win.from && win.to) return { start: win.from, stop: win.to }
  return rangeToWindow('7d')
}

watch([boundModule, activeStates, range, search, customFrom, customTo], () => {
  const window = currentWindow()
  void store.filterBounds({
    module: boundModule.value,
    state: apiBoundState.value,
    from: window.from,
    to: window.to,
    q: search.value,
  })
})

watch(
  [density, cardMode],
  () => {
    if (typeof window !== 'undefined')
      localStorage.setItem('bound-review:prefs', JSON.stringify({ density: density.value, cardMode: cardMode.value }))
  },
  { flush: 'sync' },
)

function seedProposed(value: BoundReviewItem | null): void {
  const next: Record<string, { lower: number | null; upper: number | null }> = {}
  const lower = value?.current_bounds?.lower_bounds ?? {}
  const upper = value?.current_bounds?.upper_bounds ?? {}
  for (const feature of Object.keys(lower)) {
    next[feature] = {
      lower: typeof lower[feature] === 'number' ? (lower[feature] as number) : null,
      upper: typeof upper[feature] === 'number' ? (upper[feature] as number) : null,
    }
  }
  proposed.value = next
}

watch(correctionMode, () => {
  // Action changed → any in-flight/resolved preview no longer matches the
  // current key and must not stay applyable (B3-F1).
  previewSeq += 1
  invalidateApply()
  previewKey.value = null
  preview.value = null
  previewError.value = null
  // Invalidate any in-flight suggestion; its action no longer matches (B-F3).
  suggestionSeq += 1
  suggestionLoading.value = false
  suggestionMessage.value = ''
  suggestionEvidence.value = null
  seedProposed(selectedBound.value)
})

watch(proposed, resetPreview, { deep: true })

watch(drawerTab, (value) => {
  if (value === 'correct' && selectedBound.value && !selectedHasBounds.value && !proposedFeatures.value.length)
    void suggestBounds()
})

watch(selectedBound, async (value) => {
  boundDialog.value = value !== null
  reason.value = ''
  // Row changed → invalidate any in-flight/resolved preview so a slow response
  // for the previous row cannot be applied to this one (B3-F1).
  previewSeq += 1
  invalidateApply()
  previewKey.value = null
  preview.value = null
  previewError.value = null
  previewLoading.value = false
  // Invalidate any in-flight suggestion so a slow response for the previous
  // row cannot seed this row's editable bounds (B-F3).
  suggestionSeq += 1
  suggestionLoading.value = false
  suggestionMessage.value = ''
  suggestionEvidence.value = null
  correctionMode.value = 'expand'
  drawerTab.value = 'overview'
  seedProposed(value)
  // Mirror the `detailFeatures` truth order so the initially selected feature
  // is the first row actually rendered: affected → current bound → server
  // `available_features`. The final fallback auto-selects a feature for a
  // NoBounds row so its chart loads on open (CAPTURE 36).
  selectedFeature.value =
    value?.affected_features?.[0] ??
    Object.keys(value?.current_bounds?.lower_bounds ?? {})[0] ??
    value?.available_features?.[0] ??
    null
  // Invalidate any chart request from the previously selected row and clear the
  // plot; the initial fetch reuses the sequence-guarded refreshPlot (B-F3).
  plotSeq += 1
  plotData.value = []
  plotLoading.value = false
  if (!value || !selectedFeature.value) return
  await refreshPlot()
})

watch(boundDialog, (open) => {
  // Closing the drawer via its close button leaves `selectedBound` set, so the
  // selection watcher does not fire. Invalidate the preview here too, so a
  // response that lands while the drawer is closed can never re-enable apply on
  // reopen for a correction the operator abandoned (B3-F1).
  if (open) return
  previewSeq += 1
  invalidateApply()
  previewKey.value = null
  preview.value = null
  previewError.value = null
  previewLoading.value = false
})

function currentBoundParams(): Record<string, unknown> {
  const window = currentWindow()
  return {
    module: boundModule.value,
    state: apiBoundState.value,
    from: window.from,
    to: window.to,
    q: search.value,
  }
}

/**
 * Load the live runtime gates and mirror them into the readiness cards.
 *
 * The cards render the same gate state the "Change detection modes" dialog
 * binds to, so the runtime keys must be present before the dialog is ever
 * opened -- otherwise every card would show the composable's optimistic
 * default instead of the deployed truth.
 */
async function refreshRuntimeGates(): Promise<void> {
  await configurationStore.fetchRuntime()
  runtimeGates.syncFromRuntime()
}

onMounted(() => {
  operationsRefresh.register(
    async () => {
      const refreshes: Array<Promise<void>> = [store.load(currentBoundParams())]
      if (tab.value === 'rhythm' && !rhythm.loading)
        refreshes.push(rhythm.loadFleet(rhythmModule.value, rhythmFleetSince()))
      await Promise.all(refreshes)
    },
    () => store.loading,
  )
  void operationsRefresh.refresh()
  void refreshRuntimeGates()
})
onUnmounted(operationsRefresh.unregister)
usePolling(operationsRefresh.refresh, OPERATIONS_HEAVY_POLL_INTERVAL_MS)
usePolling(refreshRuntimeGates, OPERATIONS_HEAVY_POLL_INTERVAL_MS)
usePolling(() => store.reconcileTrainingStatus(), 5000)
usePolling(() => store.advanceRetrainCooldown(), 1000)

function stateKind(state: string): 'ok' | 'warn' | 'err' | 'muted' | 'info' {
  return state === 'ready' ? 'ok' : state === 'degraded' ? 'err' : state === 'training' ? 'info' : 'warn'
}
const MODULE_HELP: Record<string, string> = {
  conn: 'Connections: per-flow connection metrics (network_metrics / conn UCIs) collapsed by wildcard ports.',
  mac_traffic: 'Assets: per-MAC device traffic (mac_traffic) used to profile individual hosts on the segment.',
  proto_traffic: 'Protocols: per-protocol traffic (proto_traffic) used to profile ICS/OT protocol behaviour.',
}
function moduleHelp(module: string): string {
  return MODULE_HELP[module] ?? `Detection module ${module}.`
}
function readinessHelp(state: string): string {
  if (state === 'ready') return 'Ready: trained bounds/profiles cover the observed series and the schema is compatible.'
  if (state === 'degraded')
    return 'Degraded: bounds exist but many observed Series/UCI have no trained bound (NoBounds) or the schema drifted; detection still runs but coverage is incomplete.'
  if (state === 'training') return 'Training: a retrain run is in progress; detection stays online meanwhile.'
  return 'Untrained / observe-only: no usable trained bounds yet, so this module only observes.'
}
function noBoundsSeries(item: { no_bounds_series_count?: number; no_bounds_count: number }): number {
  return item.no_bounds_series_count ?? item.no_bounds_count
}
function formatDate(value: string | null | undefined): string {
  return value ? new Date(value).toLocaleString('de-DE', { timeZone: 'Europe/Berlin' }) : 'Not recorded'
}

function formatTrainingWindow(status: TrainingWindowStatus): string {
  return `${formatDate(status.windowStart)} → ${formatDate(status.windowStop)} (Europe/Berlin)`
}

/**
 * Extract individual training windows from a completed-training snapshot.
 * Falls back to a single `[windowStart, windowStop]` pair when the backend
 * did not report explicit `intervals` (legacy/older runs).
 */
function trainedWindows(status: TrainingWindowStatus): [string, string][] {
  if (status.intervals?.length) return status.intervals
  if (status.windowStart && status.windowStop) return [[status.windowStart, status.windowStop]]
  return []
}

/**
 * Reuse a previously trained window: convert its UTC timestamps to
 * Europe/Berlin `datetime-local` format and append to the matching
 * interval list (bounds or classifier).
 */
function reuseWindow(scope: 'bounds' | 'ml', win: [string, string]): void {
  const target = scope === 'bounds' ? boundsIntervals : classifierIntervals
  const toLocal = (utc: string): string => {
    const d = new Date(utc)
    // datetime-local needs YYYY-MM-DDTHH:MM in the user's local timezone
    const tz = new Date(d.getTime() - d.getTimezoneOffset() * 60000)
    return tz.toISOString().slice(0, 16)
  }
  const newStart = toLocal(win[0])
  const newEnd = toLocal(win[1])
  if (hasDuplicateWindow(target, newStart, newEnd)) {
    $q.notify({ type: 'warning', message: 'This window is already in the list.' })
    return
  }
  target.push({ start: newStart, end: newEnd })
}

function _trainingStatusLine(scope: 'bounds' | 'ml'): string | null {
  const status = scope === 'bounds' ? store.boundsTrainingStatus : store.classifierTrainingStatus
  const last = scope === 'bounds' ? store.lastBoundsTraining : store.lastClassifierTraining
  if (status?.busy && status.windowStart && status.windowStop) return `Training now: ${formatTrainingWindow(status)}`
  if (last?.windowStart && last.windowStop) return `Last trained: ${formatTrainingWindow(last)}`
  return null
}

function eventCount(item: BoundReviewItem): number {
  if (item.timeline_events?.length) return item.timeline_events.length
  return item.event_count ?? (item.violation_count + (item.nobounds_count ?? 0) || item.timeline.length)
}
function stateBadgeKind(state: string): 'ok' | 'warn' | 'err' | 'muted' | 'info' {
  if (state === 'OK' || state === 'ready' || state === 'current') return 'ok'
  if (state === 'Violation' || state === 'BoundViolation' || state === 'stale') return 'warn'
  if (state === 'NoBounds' || state === 'failed' || state === 'no-data') return 'err'
  if (state === 'training') return 'info'
  return 'muted'
}
function toggleStatus(state: string): void {
  const next = new Set(activeStates.value)
  if (next.has(state)) next.delete(state)
  else next.add(state)
  // `activeStates` is the sole filter authority; the API query and combobox
  // both derive from it, so nothing else needs updating here (B-F1).
  activeStates.value = next
}
function openBound(row: BoundReviewItem): void {
  // Re-opening the same row (drawer previously closed via its button leaves
  // `selectedBound` set) must still reopen the drawer, so open it explicitly
  // rather than relying solely on the selection watcher.
  selectedBound.value = row
  boundDialog.value = true
}
function selectFeature(feature: string): void {
  selectedFeature.value = feature
  void refreshPlot()
}
async function refreshPlot(): Promise<void> {
  if (!selectedBound.value || !selectedFeature.value) return
  const seq = ++plotSeq
  const module = selectedBound.value.module
  const series = selectedBound.value.series_id
  const feature = selectedFeature.value
  plotLoading.value = true
  try {
    const { start, stop } = windowForChart()
    const data = await store.fetchSeriesTimeseries(module, series, feature, start, stop)
    if (seq !== plotSeq) return
    plotData.value = data
  } catch {
    if (seq !== plotSeq) return
    plotData.value = []
  } finally {
    // Only the latest request may release the loading flag; a stale response
    // must not clear a spinner belonging to a newer in-flight request.
    if (seq === plotSeq) plotLoading.value = false
  }
}
function boundValue(feature: string, side: 'lower' | 'upper'): string {
  const key = side === 'lower' ? 'lower_bounds' : 'upper_bounds'
  const value = selectedBound.value?.current_bounds?.[key]?.[feature]
  if (typeof value !== 'number' || !Number.isFinite(value)) return 'Not available'
  return new Intl.NumberFormat(undefined, { maximumSignificantDigits: 7 }).format(value)
}
function currentBoundValue(feature: string, side: 'lower' | 'upper'): string {
  if (!selectedHasBounds.value) return 'Not available'
  return boundValue(feature, side)
}
function featureViolationCount(feature: string): number {
  return timelineEvents.value.filter((event) => event.features.includes(feature)).length
}
function goToTraining(): void {
  tab.value = 'training'
}
function onSelectTrainTile(): void {
  createSubMode.value = 'train'
  goToTraining()
}
function resetPreview(): void {
  // Proposed values changed. Bump `proposedRev` so an in-flight preview that
  // was started against the previous proposed values is dropped when it
  // resolves, and clear the resolved preview/key so apply is disabled until a
  // fresh matching preview succeeds (B3-F1). Not `previewSeq`: a proposed edit
  // that predates the current in-flight request must not cancel that request.
  proposedRev += 1
  invalidateApply()
  previewKey.value = null
  preview.value = null
  previewError.value = null
}
function baselineDetail(baseline: Record<string, unknown>): string {
  const chunks = Number(baseline.pcap_chunk_count ?? 0)
  const sizeBytes = Number(baseline.size_bytes ?? 0)
  return `${chunks} PCAP file${chunks === 1 ? '' : 's'} · ${(sizeBytes / 1_000_000).toFixed(2)} MB`
}
function openNoBounds(module: string): void {
  tab.value = 'bounds'
  boundModule.value = module
  activeStates.value = new Set(['NoBounds'])
}
async function startTraining(): Promise<void> {
  try {
    await store.startBoundsTraining(normalizeIntervals(boundsIntervals))
    $q.notify({ type: 'info', message: 'Training started. Follow phase progress in Jobs & History.' })
  } catch (error: unknown) {
    if ((error as { status?: number }).status !== 429)
      $q.notify({ type: 'negative', message: 'Training could not be started.' })
  }
}
async function startClassifier(): Promise<void> {
  try {
    await store.startClassifierTraining(normalizeIntervals(classifierIntervals), mitreFile.value)
    $q.notify({ type: 'info', message: 'Classifier training started. Follow it in Jobs & History.' })
  } catch (error: unknown) {
    if ((error as { status?: number }).status !== 429)
      $q.notify({ type: 'negative', message: 'Classifier training could not be started.' })
  }
}

function openLabelSourcePicker(): void {
  labelSourceInput.value?.click()
}

async function onLabelSourceSelected(event: Event): Promise<void> {
  const input = event.target as HTMLInputElement
  const file = input.files?.[0]
  input.value = ''
  labelSourceError.value = ''
  if (!file) return
  if (!file.name.toLowerCase().endsWith('.json')) {
    labelSourceError.value = 'Select a JSON ground-truth file.'
    return
  }
  if (file.size > 5 * 1024 * 1024) {
    labelSourceError.value = 'Label source exceeds the 5 MiB size limit.'
    return
  }
  try {
    const content = await file.text()
    JSON.parse(content)
    const source = await store.uploadLabelSource(file.name, content)
    mitreFile.value = source.worker_path
  } catch (error: unknown) {
    labelSourceError.value =
      error instanceof Error
        ? error.message
        : typeof error === 'object' && error !== null && 'message' in error
          ? String((error as { message: unknown }).message)
          : 'Label source upload failed.'
  }
}

function addInterval(intervals: Array<{ start: string; end: string }>): void {
  intervals.push({ start: '', end: '' })
}

function intervalSummary(intervals: TrainingIntervalValue[]) {
  return summarizeTrainingIntervals(intervals)
}

function intervalDuration(interval: TrainingIntervalValue): string {
  const minutes = intervalDurationMinutes(interval)
  return minutes === null ? '—' : `${minutes} min`
}

function intervalsValid(intervals: Array<{ start: string; end: string }>): boolean {
  return (
    intervals.length > 0 &&
    intervals.every((interval) => interval.start && interval.end && interval.start < interval.end) &&
    !hasDuplicateIntervals(intervals)
  )
}

/**
 * Check whether an interval with the exact same start+end already exists
 * in the list. Used by reuseWindow to prevent adding a duplicate.
 */
function hasDuplicateWindow(intervals: Array<{ start: string; end: string }>, start: string, end: string): boolean {
  return intervals.some((interval) => interval.start === start && interval.end === end)
}

/**
 * Check whether the interval list contains any duplicate windows
 * (same start AND same end). Used by intervalsValid to block training
 * start when duplicates are present.
 */
function hasDuplicateIntervals(intervals: Array<{ start: string; end: string }>): boolean {
  const seen = new Set<string>()
  for (const interval of intervals) {
    const key = `${interval.start}|${interval.end}`
    if (seen.has(key)) return true
    seen.add(key)
  }
  return false
}

function normalizeIntervals(intervals: Array<{ start: string; end: string }>): Array<{ start: string; end: string }> {
  return [...intervals].sort((left, right) => left.start.localeCompare(right.start))
}
async function createBaseline(): Promise<void> {
  try {
    await store.createBaseline(newBaseline.name, newBaseline.start, newBaseline.end)
    newBaseline.name = ''
    newBaseline.start = ''
    newBaseline.end = ''
    $q.notify({ type: 'positive', message: 'Baseline created.' })
  } catch {
    $q.notify({ type: 'negative', message: 'Baseline could not be created.' })
  }
}
/**
 * Resolve the operator-visible on/off wording for one detection gate.
 *
 * The runtime gate state the "Change detection modes" dialog binds to is the
 * single source of truth, so a card can never contradict its own dialog. The
 * readiness payload (`bounds_state` / `frequency_state`) is only a fallback
 * for modules outside `DETECTION_GATE_MODULES` or before the first runtime
 * read resolves.
 */
function gateStateLabel(module: string, gate: keyof DetectionGateState, fallback?: string): string {
  if (DETECTION_GATE_MODULES.includes(module as DetectionGateModule)) {
    return runtimeGates.confirmed[module as DetectionGateModule][gate] ? 'enabled' : 'disabled'
  }
  return fallback ?? 'unknown'
}
function openModeDialog(module: string): void {
  if (!DETECTION_GATE_MODULES.includes(module as DetectionGateModule)) return
  selectedGateModule.value = module as DetectionGateModule
  runtimeGates.open(selectedGateModule.value)
  modeReason.value = ''
  modeDialog.value = true
  void configurationStore.fetchRuntime().then(() => runtimeGates.syncFromRuntime(selectedGateModule.value!))
}
function closeModeDialog(): void {
  runtimeGates.close()
  modeDialog.value = runtimeGates.dialogOpen.value
}
async function submitModeChange(): Promise<void> {
  const submitted = await runtimeGates.submit(modeReason.value)
  if (!submitted) return
  modeDialog.value = false
  selectedGateModule.value = null
  modeReason.value = ''
  void refreshRuntimeGates()
  $q.notify({
    type: 'positive',
    message: 'Live detection gates saved. Detector will consume the change on its next poll.',
  })
}
function proposedEnvelope(): BoundsEnvelope {
  const lower: Record<string, number | null> = {}
  const upper: Record<string, number | null> = {}
  for (const feature of proposedFeatures.value) {
    const entry = proposed.value[feature]
    lower[feature] = entry?.lower ?? null
    upper[feature] = entry?.upper ?? null
  }
  return { lower_bounds: lower, upper_bounds: upper }
}
async function computePreview(): Promise<void> {
  // Let any pending proposed-edit invalidation settle first, so `proposedRev`
  // reflects the values this preview is about to send. Without this, a proposed
  // edit made immediately before this call would fire its watcher mid-flight
  // and wrongly drop a preview that already incorporated it (B3-F1).
  await nextTick()
  const bound = selectedBound.value
  if (!bound || !canPreview.value) return
  // Capture the selection/action identity and generation tokens at request
  // start; any later row/action/drawer change bumps `previewSeq` and a later
  // proposed edit bumps `proposedRev`. Both clear `previewKey`, so a slow
  // response for this request is dropped instead of seeding the current
  // selection or an outdated set of proposed values (B3-F1).
  const seq = ++previewSeq
  const rev = proposedRev
  const action = correctionAction.value
  const key = currentPreviewKey()
  previewLoading.value = true
  previewError.value = null
  previewKey.value = null
  try {
    const before: BoundsEnvelope = selectedHasBounds.value
      ? {
          lower_bounds: { ...bound.current_bounds.lower_bounds },
          upper_bounds: { ...bound.current_bounds.upper_bounds },
        }
      : { lower_bounds: {}, upper_bounds: {} }
    const result = await store.previewBoundsCorrection(
      bound.module,
      bound.series_id,
      action,
      before,
      proposedEnvelope(),
      reason.value.trim(),
    )
    if (seq !== previewSeq || rev !== proposedRev) return
    preview.value = result
    previewKey.value = key
  } catch (error: unknown) {
    if (seq !== previewSeq || rev !== proposedRev) return
    previewError.value =
      typeof error === 'object' && error !== null && 'message' in error
        ? String((error as { message: unknown }).message)
        : 'Server preview failed.'
  } finally {
    // Only the latest request may release the spinner; a stale response must
    // not clear a loading flag that belongs to a newer preview.
    if (seq === previewSeq) previewLoading.value = false
  }
}

async function suggestBounds(): Promise<void> {
  const bound = selectedBound.value
  if (!bound) return
  const window = currentWindow()
  if (!window.from || !window.to) {
    suggestionMessage.value = 'Choose a finite time range before requesting observed-data suggestions.'
    return
  }
  const seq = ++suggestionSeq
  const module = bound.module
  const series = bound.series_id
  const action = correctionAction.value
  suggestionLoading.value = true
  suggestionMessage.value = ''
  suggestionEvidence.value = null
  try {
    const suggestion: BoundSuggestionResponse = await store.suggestBounds(
      module,
      series,
      action,
      window.from,
      window.to,
    )
    // Discard a proposal whose selection/mode has since changed so it never
    // seeds editable bounds for the wrong row or action (B-F3).
    if (seq !== suggestionSeq) return
    const features = new Set([
      ...Object.keys(suggestion.proposed.lower_bounds),
      ...Object.keys(suggestion.proposed.upper_bounds),
    ])
    proposed.value = Object.fromEntries(
      [...features].map((feature) => [
        feature,
        {
          lower: suggestion.proposed.lower_bounds[feature] ?? null,
          upper: suggestion.proposed.upper_bounds[feature] ?? null,
        },
      ]),
    )
    suggestionEvidence.value = {
      status: suggestion.status,
      evidenceCount: suggestion.evidence_count,
      windowFrom: suggestion.window_from,
      windowTo: suggestion.window_to,
    }
    suggestionMessage.value =
      suggestion.status === 'unavailable'
        ? suggestion.message
        : `${suggestion.status === 'partial' ? 'Partial' : 'Observed'} suggestion: ${suggestion.evidence_count} value(s) in [from, to). Values remain editable; Apply validates before mutation.`
  } catch (error: unknown) {
    if (seq !== suggestionSeq) return
    suggestionMessage.value = error instanceof Error ? error.message : 'Observed-data suggestion failed.'
  } finally {
    if (seq === suggestionSeq) suggestionLoading.value = false
  }
}
async function applyCorrection(): Promise<void> {
  // One-click apply: no separate Preview step is required. Apply is a
  // selection-scoped async operation, so it snapshots the immutable correction
  // identity (row + action), the proposed generation and the reason BEFORE any
  // await, and re-verifies all of them after the internal preview and before
  // mutating. A switch of row/action, a proposed edit, or closing the drawer
  // while it is pending cancels the mutation.
  if (applyLoading.value || applyStarting) return
  // Let pending proposed-edit watcher invalidations settle first so the
  // generation snapshot below reflects the values this apply will send (an edit
  // made right before the call must not cancel the apply it precedes).
  applyStarting = true
  try {
    await nextTick()
  } finally {
    applyStarting = false
  }
  const bound = selectedBound.value
  if (!boundDialog.value || !bound || !canPreview.value) return
  const seq = ++applySeq
  const key = currentPreviewKey()
  const action = correctionAction.value
  const rev = proposedRev
  const reasonText = reason.value.trim()
  const isCurrent = (): boolean =>
    seq === applySeq && rev === proposedRev && boundDialog.value && currentPreviewKey() === key
  let mutating = false
  applyLoading.value = true
  try {
    if (!preview.value || previewKey.value !== key) await computePreview()
    if (!isCurrent()) return
    const resolved = preview.value
    if (!resolved || previewKey.value !== key) return
    mutating = true
    applyMutating = true
    await store.applyBoundsCorrection(bound.module, bound.series_id, action, resolved.before, resolved.after, reasonText)
    $q.notify({ type: 'positive', message: 'Correction applied and audited.' })
    // Only close the drawer if it still shows the row that was just corrected.
    if (currentPreviewKey() === key) boundDialog.value = false
    await store.filterBounds(currentBoundParams())
  } catch (error: unknown) {
    const message =
      typeof error === 'object' && error !== null && 'message' in error
        ? String((error as { message: unknown }).message)
        : 'Correction failed.'
    $q.notify({ type: 'negative', message })
    // Keep the drawer open and retriable on conflict/error.
  } finally {
    // Only the operation that owns the loading flag may release it; an
    // invalidated apply already released it and a newer apply may hold it.
    if (mutating) {
      applyMutating = false
      applyLoading.value = false
    } else if (seq === applySeq) {
      applyLoading.value = false
    }
  }
}

function loadBoundReviewPrefs(): void {
  if (typeof window === 'undefined') return
  // Each preference is validated independently: a corrupt/missing member falls
  // back to its default (Dense / Full) without discarding a valid sibling, and
  // non-object payloads (null, arrays, primitives) never throw.
  let parsed: unknown
  try {
    parsed = JSON.parse(localStorage.getItem('bound-review:prefs') ?? '{}')
  } catch {
    return
  }
  const stored: Record<string, unknown> =
    typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed) ? (parsed as Record<string, unknown>) : {}
  if (stored.density === 'standard' || stored.density === 'dense') density.value = stored.density
  // Legacy alias: an older build persisted the hidden card mode as "collapsed".
  if (stored.cardMode === 'collapsed') cardMode.value = 'hidden'
  else if (stored.cardMode === 'full' || stored.cardMode === 'compact' || stored.cardMode === 'hidden')
    cardMode.value = stored.cardMode
}

onMounted(loadBoundReviewPrefs)
</script>

<style scoped lang="scss">
.cd-detection-page {
  width: 100%;
  min-width: 0;
}
.detection-command-bar {
  display: flex;
  align-items: center;
  min-height: 40px;
  gap: 10px;
  margin-bottom: 14px;
  border-bottom: 1px solid var(--cd-border);
}
.detection-command-bar :deep(.q-tabs) {
  min-height: 39px;
}
.detection-command-bar :deep(.q-tab) {
  min-height: 39px;
  padding: 0 16px;
  font-size: 13px;
  font-weight: 600;
}
.training-actions {
  display: flex;
  align-items: center;
  gap: 8px;
  min-width: 0;
  white-space: nowrap;
}
.training-console-frame {
  display: grid;
  gap: 14px;
  min-width: 0;
}
.training-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  align-items: stretch;
  gap: 14px;
  min-width: 0;
}
.training-panel,
.baseline-panel {
  min-width: 0;
  overflow: hidden;
  border: 1px solid color-mix(in srgb, var(--cd-border) 92%, var(--cd-surface-text));
  border-radius: $border-radius-md !important;
  box-shadow: var(--cd-shadow-sm);
  background: var(--cd-surface);
}
.training-panel {
  display: flex;
  flex-direction: column;
}
.training-panel__header {
  display: flex;
  align-items: center;
  min-height: 44px;
  gap: 7px;
  padding: 9px 14px;
  border-bottom: 1px solid color-mix(in srgb, var(--cd-border) 82%, var(--cd-surface-text));
}
.training-panel__title {
  font-size: 14px;
  font-weight: 600;
  white-space: nowrap;
}
.training-panel__descriptor {
  min-width: 0;
  overflow: hidden;
  color: var(--cd-muted);
  font-size: 11.5px;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.training-panel__body {
  display: flex;
  flex: 1;
  flex-direction: column;
  gap: 8px;
  padding: 11px 14px 10px;
}
.training-section-heading {
  display: flex;
  align-items: center;
  gap: 5px;
  min-height: 18px;
  color: var(--cd-muted);
  font-size: 11px;
  font-weight: 700;
  letter-spacing: 0.05em;
  text-transform: uppercase;
}

.training-window-status {
  min-height: 22px;
  margin: -2px 0 8px;
  color: var(--cd-text-muted);
  font-size: 12px;
  line-height: 1.4;
}
.training-window-list {
  display: flex;
  flex-direction: column;
  gap: 2px;
}
.training-window-list__label {
  font-weight: 600;
  color: var(--cd-text);
}
.training-window-list__row {
  display: flex;
  align-items: center;
  gap: 4px;
}
.training-window-list__time {
  flex: 1;
  min-width: 0;
}
.training-section-heading__copy {
  min-width: 0;
  overflow: hidden;
  font-weight: 400;
  letter-spacing: 0;
  text-overflow: ellipsis;
  text-transform: none;
  white-space: nowrap;
}
.training-section-heading--source {
  margin-top: 1px;
}
.interval-stack {
  display: flex;
  flex-direction: column;
  gap: 6px;
}
.interval-entry {
  min-width: 0;
}
.interval-row {
  display: grid;
  grid-template-columns: minmax(0, 1fr) 14px minmax(0, 1fr) 58px 28px;
  align-items: center;
  gap: 6px;
}
.interval-row__input {
  min-width: 0;
}
.interval-row__input :deep(.q-field__control) {
  height: 34px;
}
.interval-row__input :deep(.q-field__native) {
  min-width: 0;
  padding: 4px 7px;
  font-family: $font-family-mono;
  font-size: 11.5px;
}
.interval-arrow {
  color: var(--cd-muted);
  font-size: 12px;
  text-align: center;
}
.interval-duration {
  color: var(--cd-muted);
  font-family: monospace;
  font-size: 0.72rem;
  text-align: right;
  white-space: nowrap;
}
.interval-summary {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 4px;
  color: var(--cd-muted);
  font-size: 0.75rem;
}
.interval-summary b {
  color: var(--cd-surface-text);
}
.interval-summary--invalid {
  color: var(--q-negative);
}
.interval-summary--incomplete {
  color: var(--cd-muted);
}
.interval-summary--duplicate {
  color: var(--q-warning);
}
.training-add-window {
  align-self: flex-start;
  min-height: 28px;
  padding: 3px 8px;
  font-size: 12px;
}
.label-source-input {
  margin-top: -2px;
}
.label-source-input :deep(.q-field__control) {
  height: 34px;
}
.label-source-input :deep(.q-field__native) {
  font-family: $font-family-mono;
  font-size: 11.5px;
}
.label-source-input__kind {
  color: var(--cd-muted);
  font-size: 10px;
  letter-spacing: 0.04em;
  white-space: nowrap;
}
.label-source-file {
  display: none;
}
.training-panel__footer {
  display: flex;
  align-items: center;
  min-height: 52px;
  gap: 10px;
  padding: 8px 14px;
  border-top: 1px solid color-mix(in srgb, var(--cd-border) 82%, var(--cd-surface-text));
}
.training-panel__footer :deep(.q-btn) {
  min-height: 34px;
  padding: 5px 13px;
  font-size: 12px;
}
.baseline-panel__body {
  display: grid;
  gap: 9px;
  padding: 10px 14px 12px;
}
.baseline-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 9px;
}
.baseline-item {
  display: flex;
  align-items: center;
  min-width: 0;
  gap: 7px;
  padding: 8px 10px;
  border: 1px solid var(--cd-border);
  border-radius: $border-radius-md;
  background: color-mix(in srgb, var(--cd-background) 58%, var(--cd-surface));
}
.baseline-item__content {
  display: grid;
  flex: 1;
  min-width: 0;
  gap: 1px;
}
.baseline-item__content strong,
.baseline-item__content span {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.baseline-item__content strong {
  font-size: 13px;
}
.baseline-item__content span {
  color: var(--cd-muted);
  font-size: 11px;
}
.baseline-create-row {
  display: grid;
  grid-template-columns: minmax(0, 1.05fr) repeat(2, minmax(0, 1.3fr)) auto;
  align-items: center;
  gap: 8px;
}
.baseline-create-row :deep(.q-field__control) {
  height: 34px;
}
.baseline-create-row :deep(.q-field__native) {
  min-width: 0;
  font-size: 11.5px;
}
.baseline-empty {
  padding: 6px 0;
  color: var(--cd-muted);
  font-size: 12px;
}
.bound-cards {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 12px;
  margin-bottom: 10px;
}
.bound-cards.rhythm-cards {
  grid-template-columns: repeat(6, minmax(0, 1fr));
}
.bound-filter-field {
  min-height: 56px;
}
.bound-filter-field :deep(.q-field__control) {
  min-height: 56px;
  height: 56px;
}
.bound-filter-field--state :deep(.q-field__native) {
  max-height: 40px;
  overflow-y: auto;
}
.bound-cards.mode-collapsed {
  display: none;
}
.bound-cards.mode-collapsed + .active-filter-line {
  margin-top: 8px;
}
.bound-card {
  border-left: 3px solid var(--cd-primary);
  min-width: 0;
}
.bound-card.nob {
  border-left-color: var(--q-negative);
}
.bound-card.vio {
  border-left-color: var(--q-warning);
}
.bound-card.ok {
  border-left-color: var(--q-positive);
}
.bound-cards.mode-compact .bound-card .q-card__section {
  padding: 8px 12px;
}
.bound-summary-strip {
  display: flex;
  flex-wrap: nowrap;
  align-items: center;
  gap: 8px;
  width: 100%;
  padding: 7px 10px;
  border: 1px solid var(--cd-border);
  border-left: 3px solid var(--cd-primary);
  border-radius: $border-radius-sm;
}
.bound-summary-chip {
  display: flex;
  flex: 1 1 0;
  align-items: center;
  justify-content: space-between;
  min-width: 150px;
  padding: 7px 10px;
  background: transparent;
  cursor: pointer;
  font: inherit;
  text-align: left;
  white-space: nowrap;
  border: 1px solid var(--cd-border);
  border-radius: $border-radius-pill;
  color: var(--cd-muted);
  font-size: $font-size-sm;
}
.bound-summary-chip--active {
  border-color: var(--cd-primary);
  background: color-mix(in srgb, var(--cd-primary) 12%, var(--cd-surface));
  color: var(--cd-surface-text);
}
.bound-summary-total {
  flex: 0 0 auto;
  padding: 0 8px;
  white-space: nowrap;
}
.correct-editor {
  display: flex;
  flex-direction: column;
  gap: 10px;
}
.correction-tiles {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 8px;
}
.correction-tile {
  display: grid;
  grid-template-columns: auto minmax(0, 1fr);
  grid-template-rows: auto auto;
  align-items: center;
  gap: 2px 8px;
  padding: 9px 10px;
  border: 1px solid var(--cd-border);
  border-radius: $border-radius-sm;
  background: var(--cd-surface);
  color: var(--cd-surface-text);
  cursor: pointer;
  text-align: left;
  font: inherit;
}
.correction-tile:hover {
  border-color: var(--cd-primary);
}
.correction-tile--active {
  border-color: var(--cd-primary);
  box-shadow: inset 0 0 0 1px var(--cd-primary);
  background: color-mix(in srgb, var(--cd-primary) 10%, var(--cd-surface));
}
.correction-tile .q-icon {
  grid-row: 1 / span 2;
  color: var(--cd-primary);
}
.correction-tile__title {
  font-weight: 600;
  font-size: 13px;
}
.correction-tile__desc {
  color: var(--cd-muted);
  font-size: 0.72rem;
}
.correction-actionbar {
  display: flex;
  align-items: center;
  gap: 8px;
}
.correction-safety-help {
  display: inline-flex;
  align-items: center;
}
.proposed-grid {
  display: flex;
  flex-direction: column;
  border: 1px solid var(--cd-border);
  border-radius: $border-radius-sm;
}
.proposed-grid__head,
.proposed-grid__row {
  display: grid;
  grid-template-columns: minmax(0, 1.3fr) minmax(0, 1fr) minmax(0, 1fr) minmax(0, 1fr);
  align-items: center;
  gap: 8px;
  padding: 1px 8px;
}
.proposed-grid__head {
  color: var(--cd-surface-text);
  font-size: 0.875rem;
  font-weight: 700;
  border-bottom: 1px solid var(--cd-border);
}
.proposed-grid__row + .proposed-grid__row {
  border-top: 1px solid color-mix(in srgb, var(--cd-border) 60%, transparent);
}
.proposed-grid__name {
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  font-weight: 600;
}
.proposed-grid__current {
  min-width: 0;
  overflow-wrap: anywhere;
  color: var(--cd-surface-text);
  font-size: 0.875rem;
  line-height: 1.25;
}
.proposed-grid__row :deep(.q-field--outlined .q-field__control) {
  min-height: 32px;
  height: 32px;
}
.proposed-grid__row :deep(.q-field--dense .q-field__control),
.proposed-grid__row :deep(.q-field--dense .q-field__native) {
  min-height: 32px;
}
.proposed-grid__row :deep(.q-field__native),
.proposed-grid__row :deep(.q-field__input) {
  padding-top: 0;
  padding-bottom: 0;
}
.proposed-grid__row :deep(.q-field__bottom) {
  display: none;
}
.proposed-grid__empty {
  padding: 8px;
}
.suggestion-provenance strong,
.suggestion-provenance span {
  display: block;
}
.suggestion-provenance span {
  color: var(--cd-muted);
  font-size: 0.72rem;
}
.suggestion-provenance {
  display: grid;
  grid-template-columns: auto minmax(0, 1fr);
  align-items: start;
  gap: 8px;
  padding: 8px 10px;
  border: 1px solid color-mix(in srgb, var(--cd-primary) 35%, var(--cd-border));
  border-radius: $border-radius-sm;
  margin-top: 6px;
  background: color-mix(in srgb, var(--cd-primary) 5%, var(--cd-surface));
}
.suggestion-provenance--success {
  border-color: color-mix(in srgb, var(--q-positive) 48%, var(--cd-border));
  background: color-mix(in srgb, var(--q-positive) 10%, var(--cd-surface));
}
.suggestion-provenance--success .q-icon {
  color: var(--q-positive) !important;
}
.display-settings-card {
  width: min(360px, calc(100vw - 32px));
}
.bound-number {
  font-size: 1.65rem;
  font-weight: 700;
  line-height: 1.25;
}
.active-filter-line {
  min-height: 26px;
  color: var(--cd-muted);
  font-size: 0.75rem;
}
.series-id {
  overflow: hidden;
  max-width: 100%;
  text-overflow: ellipsis;
  white-space: nowrap;
  font-family: inherit;
}
.module-friendly {
  font-family: inherit;
}
.drawer-series {
  flex: 1 1 auto;
  min-width: 0;
}
.bound-drawer {
  top: 50px !important;
  width: min(640px, 100vw) !important;
  height: calc(100dvh - 50px) !important;
}
:deep(.bound-drawer) {
  max-width: 100vw;
}
:deep(.q-table__middle) {
  max-width: 100%;
  overflow-x: auto;
}
.drawer-shell {
  display: flex;
  height: 100%;
  min-height: 0;
  flex-direction: column;
}
.drawer-head {
  flex: 0 0 auto;
  padding: 8px 12px;
  background: var(--cd-surface);
}
.drawer-head-line {
  gap: 8px;
  min-width: 0;
}
.drawer-head-type {
  flex: 0 0 auto;
  white-space: nowrap;
  font-size: 0.75rem;
}
.drawer-scroll {
  flex: 1 1 auto;
  min-height: 0;
  overflow-y: auto;
  scrollbar-color: color-mix(in srgb, var(--cd-muted) 72%, transparent) transparent;
  scrollbar-gutter: stable;
  scrollbar-width: auto;
  padding: 10px 12px max(128px, calc(env(safe-area-inset-bottom) + 96px));
}
.drawer-scroll::-webkit-scrollbar {
  width: 10px;
}
.drawer-scroll::-webkit-scrollbar-thumb {
  border: 2px solid transparent;
  border-radius: 999px;
  background: color-mix(in srgb, var(--cd-muted) 70%, transparent);
  background-clip: padding-box;
}
.drawer-scroll::-webkit-scrollbar-track {
  background: color-mix(in srgb, var(--cd-border) 28%, transparent);
}
.drawer-kv {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 8px;
}
.drawer-kv > div {
  padding: 10px;
  border: 1px solid var(--cd-border);
  border-radius: 4px;
}
.drawer-kv span,
.drawer-kv b {
  display: block;
}
.drawer-kv span {
  color: var(--cd-muted);
  font-size: 0.7rem;
  text-transform: uppercase;
}
.feature-selected {
  background: color-mix(in srgb, var(--cd-primary) 14%, transparent);
}
.drawer-scroll--flush {
  display: flex;
  flex-direction: column;
  overflow: hidden;
  padding-bottom: 10px;
}
.overview-pane {
  display: flex;
  flex: 1 1 auto;
  min-height: 0;
  flex-direction: column;
  gap: 8px;
}
.overview-pane__banner,
.overview-pane__kpis,
.overview-pane__label {
  flex: 0 0 auto;
}
.drawer-kpi-tile {
  border: 1px solid var(--cd-border-strong, var(--cd-border));
}
.timeline-list {
  flex: 1 1 auto;
  min-height: 0;
  overflow-y: auto;
  margin: 0;
  padding: 0;
  list-style: none;
  border: 1px solid var(--cd-border);
  border-radius: $border-radius-sm;
}
.timeline-row {
  display: grid;
  grid-template-columns: auto auto minmax(0, 1fr);
  align-items: center;
  gap: 8px;
  padding: 5px 9px;
  font-size: 0.78rem;
}
.timeline-row + .timeline-row {
  border-top: 1px solid color-mix(in srgb, var(--cd-border) 60%, transparent);
}
.timeline-row__ts {
  white-space: nowrap;
  color: var(--cd-muted);
}
.timeline-row__feat {
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.correction-safety-dot {
  color: #f4b400;
  font-size: 1rem;
  line-height: 1;
}
.stats {
  display: grid;
  grid-template-columns: 1fr auto;
  gap: 8px 16px;
}
.stats span {
  color: var(--cd-muted);
}
.plot {
  min-height: 180px;
  border: 1px solid var(--cd-border);
}
// Light theme: keep the native indicator but guarantee it is dark enough to
// read against the light field. Dark theme rules live in the page-local
// non-scoped block below so `color-scheme` flips the browser-drawn glyph to a
// light color WITHOUT any body-level filter (which would create a containing
// block and break the fixed chat FAB).
.cd-detection-page :deep(input[type='datetime-local'])::-webkit-calendar-picker-indicator {
  opacity: 1;
  cursor: pointer;
}
:global(body) {
  overflow-x: clip;
}
@media (max-width: 1310px) {
  .training-grid {
    grid-template-columns: 1fr;
  }
  .training-panel__body {
    min-height: 137px;
  }
  .baseline-create-row {
    grid-template-columns: minmax(0, 1.05fr) repeat(2, minmax(0, 1.3fr)) auto;
  }
}
@media (max-width: 900px) {
  .bound-cards {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
  .bound-cards.rhythm-cards {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
  .bound-review-head {
    align-items: flex-start;
    flex-wrap: wrap;
  }
}
@media (max-width: 600px) {
  .cd-detection-page {
    width: 100%;
  }
  .detection-command-bar {
    align-items: flex-start;
    flex-direction: column;
  }
  .training-actions {
    white-space: normal;
  }
  .interval-row {
    grid-template-columns: minmax(0, 1fr) 12px minmax(0, 1fr) 42px 28px;
  }
  .baseline-create-row {
    grid-template-columns: 1fr;
  }
  .bound-cards {
    grid-template-columns: 1fr;
  }
  .bound-summary-strip {
    align-items: stretch;
    flex-direction: column;
  }
  .bound-summary-chip {
    flex: 1 1 auto;
  }
  .drawer-kv {
    grid-template-columns: 1fr;
  }
  .correction-tiles {
    grid-template-columns: 1fr;
  }
  .proposed-grid__head {
    display: none;
  }
  .proposed-grid__row {
    grid-template-columns: minmax(0, 1fr) minmax(0, 1fr);
  }
}

// UI-101 Rhythm Review — mirrors the Bound Review drawer geometry (640px right
// overlay) and mockup 004's fleet-table density.
.rhythm-state-strip {
  display: flex;
  gap: 7px;
  align-items: center;
  flex-wrap: wrap;
  padding: 6px 0 10px;
}

.rhythm-state-btn {
  border: 1px solid rgba(255, 255, 255, 0.14);
  border-radius: 14px;

  &--on {
    border-color: var(--q-primary);
  }
}

.rhythm-counts {
  // The filter fields resolve to a 64px grid cell (56px control + the
  // q-field bottom slot), identical to Bound Review. Left unconstrained
  // this caption wrapped to 96px and stretched the whole toolbar row, so
  // it is pinned to the same cell height and its own leading tightened
  // to fit rather than letting text set the row height.
  display: flex;
  height: 64px;
  flex-direction: column;
  align-items: flex-end;
  justify-content: center;
  overflow: hidden;
  line-height: 1.2;
  text-align: right;
}

.rhythm-state-select :deep(.q-field__native.row) {
  flex-wrap: nowrap;
  overflow: hidden;
}

.rhythm-state-select :deep(.q-chip) {
  flex: 0 0 auto;
}

.rhythm-form-grid {
  display: flex;
  flex-direction: column;
  margin-top: 6px;
  border: 1px solid var(--cd-border);
  border-radius: $border-radius-sm;
}

.rhythm-form-head,
.rhythm-form-row {
  display: grid;
  grid-template-columns: minmax(0, 1.3fr) minmax(0, 1fr) minmax(0, 1fr) auto;
  gap: 8px;
  align-items: center;
  padding: 1px 8px;
}

.rhythm-form-head {
  color: var(--cd-surface-text);
  font-size: 0.75rem;
  font-weight: 700;
  border-bottom: 1px solid var(--cd-border);
}

.rhythm-form-row {
  border-top: 1px solid color-mix(in srgb, var(--cd-border) 60%, transparent);

  label {
    font-size: 12px;
  }
}

.rhythm-current-value {
  color: var(--cd-surface-text);
}

.rhythm-form-row :deep(.rhythm-proposed--changed .q-field__control) {
  border-color: var(--q-warning);
  background: color-mix(in srgb, var(--q-warning) 12%, transparent);
}

.rhythm-history-empty {
  display: flex;
  min-height: 220px;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: 8px;
  color: var(--cd-muted);
  border: 1px dashed var(--cd-border);
  border-radius: $border-radius-sm;
  background: color-mix(in srgb, var(--cd-border) 18%, transparent);
  text-align: center;
}

.rhythm-preview-result {
  border-top: 1px solid rgba(255, 255, 255, 0.1);
  padding-top: 8px;
}

.rhythm-confirm-card {
  min-width: 420px;
}
</style>

<!--
  Dark-mode datetime-local picker styling is authored in a non-scoped block on
  purpose. When written as scoped `:global(.body--dark) ...::-webkit-calendar-picker-indicator`
  the bundler collapses the vendor pseudo-element + color-scheme override onto a
  bare `.body--dark { filter: ... }` rule, which applies a filter to <body> and
  turns it into the containing block for every position:fixed descendant (the
  chat FAB then anchors to page height instead of the viewport). Anchoring the
  rules under `.body--dark .cd-detection-page` keeps them page-local and keeps
  the filter on the input indicator only.
-->
<style lang="scss">
// Dark mode: `color-scheme: dark` makes the browser draw the native calendar
// picker indicator in a LIGHT color, so it is pixel-visible against the dark
// field. The filter is applied ONLY to the indicator pseudo-element (never the
// body), and a brightness boost guarantees high contrast rather than a faint
// grey glyph. This is page-local (.cd-detection-page) so it can never turn the
// body into a containing block for the fixed chat FAB.
.body--dark .cd-detection-page input[type='datetime-local'] {
  color-scheme: dark;
}
.body--dark .cd-detection-page input[type='datetime-local']::-webkit-calendar-picker-indicator {
  opacity: 1;
  filter: brightness(0) invert(0.85) sepia(0.4) saturate(4) hue-rotate(150deg) brightness(1.2);
}
</style>
