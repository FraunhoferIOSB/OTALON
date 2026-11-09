<template>
  <q-dialog v-model="open" position="right">
    <q-card style="min-width: 320px" class="settings-dialog">
      <q-card-section class="row items-center no-wrap q-pb-sm">
        <q-icon name="tune" size="20px" class="q-mr-sm" />
        <span class="text-subtitle1 text-weight-bold">Display Settings</span>
        <q-space />
        <q-btn flat round dense icon="close" @click="open = false" />
      </q-card-section>
      <q-separator />

      <q-card-section>
        <div class="text-caption text-weight-bold q-mb-xs">Font Size ({{ modelValue.fontSize }}px)</div>
        <q-slider
          :model-value="modelValue.fontSize"
          :min="minFontSize"
          :max="maxFontSize"
          :step="1"
          label
          label-always
          :label-value="`${modelValue.fontSize}px`"
          color="primary"
          class="q-mb-md"
          @update:model-value="onFontSizeChange"
          @change="onCommit"
        />

        <div class="text-caption text-weight-bold q-mb-xs">Row Density</div>
        <q-btn-toggle
          :model-value="modelValue.density"
          :options="densityOptions"
          no-caps
          color="grey-3"
          text-color="grey-9"
          toggle-color="primary"
          toggle-text-color="white"
          spread
          class="q-mb-md"
          @update:model-value="onDensityChange"
        />

        <div class="text-caption text-weight-bold q-mb-xs">
          Rows per page ({{ modelValue.rowsPerPage === 0 ? 'all' : modelValue.rowsPerPage }})
        </div>
        <q-slider
          :model-value="modelValue.rowsPerPage"
          :min="0"
          :max="100"
          :step="5"
          label
          label-always
          :label-value="modelValue.rowsPerPage === 0 ? 'all' : String(modelValue.rowsPerPage)"
          color="primary"
          class="q-mb-md"
          @update:model-value="onRowsPerPageChange"
          @change="onCommit"
        />

        <q-separator class="q-my-md" />

        <div class="text-caption text-weight-bold q-mb-xs">Visible Columns</div>
        <q-toggle
           v-for="col in tableColumns"
          :key="col.value"
          :model-value="modelValue.visibleColumns[col.value] ?? true"
          :label="col.label"
          color="primary"
          dense
          class="q-mr-md q-mb-xs"
          @update:model-value="(val: boolean) => onColumnToggle(col.value, val)"
        />

        <q-separator v-if="featureToggles.length > 0" class="q-my-md" />

        <div v-if="featureToggles.length > 0" class="text-caption text-weight-bold q-mb-xs">Feature Toggles</div>
        <q-toggle
          v-for="toggle in featureToggles"
          :key="toggle.value"
          :model-value="modelValue.featureToggles?.[toggle.value] ?? toggle.defaultValue"
          :label="toggle.label"
          color="primary"
          dense
          class="q-mr-md q-mb-xs"
          @update:model-value="(val: boolean) => onFeatureToggle(toggle.value, val)"
        />

        <template v-if="featureNames.length > 0">
          <q-separator class="q-my-md" />
          <div class="text-subtitle2 text-weight-bold q-mb-sm">Feature Plots</div>
          <div class="row items-center justify-between q-mb-sm">
            <div class="text-caption text-weight-bold">Visible Features</div>
            <q-btn
              v-if="defaultFeatures.length > 0"
              flat
              dense
              size="sm"
              icon="restart_alt"
              label="Restore defaults"
              @click="emit('update:visibleFeatures', [...defaultFeatures])"
            />
          </div>
          <q-option-group
            :model-value="visibleFeatures"
            :options="featureOptions"
            type="checkbox"
            dense
            @update:model-value="onVisibleFeaturesChange"
          />

          <div class="text-caption text-weight-bold q-mt-md">Data point cap</div>
          <q-select
            :model-value="sampleMaxPoints"
            :options="sampleOptions"
            emit-value
            map-options
            dense
            outlined
            @update:model-value="onSampleMaxPointsChange"
          />
          <div class="text-caption text-grey-7 q-mt-xs">
            Default: 300 points. Higher values preserve more detail; lower values aggregate more.
          </div>

          <q-toggle v-model="sharedCrosshairEnabled" label="Shared Crosshair" dense class="q-mt-md" />
          <div class="text-caption text-grey-7">Synchronize time position across CADENCE and feature plots</div>

          <div class="text-caption text-weight-bold q-mt-md q-mb-sm">Grid Columns</div>
          <q-btn-toggle
            :model-value="gridColumns"
            :options="columnOptions"
            dense
            spread
            no-caps
            toggle-color="primary"
            @update:model-value="onColumnsChange"
          />

          <div class="text-caption text-weight-bold q-mt-md q-mb-sm">Plot Size</div>
          <q-btn-toggle
            :model-value="plotSize"
            :options="sizeOptions"
            dense
            spread
            no-caps
            toggle-color="primary"
            @update:model-value="onPlotSizeChange"
          />

          <div
            v-if="showPortColumn !== undefined || showIdColumn !== undefined || visibleTableColumns"
            class="text-caption text-weight-bold q-mt-md q-mb-sm"
          >
            Table Columns
          </div>
          <q-toggle
            v-if="showPortColumn !== undefined"
            :model-value="showPortColumn"
            label="Show Port column"
            dense
            @update:model-value="(val: boolean) => emit('update:showPortColumn', val)"
          />
          <q-toggle
            v-if="showIdColumn !== undefined"
            :model-value="showIdColumn"
            label="Show ID column"
            dense
            @update:model-value="(val: boolean) => emit('update:showIdColumn', val)"
          />
          <q-option-group
            v-if="visibleTableColumns"
            :model-value="visibleTableColumns"
            :options="tableColumnOptions"
            type="checkbox"
            dense
            @update:model-value="onVisibleTableColumnsChange"
          />
        </template>

        <q-separator class="q-my-md" />

        <q-btn
          flat
          no-caps
          color="negative"
          icon="restart_alt"
          label="Reset to defaults"
          class="full-width"
          @click="$emit('reset')"
        />
      </q-card-section>
    </q-card>
  </q-dialog>
</template>

<script setup lang="ts">
import { useSharedCrosshair } from '~/composables/useSharedCrosshair'

/**
 * Reusable display-settings side dialog used by table-heavy pages
 * (Assets, Alarms, …).
 *
 * Exposes a numeric font-size slider, a row-density toggle, a
 * rows-per-page slider, and per-column visibility switches.  All
 * mutations are surfaced via ``v-model`` so the parent component owns
 * persistence (typically `localStorage`).
 */

export interface DisplaySettingsValue {
  fontSize: number
  density: 'compact' | 'normal' | 'comfortable'
  rowsPerPage: number
  visibleColumns: Record<string, boolean>
  featureToggles?: Record<string, boolean>
}

export interface ColumnDefinition {
  value: string
  label: string
}

export interface FeatureToggleDefinition {
  value: string
  label: string
  defaultValue: boolean
}

export interface FeaturePlotSettingsProps {
  featureNames: string[]
  featureLabels: Record<string, string>
  defaultFeatures: string[]
  visibleFeatures: string[]
  columns: number
  plotSize: string
  sampleMaxPoints: number
  showPortColumn?: boolean
  showIdColumn?: boolean
  visibleTableColumns?: string[]
}

interface Props {
  modelValue: DisplaySettingsValue
  open: boolean
  tableColumns: ColumnDefinition[]
  featureToggles?: FeatureToggleDefinition[]
  minFontSize?: number
  maxFontSize?: number
  featureNames?: string[]
  featureLabels?: Record<string, string>
  defaultFeatures?: string[]
  visibleFeatures?: string[]
  gridColumns?: number
  plotSize?: string
  sampleMaxPoints?: number
  showPortColumn?: boolean
  showIdColumn?: boolean
  visibleTableColumns?: string[]
}

interface Emits {
  (e: 'update:modelValue', value: DisplaySettingsValue): void
  (e: 'update:open' | 'update:showPortColumn' | 'update:showIdColumn', value: boolean): void
  (e: 'reset' | 'commit'): void
  (e: 'update:visibleFeatures' | 'update:visibleTableColumns', value: string[]): void
  (e: 'update:gridColumns' | 'update:sampleMaxPoints', value: number): void
  (e: 'update:plotSize', value: string): void
}

const props = withDefaults(defineProps<Props>(), {
  minFontSize: 10,
  maxFontSize: 22,
  featureToggles: () => [],
  featureNames: () => [],
  featureLabels: () => ({}),
  defaultFeatures: () => [],
  visibleFeatures: () => [],
  gridColumns: 1,
  plotSize: 'normal',
  sampleMaxPoints: 300,
})
const emit = defineEmits<Emits>()

const densityOptions = [
  { label: 'Compact', value: 'compact' as const },
  { label: 'Normal', value: 'normal' as const },
  { label: 'Comfortable', value: 'comfortable' as const },
]

const sampleOptions = [150, 300, 600, 1200, 2400].map((value) => ({ label: `${value} points`, value }))
const columnOptions = [1, 2, 3, 5].map((value) => ({ label: `${value}×N`, value }))
const sizeOptions = [
  { label: 'Compact', value: 'compact' },
  { label: 'Normal', value: 'normal' },
  { label: 'Large', value: 'large' },
]
const tableColumnOptions = [
  { label: 'Status', value: 'state' },
  { label: 'Name', value: 'name' },
  { label: 'IP', value: 'ip' },
  { label: 'MAC', value: 'mac' },
]
const featureOptions = computed(() => props.featureNames.map((name) => ({ label: props.featureLabels[name] ?? name, value: name })))
const sharedCrosshairEnabled = useSharedCrosshair().enabled

const open = computed({
  get: () => props.open,
  set: (val: boolean) => emit('update:open', val),
})

function emitUpdate(patch: Partial<DisplaySettingsValue>): void {
  emit('update:modelValue', { ...props.modelValue, ...patch })
}

function onFeatureToggle(feature: string, value: boolean): void {
  emitUpdate({ featureToggles: { ...props.modelValue.featureToggles, [feature]: value } })
  emit('commit')
}

function onFontSizeChange(value: number | null): void {
  if (typeof value === 'number') emitUpdate({ fontSize: value })
}

function onDensityChange(value: 'compact' | 'normal' | 'comfortable'): void {
  emitUpdate({ density: value })
  emit('commit')
}

function onRowsPerPageChange(value: number | null): void {
  if (typeof value === 'number') emitUpdate({ rowsPerPage: value })
}

function onColumnToggle(column: string, value: boolean): void {
  emitUpdate({ visibleColumns: { ...props.modelValue.visibleColumns, [column]: value } })
  emit('commit')
}

function onCommit(): void {
  emit('commit')
}

function onVisibleFeaturesChange(value: string[]): void {
  emit('update:visibleFeatures', value)
}

function onSampleMaxPointsChange(value: number): void {
  emit('update:sampleMaxPoints', value)
  emit('commit')
}

function onColumnsChange(value: number): void {
  emit('update:gridColumns', value)
}

function onPlotSizeChange(value: string): void {
  emit('update:plotSize', value)
}

function onVisibleTableColumnsChange(value: string[]): void {
  emit('update:visibleTableColumns', value)
}
</script>

<style scoped lang="scss">
.settings-dialog {
  background-color: var(--cd-surface);
}
</style>
