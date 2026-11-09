<template>
  <div class="subject-heading" data-testid="panel-subject-heading">
    <div class="row items-center no-wrap q-gutter-x-sm">
      <q-icon :name="icon" size="20px" color="primary" />
      <span class="subject-heading__label ellipsis" :title="label ?? undefined">
        {{ label || placeholder }}
      </span>
      <q-badge v-if="silent" color="warning" text-color="dark" label="SILENT" class="q-ml-xs" />
    </div>
    <div class="subject-heading__noun text-caption">
      {{ noun }}
    </div>
    <div v-if="rawId" class="subject-heading__raw-id text-mono text-caption ellipsis" :title="rawId">
      {{ rawId }}
    </div>
    <div
      v-if="rhythmAnomaly"
      class="subject-heading__features row items-center q-gutter-xs"
      data-testid="rhythm-anomaly-badge"
    >
      <q-badge color="warning" text-color="dark" label="Cadence" />
    </div>
    <div
      v-if="affectedFeatureState === 'NoBounds'"
      class="subject-heading__features row items-center q-gutter-xs"
      data-testid="affected-features"
    >
      <q-badge color="negative" label="NoBounds" data-testid="no-bounds-badge" />
    </div>
    <div
      v-else-if="affectedFeatures?.length"
      class="subject-heading__features row items-center q-gutter-xs"
      data-testid="affected-features"
    >
      <span class="text-caption text-muted">Affected features:</span>
      <q-btn
        v-for="feature in affectedFeatures"
        :key="feature"
        dense
        no-caps
        outline
        color="warning"
        size="sm"
        class="subject-heading__feature"
        :label="featureLabels[feature] ?? feature"
        :data-feature-badge="feature"
        @click="jumpToFeature(feature)"
      />
    </div>
  </div>
</template>

<script setup lang="ts">
/**
 * Heading naming the currently selected subject of the analysis panel.
 *
 * The panel stacks a rhythm lane and a feature-plot grid, all describing the
 * same subject, so the name belongs above the whole panel rather than inside
 * one of its widgets (UI-094). It used to sit as small mono text beside the
 * lane's own "RHYTHM" title, which read as a property of that one widget.
 */
interface Props {
  /** Readable subject name, e.g. a UCI, MAC address or protocol stack. */
  label?: string | null
  /** What kind of subject this is; rendered underneath the name. */
  noun: string
  /** Quasar icon name shown next to the name. */
  icon?: string
  /** Whether the subject is profiled but currently silent. */
  silent?: boolean
  /** Text shown while nothing is selected. */
  placeholder?: string
  /** Raw series identifier, shown below the readable subject heading. */
  rawId?: string | null
  /** Per-series affected-feature detection state. */
  affectedFeatureState?: 'NoBounds' | 'BoundViolation'
  affectedFeatures?: string[]
  /** Readable labels for raw feature keys shown in affected-feature badges. */
  featureLabels?: Record<string, string>
  /** Features currently rendered by the sibling plot grid. */
  visibleFeatures?: string[]
  /** Whether selected series has an active FrequencyAnomaly or AbsenceAnomaly. */
  rhythmAnomaly?: boolean
}

const props = withDefaults(defineProps<Props>(), {
  label: null,
  icon: 'insights',
  silent: false,
  placeholder: 'Nothing selected',
  rawId: null,
  affectedFeatureState: undefined,
  affectedFeatures: () => [],
  featureLabels: () => ({}),
  visibleFeatures: () => [],
  rhythmAnomaly: false,
})

const emit = defineEmits<{
  (event: 'reveal-feature', feature: string): void
}>()

async function jumpToFeature(feature: string): Promise<void> {
  if (!props.visibleFeatures.includes(feature)) {
    emit('reveal-feature', feature)
    await nextTick()
  }
  if (typeof document === 'undefined') return
  const cell = document.querySelector<HTMLElement>(`.plot-cell[data-feature="${CSS.escape(feature)}"]`)
  cell?.scrollIntoView({ behavior: 'smooth', block: 'nearest' })
}
</script>

<style scoped lang="scss">
.subject-heading {
  padding: 4px 0 8px;
  border-bottom: 1px solid var(--cd-border);
  margin-bottom: 8px;
}

.subject-heading__label {
  font-size: 1.05rem;
  font-weight: 600;
  line-height: 1.3;
  color: var(--cd-text-primary, inherit);
  min-width: 0;
}

.subject-heading__noun {
  margin-left: 28px;
  text-transform: uppercase;
  letter-spacing: 0.06em;
  color: var(--cd-text-secondary, #90a4ae);
}

.subject-heading__raw-id {
  margin-left: 28px;
  font-family: $font-family-mono;
  font-size: 11px;
  user-select: all;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  color: var(--cd-text-secondary, #90a4ae);
}

.subject-heading__features {
  margin: 6px 0 0 28px;
}

.subject-heading__feature {
  font-size: 11px;
}
</style>
