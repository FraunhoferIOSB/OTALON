<template>
  <q-dialog v-model="show" persistent>
    <q-card style="min-width: 480px; max-width: 720px">
      <q-card-section class="row items-center q-pb-none">
        <div class="text-h6 row items-center">
          <q-icon name="psychology" color="teal" class="q-mr-sm" />
          Re-Analyze Alarm
        </div>
        <q-space />
        <q-btn v-close-popup icon="close" flat round dense />
      </q-card-section>

      <q-card-section class="q-pt-sm">
        <p class="text-body2 text-muted q-mb-md">
          A subagent will independently investigate this alarm using the live MCP tool surface and produce a two-step
          classification (attack method + MITRE ICS technique). Typical runtime: 2-5 minutes.
        </p>

        <q-select
          v-model="form.prompt_variant"
          :options="promptOptions"
          label="System prompt"
          dense
          outlined
          emit-value
          map-options
          class="q-mb-md"
        />

        <q-select
          v-model="form.reasoning_effort"
          :options="reasoningOptions"
          label="Reasoning effort"
          dense
          outlined
          emit-value
          map-options
          clearable
          class="q-mb-md"
          hint="Higher effort = more thorough but slower (Azure GPT-5.4 only)"
        />

        <q-select
          v-model="form.baseline_id"
          :options="baselineOptions"
          label="Baseline (optional)"
          dense
          outlined
          emit-value
          map-options
          clearable
          class="q-mb-md"
          :loading="loadingBaselines"
          hint="Curated quiet-traffic window for comparison tools"
        />
      </q-card-section>

      <q-separator />

      <q-card-actions align="right" class="q-pa-md">
        <q-btn v-close-popup flat label="Cancel" :disable="submitting" />
        <q-btn color="primary" icon="play_arrow" label="Start analysis" :loading="submitting" @click="submit" />
      </q-card-actions>
    </q-card>
  </q-dialog>
</template>

<script setup lang="ts">
import { useQuasar } from 'quasar'
import { computed, onMounted, reactive, ref, watch } from 'vue'

import { useSubagentStore } from '~/stores/subagentStore'
import type { Baseline, CreateSubagentJobRequest } from '~/types/api'

const props = defineProps<{
  modelValue: boolean
  alarmId: string
}>()

const emit = defineEmits<{
  (e: 'update:modelValue', value: boolean): void
  (e: 'started', jobId: string): void
}>()

const $q = useQuasar()
const store = useSubagentStore()

const show = computed({
  get: () => props.modelValue,
  set: (v) => emit('update:modelValue', v),
})

const submitting = ref(false)
const loadingBaselines = ref(false)
const baselines = ref<Baseline[]>([])

const promptOptions = [
  { label: 'Expert (158-line, 5-phase methodology) — recommended', value: 'expert' },
  { label: 'Open (114-line, no methodology)', value: 'open' },
  { label: 'Forensic (FP-first, conservative verdict) — expert + false-positive reasoning', value: 'forensic' },
]

const reasoningOptions = [
  { label: 'Low — fast (~30 s)', value: 'low' },
  { label: 'Medium — balanced (paper default)', value: 'medium' },
  { label: 'High — thorough (~5 min)', value: 'high' },
]

const form = reactive<CreateSubagentJobRequest>({
  prompt_variant: 'expert',
  reasoning_effort: 'medium',
  baseline_id: null,
})

const baselineOptions = computed(() => {
  return baselines.value.map((b) => ({
    label: `${b.name}${b.is_active ? ' (active)' : ''}`,
    value: b.id,
  }))
})

async function loadBaselines(): Promise<void> {
  loadingBaselines.value = true
  try {
    const res = await fetch('/api/v1/baselines')
    if (res.ok) {
      baselines.value = (await res.json()) as Baseline[]
      // Pre-select the active baseline if any
      const active = baselines.value.find((b) => b.is_active)
      if (active && form.baseline_id == null) {
        form.baseline_id = active.id
      }
    }
  } catch (err) {
    console.warn('Could not load baselines', err)
  } finally {
    loadingBaselines.value = false
  }
}

watch(show, (v) => {
  if (v) {
    void loadBaselines()
  }
})

onMounted(() => {
  if (show.value) void loadBaselines()
})

async function submit(): Promise<void> {
  submitting.value = true
  const payload: CreateSubagentJobRequest = { ...form }
  // AI-045: the model is set only in Operations > Configuration; never sent from here.
  delete payload.llm_model
  if (!payload.baseline_id) delete payload.baseline_id
  const result = await store.startClassification(props.alarmId, payload)
  submitting.value = false
  if (result) {
    $q.notify({
      type: 'positive',
      message: `Forensic analysis started (~${result.eta_seconds}s)`,
      timeout: 3000,
    })
    emit('started', result.job_id)
    show.value = false
  } else {
    $q.notify({
      type: 'negative',
      message: store.error ?? 'Failed to start analysis',
      timeout: 5000,
    })
  }
}
</script>
