<template>
  <div v-if="isOpen" class="tour-spotlight" :style="spotlightStyle" aria-hidden="true" />
  <q-dialog v-model="isOpen" aria-label="OTALON guided tour" persistent>
    <q-card class="onboarding-tour" role="dialog" aria-modal="true" aria-labelledby="onboarding-tour-title">
      <q-card-section class="row items-start no-wrap q-pb-sm">
        <div>
          <div class="text-overline text-primary">Getting started · {{ currentIndex + 1 }}/{{ steps.length }}</div>
          <h2 id="onboarding-tour-title" class="text-h6 q-my-xs">{{ currentStep.title }}</h2>
        </div>
        <q-space />
        <q-btn flat round dense icon="close" aria-label="Dismiss guided tour" @click="dismiss" />
      </q-card-section>

      <q-card-section class="q-pt-none">
        <div class="tour-visual" :data-visual="currentStep.visual"><q-icon :name="visualIcon" size="42px" color="primary" /></div>
        <p class="text-body1 q-mb-sm">{{ currentStep.description }}</p>
        <p class="text-body2 text-muted q-mb-md">{{ currentStep.guidance }}</p>
        <q-linear-progress :value="(currentIndex + 1) / steps.length" color="primary" rounded aria-label="Tour progress" />
      </q-card-section>

      <q-card-actions align="between">
        <q-btn flat label="Skip tour" @click="dismiss" />
        <div class="row q-gutter-sm">
          <q-btn v-if="currentIndex > 0" flat label="Back" @click="previous" />
          <q-btn v-if="currentStep.route" outline label="Open area" @click="openArea" />
          <q-btn color="primary" :label="isLastStep ? 'Done' : 'Next'" @click="next" />
        </div>
      </q-card-actions>
    </q-card>
  </q-dialog>
</template>

<script setup lang="ts">
import { useOnboardingTour } from '~/composables/useOnboardingTour'

const router = useRouter()
const { currentIndex, currentStep, dismiss, isLastStep, isOpen, next, previous, steps } = useOnboardingTour()
const spotlightStyle = ref<Record<string, string>>({ display: 'none' })
const visualIcon = computed(() => ({ dashboard: 'dashboard', alarms: 'notifications', assets: 'devices', scan: 'radar', chat: 'smart_toy', operations: 'settings' })[currentStep.value.visual] ?? 'info')

function updateSpotlight(): void {
  if (!import.meta.client) return
  const target = document.querySelector<HTMLElement>(currentStep.value.target)
  if (!target) {
    spotlightStyle.value = { display: 'none' }
    return
  }
  const rect = target.getBoundingClientRect()
  spotlightStyle.value = {
    display: 'block',
    left: `${Math.max(8, rect.left - 8)}px`,
    top: `${Math.max(8, rect.top - 8)}px`,
    width: `${rect.width + 16}px`,
    height: `${rect.height + 16}px`,
  }
}

function openArea(): void {
  if (currentStep.value.route) void router.push(currentStep.value.route)
}

watch([isOpen, currentIndex], async () => {
  if (!isOpen.value) return
  await nextTick()
  updateSpotlight()
})
onMounted(() => window.addEventListener('resize', updateSpotlight))
onBeforeUnmount(() => window.removeEventListener('resize', updateSpotlight))
</script>

<style scoped lang="scss">
.onboarding-tour {
  position: fixed;
  right: 32px;
  bottom: 32px;
  width: min(520px, calc(100vw - 32px));
  max-width: 100%;
  z-index: 2;
}

.tour-spotlight {
  position: fixed;
  border: 2px solid var(--q-primary);
  border-radius: 8px;
  box-shadow: 0 0 0 9999px rgba(0, 0, 0, 0.28), 0 0 22px rgba(38, 166, 154, 0.85);
  pointer-events: none;
  transition: all 180ms ease;
  z-index: 7001;
}

.tour-visual {
  display: grid;
  place-items: center;
  min-height: 72px;
  margin-bottom: 16px;
  border: 1px solid var(--cd-border);
  border-radius: 10px;
  background: linear-gradient(135deg, rgba(38, 166, 154, 0.16), rgba(38, 166, 154, 0.03));
}
</style>
