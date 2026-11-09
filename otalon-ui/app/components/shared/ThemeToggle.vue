<template>
  <q-btn
    flat
    dense
    round
    :icon="isDark ? 'light_mode' : 'dark_mode'"
    :aria-label="isDark ? 'Switch to light mode' : 'Switch to dark mode'"
    @click="onToggle"
  />
</template>

<script setup lang="ts">
import { useQuasar } from 'quasar'
import { computed } from 'vue'

import { useAppStore } from '~/stores/appStore'

const $q = useQuasar()
const appStore = useAppStore()

const isDark = computed(() => appStore.isDark)

function onToggle(): void {
  appStore.toggleTheme()
  $q.dark.set(appStore.isDark)
}
</script>
