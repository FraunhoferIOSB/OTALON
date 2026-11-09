<script setup lang="ts">
import { onMounted } from 'vue'

import { useSse } from '~/composables/useSse'
import { useOperationsJobsStore } from '~/stores/operationsJobsStore'

/**
 * Invisible component that keeps operations-jobs SSE live in the default
 * layout so the shell indicator and shared page state update without
 * opening a second stream on the Jobs & History page.
 */
const store = useOperationsJobsStore()

useSse('jobs', {
  onEvent: (_topic, data) => {
    store.handleJobEvent(data)
  },
})

onMounted(() => {
  store.fetchJobs()
})
</script>

<template>
  <span style="display: none" aria-hidden="true"></span>
</template>
