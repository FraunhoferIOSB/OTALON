<template>
  <div class="chat-welcome column items-center justify-center q-pa-lg">
    <q-icon name="smart_toy" size="48px" color="grey-5" />
    <div class="text-body2 text-muted q-mt-md text-center">
      I'm the OTALON assistant — I can query network metrics (InfluxDB), alarms &amp; assets (PostgreSQL), packet
      captures (PCAP) and MITRE ATT&amp;CK for ICS.
    </div>
    <div v-if="sendUiContext" class="text-caption text-muted q-mt-xs text-center">
      The current page context is shared when "Send UI context" is on.
    </div>
    <div class="row q-gutter-sm q-mt-md justify-center">
      <q-chip
        v-for="(ex, idx) in visibleExamples"
        :key="idx"
        clickable
        dense
        color="primary"
        text-color="white"
        @click="emit('example-click', ex)"
      >
        {{ ex }}
      </q-chip>
    </div>
  </div>
</template>

<script setup lang="ts">
/**
 * Welcome empty-state message for the chat panel.
 *
 * Renders a short capability intro and page-aware example questions.
 * Disappears automatically once a real message is added.
 */

const emit = defineEmits<{
  (e: 'example-click', text: string): void
}>()

const route = useRoute()
const { sendUiContext } = useChatSettings()

const ROUTE_EXAMPLES: Record<string, string> = {
  '/dashboard': 'What is the current network health?',
  '/alarms': 'Explain the currently selected alarm.',
  '/devices': 'Which of my assets have known CVEs?',
  '/connections': 'Is this connection volume unusual?',
  '/mac-timeseries': 'What traffic patterns does this MAC show?',
  '/proto-timeseries': 'Which protocols are most active?',
  '/topology': 'Are there any anomalous nodes?',
  '/management': 'What is the overall service health?',
  '/vulnerabilities': 'List my critical vulnerabilities.',
}

const DEFAULT_EXAMPLES = ['What happened in my network in the last hour?', 'Show me recent anomalies.']

const visibleExamples = computed(() => {
  const path = route.path || '/'
  const pageSpecific = ROUTE_EXAMPLES[path]
  if (pageSpecific) {
    return [pageSpecific, ...DEFAULT_EXAMPLES]
  }
  return DEFAULT_EXAMPLES
})
</script>

<style scoped lang="scss">
.chat-welcome {
  height: 100%;
  opacity: 0.9;
}
</style>
