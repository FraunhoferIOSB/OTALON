<script setup lang="ts">
import { computed, watch } from 'vue'

import { useJobNotificationsStore } from '~/stores/jobNotificationsStore'
import { useCveLookupSse } from '~/composables/useCveLookupSse'
import { useJobStream } from '~/composables/useJobStream'
import type { TerminalStatus } from '~/stores/jobNotificationsStore'

const props = defineProps<{
  kind: 'lookup' | 'scan'
  jobId: string
}>()

const store = useJobNotificationsStore()
const id = computed(() => `${props.kind}:${props.jobId}`)

function inferScanTerminalStatus(data: unknown): TerminalStatus {
  if (data && typeof data === 'object') {
    const obj = data as Record<string, unknown>
    const status = obj.status
    if (typeof status === 'string') {
      const lower = status.toLowerCase()
      if (lower === 'failed' || lower === 'error') return 'failed'
      if (lower === 'aborted' || lower === 'cancelled_partial') return 'cancelled'
    }
  }
  return 'completed'
}

function recordLookupDone(cvesFound: number, critical: number): void {
  store.addNotification({
    id: id.value,
    kind: 'lookup',
    jobId: props.jobId,
    status: 'completed',
    title: 'CVE Lookup completed',
    message: `${cvesFound} CVEs found, ${critical} critical`,
  })
}

function recordLookupFailed(error?: string): void {
  store.addNotification({
    id: id.value,
    kind: 'lookup',
    jobId: props.jobId,
    status: 'failed',
    title: 'CVE Lookup failed',
    message: error || 'Unknown error',
  })
}

function recordScanTerminal(status: TerminalStatus, message?: string): void {
  store.addNotification({
    id: id.value,
    kind: 'scan',
    jobId: props.jobId,
    status,
    title: status === 'completed' ? 'Scan completed' : 'Scan failed',
    message: message || `Scan ${status}`,
  })
}

if (props.kind === 'lookup') {
  const jobIdRef = computed(() => props.jobId)
  const sse = useCveLookupSse(jobIdRef)
  watch(
    () => sse.terminalEvent.value,
    (terminal) => {
      if (!terminal) return
      if ('cves_found' in terminal) {
        recordLookupDone(terminal.cves_found, terminal.critical)
      } else {
        recordLookupFailed(terminal.error)
      }
    },
  )
} else {
  const url = computed(() => `/api/v1/scans/${props.jobId}/events`)
  let handled = false

  /**
   * Mark the scan as finished and tear the stream down.
   *
   * Setting `handled` only stops us from acting on further events — the
   * EventSource stays open and keeps reconnecting, leaking one connection
   * per finished scan for the lifetime of the page. The stream must be
   * closed explicitly (audit UI-09).
   */
  const finish = (status: TerminalStatus, message?: string): void => {
    handled = true
    recordScanTerminal(status, message)
    close()
  }

  const { close } = useJobStream({
    url,
    onEvent: (type, data) => {
      if (handled) return
      if (type === 'result' || type === 'final') {
        finish(inferScanTerminalStatus(data))
      } else if (type === 'error') {
        finish('failed', 'Scan encountered an error')
      } else if (type === 'status') {
        const status = inferScanTerminalStatus(data)
        if (status === 'failed' || status === 'cancelled') {
          finish(status)
        }
      }
    },
  })
}
</script>

<template>
  <span style="display: none"></span>
</template>
