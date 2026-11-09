/**
 * Global job-completion notification store.
 *
 * Tracks watched asynchronous jobs (CVE lookups and active scans) and
 * exposes a deduplicated pending-notification queue. The default layout
 * consumes this queue and fires Quasar Notify toasts. Dialogs register
 * watches when a job starts so completion toasts survive dialog close.
 */
import { defineStore } from 'pinia'

export type JobKind = 'lookup' | 'scan'
export type TerminalStatus = 'completed' | 'failed' | 'cancelled'

export interface JobNotification {
  id: string
  kind: JobKind
  jobId: string
  status: TerminalStatus
  title: string
  message: string
  timestamp: number
  shown: boolean
}

interface JobNotificationsState {
  watched: string[]
  notified: string[]
  pending: JobNotification[]
}

export const useJobNotificationsStore = defineStore('jobNotifications', {
  state: (): JobNotificationsState => ({
    watched: [],
    notified: [],
    pending: [],
  }),

  getters: {
    watchedLookupIds(state): string[] {
      return state.watched.filter((id) => id.startsWith('lookup:')).map((id) => id.slice('lookup:'.length))
    },
    watchedScanIds(state): string[] {
      return state.watched.filter((id) => id.startsWith('scan:')).map((id) => id.slice('scan:'.length))
    },
    unshown(state): JobNotification[] {
      return state.pending.filter((n) => !n.shown)
    },
  },

  actions: {
    /**
     * Register a CVE-lookup job for global completion tracking.
     *
     * @param jobId - The lookup job UUID returned by the backend.
     */
    watchLookup(jobId: string): void {
      const id = `lookup:${jobId}`
      if (!this.watched.includes(id)) {
        this.watched.push(id)
      }
    },

    /**
     * Register an active scan for global completion tracking.
     *
     * @param scanId - The scan UUID returned by the backend.
     */
    watchScan(scanId: string): void {
      const id = `scan:${scanId}`
      if (!this.watched.includes(id)) {
        this.watched.push(id)
      }
    },

    /**
     * Add a terminal notification unless this job was already notified.
     *
     * @param notification - Notification payload (without timestamp/shown).
     */
    addNotification(notification: Omit<JobNotification, 'timestamp' | 'shown'>): void {
      if (this.notified.includes(notification.id)) return
      this.notified.push(notification.id)
      this.pending.push({
        ...notification,
        timestamp: Date.now(),
        shown: false,
      })
    },

    /**
     * Mark a single notification as shown so the layout does not re-toast it.
     *
     * @param id - Stable job id (`lookup:<job_id>` or `scan:<scan_id>`).
     */
    markShown(id: string): void {
      const n = this.pending.find((p) => p.id === id)
      if (n) n.shown = true
    },

    /**
     * Remove a notification from the pending queue.
     *
     * @param id - Stable job id.
     */
    removePending(id: string): void {
      this.pending = this.pending.filter((p) => p.id !== id)
    },
  },
})
