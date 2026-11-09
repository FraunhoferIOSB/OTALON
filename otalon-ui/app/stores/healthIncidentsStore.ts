import { defineStore } from 'pinia'

import type { HealthIncidentListResponse, HealthIncidentSummary, HealthResponse } from '~/types/api'

export const useHealthIncidentsStore = defineStore('healthIncidents', {
  state: () => ({
    active: [] as HealthIncidentSummary[],
    recent: [] as HealthIncidentSummary[],
    unacknowledged: [] as HealthIncidentSummary[],
    history: [] as HealthIncidentSummary[],
    selected: null as HealthIncidentSummary | null,
    drawerOpen: false,
    retention: { max_incidents: 50, max_days: 7 },
    isLoading: false,
    isDetailLoading: false,
    detailRequestSeq: 0,
    error: null as string | null,
    // Per-incident acknowledge pending state so each row can disable its own
    // button / show its own spinner without blocking the others.
    acknowledging: [] as string[],
    // Last acknowledge failure, surfaced inline/in a banner by Overview + System.
    acknowledgeError: null as string | null,
  }),
  getters: {
    current: (state): HealthIncidentSummary[] => [...state.active, ...state.recent],
    latest: (state): HealthIncidentSummary | null => state.active[0] ?? state.recent[0] ?? null,
    hasActive: (state): boolean => state.active.length > 0,
    // A recovered incident stays inspectable for 15 minutes; the header chip
    // keeps a recent-incident ring/affordance during that window even though
    // the aggregate status has returned to healthy. A successful acknowledge
    // removes the row from ``recent`` (see ``acknowledge``), so this getter
    // hides the ring immediately for the acknowledged incident rather than
    // waiting for the next health refresh.
    hasRecent: (state): boolean => state.recent.length > 0,
    hasUnacknowledged: (state): boolean => state.unacknowledged.length > 0,
    /** True while an acknowledge POST for ``id`` is in flight. */
    isAcknowledging:
      (state) =>
      (id: string): boolean =>
        state.acknowledging.includes(id),
  },
  actions: {
    applyHealth(response: HealthResponse): void {
      this.active = response.active_incidents ?? []
      this.recent = response.recent_incidents ?? []
      this.unacknowledged =
        response.unacknowledged_incidents ?? this.current.filter((incident) => !incident.acknowledged)
    },
    async fetchHistory(status?: HealthIncidentStatusFilter): Promise<void> {
      this.isLoading = true
      this.error = null
      try {
        const query = status ? `?status=${status}` : ''
        const response = await $fetch<HealthIncidentListResponse>(`/api/v1/operations/health-incidents${query}`)
        this.history = response.items
        this.retention = response.retention
      } catch (error: unknown) {
        this.error = error instanceof Error ? error.message : 'Health incident history unavailable.'
      } finally {
        this.isLoading = false
      }
    },
    async select(id: string): Promise<HealthIncidentSummary | null> {
      const cached = [...this.history, ...this.current].find((incident) => incident.id === id)
      const requestSeq = ++this.detailRequestSeq
      this.isDetailLoading = true
      this.selected = null
      try {
        const result = await $fetch<HealthIncidentSummary>(
          `/api/v1/operations/health-incidents/${encodeURIComponent(id)}`,
        )
        if (requestSeq !== this.detailRequestSeq) return this.selected
        this.selected = result
        this.error = null
        return this.selected
      } catch (error: unknown) {
        if (requestSeq !== this.detailRequestSeq) return this.selected
        this.selected = cached ?? null
        this.error = error instanceof Error ? error.message : 'Health incident detail unavailable.'
        return this.selected
      } finally {
        if (requestSeq === this.detailRequestSeq) this.isDetailLoading = false
      }
    },
    async open(id: string): Promise<HealthIncidentSummary | null> {
      const result = await this.select(id)
      this.drawerOpen = true
      return result
    },
    async acknowledge(id: string): Promise<HealthIncidentSummary | null> {
      if (this.acknowledging.includes(id)) return null
      this.acknowledging = [...this.acknowledging, id]
      this.acknowledgeError = null
      try {
        const result = await $fetch<HealthIncidentSummary>(
          `/api/v1/operations/health-incidents/${encodeURIComponent(id)}/acknowledge`,
          { method: 'POST' },
        )
        // Active incidents keep their (now acknowledged) row so the header
        // health latch stays truthful; the acknowledged incident is removed
        // from BOTH the Overview ``unacknowledged`` list AND the ``recent``
        // ring so the global recent-incident affordance hides IMMEDIATELY
        // instead of persisting until the next health refresh (CAPTURE 45).
        this.active = this.active.map((incident) => (incident.id === id ? result : incident))
        this.recent = this.recent.filter((incident) => incident.id !== id)
        this.unacknowledged = this.unacknowledged.filter((incident) => incident.id !== id)
        // System history retains the row with an updated acknowledged badge —
        // acknowledgement never deletes evidence.
        this.history = this.history.map((incident) => (incident.id === id ? result : incident))
        this.selected = this.selected?.id === id ? result : this.selected
        this.error = null
        return result
      } catch (error: unknown) {
        const message = error instanceof Error ? error.message : 'Health incident acknowledgement failed.'
        this.error = message
        this.acknowledgeError = message
        return null
      } finally {
        this.acknowledging = this.acknowledging.filter((pending) => pending !== id)
      }
    },
    close(): void {
      this.drawerOpen = false
      this.clearSelection()
    },
    clearSelection(): void {
      this.detailRequestSeq += 1
      this.selected = null
      this.isDetailLoading = false
    },
  },
})

export type HealthIncidentStatusFilter = 'active' | 'recovered'
