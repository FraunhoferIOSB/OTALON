/**
 * Pinia store for subagent classification jobs.
 *
 * Subagent jobs are independent zero-shot LLM classifications produced by
 * the otalon-ai service. The store tracks:
 * - history per alarm id (newest first, summary view),
 * - per-job live state (full record + tool trace) populated via SSE,
 * - in-flight job ids so the UI can disable redundant triggers.
 */
import { defineStore } from 'pinia'

import type {
  CreateSubagentJobRequest,
  CreateSubagentJobResponse,
  SubagentJob,
  SubagentJobListResponse,
  SubagentJobStatus,
  SubagentJobSummary,
  SubagentTraceEntry,
} from '~/types/api'

export interface SubagentLiveJob extends SubagentJob {
  /** Whether this job is currently being streamed via SSE. */
  streaming: boolean
}

interface SubagentState {
  jobsByAlarm: Record<string, SubagentJobSummary[]>
  liveJobsById: Record<string, SubagentLiveJob>
  inflightAlarmIds: string[]
  loadingHistory: Record<string, boolean>
  error: string | null
}

export const useSubagentStore = defineStore('subagent', {
  state: (): SubagentState => ({
    jobsByAlarm: {},
    liveJobsById: {},
    inflightAlarmIds: [],
    loadingHistory: {},
    error: null,
  }),

  getters: {
    historyFor:
      (state) =>
      (alarmId: string): SubagentJobSummary[] => {
        return state.jobsByAlarm[alarmId] ?? []
      },
    liveJob:
      (state) =>
      (jobId: string): SubagentLiveJob | undefined => {
        return state.liveJobsById[jobId]
      },
    isAlarmInflight:
      (state) =>
      (alarmId: string): boolean => {
        return state.inflightAlarmIds.includes(alarmId)
      },
  },

  actions: {
    /**
     * Fetch the historical (summary) jobs for an alarm.
     */
    async loadHistory(alarmId: string): Promise<void> {
      this.loadingHistory[alarmId] = true
      try {
        const params = new URLSearchParams({
          alarm_id: alarmId,
          summary: 'true',
          limit: '20',
          offset: '0',
        })
        const res = await fetch(`/api/v1/subagent-jobs?${params.toString()}`)
        if (!res.ok) throw new Error(`subagent-jobs HTTP ${res.status}`)
        const data = (await res.json()) as SubagentJobListResponse
        this.jobsByAlarm[alarmId] = (data.items ?? []) as SubagentJobSummary[]
      } catch (err) {
        this.error = err instanceof Error ? err.message : String(err)
      } finally {
        this.loadingHistory[alarmId] = false
      }
    },

    /**
     * Load the full record of the latest few completed jobs for an alarm.
     *
     * Used by the chat-context provider so the LLM gets the subagent's
     * Step-1 method, observed activity, and full Step-2 reasoning — none
     * of which is present in the summary list response.
     *
     * Side effect: history is also (re-)loaded so the UI history panel
     * stays in sync.
     */
    async loadLatestFullJobs(alarmId: string, n = 3): Promise<void> {
      if (!alarmId) return
      // Make sure summaries are up to date so we know what to fetch.
      await this.loadHistory(alarmId)
      const summaries = this.jobsByAlarm[alarmId] ?? []
      const targets = summaries.filter((j) => j.status === 'completed').slice(0, n)
      await Promise.all(targets.map((j) => this.loadJob(j.id)))
    },

    /**
     * Fetch a full job record (including tool_trace) by id.
     */
    async loadJob(jobId: string): Promise<SubagentJob | null> {
      try {
        const res = await fetch(`/api/v1/subagent-jobs/${jobId}`)
        if (!res.ok) {
          if (res.status === 404) return null
          throw new Error(`subagent-job HTTP ${res.status}`)
        }
        const job = (await res.json()) as SubagentJob
        this.liveJobsById[jobId] = { ...job, streaming: false }
        return job
      } catch (err) {
        this.error = err instanceof Error ? err.message : String(err)
        return null
      }
    },

    /**
     * Start a new classification job for the given alarm.
     */
    async startClassification(
      alarmId: string,
      payload: CreateSubagentJobRequest = {},
    ): Promise<CreateSubagentJobResponse | null> {
      try {
        const res = await fetch(`/api/v1/alerts/${alarmId}/classify`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
        })
        if (!res.ok) {
          let detail = ''
          try {
            detail = (await res.text()) || ''
          } catch {
            /* ignore */
          }
          throw new Error(`classify HTTP ${res.status}${detail ? ': ' + detail : ''}`)
        }
        const data = (await res.json()) as CreateSubagentJobResponse
        // Seed a minimal live placeholder so UI can show 'pending' immediately.
        this.liveJobsById[data.job_id] = {
          id: data.job_id,
          alarm_id: alarmId,
          status: data.status,
          prompt_variant: payload.prompt_variant ?? 'expert',
          prompt_hash: '',
          llm_provider: payload.llm_provider ?? 'azure_openai',
          llm_model: payload.llm_model ?? 'gpt-5.4',
          llm_endpoint: null,
          reasoning_effort: payload.reasoning_effort ?? null,
          baseline_id: payload.baseline_id ?? null,
          timeout_seconds: payload.timeout_seconds ?? 600,
          trigger_source: 'ui',
          started_at: null,
          finished_at: null,
          duration_seconds: null,
          step1_technical: null,
          step2_classification: null,
          verdict: null,
          tool_trace: [],
          tokens_prompt: 0,
          tokens_completion: 0,
          error_message: null,
          created_at: new Date().toISOString(),
          streaming: true,
        }
        if (!this.inflightAlarmIds.includes(alarmId)) {
          this.inflightAlarmIds.push(alarmId)
        }
        return data
      } catch (err) {
        this.error = err instanceof Error ? err.message : String(err)
        return null
      }
    },

    /**
     * Append a tool-call entry to a live job's trace.
     */
    appendTraceEntry(jobId: string, entry: SubagentTraceEntry): void {
      const job = this.liveJobsById[jobId]
      if (!job) return
      job.tool_trace = [...(job.tool_trace ?? []), entry]
      if (job.status === 'pending') job.status = 'running'
    },

    /**
     * Mark a live job as terminated and apply final classification.
     */
    finalizeJob(
      jobId: string,
      finalState: {
        status: SubagentJobStatus
        step1_technical: SubagentJob['step1_technical']
        step2_classification: SubagentJob['step2_classification']
        verdict: SubagentJob['verdict']
        duration_seconds?: number
        tokens_prompt?: number
        tokens_completion?: number
        error_message?: string | null
      },
    ): void {
      const job = this.liveJobsById[jobId]
      if (!job) return
      job.status = finalState.status
      job.step1_technical = finalState.step1_technical
      job.step2_classification = finalState.step2_classification
      job.verdict = finalState.verdict
      job.duration_seconds = finalState.duration_seconds ?? job.duration_seconds
      job.tokens_prompt = finalState.tokens_prompt ?? job.tokens_prompt
      job.tokens_completion = finalState.tokens_completion ?? job.tokens_completion
      job.error_message = finalState.error_message ?? null
      job.streaming = false
      job.finished_at = new Date().toISOString()
      // Drop from in-flight list
      this.inflightAlarmIds = this.inflightAlarmIds.filter((id) => id !== job.alarm_id)
    },

    /**
     * Cancel a running job (best-effort).
     */
    async cancel(jobId: string): Promise<boolean> {
      try {
        const res = await fetch(`/api/v1/subagent-jobs/${jobId}/cancel`, {
          method: 'POST',
        })
        return res.ok
      } catch (err) {
        this.error = err instanceof Error ? err.message : String(err)
        return false
      }
    },
  },
})
