/**
 * Shared TypeScript types for the chat UI context payload.
 *
 * Lives in ``shared/`` so it is import-safe from both the Nuxt server
 * runtime (Node) and the client-side composable (Vue). No Vue or
 * Nuxt imports here.
 */

export type ChatContextCell = string | number | boolean | null

export interface ChatVisibleTable {
  /** Stable name (e.g. ``"recent_alarms"``, ``"top_connections"``). */
  name: string
  /** Column order. */
  columns: string[]
  /** Up to ``MAX_VISIBLE_ROWS`` rows. Long string cells are truncated. */
  rows: Array<Record<string, ChatContextCell>>
  /** Total number of rows the user could see (before truncation). */
  total_rows: number
  /** Number of rows actually included in ``rows``. */
  showing_rows: number
}

export interface ChatContextSelection {
  kind: string
  id: string
  label?: string
  fields?: Record<string, ChatContextCell>
}

/**
 * Compact representation of a completed subagent classification.
 * Attached to the UI context when the operator has the selected alarm
 * already analysed by the subagent — lets the chat agent pick up the
 * existing Step-1 / Step-2 result instead of restating it from scratch.
 */
export interface ChatSubagentClassification {
  /** Subagent job UUID. */
  job_id: string
  /** ID of the alarm this classification belongs to. */
  alarm_id: string
  /** Prompt variant the subagent used (``open`` or ``expert``). */
  prompt_variant: string
  /** LLM provider + model used (``azure_openai/gpt-5.4`` etc.). */
  llm: string
  /** Job creation time, ISO 8601 UTC. */
  created_at: string
  /** Worker duration in seconds, rounded. */
  duration_seconds?: number | null
  /** Step-1 attack-method label (short, lowercase). */
  step1_method?: string | null
  /** Step-1 free-text description of what was observed. */
  step1_activity?: string | null
  /**
   * Step-2 MITRE classifications, sorted by confidence descending.
   * Capped to the top few entries so the context block stays small.
   */
  step2: Array<{
    technique_id: string
    technique_name?: string | null
    confidence: number
    reasoning?: string | null
  }>
  /** Non-attack outcome and concrete reasoning, when supplied. */
  verdict?: { outcome: string; reasoning?: string | null } | null
}

/** Per-page contribution merged into :class:`UiContext` at snapshot time. */
export interface ChatContextContribution {
  selection?: ChatContextSelection
  filters?: Record<string, ChatContextCell | ChatContextCell[]>
  visible_data?: ChatVisibleTable[]
  summary?: Record<string, ChatContextCell>
  widgets?: { visible: string[]; hidden: string[] }
  notes?: string[]
  /**
   * Recent subagent classifications for the currently selected entity
   * (e.g. an alarm). Limited to a small number of latest jobs — see
   * ``MAX_SUBAGENT_CLASSIFICATIONS`` for the cap.
   */
  subagent?: ChatSubagentClassification[]
}

/** Final snapshot passed to ``/api/chat``. */
export interface UiContext {
  app: {
    version: string
    locale: string
    theme: 'light' | 'dark'
    timestamp: string
  }
  route: {
    path: string
    name: string
    title: string
    query: Record<string, string>
  }
  time: {
    mode: 'live' | 'manual'
    liveIntervalSeconds?: number
    start: string
    stop: string
    label: string
  }
  selection?: ChatContextSelection
  filters?: Record<string, ChatContextCell | ChatContextCell[]>
  visible_data?: ChatVisibleTable[]
  summary?: Record<string, ChatContextCell>
  widgets?: { visible: string[]; hidden: string[] }
  notes?: string[]
  /** Recent subagent classifications relevant to the current selection. */
  subagent?: ChatSubagentClassification[]
}

/** Hard cap on rows per ``ChatVisibleTable``. */
export const MAX_VISIBLE_ROWS = 5

/** Hard cap on string-cell length inside ``ChatVisibleTable.rows``. */
export const MAX_CELL_LENGTH = 80

/**
 * Hard cap on the number of subagent classifications attached to the
 * UI context. Keeps the rendered Markdown block small even if an alarm
 * has been re-classified many times.
 */
export const MAX_SUBAGENT_CLASSIFICATIONS = 3

/**
 * Hard cap on the number of MITRE techniques shown per subagent
 * classification in the context block.
 */
export const MAX_SUBAGENT_STEP2_PER_JOB = 3

/**
 * Hard cap on the length of free-form text fields (Step-1 activity,
 * Step-2 reasoning) inside the subagent context block.
 */
export const MAX_SUBAGENT_TEXT_LENGTH = 240
