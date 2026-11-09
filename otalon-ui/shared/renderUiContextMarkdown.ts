/**
 * Pure helpers to render a :class:`UiContext` snapshot to Markdown.
 *
 * Used by both:
 *   - ``server/utils/chatPayload.ts`` — to build the single
 *     ``metadata.ui_context_markdown`` channel consumed by otalon-ai.
 *   - ``app/components/chat/ContextPreview.vue`` — to show the user
 *     exactly what is sent.
 *
 * Lives under ``shared/`` so it is import-safe from both server and
 * client. No Vue/Nuxt imports here.
 */

import type { ChatContextSelection, ChatSubagentClassification, ChatVisibleTable, UiContext } from './uiContext'
import { MAX_SUBAGENT_TEXT_LENGTH } from './uiContext'

const MAX_FIELD_LENGTH = 200

function fmtCell(value: unknown): string {
  if (value === null || value === undefined) return ''
  if (typeof value === 'string') {
    if (value.length <= MAX_FIELD_LENGTH) return value
    return value.slice(0, MAX_FIELD_LENGTH - 1) + '…'
  }
  if (typeof value === 'number' || typeof value === 'boolean') return String(value)
  return JSON.stringify(value)
}

function renderKeyValueList(record: Record<string, unknown>): string[] {
  return Object.entries(record).map(([k, v]) => `  - ${k}: ${fmtCell(v)}`)
}

function renderSelection(sel: ChatContextSelection): string[] {
  const lines: string[] = []
  const head = `- Selection: ${sel.kind} \`${sel.id}\``
  lines.push(sel.label ? `${head} — ${fmtCell(sel.label)}` : head)
  if (sel.fields) {
    for (const [k, v] of Object.entries(sel.fields)) {
      lines.push(`  - ${k}: ${fmtCell(v)}`)
    }
  }
  return lines
}

function truncateText(value: string | null | undefined, max: number): string {
  if (!value) return ''
  const s = String(value)
  return s.length <= max ? s : s.slice(0, max - 1) + '…'
}

function renderSubagentClassifications(jobs: ChatSubagentClassification[]): string[] {
  const lines: string[] = []
  lines.push(`- Subagent classifications (${jobs.length}):`)
  for (const j of jobs) {
    const ts = j.created_at ? new Date(j.created_at).toISOString() : ''
    const header = `  - job \`${j.job_id.slice(0, 8)}\` (${j.prompt_variant}/${j.llm}, ${ts})`
    lines.push(header)
    if (j.duration_seconds != null) {
      lines.push(`    - duration: ${j.duration_seconds.toFixed(1)}s`)
    }
    if (j.step1_method) {
      lines.push(`    - step1.method: \`${j.step1_method}\``)
    }
    if (j.step1_activity) {
      lines.push(`    - step1.observed: ${truncateText(j.step1_activity, MAX_SUBAGENT_TEXT_LENGTH)}`)
    }
    if (j.step2.length > 0) {
      lines.push(`    - step2 (top ${j.step2.length}):`)
      for (const c of j.step2) {
        const conf = Math.round((c.confidence ?? 0) * 100)
        const name = c.technique_name ? ` ${c.technique_name}` : ''
        lines.push(`      - **${c.technique_id}**${name} — confidence ${conf}%`)
        if (c.reasoning) {
          lines.push(`        - reasoning: ${truncateText(c.reasoning, MAX_SUBAGENT_TEXT_LENGTH)}`)
        }
      }
    }
  }
  return lines
}

function renderTable(t: ChatVisibleTable): string[] {
  const lines: string[] = []
  lines.push(`- Visible data — ${t.name} (showing ${t.showing_rows} of ${t.total_rows}):`)
  if (t.rows.length === 0) {
    lines.push('  - (empty)')
    return lines
  }
  const header = `  | ${t.columns.join(' | ')} |`
  const sep = `  | ${t.columns.map(() => '---').join(' | ')} |`
  lines.push(header)
  lines.push(sep)
  for (const row of t.rows) {
    const cells = t.columns.map((col) => fmtCell(row[col]))
    lines.push(`  | ${cells.join(' | ')} |`)
  }
  return lines
}

/**
 * Render a :class:`UiContext` snapshot as a compact Markdown block.
 *
 * The output starts with a ``## UI Context`` header so the LLM can
 * reliably distinguish it from the user's question.
 */
export function renderUiContextMarkdown(ctx: UiContext): string {
  const lines: string[] = ['## UI Context', '']
  lines.push(`- Page: ${ctx.route.title} (${ctx.route.path})`)
  lines.push(`- Time: ${ctx.time.label} (${ctx.time.start} .. ${ctx.time.stop})`)
  lines.push(`- Theme: ${ctx.app.theme}, locale: ${ctx.app.locale}`)
  if (ctx.widgets) {
    lines.push(`- Visible widgets: ${ctx.widgets.visible.join(', ') || '(none)'}`)
    if (ctx.widgets.hidden.length > 0) {
      lines.push(`- Hidden widgets: ${ctx.widgets.hidden.join(', ')}`)
    }
  }
  if (ctx.summary && Object.keys(ctx.summary).length > 0) {
    lines.push('- Summary:')
    lines.push(...renderKeyValueList(ctx.summary))
  }
  if (ctx.filters && Object.keys(ctx.filters).length > 0) {
    lines.push('- Filters:')
    lines.push(...renderKeyValueList(ctx.filters))
  }
  if (ctx.selection) {
    lines.push(...renderSelection(ctx.selection))
  }
  if (ctx.subagent && ctx.subagent.length > 0) {
    lines.push(...renderSubagentClassifications(ctx.subagent))
  }
  if (ctx.visible_data && ctx.visible_data.length > 0) {
    for (const t of ctx.visible_data) lines.push(...renderTable(t))
  }
  if (ctx.notes && ctx.notes.length > 0) {
    lines.push('- Notes:')
    for (const n of ctx.notes) lines.push(`  - ${fmtCell(n)}`)
  }
  return lines.join('\n')
}
