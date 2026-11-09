<template>
  <q-expansion-item
    icon="my_location"
    :label="contextChipLabel"
    :caption="contextChipCaption"
    dense
    dense-toggle
    class="chat-context-preview"
    data-test="chat-context-preview"
  >
    <q-card flat>
      <q-card-section class="q-pa-sm">
        <div class="text-caption text-muted q-mb-xs">
          The block below is sent to the AI agent before your message. Toggle this off in
          <q-icon name="settings" size="14px" /> Settings → "Send UI context".
        </div>
        <pre class="chat-context-preview__code">{{ markdown }}</pre>
      </q-card-section>
    </q-card>
  </q-expansion-item>
</template>

<script setup lang="ts">
/**
 * Live preview of the structured ``UiContext`` snapshot that will be
 * sent with the next chat message. Helps users understand what the
 * AI agent sees and aids debugging when answers seem off-topic.
 */
import { computed } from 'vue'

import { useChatContext } from '~/composables/useChatContext'
import { useChatSettings } from '~/composables/useChatSettings'
import { renderUiContextMarkdown } from '#shared/renderUiContextMarkdown'

const { snapshot } = useChatContext()
const { sendUiContext } = useChatSettings()

/**
 * Build a fresh snapshot every time the component is rendered. The
 * snapshot itself is cheap to assemble so we recompute on every paint
 * triggered by any reactive dependency the page providers consume.
 */
const currentSnapshot = computed(() => snapshot())
const markdown = computed(() => renderUiContextMarkdown(currentSnapshot.value))

const contextChipLabel = computed(() => {
  const ctx = currentSnapshot.value
  return sendUiContext.value ? `${ctx.route.title} · ${ctx.time.label}` : 'UI context disabled'
})

const contextChipCaption = computed(() => {
  if (!sendUiContext.value) return 'Enable in Settings to share what you see'
  const ctx = currentSnapshot.value
  const parts: string[] = []
  if (ctx.summary && Object.keys(ctx.summary).length > 0) {
    parts.push(`${Object.keys(ctx.summary).length} summary fields`)
  }
  if (ctx.selection) parts.push(`selection: ${ctx.selection.kind}`)
  if (ctx.visible_data && ctx.visible_data.length > 0) {
    const totalRows = ctx.visible_data.reduce((s, t) => s + t.total_rows, 0)
    parts.push(`${totalRows} visible rows`)
  }
  if (parts.length === 0) return 'route + time only'
  return parts.join(' · ')
})
</script>

<style scoped lang="scss">
.chat-context-preview {
  font-size: 12px;
  color: var(--cd-surface-text);
  background-color: var(--cd-surface);
  border-top: 1px solid var(--cd-border);

  :deep(.q-item__label--caption) {
    font-size: 10px;
    opacity: 0.7;
  }
}

.chat-context-preview__code {
  margin: 0;
  padding: 6px 8px;
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 11px;
  line-height: 1.4;
  white-space: pre-wrap;
  word-break: break-word;
  background-color: rgba(127, 127, 127, 0.08);
  border-radius: 4px;
  max-height: 220px;
  overflow-y: auto;
}
</style>
