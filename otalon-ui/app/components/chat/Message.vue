<template>
  <div class="chat-message" :class="alignmentClass">
    <div class="chat-message__row row items-end no-wrap" :class="rowClass">
      <q-avatar :size="'28px'" :color="avatarColor" text-color="white" class="chat-message__avatar">
        <q-icon :name="avatarIcon" size="16px" />
      </q-avatar>
      <div class="chat-message__bubble" :class="bubbleClass">
        <div v-if="message.toolEvents && message.toolEvents.length > 0" class="chat-message__tools q-mb-xs">
          <q-chip
            v-for="(te, idx) in message.toolEvents"
            :key="idx"
            dense
            size="sm"
            :color="te.ok === true ? 'positive' : te.ok === false ? 'negative' : 'grey-6'"
            text-color="white"
          >
            <q-icon name="build" size="12px" class="q-mr-xs" />
            {{ te.name }}
            <q-icon v-if="te.ok === true" name="check" size="12px" class="q-ml-xs" />
            <q-icon v-else-if="te.ok === false" name="close" size="12px" class="q-ml-xs" />
          </q-chip>
        </div>
        <div v-if="isUser" class="chat-message__content chat-message__content--plain text-body2">
          {{ message.content }}
        </div>
        <!-- eslint-disable-next-line vue/no-v-html -->
        <div v-else class="chat-message__content chat-message__content--markdown text-body2" v-html="renderedContent" />
        <div v-if="!isUser && message.streaming" class="chat-message__cursor" />
        <div v-for="jobId in subagentJobIds" :key="jobId" class="chat-message__subagent-card q-mt-sm">
          <SubagentTraceCard :job-id="jobId" compact />
        </div>
        <div v-if="showTimestamps" class="chat-message__time text-caption">{{ formattedTime }}</div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import DOMPurify from 'dompurify'
import { marked } from 'marked'

import SubagentTraceCard from '~/components/subagent/TraceCard.vue'
import type { ChatMessage } from '~/composables/useChat'
import { useChatSettings } from '~/composables/useChatSettings'

const SUBAGENT_TOKEN_RE = /\[subagent-job:([0-9a-f-]{8,})\]/gi

/**
 * Single chat message bubble with avatar, content, and timestamp.
 *
 * Renders user messages as plain text and assistant messages as
 * sanitized Markdown so that lists, tables, code blocks and emphasis
 * from the LLM are displayed correctly.
 */
const props = defineProps<{
  message: ChatMessage
}>()

const { showTimestamps } = useChatSettings()

const isUser = computed(() => props.message.role === 'user')

const alignmentClass = computed(() => (isUser.value ? 'chat-message--user' : 'chat-message--assistant'))
const rowClass = computed(() => (isUser.value ? 'reverse' : ''))
const bubbleClass = computed(() => (isUser.value ? 'chat-message__bubble--user' : 'chat-message__bubble--assistant'))
const avatarColor = computed(() => (isUser.value ? 'primary' : 'grey-7'))
const avatarIcon = computed(() => (isUser.value ? 'person' : 'smart_toy'))

marked.use({
  gfm: true,
  breaks: true,
  pedantic: false,
})

const subagentJobIds = computed<string[]>(() => {
  const raw = String(props.message.content ?? '')
  const ids: string[] = []
  for (const m of raw.matchAll(SUBAGENT_TOKEN_RE)) {
    if (m[1]) ids.push(m[1])
  }
  return ids
})

const visibleText = computed<string>(() => {
  const raw = String(props.message.content ?? '')
  return raw.replace(SUBAGENT_TOKEN_RE, '').trim()
})

const renderedContent = computed<string>(() => {
  const raw = visibleText.value
  if (!raw) return ''
  const html = marked.parse(raw, { async: false }) as string
  return DOMPurify.sanitize(html, {
    USE_PROFILES: { html: true },
    FORBID_TAGS: ['style', 'form', 'input', 'button', 'textarea', 'select', 'iframe', 'object', 'embed'],
    FORBID_ATTR: ['srcset', 'formaction'],
  })
})

const formattedTime = computed(() => {
  const date = new Date(props.message.timestamp)
  const hours = date.getHours().toString().padStart(2, '0')
  const minutes = date.getMinutes().toString().padStart(2, '0')
  return `${hours}:${minutes}`
})
</script>

<style scoped lang="scss">
.chat-message {
  padding: var(--cd-chat-row-pad-y, 4px) 12px;
  font-family: var(--cd-chat-font-family, inherit);
  font-size: var(--cd-chat-font-size, 14px);

  &--user {
    display: flex;
    justify-content: flex-end;
  }

  &--assistant {
    display: flex;
    justify-content: flex-start;
  }

  &__row {
    max-width: 85%;
    gap: 8px;
  }

  &__avatar {
    flex-shrink: 0;
  }

  &__bubble {
    border-radius: 12px;
    padding: var(--cd-chat-bubble-pad-y, 8px) var(--cd-chat-bubble-pad-x, 12px);
    word-break: break-word;
    font-family: inherit;
    font-size: inherit;

    &--user {
      background-color: var(--q-primary);
      color: white;
      border-bottom-right-radius: 4px;
    }

    &--assistant {
      background-color: var(--cd-surface);
      color: var(--cd-surface-text);
      border: 1px solid var(--cd-border);
      border-bottom-left-radius: 4px;
    }
  }

  &__content {
    line-height: 1.45;
    font-size: inherit;
    font-family: inherit;
  }

  &__content--markdown {
    :deep(p) {
      margin: 0 0 0.5em 0;
    }

    :deep(p:last-child) {
      margin-bottom: 0;
    }

    :deep(ul),
    :deep(ol) {
      margin: 0.25em 0 0.5em 0;
      padding-left: 1.4em;
    }

    :deep(li) {
      margin: 0.15em 0;
    }

    :deep(code) {
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      font-size: 0.88em;
      padding: 1px 5px;
      border-radius: 4px;
      background-color: rgba(127, 127, 127, 0.18);
    }

    :deep(pre) {
      margin: 0.4em 0 0.6em 0;
      padding: 8px 10px;
      border-radius: 6px;
      background-color: rgba(127, 127, 127, 0.14);
      overflow-x: auto;
      max-width: 100%;

      code {
        background: transparent;
        padding: 0;
        font-size: 0.85em;
      }
    }

    :deep(table) {
      border-collapse: collapse;
      margin: 0.4em 0 0.6em 0;
      font-size: 0.92em;
      max-width: 100%;
      display: block;
      overflow-x: auto;
    }

    :deep(th),
    :deep(td) {
      border: 1px solid var(--cd-border);
      padding: 4px 8px;
      text-align: left;
    }

    :deep(th) {
      background-color: rgba(127, 127, 127, 0.12);
      font-weight: 600;
    }

    :deep(blockquote) {
      margin: 0.4em 0;
      padding: 2px 10px;
      border-left: 3px solid var(--cd-border);
      color: inherit;
      opacity: 0.85;
    }

    :deep(a) {
      color: var(--q-primary);
      text-decoration: underline;
    }

    :deep(h1),
    :deep(h2),
    :deep(h3),
    :deep(h4) {
      margin: 0.5em 0 0.3em 0;
      line-height: 1.25;
      font-weight: 600;
    }

    :deep(h1) {
      font-size: 1.15em;
    }
    :deep(h2) {
      font-size: 1.08em;
    }
    :deep(h3) {
      font-size: 1.02em;
    }
    :deep(h4) {
      font-size: 0.98em;
    }

    :deep(hr) {
      border: 0;
      border-top: 1px solid var(--cd-border);
      margin: 0.6em 0;
    }
  }

  &__cursor {
    display: inline-block;
    width: 2px;
    height: 1em;
    background-color: currentColor;
    margin-left: 2px;
    vertical-align: text-bottom;
    animation: blink-cursor 1s step-end infinite;
  }

  &__time {
    opacity: 0.7;
    font-size: 10px;
    margin-top: var(--cd-chat-bubble-gap, 4px);
    text-align: right;
  }

  &__tools {
    display: flex;
    flex-wrap: wrap;
    gap: 4px;
  }
}

@keyframes blink-cursor {
  0%,
  100% {
    opacity: 1;
  }
  50% {
    opacity: 0;
  }
}
</style>
