<template>
  <q-btn-dropdown
    flat
    dense
    rounded
    dropdown-icon="settings"
    color="white"
    size="sm"
    aria-label="Chat settings"
    class="chat-settings-btn"
    :menu-offset="[0, 8]"
    content-class="chat-settings-menu-content"
    content-style="z-index: 10100"
  >
    <q-list dense class="chat-settings-menu" data-test="chat-settings-menu">
      <q-item-label header class="text-weight-bold">Chat appearance</q-item-label>

      <q-item dense>
        <q-item-section>
          <q-item-label caption>Font family</q-item-label>
          <q-btn-toggle
            v-model="fontFamily"
            data-test="chat-settings-font-family"
            spread
            no-caps
            unelevated
            dense
            :options="fontFamilyOptions"
            color="grey-3"
            text-color="dark"
            toggle-color="primary"
            toggle-text-color="white"
            class="q-mt-xs"
          />
        </q-item-section>
      </q-item>

      <q-item dense>
        <q-item-section>
          <q-item-label caption>
            Font size
            <span class="chat-settings__font-size-value text-grey-7"> {{ fontSize }} px </span>
          </q-item-label>
          <div class="row items-center no-wrap q-mt-xs q-gutter-sm">
            <q-slider
              :model-value="fontSize"
              :min="fontSizeMin"
              :max="fontSizeMax"
              :step="1"
              dense
              color="primary"
              class="col"
              data-test="chat-settings-font-size-slider"
              @update:model-value="(value) => onFontSizeChange(value)"
            />
            <q-input
              :model-value="fontSize"
              type="number"
              dense
              outlined
              :min="fontSizeMin"
              :max="fontSizeMax"
              style="width: 78px"
              input-class="text-right"
              data-test="chat-settings-font-size-input"
              @update:model-value="(value) => onFontSizeChange(value)"
            >
              <template #append>
                <span class="text-caption text-grey-7">px</span>
              </template>
            </q-input>
          </div>
        </q-item-section>
      </q-item>

      <q-item dense>
        <q-item-section>
          <q-item-label caption>Density</q-item-label>
          <q-btn-toggle
            v-model="density"
            data-test="chat-settings-density"
            spread
            no-caps
            unelevated
            dense
            :options="densityOptions"
            color="grey-3"
            text-color="dark"
            toggle-color="primary"
            toggle-text-color="white"
            class="q-mt-xs"
          />
        </q-item-section>
      </q-item>

      <q-separator class="q-my-sm" />

      <q-item v-ripple tag="label" dense clickable>
        <q-item-section>
          <q-item-label>Show timestamps</q-item-label>
          <q-item-label caption>Display the time below each message bubble.</q-item-label>
        </q-item-section>
        <q-item-section side>
          <q-toggle v-model="showTimestamps" data-test="chat-settings-timestamps" color="primary" />
        </q-item-section>
      </q-item>

      <q-item v-ripple tag="label" dense clickable>
        <q-item-section>
          <q-item-label>Stream responses</q-item-label>
          <q-item-label caption>Show the answer token by token as it is generated.</q-item-label>
        </q-item-section>
        <q-item-section side>
          <q-toggle v-model="streamResponses" data-test="chat-settings-stream" color="primary" />
        </q-item-section>
      </q-item>

      <q-item v-ripple tag="label" dense clickable>
        <q-item-section>
          <q-item-label>Send UI context</q-item-label>
          <q-item-label caption>
            Share the page, time window, selection and visible data with the AI so it can answer about what you see.
          </q-item-label>
        </q-item-section>
        <q-item-section side>
          <q-toggle v-model="sendUiContext" data-test="chat-settings-send-ui-context" color="primary" />
        </q-item-section>
      </q-item>

      <q-item dense>
        <q-item-section>
          <q-item-label>Send shortcut</q-item-label>
          <q-item-label caption>How pressing Enter behaves in the input.</q-item-label>
          <q-btn-toggle
            v-model="sendShortcut"
            data-test="chat-settings-send-shortcut"
            spread
            no-caps
            unelevated
            dense
            :options="sendShortcutOptions"
            color="grey-3"
            text-color="dark"
            toggle-color="primary"
            toggle-text-color="white"
            class="q-mt-xs"
          />
        </q-item-section>
      </q-item>

      <q-separator class="q-my-sm" />

      <q-item dense>
        <q-item-section>
          <q-btn
            flat
            dense
            no-caps
            icon="restart_alt"
            label="Reset to defaults"
            color="grey-8"
            data-test="chat-settings-reset"
            @click="onReset"
          />
        </q-item-section>
        <q-item-section side>
          <q-btn
            flat
            dense
            no-caps
            icon="delete_sweep"
            label="Clear chat"
            color="negative"
            data-test="chat-settings-clear"
            @click="onClear"
          />
        </q-item-section>
      </q-item>
    </q-list>
  </q-btn-dropdown>
</template>

<script setup lang="ts">
/**
 * Chat settings dropdown menu.
 *
 * Controls font family, font size, bubble density, timestamp
 * visibility and send shortcut. Also exposes "Reset to defaults"
 * and "Clear chat" shortcut actions. Settings are persisted via
 * the ``useChatSettings`` composable.
 */
import { CHAT_FONT_SIZE_MAX, CHAT_FONT_SIZE_MIN, useChatSettings } from '~/composables/useChatSettings'
import { useChat } from '~/composables/useChat'

const { fontFamily, fontSize, density, showTimestamps, sendShortcut, sendUiContext, streamResponses, reset } =
  useChatSettings()
const { clearMessages } = useChat()

const fontSizeMin = CHAT_FONT_SIZE_MIN
const fontSizeMax = CHAT_FONT_SIZE_MAX

function onFontSizeChange(value: number | string | null): void {
  if (value === null || value === undefined || value === '') return
  const parsed = typeof value === 'number' ? value : Number(value)
  if (!Number.isFinite(parsed)) return
  // The composable clamps to the supported range internally.
  fontSize.value = parsed
}

const fontFamilyOptions = [
  { label: 'System', value: 'system' },
  { label: 'Sans', value: 'sans' },
  { label: 'Serif', value: 'serif' },
  { label: 'Mono', value: 'mono' },
]

const densityOptions = [
  { label: 'Compact', value: 'compact' },
  { label: 'Comfortable', value: 'comfortable' },
  { label: 'Spacious', value: 'spacious' },
]

const sendShortcutOptions = [
  { label: 'Enter', value: 'enter' },
  { label: 'Ctrl+Enter', value: 'mod-enter' },
]

function onReset(): void {
  reset()
}

function onClear(): void {
  clearMessages()
}
</script>

<style scoped lang="scss">
.chat-settings-menu {
  min-width: 300px;
  padding: 4px 8px 8px 8px;
}

.chat-settings__font-size-value {
  margin-left: 6px;
  font-variant-numeric: tabular-nums;
}
</style>
