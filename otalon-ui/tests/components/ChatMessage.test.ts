// @vitest-environment jsdom
/**
 * Component tests for the chat Message component.
 *
 * Runs under jsdom: DOMPurify does not support happy-dom, which fails to
 * strip/retain elements consistently, so sanitation is only meaningful here.
 *
 * Verifies that user messages are rendered as plain text (no HTML
 * interpretation) while assistant messages are rendered as sanitized
 * Markdown so that lists, tables, code blocks and emphasis from the
 * LLM are displayed correctly.
 */
import { beforeEach, describe, expect, it } from 'vitest'

import ChatMessage from '~/components/chat/Message.vue'
import { useChatSettings } from '~/composables/useChatSettings'
import { mountWithPlugins } from '../helpers/mount'

function makeMessage(role: 'user' | 'assistant', content: string) {
  return {
    id: 'm1',
    role,
    content,
    timestamp: new Date('2026-05-07T13:30:00Z'),
  }
}

describe('chat/Message', () => {
  beforeEach(() => {
    window.localStorage.clear()
    ;(globalThis as unknown as { __NUXT_STATE__: Record<string, unknown> }).__NUXT_STATE__ = {}
  })

  it('renders user content as plain text without HTML interpretation', () => {
    const dangerous = 'Hello **world** <script>alert(1)</script>'
    const wrapper = mountWithPlugins(ChatMessage, {
      props: { message: makeMessage('user', dangerous) },
    })

    const content = wrapper.find('.chat-message__content--plain')
    expect(content.exists()).toBe(true)
    // Asterisks must be visible (not interpreted as bold).
    expect(content.text()).toContain('**world**')
    // Script tags must NOT be present in the DOM at all.
    expect(wrapper.html()).not.toContain('<script>')
  })

  it('renders assistant Markdown emphasis as <strong>', () => {
    const wrapper = mountWithPlugins(ChatMessage, {
      props: { message: makeMessage('assistant', 'Hello **world**') },
    })

    const content = wrapper.find('.chat-message__content--markdown')
    expect(content.exists()).toBe(true)
    expect(content.html()).toContain('<strong>world</strong>')
  })

  it('renders assistant Markdown bullet lists', () => {
    const md = ['- one', '- two', '- three'].join('\n')
    const wrapper = mountWithPlugins(ChatMessage, {
      props: { message: makeMessage('assistant', md) },
    })

    const content = wrapper.find('.chat-message__content--markdown')
    const html = content.html()
    expect(html).toContain('<ul>')
    expect(html).toContain('<li>one</li>')
    expect(html).toContain('<li>three</li>')
  })

  it('sanitizes <script> tags in assistant Markdown output', () => {
    const md = 'Safe **bold** <script>alert(1)</script> end'
    const wrapper = mountWithPlugins(ChatMessage, {
      props: { message: makeMessage('assistant', md) },
    })

    const html = wrapper.find('.chat-message__content--markdown').html()
    expect(html).toContain('<strong>bold</strong>')
    expect(html).not.toContain('<script>')
    expect(html).not.toContain('alert(1)')
  })

  it('strips inline event handlers and javascript: URLs from assistant Markdown output', () => {
    const md = ['<img src="x" onerror="alert(1)">', '', '[click](javascript:alert(2))'].join('\n')
    const wrapper = mountWithPlugins(ChatMessage, {
      props: { message: makeMessage('assistant', md) },
    })

    const html = wrapper.find('.chat-message__content--markdown').html()
    expect(html).not.toContain('onerror')
    expect(html).not.toContain('javascript:')
  })

  it('renders Markdown tables', () => {
    const md = ['| col | val |', '| --- | --- |', '| a | 1 |'].join('\n')
    const wrapper = mountWithPlugins(ChatMessage, {
      props: { message: makeMessage('assistant', md) },
    })

    const html = wrapper.find('.chat-message__content--markdown').html()
    expect(html).toContain('<table>')
    expect(html).toContain('<th>col</th>')
    expect(html).toContain('<td>a</td>')
  })

  it('renders fenced code blocks', () => {
    const md = '```js\nconsole.log("hi")\n```'
    const wrapper = mountWithPlugins(ChatMessage, {
      props: { message: makeMessage('assistant', md) },
    })

    const html = wrapper.find('.chat-message__content--markdown').html()
    expect(html).toContain('<pre>')
    expect(html).toContain('<code')
    expect(html).toContain('console.log')
  })

  it('shows the timestamp by default', () => {
    const wrapper = mountWithPlugins(ChatMessage, {
      props: { message: makeMessage('assistant', 'Hi') },
    })

    expect(wrapper.find('.chat-message__time').exists()).toBe(true)
  })

  it('hides the timestamp when chat settings disable it', async () => {
    const settings = useChatSettings()
    settings.showTimestamps.value = false

    const wrapper = mountWithPlugins(ChatMessage, {
      props: { message: makeMessage('assistant', 'Hi') },
    })

    expect(wrapper.find('.chat-message__time').exists()).toBe(false)
  })
})
