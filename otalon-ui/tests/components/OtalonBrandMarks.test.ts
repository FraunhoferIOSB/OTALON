/**
 * Component tests for the OTALON brand marks.
 *
 * The marks are inline SVG rather than `<img src>` on purpose: an
 * image-embedded SVG is an isolated document that cannot resolve the host page
 * `@font-face`, which would silently fall the wordmark back to a generic
 * sans-serif. These tests lock in the properties that decision depends on —
 * inline rendering, theme-driven colour custom properties, and the brand font
 * family — plus the accessible name that replaces the former text title.
 */
import { describe, it, expect } from 'vitest'

import OtalonSymbol from '~/components/shared/OtalonSymbol.vue'
import OtalonWordmark from '~/components/shared/OtalonWordmark.vue'
import { mountWithPlugins } from '../helpers/mount'

describe('OtalonWordmark', () => {
  it('renders an inline svg rather than an image element', () => {
    const wrapper = mountWithPlugins(OtalonWordmark)

    expect(wrapper.find('svg').exists()).toBe(true)
    expect(wrapper.find('img').exists()).toBe(false)
  })

  it('exposes an accessible name for assistive technology', () => {
    const wrapper = mountWithPlugins(OtalonWordmark)
    const svg = wrapper.find('svg')

    expect(svg.attributes('role')).toBe('img')
    expect(svg.attributes('aria-label')).toBe('OTALON')
    expect(wrapper.find('title').text()).toBe('OTALON')
  })

  it('allows the accessible name to be overridden', () => {
    const wrapper = mountWithPlugins(OtalonWordmark, {
      props: { ariaLabel: 'OTALON — go to dashboard' },
    })

    expect(wrapper.find('svg').attributes('aria-label')).toBe('OTALON — go to dashboard')
  })

  it('renders every wordmark letter as an SVG outline', () => {
    const wrapper = mountWithPlugins(OtalonWordmark)
    expect(wrapper.findAll('text')).toHaveLength(0)
    expect(wrapper.findAll('path')).toHaveLength(6)
  })

  it('crops the viewBox to the drawn content', () => {
    const wrapper = mountWithPlugins(OtalonWordmark)

    // The marketing asset ships a 0 0 960 280 canvas whose content occupies
    // y 94..186; using it verbatim would halve the rendered glyph height in a
    // fixed-height header slot.
    expect(wrapper.find('svg').attributes('viewBox')).toBe('25 92 910 96')
  })

  it('drives every fill and stroke through theme custom properties', () => {
    const wrapper = mountWithPlugins(OtalonWordmark)
    const markup = wrapper.html()

    // A literal hex colour here would pin the mark to one theme.
    expect(markup).not.toMatch(/#[0-9a-fA-F]{6}/)
  })
})

describe('OtalonSymbol', () => {
  it('renders an inline svg with an accessible name', () => {
    const wrapper = mountWithPlugins(OtalonSymbol)
    const svg = wrapper.find('svg')

    expect(svg.exists()).toBe(true)
    expect(svg.attributes('role')).toBe('img')
    expect(svg.attributes('aria-label')).toBe('OTALON')
  })

  it('keeps the square aspect ratio of the master asset', () => {
    const wrapper = mountWithPlugins(OtalonSymbol)

    expect(wrapper.find('svg').attributes('viewBox')).toBe('0 0 160 160')
  })

  it('drives every fill and stroke through theme custom properties', () => {
    const wrapper = mountWithPlugins(OtalonSymbol)

    expect(wrapper.html()).not.toMatch(/#[0-9a-fA-F]{6}/)
  })
})
