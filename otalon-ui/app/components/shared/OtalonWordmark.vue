<template>
  <svg
    class="otalon-wordmark"
    viewBox="25 92 910 96"
    role="img"
    :aria-label="ariaLabel"
    focusable="false"
    xmlns="http://www.w3.org/2000/svg"
  >
    <title>{{ ariaLabel }}</title>
    <line class="otalon-wordmark__line" x1="28" y1="140" x2="398" y2="140" />
    <line class="otalon-wordmark__line" x1="462" y1="140" x2="932" y2="140" />
    <g class="otalon-wordmark__text" transform="translate(92 174) scale(.104 -.104)">
      <path d="M47 351Q47 514 135 611Q222 709 389 710Q555 708 643 610Q731 513 731 351Q730 190 644 91Q556 -10 389 -12Q221 -10 135 90Q47 188 47 351ZM193 351Q192 253 238 178Q284 100 389 98Q443 98 481 120Q519 142 541 178Q585 253 585 351Q585 448 540 522Q493 598 389 600Q286 598 240 522Q193 448 193 351Z" />
      <path transform="translate(787 0)" d="M208 588H8V698H548V588H348V0H208Z" />
      <path transform="translate(1352 0)" d="M358 558H356L255 270H459ZM281 698H439L713 0H558L498 160H215L154 0H9Z" />
      <path transform="translate(2083 0)" d="M81 698H221V110H492V0H81Z" />
    </g>
    <path
      class="otalon-wordmark__zigzag"
      d="M398 140 L407 140 L413 134 L419 144 L425 139 L433 140 L440 120 L447 150 L453 140 L462 140"
    />
    <circle class="otalon-wordmark__anomaly" cx="440" cy="120" r="7" />
    <circle class="otalon-wordmark__aperture" cx="430" cy="140" r="39" />
    <rect class="otalon-wordmark__connector" x="378" y="131" width="18" height="18" rx="4" />
    <rect class="otalon-wordmark__connector" x="464" y="131" width="18" height="18" rx="4" />
    <path class="otalon-wordmark__text" transform="translate(486 174) scale(.104 -.104)" d="M74 698H246L512 176H514V698H648V0H477L210 522H208V0H74Z" />
  </svg>
</template>

<script setup lang="ts">
/**
 * OTALON brand wordmark ("Industrial Sight Glass").
 *
 * Geometry is a verbatim copy of the canonical marketing asset
 * `public/images/otalon-wordmark.svg`; keep both in sync when the brand
 * asset changes. Two deliberate deviations exist:
 *
 * 1. The `viewBox` is cropped to the drawn content (the source file carries
 *    ~40% vertical padding, which would shrink the glyphs to roughly half the
 *    intended size inside a fixed-height header slot).
 * 2. Fills and strokes resolve through the `--otalon-*` custom properties
 *    defined in `assets/styles/global.scss`, so light and dark themes share a
 *    single markup source instead of two divergent files.
 *
  * Letterforms are inline SVG outlines generated from the licensed desktop font;
  * no font software is redistributed to clients.
 *
 * @example
 * ```vue
 * <OtalonWordmark class="app-logo" />
 * ```
 */
withDefaults(
  defineProps<{
    /** Accessible name exposed to assistive technology. */
    ariaLabel?: string
  }>(),
  { ariaLabel: 'OTALON' },
)
</script>

<style scoped lang="scss">
.otalon-wordmark {
  display: block;
  height: 22px;
  width: auto;
  // The mark must never be squeezed by a flex parent; it is a fixed-ratio asset.
  flex: 0 0 auto;
}

.otalon-wordmark__line {
  stroke: var(--otalon-accent);
  stroke-width: 5;
  stroke-linecap: round;
}

.otalon-wordmark__text {
  fill: var(--otalon-ink);
}

.otalon-wordmark__zigzag {
  fill: none;
  stroke: var(--otalon-ink);
  stroke-width: 5;
  stroke-linecap: round;
  stroke-linejoin: round;
}

.otalon-wordmark__anomaly {
  fill: var(--otalon-alert);
}

.otalon-wordmark__aperture {
  fill: none;
  stroke: var(--otalon-ink);
  stroke-width: 14;
}

.otalon-wordmark__connector {
  fill: var(--otalon-ink);
}
</style>
