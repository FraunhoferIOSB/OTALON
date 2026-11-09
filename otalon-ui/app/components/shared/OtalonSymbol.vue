<template>
  <svg
    class="otalon-symbol"
    viewBox="0 0 160 160"
    role="img"
    :aria-label="ariaLabel"
    focusable="false"
    xmlns="http://www.w3.org/2000/svg"
  >
    <title>{{ ariaLabel }}</title>
    <line class="otalon-symbol__line" x1="4" y1="80" x2="48" y2="80" />
    <line class="otalon-symbol__line" x1="112" y1="80" x2="156" y2="80" />
    <path class="otalon-symbol__zigzag" d="M48 80 L57 80 L63 74 L69 84 L75 79 L83 80 L90 60 L97 90 L103 80 L112 80" />
    <circle class="otalon-symbol__anomaly" cx="90" cy="60" r="7" />
    <circle class="otalon-symbol__aperture" cx="80" cy="80" r="39" />
    <rect class="otalon-symbol__connector" x="28" y="71" width="18" height="18" rx="4" />
    <rect class="otalon-symbol__connector" x="114" y="71" width="18" height="18" rx="4" />
  </svg>
</template>

<script setup lang="ts">
/**
 * OTALON brand symbol (analysis aperture, standalone).
 *
 * Geometry is a verbatim copy of `public/images/otalon-symbol-color.svg`; keep
 * both in sync when the brand asset changes. Colours resolve through the
 * `--otalon-*` custom properties from `assets/styles/global.scss` so a single
 * markup source serves both themes.
 *
 * Used in the application header below the wordmark breakpoint, where the full
 * wordmark would crowd out the route title and the toolbar controls.
 *
 * @example
 * ```vue
 * <OtalonSymbol class="app-logo-symbol" />
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
.otalon-symbol {
  display: block;
  height: 22px;
  width: auto;
  flex: 0 0 auto;
}

.otalon-symbol__line {
  stroke: var(--otalon-accent);
  stroke-width: 5;
  stroke-linecap: round;
}

.otalon-symbol__zigzag {
  fill: none;
  stroke: var(--otalon-ink);
  stroke-width: 5;
  stroke-linecap: round;
  stroke-linejoin: round;
}

.otalon-symbol__anomaly {
  fill: var(--otalon-alert);
}

.otalon-symbol__aperture {
  fill: none;
  stroke: var(--otalon-ink);
  stroke-width: 14;
}

.otalon-symbol__connector {
  fill: var(--otalon-ink);
}
</style>
