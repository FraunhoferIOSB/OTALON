import { useElementSize } from '@vueuse/core'

export interface WidgetSize {
  width: number
  height: number
}

/**
 * Track the pixel size of a widget root element.
 *
 * Usage:
 * ```ts
 * const el = ref<HTMLElement | null>(null)
 * const { width, height } = useWidgetSize(el)
 * const maxRows = computed(() => clamp(Math.floor((height.value - 64) / 36), 2, 8))
 * ```
 *
 * @param el - Ref to the widget root element.
 * @returns Reactive width and height in pixels.
 */
export function useWidgetSize(el: Ref<HTMLElement | null>): WidgetSize {
  const { width, height } = useElementSize(el)
  return { width, height }
}
