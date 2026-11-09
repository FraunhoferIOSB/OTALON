/**
 * Mock versions of Nuxt auto-imported functions for the Vitest environment.
 *
 * Re-exports real Vue reactivity primitives and provides lightweight
 * stubs for Nuxt-specific composables that are unavailable outside
 * the Nuxt runtime.
 */
import { ref, type Ref } from 'vue'

export {
  computed,
  isRef,
  nextTick,
  onBeforeUnmount,
  onMounted,
  onUnmounted,
  reactive,
  readonly,
  ref,
  toRaw,
  toRef,
  toValue,
  watch,
} from 'vue'

const stateCache = new Map<string, Ref<unknown>>()

export function useState<T>(key: string, init: () => T): Ref<T> {
  const cached = stateCache.get(key)
  if (cached) return cached as Ref<T>
  const created = ref(init()) as Ref<T>
  stateCache.set(key, created as Ref<unknown>)
  return created
}

export function __resetUseStateCache(): void {
  stateCache.clear()
}

export function useRuntimeConfig() {
  return { public: { apiKey: 'test-api-key' } }
}

export function useRoute() {
  return { meta: {}, query: {}, params: {}, path: '/' }
}

export function useRouter() {
  return { push: () => {}, replace: () => {} }
}

export function navigateTo(_path: string) {
  return Promise.resolve()
}

export function definePageMeta(_meta: Record<string, unknown>) {}
