import type { Ref } from 'vue'

/**
 * Return type for the usePageData composable.
 */
export interface PageDataReturn<T> {
  data: Ref<T | null>
  isLoading: Ref<boolean>
  error: Ref<string | null>
  reload: () => Promise<void>
}

/**
 * Generic composable for page-level data loading with loading and error states.
 *
 * Wraps a data loader function with reactive isLoading and error refs.
 * Currently used with synchronous golden data loaders that resolve immediately,
 * but designed to support async API calls once the migration happens.
 *
 * @param loader - Function that returns the data synchronously or as a Promise.
 * @returns Reactive data, isLoading flag, error message, and reload function.
 */
export function usePageData<T>(loader: () => T | Promise<T>): PageDataReturn<T> {
  const data = ref<T | null>(null) as Ref<T | null>
  const isLoading = ref(true)
  const error = ref<string | null>(null)

  async function load(): Promise<void> {
    isLoading.value = true
    error.value = null
    try {
      data.value = await loader()
    } catch (e: unknown) {
      error.value = e instanceof Error ? e.message : 'An unexpected error occurred'
    } finally {
      isLoading.value = false
    }
  }

  load()

  return { data, isLoading, error, reload: load }
}
