import { useQuasar } from 'quasar'

/**
 * Options accepted by the operations notify helper.
 */
export interface OperationsNotifyOptions {
  message: string
  type?: 'positive' | 'negative' | 'warning' | 'info'
  timeout?: number
}

/**
 * Operations-aware toast helper that enforces a maximum of one transient
 * toast at a time. Triggering a second toast dismisses the previous one.
 *
 * @example
 * ```ts
 * const notify = useOperationsNotify()
 * notify({ message: 'Pipeline refreshed', type: 'positive' })
 * ```
 */
export function useOperationsNotify() {
  const $q = useQuasar()
  let dismissPrevious: (() => void) | null = null

  /**
   * Show a single transient toast, dismissing any existing toast first.
   *
   * @param options - Toast content and severity.
   */
  return function notify(options: OperationsNotifyOptions): void {
    if (dismissPrevious) {
      dismissPrevious()
      dismissPrevious = null
    }

    const { message, type = 'info', timeout = 4000 } = options
    dismissPrevious = $q.notify({
      message,
      type,
      timeout,
      position: 'bottom-right',
      actions: [{ icon: 'close', color: 'white' }],
    })
  }
}
