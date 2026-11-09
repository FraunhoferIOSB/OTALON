/**
 * Composable for Dark/Light mode toggling via Quasar Dark Plugin.
 *
 * Persists the user preference in localStorage and initializes from
 * the system preference on first visit using VueUse's usePreferredDark.
 */

import { useQuasar } from 'quasar'
// Note: usePreferredDark import removed — initTheme currently defaults
// dark to true rather than honouring the system preference. Restoring
// system-preference fallback is tracked separately (UI polish backlog).

const STORAGE_KEY = 'cd-theme-dark'

/**
 * Provide reactive dark mode state and toggle function.
 *
 * @returns Object with isDark ref and toggle function.
 */
export function useTheme() {
  const $q = useQuasar()

  const isDark = computed(() => $q.dark.isActive)

  function initTheme(): void {
    const stored = localStorage.getItem(STORAGE_KEY)
    if (stored !== null) {
      $q.dark.set(stored === 'true')
    } else {
      $q.dark.set(true)
    }
  }

  function toggleDark(): void {
    $q.dark.toggle()
    localStorage.setItem(STORAGE_KEY, String($q.dark.isActive))
  }

  function setDark(value: boolean): void {
    $q.dark.set(value)
    localStorage.setItem(STORAGE_KEY, String(value))
  }

  return {
    isDark,
    initTheme,
    toggleDark,
    setDark,
  }
}
