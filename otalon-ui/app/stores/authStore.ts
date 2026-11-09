import { defineStore } from 'pinia'

import { useApi, type ApiError } from '~/composables/useApi'
import type { CurrentUser, LoginResponse } from '~/types/identity'

export type AuthStatus = 'idle' | 'loading' | 'authenticated' | 'unauthenticated'

interface AuthState {
  status: AuthStatus
  user: CurrentUser | null
  error: string
  bootstrapped: boolean
}

function isApiError(error: unknown): error is ApiError {
  return typeof error === 'object' && error !== null && 'status' in error
}

function safeRedirectTarget(target: unknown): string {
  if (typeof target !== 'string' || !target.startsWith('/') || target.startsWith('//')) return '/dashboard'
  return target
}

/**
 * Store for the server-backed product session.
 *
 * Session cookies remain HttpOnly and are never copied into Pinia or browser
 * storage. Use `useAuthStore()` from app bootstrap and auth lifecycle pages.
 *
 * @example
 * ```ts
 * const auth = useAuthStore()
 * await auth.bootstrap()
 * ```
 */
export const useAuthStore = defineStore('auth', {
  state: (): AuthState => ({
    status: 'idle',
    user: null,
    error: '',
    bootstrapped: false,
  }),

  getters: {
    isAuthenticated: (state): boolean => state.status === 'authenticated' && state.user !== null,
    isAdmin: (state): boolean => state.user?.role === 'admin' && !state.user.must_change_password,
    mustChangePassword: (state): boolean => state.user?.must_change_password ?? false,
  },

  actions: {
    async bootstrap(): Promise<CurrentUser | null> {
      if (this.bootstrapped && this.status !== 'loading') return this.user
      this.status = 'loading'
      this.error = ''
      try {
        const user = await useApi().get<CurrentUser>('/api/v1/auth/me')
        this.user = user
        this.status = 'authenticated'
        this.bootstrapped = true
        return user
      } catch (error: unknown) {
        this.user = null
        this.status = 'unauthenticated'
        this.bootstrapped = true
        if (!isApiError(error) || error.status !== 401) this.error = 'Unable to verify session.'
        return null
      }
    },

    async login(username: string, password: string): Promise<CurrentUser | null> {
      this.error = ''
      try {
        await useApi().post<LoginResponse>('/api/v1/auth/login', { username, password })
        const user = await useApi().get<CurrentUser>('/api/v1/auth/me')
        this.user = user
        this.status = 'authenticated'
        this.bootstrapped = true
        return user
      } catch (error: unknown) {
        this.user = null
        this.status = 'unauthenticated'
        this.error = isApiError(error) && error.status === 401 ? 'Invalid username or password.' : 'Sign-in failed.'
        return null
      }
    },

    async logout(): Promise<void> {
      try {
        if (this.isAuthenticated) await useApi().post('/api/v1/auth/logout')
      } finally {
        this.user = null
        this.status = 'unauthenticated'
        this.error = ''
        this.bootstrapped = false
      }
    },

    async changePassword(newPassword: string): Promise<CurrentUser | null> {
      try {
        const user = await useApi().post<CurrentUser>('/api/v1/auth/change-password', { new_password: newPassword })
        this.user = user
        this.status = 'authenticated'
        this.error = ''
        return user
      } catch (error: unknown) {
        this.error = isApiError(error) && error.status === 422 ? 'Password must contain at least 12 characters.' : 'Password change failed.'
        return null
      }
    },

    loginTarget(query: Record<string, unknown>): string {
      return safeRedirectTarget(query.redirect)
    },
  },
})
