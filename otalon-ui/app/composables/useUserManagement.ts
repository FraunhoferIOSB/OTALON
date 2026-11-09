import { ref, type Ref } from 'vue'

import { useApi, type ApiError } from '~/composables/useApi'
import type {
  AdminUser,
  DeleteUserResponse,
  OneTimePasswordResponse,
  ProductUserRole,
  UserListResponse,
} from '~/types/identity'

export interface UserManagementReturn {
  users: Ref<AdminUser[]>
  loading: Ref<boolean>
  saving: Ref<boolean>
  error: Ref<string>
  oneTimePassword: Ref<string | null>
  load: () => Promise<void>
  create: (username: string, role: ProductUserRole) => Promise<AdminUser | null>
  update: (id: number, changes: { role?: ProductUserRole; disabled?: boolean }) => Promise<AdminUser | null>
  resetPassword: (id: number) => Promise<AdminUser | null>
  remove: (id: number) => Promise<boolean>
  clearOneTimePassword: () => void
}

function apiMessage(error: unknown, fallback: string): string {
  if (typeof error === 'object' && error !== null && 'detail' in error) {
    const detail = (error as ApiError).detail
    if (typeof detail === 'string') return detail
  }
  return fallback
}

/**
 * Admin-only user CRUD client.
 *
 * Generated passwords exist only in `oneTimePassword` until the admin closes
 * its display. They are never logged, persisted, or included in user state.
 *
 * @example
 * ```ts
 * const management = useUserManagement()
 * await management.load()
 * ```
 */
export function useUserManagement(): UserManagementReturn {
  const api = useApi()
  const users = ref<AdminUser[]>([])
  const loading = ref(false)
  const saving = ref(false)
  const error = ref('')
  const oneTimePassword = ref<string | null>(null)

  async function load(): Promise<void> {
    loading.value = true
    error.value = ''
    try {
      const response = await api.get<UserListResponse>('/api/v1/admin/users')
      users.value = response.users
    } catch (caught: unknown) {
      error.value = apiMessage(caught, 'Users could not be loaded.')
    } finally {
      loading.value = false
    }
  }

  async function create(username: string, role: ProductUserRole): Promise<AdminUser | null> {
    saving.value = true
    error.value = ''
    try {
      const response = await api.post<OneTimePasswordResponse>('/api/v1/admin/users', { username, role })
      users.value = [...users.value, response.user]
      oneTimePassword.value = response.one_time_password
      return response.user
    } catch (caught: unknown) {
      error.value = apiMessage(caught, 'User could not be created.')
      return null
    } finally {
      saving.value = false
    }
  }

  async function update(id: number, changes: { role?: ProductUserRole; disabled?: boolean }): Promise<AdminUser | null> {
    saving.value = true
    error.value = ''
    try {
      const user = await api.patch<AdminUser>(`/api/v1/admin/users/${id}`, changes)
      users.value = users.value.map((entry) => (entry.id === id ? user : entry))
      return user
    } catch (caught: unknown) {
      error.value = apiMessage(caught, 'User could not be updated.')
      return null
    } finally {
      saving.value = false
    }
  }

  async function resetPassword(id: number): Promise<AdminUser | null> {
    saving.value = true
    error.value = ''
    try {
      const response = await api.post<OneTimePasswordResponse>(`/api/v1/admin/users/${id}/reset-password`)
      users.value = users.value.map((entry) => (entry.id === id ? response.user : entry))
      oneTimePassword.value = response.one_time_password
      return response.user
    } catch (caught: unknown) {
      error.value = apiMessage(caught, 'Password could not be reset.')
      return null
    } finally {
      saving.value = false
    }
  }

  async function remove(id: number): Promise<boolean> {
    saving.value = true
    error.value = ''
    try {
      const response = await api.del<DeleteUserResponse>(`/api/v1/admin/users/${id}`)
      if (response.deleted) users.value = users.value.filter((entry) => entry.id !== id)
      return response.deleted
    } catch (caught: unknown) {
      error.value = apiMessage(caught, 'User could not be deleted.')
      return false
    } finally {
      saving.value = false
    }
  }

  function clearOneTimePassword(): void {
    oneTimePassword.value = null
  }

  return { users, loading, saving, error, oneTimePassword, load, create, update, resetPassword, remove, clearOneTimePassword }
}
