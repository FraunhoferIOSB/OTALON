import { afterEach, describe, expect, it, vi } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'

import { useAuthStore } from '~/stores/authStore'

const api = {
  get: vi.fn(),
  post: vi.fn(),
}

vi.mock('~/composables/useApi', () => ({ useApi: () => api }))

describe('authStore', () => {
  afterEach(() => {
    api.get.mockReset()
    api.post.mockReset()
  })

  it('bootstraps from /me and keeps session cookie material out of state', async () => {
    setActivePinia(createPinia())
    const user = { id: 1, username: 'admin', role: 'admin', must_change_password: false }
    api.get.mockResolvedValueOnce(user)
    const auth = useAuthStore()

    await expect(auth.bootstrap()).resolves.toEqual(user)
    expect(api.get).toHaveBeenCalledWith('/api/v1/auth/me')
    expect(auth.user).toEqual(user)
    expect(JSON.stringify(auth.$state)).not.toContain('session')
  })

  it('maps invalid credentials to uniform UI feedback and no authenticated state', async () => {
    setActivePinia(createPinia())
    api.post.mockRejectedValueOnce({ status: 401, message: 'Unauthorized' })
    const auth = useAuthStore()

    await expect(auth.login('admin', 'wrong-password')).resolves.toBeNull()
    expect(auth.error).toBe('Invalid username or password.')
    expect(auth.user).toBeNull()
    expect(api.get).not.toHaveBeenCalled()
  })

  it('completes forced password change through auth endpoint', async () => {
    setActivePinia(createPinia())
    api.post.mockResolvedValueOnce({ id: 1, username: 'admin', role: 'admin', must_change_password: false })
    const auth = useAuthStore()

    await expect(auth.changePassword('a-new-password-longer')).resolves.toMatchObject({ must_change_password: false })
    expect(api.post).toHaveBeenCalledWith('/api/v1/auth/change-password', { new_password: 'a-new-password-longer' })
  })

  it('does not cache a logged-out bootstrap result before the next /me request', async () => {
    setActivePinia(createPinia())
    api.get.mockResolvedValueOnce({ id: 1, username: 'admin', role: 'admin', must_change_password: false })
    api.post.mockResolvedValueOnce({ status: 'logged_out' })
    const auth = useAuthStore()

    await auth.bootstrap()
    await auth.logout()
    api.get.mockRejectedValueOnce({ status: 401, message: 'Unauthorized' })
    await expect(auth.bootstrap()).resolves.toBeNull()
    expect(api.get).toHaveBeenCalledTimes(2)
  })
})
