import { beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises } from '@vue/test-utils'
import { ref } from 'vue'

const management = {
  users: ref<unknown[]>([]),
  loading: ref(false),
  saving: ref(false),
  error: ref(''),
  oneTimePassword: ref<string | null>(null),
  load: vi.fn(),
  create: vi.fn(),
  update: vi.fn(),
  resetPassword: vi.fn(),
  remove: vi.fn(),
  clearOneTimePassword: vi.fn(),
}

vi.mock('~/composables/useUserManagement', () => ({ useUserManagement: () => management }))

async function mountPanel() {
  const { mountWithPlugins } = await import('../helpers/mount')
  const mod = await import('~/components/identity/AccessUsersPanel.vue')
  return mountWithPlugins(mod.default)
}

beforeEach(() => {
  management.users.value = [
    {
      id: 1,
      username: 'admin',
      role: 'admin',
      disabled: false,
      must_change_password: false,
      created_at: null,
      last_login_at: null,
    },
  ]
  management.load.mockReset().mockResolvedValue(undefined)
  management.create.mockReset()
  management.update.mockReset()
  management.resetPassword.mockReset()
  management.remove.mockReset()
})

describe('AccessUsersPanel', () => {
  it('renders calm-spacious cards with role, status and add-user entry point', async () => {
    const wrapper = await mountPanel()
    expect(wrapper.find('[data-test="user-card-1"]').text()).toContain('admin')
    expect(wrapper.find('.role-chip.admin').text()).toBe('admin')
    expect(wrapper.find('.status-line').text()).toContain('Active')
    expect(wrapper.find('[data-test="add-user"]').exists()).toBe(true)
    expect(management.load).toHaveBeenCalledTimes(1)
  })

  it('shows generated password once and clears it when dismissed', async () => {
    management.create.mockImplementation(async () => {
      management.oneTimePassword.value = 'one-time-only'
      return management.users.value[0]
    })
    const wrapper = await mountPanel()
    await wrapper.find('[data-test="add-user"]').trigger('click')
    await wrapper.find('[data-test="user-username"]').setValue('operator')
    await wrapper.find('.identity-modal .identity-button').trigger('click')
    await flushPromises()

    expect(wrapper.find('[data-test="one-time-password"]').text()).toBe('one-time-only')
    await wrapper.find('[data-test="one-time-password-modal"] .identity-button').trigger('click')
    expect(management.clearOneTimePassword).toHaveBeenCalledTimes(1)
  })

  it('binds role and disabled updates to management client', async () => {
    management.update.mockResolvedValue(management.users.value[0])
    const wrapper = await mountPanel()
    await wrapper.find('[data-test="edit-user-1"]').trigger('click')
    await wrapper.find('[data-test="user-role"]').setValue('operator')
    await wrapper.find('[data-test="user-modal"] .identity-button').trigger('click')
    await flushPromises()
    expect(management.update).toHaveBeenCalledWith(1, { role: 'operator', disabled: false })
  })
})
