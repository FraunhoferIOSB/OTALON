<template>
  <section class="access-users" data-test="access-users-panel">
    <div v-if="error" class="access-error" role="alert" data-test="users-error">{{ error }}</div>
    <div class="access-page-head">
      <div class="access-titles">
        <h2>Access &amp; Users</h2>
        <p>Manage who can sign in to this OTALON instance and what they're allowed to do. Three roles: viewer, operator, admin.</p>
      </div>
    </div>
    <div class="user-grid" data-test="user-grid">
      <article v-for="user in users" :key="user.id" class="user-card" :data-test="`user-card-${user.id}`">
        <div class="user-head">
          <div class="user-avatar">{{ initial(user.username) }}</div>
          <div class="user-name">
            {{ user.username }}
            <div class="status-line"><span class="status-dot" :class="user.disabled ? 'disabled' : 'active'" />{{ user.disabled ? 'Disabled' : 'Active' }} · last login {{ formatLastLogin(user.last_login_at) }}</div>
          </div>
        </div>
        <span class="role-chip" :class="user.role">{{ user.role }}</span>
        <div v-if="user.must_change_password" class="forced-change" data-test="forced-change-state">Password change required</div>
        <div class="card-actions">
          <button type="button" :data-test="`edit-user-${user.id}`" @click="openEdit(user)">Edit</button>
          <button type="button" :data-test="`reset-user-${user.id}`" @click="openReset(user)">Reset PW</button>
          <button type="button" :data-test="`toggle-user-${user.id}`" @click="toggleDisabled(user)">{{ user.disabled ? 'Enable' : 'Disable' }}</button>
          <button type="button" class="danger-action" :data-test="`delete-user-${user.id}`" @click="removeUser(user)">Delete</button>
        </div>
      </article>
      <button type="button" class="add-card" data-test="add-user" @click="openCreate">
        <span class="plus">+</span>
        <span>Add user</span>
      </button>
    </div>

    <div v-if="modal === 'create' || modal === 'edit'" class="modal-backdrop show" data-test="user-modal">
      <div class="identity-modal" role="dialog" aria-modal="true" :aria-labelledby="`${modal}-user-title`">
        <h3 :id="`${modal}-user-title`">{{ modal === 'create' ? 'Add user' : 'Edit user' }}</h3>
        <div class="identity-field"><label for="user-username">Username</label><input id="user-username" v-model="form.username" :readonly="modal === 'edit'" type="text" data-test="user-username" /></div>
        <div class="identity-field"><label for="user-role">Role</label><select id="user-role" v-model="form.role" data-test="user-role"><option value="viewer">viewer — read-only</option><option value="operator">operator — day-to-day ops</option><option value="admin">admin — user mgmt + destructive ops</option></select></div>
        <label v-if="modal === 'edit'" class="disabled-toggle"><input v-model="form.disabled" type="checkbox" /> Disabled</label>
        <div class="modal-actions"><button type="button" class="secondary-button" @click="closeModal">Cancel</button><button type="button" class="identity-button" @click="saveUser">{{ modal === 'create' ? 'Create' : 'Save' }}</button></div>
      </div>
    </div>

    <div v-if="modal === 'reset'" class="modal-backdrop show" data-test="reset-modal">
      <div class="identity-modal" role="dialog" aria-modal="true" aria-labelledby="reset-user-title">
        <h3 id="reset-user-title">Reset password</h3>
        <p class="modal-copy">A one-time password will be generated for <b>{{ target?.username }}</b>. They must change it on next login.</p>
        <div class="modal-actions"><button type="button" class="secondary-button" @click="closeModal">Cancel</button><button type="button" class="danger-button" @click="confirmReset">Reset password</button></div>
      </div>
    </div>

    <div v-if="oneTimePassword" class="modal-backdrop show" data-test="one-time-password-modal">
      <div class="identity-modal" role="dialog" aria-modal="true" aria-labelledby="one-time-password-title">
        <h3 id="one-time-password-title">One-time password</h3>
        <p class="modal-copy">Show this password to the user now. It will not be shown again.</p>
        <output class="one-time-password" data-test="one-time-password">{{ oneTimePassword }}</output>
        <div class="modal-actions"><button type="button" class="identity-button" @click="dismissPassword">Done</button></div>
      </div>
    </div>

    <div v-if="toast" class="toast show" role="status" data-test="users-toast">{{ toast }}</div>
  </section>
</template>

<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'

import type { AdminUser, ProductUserRole } from '~/types/identity'
import { useUserManagement } from '~/composables/useUserManagement'

const management = useUserManagement()
const { users, error, oneTimePassword } = management
const modal = ref<'create' | 'edit' | 'reset' | null>(null)
const target = ref<AdminUser | null>(null)
const toast = ref('')
const form = reactive<{ username: string; role: ProductUserRole; disabled: boolean }>({ username: '', role: 'viewer', disabled: false })

function initial(username: string): string { return username.replace(/[^a-zA-Z]/g, '').charAt(0).toUpperCase() || '?' }
function formatLastLogin(value: string | null): string { return value ? new Date(value).toLocaleString() : 'never' }
function notify(message: string): void { toast.value = message; window.setTimeout(() => { toast.value = '' }, 2400) }
function openCreate(): void { form.username = ''; form.role = 'viewer'; form.disabled = false; modal.value = 'create' }
function openEdit(user: AdminUser): void { target.value = user; form.username = user.username; form.role = user.role; form.disabled = user.disabled; modal.value = 'edit' }
function openReset(user: AdminUser): void { target.value = user; modal.value = 'reset' }
function closeModal(): void { modal.value = null; target.value = null }

async function saveUser(): Promise<void> {
  const action = modal.value
  const user = action === 'create' ? await management.create(form.username.trim(), form.role) : target.value ? await management.update(target.value.id, { role: form.role, disabled: form.disabled }) : null
  if (!user) return
  closeModal()
  notify(action === 'create' ? `User "${user.username}" created.` : `User "${user.username}" updated.`)
}

async function toggleDisabled(user: AdminUser): Promise<void> { if (await management.update(user.id, { disabled: !user.disabled })) notify(`${user.username} ${user.disabled ? 'enabled' : 'disabled'}.`) }
async function removeUser(user: AdminUser): Promise<void> { if (window.confirm(`Delete user "${user.username}"?`)) { if (await management.remove(user.id)) notify(`User "${user.username}" deleted.`) } }
async function confirmReset(): Promise<void> { if (target.value && await management.resetPassword(target.value.id)) closeModal() }
function dismissPassword(): void { management.clearOneTimePassword() }

onMounted(() => { void management.load() })
</script>

<style scoped lang="scss">
.access-users { color: #e0e0e0; }
.access-page-head { display: flex; align-items: flex-start; margin-bottom: 24px; }
.access-titles { flex: 1; }
.access-titles h2 { font-size: 22px; margin: 0 0 6px; }
.access-titles p { color: #90a4ae; font-size: 13px; margin: 0; max-width: 480px; }
.access-error { background: rgba(211,47,47,.15); border: 1px solid #d32f2f; border-radius: 10px; color: #ff8a80; margin-bottom: 16px; padding: 10px 14px; }
.user-grid { display: grid; gap: 16px; grid-template-columns: repeat(auto-fill, minmax(260px, 1fr)); }
.user-card { background: #1e1e1e; border: 1px solid #2a2a2a; border-radius: 14px; display: flex; flex-direction: column; gap: 12px; padding: 20px; }
.user-head { display: flex; gap: 12px; min-height: 60px; }
.user-avatar { align-items: center; background: #26a69a; border-radius: 50%; color: #04211e; display: flex; flex-shrink: 0; font-size: 14px; font-weight: 700; height: 40px; justify-content: center; width: 40px; }
.user-name { font-size: 15px; font-weight: 600; min-height: 34px; overflow-wrap: anywhere; }
.status-line { align-items: center; color: #90a4ae; display: flex; flex-wrap: wrap; font-size: 11px; font-weight: 400; gap: 5px; margin-top: 4px; }
.status-dot { border-radius: 50%; display: inline-block; height: 7px; width: 7px; }.status-dot.active { background: #16a34a; }.status-dot.disabled { background: #90a4ae; }
.role-chip { align-self: flex-start; border-radius: 999px; font-size: 11px; font-weight: 700; letter-spacing: .3px; padding: 4px 10px; text-transform: uppercase; }.role-chip.admin { background: rgba(211,47,47,.18); color: #ff8a80; }.role-chip.operator { background: rgba(38,166,154,.18); color: #26a69a; }.role-chip.viewer { background: rgba(144,164,174,.18); color: #90a4ae; }
.forced-change { color: #f59e0b; font-size: 11px; }
.card-actions { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 4px; }.card-actions button { background: none; border: 1px solid #3a3a3a; border-radius: 8px; color: #90a4ae; cursor: pointer; flex: 1 1 60px; font-size: 11px; padding: 7px; }.card-actions button:hover { border-color: #90a4ae; color: #e0e0e0; }.card-actions .danger-action:hover { border-color: #ef5350; color: #ef5350; }
.add-card { align-items: center; background: transparent; border: 1px dashed #3a3a3a; border-radius: 14px; color: #90a4ae; cursor: pointer; display: flex; flex-direction: column; font-size: 13px; gap: 8px; justify-content: center; min-height: 148px; }.add-card:hover { border-color: #26a69a; color: #26a69a; }.plus { font-size: 28px; line-height: 1; }
.modal-backdrop { align-items: center; background: rgba(0,0,0,.6); display: flex; inset: 0; justify-content: center; position: fixed; z-index: 50; }.identity-modal { background: #1e1e1e; border: 1px solid #2a2a2a; border-radius: 16px; box-shadow: 0 4px 16px rgba(0,0,0,.5); padding: 28px; width: min(360px, calc(100vw - 32px)); }.identity-modal h3 { font-size: 16px; margin: 0 0 16px; }.identity-field { margin-bottom: 16px; }.identity-field label { color: #90a4ae; display: block; font-size: 12px; margin-bottom: 6px; }.identity-field input, .identity-field select { background: #141414; border: 1px solid #3a3a3a; border-radius: 10px; box-sizing: border-box; color: #e0e0e0; font-size: 14px; padding: 11px 14px; width: 100%; }.identity-field input:focus, .identity-field select:focus { border-color: #26a69a; outline: none; }.disabled-toggle { color: #90a4ae; font-size: 13px; }.disabled-toggle input { accent-color: #26a69a; margin-right: 8px; }.modal-copy { color: #90a4ae; font-size: 13px; margin: 0 0 20px; }.modal-copy b { color: #e0e0e0; }.modal-actions { display: flex; gap: 10px; margin-top: 20px; }.identity-button, .secondary-button, .danger-button { border-radius: 10px; cursor: pointer; flex: 1; font-size: 14px; font-weight: 700; padding: 12px 16px; }.identity-button { background: #26a69a; border: 0; color: #04211e; }.secondary-button { background: transparent; border: 1px solid #3a3a3a; color: #90a4ae; }.danger-button { background: #d32f2f; border: 0; color: #fff; }.one-time-password { background: #141414; border: 1px solid #26a69a; border-radius: 10px; color: #26a69a; display: block; font-family: monospace; font-size: 18px; letter-spacing: 1px; padding: 14px; text-align: center; user-select: text; }.toast { background: #1e1e1e; border: 1px solid #26a69a; border-radius: 12px; bottom: 28px; box-shadow: 0 2px 8px rgba(0,0,0,.4); padding: 12px 18px; position: fixed; right: 28px; z-index: 60; }
@media (max-width: 600px) { .user-grid { grid-template-columns: 1fr; }.toast { bottom: 16px; left: 16px; right: 16px; } }
</style>
