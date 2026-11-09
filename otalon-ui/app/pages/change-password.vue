<template>
  <main class="identity-login" data-test="change-password-page">
    <section class="login-card" aria-labelledby="change-password-title">
      <div class="login-logo"><img class="login-logo-mark" src="/images/otalon-symbol-dark.svg" alt="OTALON" /></div>
      <h1 id="change-password-title">Choose a new password</h1>
      <p class="login-sub">Your temporary password must be replaced before using the console.</p>
      <div v-if="auth.error" class="login-error" role="alert" data-test="change-password-error">{{ auth.error }}</div>
      <form @submit="submit">
        <div class="identity-field">
          <label for="new-password">New password</label>
          <input id="new-password" v-model="password" type="password" minlength="12" autocomplete="new-password" required data-test="new-password" />
        </div>
        <div class="identity-field">
          <label for="confirm-password">Confirm new password</label>
          <input id="confirm-password" v-model="confirmation" type="password" minlength="12" autocomplete="new-password" required data-test="confirm-password" />
        </div>
        <button class="identity-button" type="submit" :disabled="submitting" data-test="change-password-submit">Save password</button>
      </form>
    </section>
  </main>
</template>

<script setup lang="ts">
import { ref } from 'vue'

import { useAuthStore } from '~/stores/authStore'

definePageMeta({ layout: false })

const auth = useAuthStore()
const password = ref('')
const confirmation = ref('')
const submitting = ref(false)

async function submit(event: Event): Promise<void> {
  event.preventDefault()
  auth.error = password.value === confirmation.value ? '' : 'Passwords do not match.'
  if (auth.error) return
  submitting.value = true
  const user = await auth.changePassword(password.value)
  password.value = ''
  confirmation.value = ''
  submitting.value = false
  if (user) window.location.href = '/dashboard'
}
</script>

<style scoped lang="scss">
.identity-login { align-items: center; background: radial-gradient(circle at 70% 30%, rgba(38, 166, 154, 0.1), transparent 55%), #141414; color: #e0e0e0; display: flex; font-family: 'Calibri', 'Helvetica Neue', Arial, sans-serif; justify-content: center; min-height: 100vh; padding: 24px; }
.login-card { background: #1e1e1e; border: 1px solid #2a2a2a; border-radius: 16px; box-shadow: 0 4px 16px rgba(0, 0, 0, 0.5); padding: 40px 36px; text-align: center; width: 380px; }
.login-logo { display: flex; flex-direction: column; align-items: center; margin-bottom: 6px; }
.login-logo-mark { display: block; height: 46px; margin: 0 auto 8px; width: auto; }
h1 { font-size: 20px; margin: 0 0 8px; }
.login-sub { color: #90a4ae; font-size: 13px; margin: 0 0 28px; }
.identity-field { margin-bottom: 16px; text-align: left; }
.identity-field label { color: #90a4ae; display: block; font-size: 12px; margin-bottom: 6px; }
.identity-field input { background: #141414; border: 1px solid #3a3a3a; border-radius: 10px; box-sizing: border-box; color: #e0e0e0; font-size: 14px; padding: 12px 14px; width: 100%; }
.identity-field input:focus { border-color: #26a69a; box-shadow: 0 0 0 3px rgba(38, 166, 154, 0.15); outline: none; }
.identity-button { background: #26a69a; border: 0; border-radius: 10px; color: #04211e; cursor: pointer; font-size: 14px; font-weight: 700; padding: 12px 16px; width: 100%; }
.identity-button:disabled { cursor: wait; opacity: 0.65; }
.login-error { background: rgba(211, 47, 47, 0.15); border: 1px solid #d32f2f; border-radius: 10px; color: #ff8a80; font-size: 13px; margin-bottom: 16px; padding: 10px 14px; text-align: left; }
@media (max-width: 480px) { .identity-login { padding: 16px; } .login-card { padding: 32px 24px; width: min(380px, 100%); } }
</style>
