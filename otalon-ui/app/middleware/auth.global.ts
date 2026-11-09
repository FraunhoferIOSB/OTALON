import { useAuthStore } from '~/stores/authStore'

const PUBLIC_ROUTES = new Set(['/login'])

export default defineNuxtRouteMiddleware(async (to) => {
  if (PUBLIC_ROUTES.has(to.path)) return

  const auth = useAuthStore()
  const user = await auth.bootstrap()
  if (!user) {
    return navigateTo({ path: '/login', query: { redirect: to.fullPath } })
  }

  if (user.must_change_password && to.path !== '/change-password') {
    return navigateTo('/change-password')
  }
  if (to.path === '/operations/configuration' && to.query.tab === 'access' && user.role !== 'admin') {
    return navigateTo('/operations/configuration?tab=runtime')
  }
  if (to.path === '/change-password' && !user.must_change_password) {
    return navigateTo('/dashboard')
  }
  if (to.path === '/') {
    return navigateTo('/dashboard', { replace: true })
  }
})
