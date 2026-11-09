/**
 * Unit tests for useNavigation.
 *
 * Verifies the production Operations group and retired legacy navigation.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'

const authState = { user: null as { role: 'viewer' | 'operator' | 'admin' } | null }

vi.mock('~/stores/authStore', () => ({
  useAuthStore: () => authState,
}))

const { useNavigation } = await import('~/composables/useNavigation')

describe('useNavigation', () => {
  const routeMock = vi.fn()

  beforeEach(() => {
    authState.user = { role: 'admin' }
    routeMock.mockReturnValue({ path: '/dashboard', meta: {}, query: {}, params: {} })
    vi.stubGlobal('useRoute', routeMock)
  })

  afterEach(() => {
    vi.unstubAllGlobals()
    routeMock.mockReset()
  })

  it('returns exactly one Operations group with six production children on production routes', () => {
    const { navItems } = useNavigation()
    const items = navItems.value

    const operationsGroups = items.filter((entry) => 'children' in entry && entry.label === 'Operations')
    // Exactly one Operations group on production routes.
    expect(operationsGroups).toHaveLength(1)
    const operations = operationsGroups[0]!
    expect('children' in operations && operations.children).toHaveLength(6)

    const routes = 'children' in operations ? operations.children.map((c) => c.route) : []
    expect(routes).toEqual([
      '/operations/overview',
      '/operations/data-sources',
      '/operations/detection',
      '/operations/jobs',
      '/operations/configuration',
      '/operations/system',
    ])
  })

  it('has no top-level Management item', () => {
    const { navItems } = useNavigation()
    const items = navItems.value

    const management = items.find((entry) => 'route' in entry && entry.route === '/management')
    expect(management).toBeUndefined()
  })

  it('does not swap navigation for retired concept routes', () => {
    routeMock.mockReturnValue({ path: '/concepts/ui075-operations/overview', meta: {}, query: {}, params: {} })
    const { navItems, isConceptRoute } = useNavigation()
    expect(isConceptRoute.value).toBe(false)
    expect(navItems.value.some((entry) => 'route' in entry && entry.route.startsWith('/concepts/'))).toBe(false)
  })

  it.each([
    ['viewer', 0],
    ['operator', 6],
    ['admin', 6],
  ] as const)('%s sees only Operations pages permitted by role', (role, expectedChildren) => {
    authState.user = { role }
    const { navItems } = useNavigation()
    const operations = navItems.value.find((entry) => 'children' in entry && entry.label === 'Operations')

    if (expectedChildren === 0) {
      expect(operations).toBeUndefined()
    } else {
      expect(operations && 'children' in operations ? operations.children : []).toHaveLength(expectedChildren)
    }
  })
})
