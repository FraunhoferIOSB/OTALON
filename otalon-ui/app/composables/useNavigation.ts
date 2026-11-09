import { useAuthStore } from '~/stores/authStore'
import type { ProductUserRole } from '~/types/identity'

/**
 * Composable for navigation items and active route detection.
 *
 * Provides the sidebar navigation structure with icons, labels,
 * and routes for all application pages.
 */

export interface NavigationItem {
  icon: string
  label: string
  route: string
  minimumRole?: ProductUserRole
}

export interface NavigationGroup {
  icon: string
  label: string
  children: NavigationItem[]
}

export type NavigationEntry = NavigationItem | NavigationGroup

export const DOMAIN_ICONS = {
  assets: 'devices',
  connections: 'cable',
  protocols: 'layers',
} as const

export function isNavigationItem(entry: NavigationEntry): entry is NavigationItem {
  return 'route' in entry
}

export function isNavigationGroup(entry: NavigationEntry): entry is NavigationGroup {
  return 'children' in entry
}

const OPERATIONS_GROUP: NavigationGroup = {
  icon: 'admin_panel_settings',
  label: 'Operations',
  children: [
    { icon: 'monitor_heart', label: 'Overview', route: '/operations/overview', minimumRole: 'operator' },
    { icon: 'cloud_upload', label: 'Data Sources', route: '/operations/data-sources', minimumRole: 'operator' },
    { icon: 'psychology', label: 'Detection & Training', route: '/operations/detection', minimumRole: 'operator' },
    { icon: 'work_history', label: 'Jobs & History', route: '/operations/jobs', minimumRole: 'operator' },
    { icon: 'tune', label: 'Configuration', route: '/operations/configuration', minimumRole: 'operator' },
    { icon: 'engineering', label: 'System', route: '/operations/system', minimumRole: 'operator' },
  ],
}

const DEFAULT_NAV_ITEMS: NavigationEntry[] = [
  { icon: 'dashboard', label: 'Dashboard', route: '/dashboard' },
  { icon: 'warning', label: 'Alarms', route: '/alarms' },
  { icon: DOMAIN_ICONS.assets, label: 'Assets', route: '/devices' },
  { icon: 'hub', label: 'Topology', route: '/topology' },
  {
    icon: 'area_chart',
    label: 'Timeseries Data',
    children: [
      { icon: DOMAIN_ICONS.connections, label: 'Connections', route: '/connections' },
      { icon: DOMAIN_ICONS.assets, label: 'Assets', route: '/mac-timeseries' },
      { icon: DOMAIN_ICONS.protocols, label: 'Protocols', route: '/proto-timeseries' },
    ],
  },
  OPERATIONS_GROUP,
]

/**
 * Provide navigation items and active route detection.
 *
 * @returns Object with navigation items, isActive, and isGroupActive helpers.
 */
export function useNavigation() {
  const route = useRoute()
  const auth = useAuthStore()

  const roleOrder: Record<ProductUserRole, number> = { viewer: 0, operator: 1, admin: 2 }
  const canAccess = (item: NavigationItem): boolean => {
    if (!item.minimumRole) return true
    const role = auth.user?.role
    return role !== undefined && roleOrder[role] >= roleOrder[item.minimumRole]
  }

  const isConceptRoute = computed(() => false)
  const navItems = computed(() =>
    DEFAULT_NAV_ITEMS.flatMap((entry) => {
      if (!isNavigationGroup(entry)) return canAccess(entry) ? [entry] : []
      const children = entry.children.filter(canAccess)
      return children.length > 0 ? [{ ...entry, children }] : []
    }),
  )

  function isActive(item: NavigationItem): boolean {
    return route.path === item.route
  }

  function isGroupActive(group: NavigationGroup): boolean {
    return group.children.some((child) => route.path === child.route)
  }

  return {
    navItems,
    isActive,
    isGroupActive,
    isConceptRoute,
  }
}
