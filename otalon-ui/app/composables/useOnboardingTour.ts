import { computed, ref } from 'vue'

export const ONBOARDING_TOUR_STORAGE_KEY = 'cd-onboarding-tour:v1'

export interface OnboardingTourStep {
  id: string
  title: string
  description: string
  guidance: string
  target: string
  visual: string
  route?: string
}

export const ONBOARDING_TOUR_STEPS: readonly OnboardingTourStep[] = [
  {
    id: 'dashboard',
    title: 'Dashboard',
    description: 'Your operational overview: health, traffic, assets, and current anomaly volume.',
    guidance:
      'Use the time toolbar to compare a quiet baseline with a live incident window. Widget layout and font size are saved per operator.',
    visual: 'dashboard',
    target: '.time-toolbar-page',
    route: '/dashboard',
  },
  {
    id: 'alarms',
    title: 'Alarms',
    description: 'The alarm queue turns detections into an investigation worklist.',
    guidance:
      'Select a group to inspect evidence, affected features, and confirmation state. Confirm only after reviewing the supporting timeseries.',
    visual: 'alarms',
    target: '[aria-label="Alarms"]',
    route: '/alarms',
  },
  {
    id: 'assets',
    title: 'Assets',
    description: 'Assets are discovered devices and interfaces available for analysis.',
    guidance: 'Use filters and row selection to move from an asset to its connection, MAC, or protocol telemetry.',
    visual: 'assets',
    target: '[aria-label="Assets"]',
    route: '/devices',
  },
  {
    id: 'scan',
    title: 'Active scan',
    description: 'Active scans add current reachability and service evidence to an asset.',
    guidance: 'Choose a small target set first. Scan results remain linked to the asset history for later comparison.',
    visual: 'scan',
    target: '[aria-label="Assets"]',
    route: '/devices',
  },
  {
    id: 'chat',
    title: 'AI Assistant',
    description: 'The assistant provides read-only investigation help alongside the console.',
    guidance: 'Ask for summaries or evidence paths. It cannot change detection settings or mutate operator data.',
    visual: 'chat',
    target: '.sidebar-chat-slot',
  },
  {
    id: 'operations',
    title: 'Operations',
    description: 'Operations exposes service readiness, capture sources, jobs, and detection controls.',
    guidance:
      'Start with Overview when triaging platform health, then use Jobs and Data Sources for execution evidence.',
    visual: 'operations',
    target: '.page-title',
    route: '/operations/overview',
  },
]

const isOpen = ref(false)
const hasCompleted = ref(false)
const currentIndex = ref(0)
const activeRoute = ref('/dashboard')

const TOUR_STATE_ENDPOINT = '/api/v1/dashboard/tour'

interface TourStatePayload {
  completed: boolean
}

let loadSequence = 0

export const PAGE_TOUR_STEPS: Record<string, readonly OnboardingTourStep[]> = {
  '/dashboard': ONBOARDING_TOUR_STEPS.filter((step) => step.id === 'dashboard'),
  '/alarms': ONBOARDING_TOUR_STEPS.filter((step) => step.id === 'alarms'),
  '/devices': ONBOARDING_TOUR_STEPS.filter((step) => step.id === 'assets' || step.id === 'scan'),
  '/operations/overview': ONBOARDING_TOUR_STEPS.filter((step) => step.id === 'operations'),
  '/connections': [
    {
      id: 'connections-toolbar',
      title: 'Connection telemetry',
      description: 'The time toolbar and Alarm Filter narrow connection traffic to an investigation window.',
      guidance:
        'Adjust the time range, then use Alarm Filter to isolate connection series affected by a selected alarm group.',
      visual: 'connections',
      target: '.time-toolbar-page',
    },
    {
      id: 'connections-selector',
      title: 'Select a connection',
      description:
        'The left Connection Selector Table lists profiled connection series; the right panel shows their feature plots.',
      guidance:
        'Select a UCI in the table to load its cadence lane and feature grid, then use Display settings to control visible features and plot density.',
      visual: 'connections',
      target: '.connections-splitter',
    },
  ],
  '/mac-timeseries': [
    {
      id: 'mac-timeseries',
      title: 'MAC timeseries',
      description: 'MAC address telemetry is selected on the left and rendered as feature plots on the right.',
      guidance:
        'Choose a MAC row, review its cadence lane and MAC traffic features, and use Display settings for visible features and table columns.',
      visual: 'assets',
      target: '.mac-timeseries-splitter',
    },
  ],
  '/proto-timeseries': [
    {
      id: 'proto-timeseries',
      title: 'Protocol timeseries',
      description: 'Protocol telemetry is selected on the left and plotted by protocol identity on the right.',
      guidance:
        'Select a protocol, inspect its protocol traffic cadence and feature plots, and use Display settings to tune the visible series.',
      visual: 'assets',
      target: '.proto-timeseries-splitter',
    },
  ],
  '/operations/detection': [
    {
      id: 'detection-bounds',
      title: 'Bound Review',
      description: 'Bound Review turns NoBounds and BoundViolation series into a review queue.',
      guidance:
        'Use the state, module, and feature filters to focus review, open a series for evidence, and use Display Settings to control the review view.',
      visual: 'operations',
      target: '[data-test="detection-command-bar"]',
    },
    {
      id: 'detection-rhythm',
      title: 'Cadence Review',
      description: 'Cadence Review exposes cadence anomalies and their affected series in a dedicated review table.',
      guidance:
        'Switch to Cadence Review, filter the fleet table, select a series, and inspect the cadence evidence before applying a correction.',
      visual: 'operations',
      target: '[data-test="tab-rhythm"]',
    },
  ],
}

function routeKey(route: string): string {
  return route.split(/[?#]/, 1)[0] || '/dashboard'
}

function storageState(): Record<string, boolean> {
  if (typeof window === 'undefined') return {}
  try {
    const parsed: unknown = JSON.parse(window.localStorage.getItem(ONBOARDING_TOUR_STORAGE_KEY) ?? '{}')
    return parsed && typeof parsed === 'object' ? (parsed as Record<string, boolean>) : {}
  } catch {
    return {}
  }
}

/**
 * Whether the legacy localStorage cache indicates a completed tour.
 *
 * The cache is a READ-side fallback only (server state wins on load).
 * A completed cache is either the legacy literal string `completed`
 * (pre-global-flag seeding shape) or any per-route object with at
 * least one `true` entry.
 */
function cacheIndicatesCompleted(): boolean {
  if (typeof window === 'undefined') return false
  let raw: string | null = null
  try {
    raw = window.localStorage.getItem(ONBOARDING_TOUR_STORAGE_KEY)
  } catch {
    return false
  }
  if (raw === null) return false
  if (raw === 'completed') return true
  try {
    const parsed: unknown = JSON.parse(raw)
    if (parsed !== null && typeof parsed === 'object' && !Array.isArray(parsed)) {
      return Object.values(parsed as Record<string, unknown>).some((value) => value === true)
    }
  } catch {
    /* non-JSON value: only the literal 'completed' string counts */
  }
  return false
}

/**
 * Global onboarding-tour state, one completion flag per account.
 *
 * Server-first via `GET/PUT /api/v1/dashboard/tour`; the legacy localStorage
 * key `cd-onboarding-tour:v1` stays as a read-side cache merged by OR.
 *
 * @example
 * ```ts
 * const tour = useOnboardingTour()
 * await tour.setRoute(route.path)
 * if (!tour.hasCompleted.value) tour.open()
 * ```
 */
export function useOnboardingTour() {
  const steps = computed(
    () =>
      PAGE_TOUR_STEPS[activeRoute.value] ?? [
        {
          id: activeRoute.value,
          title: 'Getting Started',
          description: 'Key controls for this workspace page.',
          guidance: 'Use highlighted controls to inspect data and take the next operator action.',
          visual: 'operations',
          target: '.page-title',
        },
      ],
  )
  const currentStep = computed<OnboardingTourStep>(() => steps.value[currentIndex.value] ?? steps.value[0]!)
  const isLastStep = computed(() => currentIndex.value === steps.value.length - 1)

  /**
   * Load the global tour-completion flag.
   *
   * Merges the server state (`GET /api/v1/dashboard/tour`) with the legacy
   * localStorage cache by OR: completion is global per account, so any
   * recorded completion (server, legacy literal `completed`, or any
   * per-route `true`) suppresses the tour everywhere. The cache value is
   * applied synchronously; the server value closes an open dialog once it
   * resolves. Server fetch failures are non-fatal (offline or Playwright
   * contexts with a mocked backend decide from the cache alone).
   */
  async function load(): Promise<void> {
    if (typeof window === 'undefined') return
    const fromCache = cacheIndicatesCompleted()
    hasCompleted.value = hasCompleted.value || fromCache
    const requestId = ++loadSequence
    try {
      const remote = await $fetch<TourStatePayload>(TOUR_STATE_ENDPOINT)
      if (requestId !== loadSequence) return
      if (remote && typeof remote.completed === 'boolean') {
        hasCompleted.value = hasCompleted.value || remote.completed
      }
    } catch {
      /* non-fatal: server unreachable or unmocked */
    }
    if (hasCompleted.value) isOpen.value = false
  }

  /**
   * Mark the tour completed globally and sync to the server.
   *
   * Keeps the legacy per-route localStorage write shape (a superset merge)
   * so seeded caches and the offline fallback stay effective, and fires
   * `PUT /api/v1/dashboard/tour` with `{"completed": true}`. The server
   * write failure is non-fatal (the cache holds the offline copy).
   */
  function complete(): void {
    hasCompleted.value = true
    isOpen.value = false
    if (typeof window !== 'undefined') {
      window.localStorage.setItem(
        ONBOARDING_TOUR_STORAGE_KEY,
        JSON.stringify({ ...storageState(), [routeKey(activeRoute.value)]: true }),
      )
    }
    void pushCompletedToServer()
  }

  async function pushCompletedToServer(): Promise<void> {
    try {
      await $fetch<TourStatePayload>(TOUR_STATE_ENDPOINT, { method: 'PUT', body: { completed: true } })
    } catch {
      /* non-fatal: localStorage holds the offline cache */
    }
  }

  function open(): void {
    currentIndex.value = 0
    isOpen.value = true
  }

  /**
   * Switch the active route context.
   *
   * Completion is global: an incomplete route no longer re-opens the tour
   * once it was completed or skipped anywhere.
   */
  async function setRoute(route: string): Promise<void> {
    activeRoute.value = routeKey(route)
    currentIndex.value = 0
    await load()
    if (hasCompleted.value) isOpen.value = false
  }

  function dismiss(): void {
    complete()
  }

  function next(): void {
    if (isLastStep.value) {
      complete()
      return
    }
    currentIndex.value += 1
  }

  function previous(): void {
    if (currentIndex.value > 0) currentIndex.value -= 1
  }

  return {
    currentIndex,
    currentStep,
    dismiss,
    hasCompleted,
    isLastStep,
    isOpen,
    load,
    next,
    open,
    previous,
    setRoute,
    steps,
  }
}
