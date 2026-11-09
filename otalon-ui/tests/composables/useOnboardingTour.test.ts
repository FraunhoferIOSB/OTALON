import { beforeEach, describe, expect, it } from 'vitest'
import { http, HttpResponse } from 'msw'
import {
  ONBOARDING_TOUR_STORAGE_KEY,
  ONBOARDING_TOUR_STEPS,
  PAGE_TOUR_STEPS,
  useOnboardingTour,
} from '~/composables/useOnboardingTour'
import { server } from '../mocks/server'

describe('useOnboardingTour', () => {
  beforeEach(() => {
    window.localStorage.clear()
    const tour = useOnboardingTour()
    tour.dismiss()
    window.localStorage.clear()
    tour.isOpen.value = false
    tour.hasCompleted.value = false
    tour.currentIndex.value = 0
  })

  it('opens on first run and persists dismissal', async () => {
    const tour = useOnboardingTour()
    await tour.load()
    expect(tour.hasCompleted.value).toBe(false)
    tour.open()
    tour.dismiss()
    expect(tour.isOpen.value).toBe(false)
    expect(JSON.parse(window.localStorage.getItem(ONBOARDING_TOUR_STORAGE_KEY) ?? '{}')).toEqual({ '/dashboard': true })
  })

  it('walks through all production areas and can be reopened', () => {
    const tour = useOnboardingTour()
    tour.open()
    for (let index = 0; index < ONBOARDING_TOUR_STEPS.length; index += 1) tour.next()
    expect(tour.hasCompleted.value).toBe(true)
    tour.open()
    expect(tour.currentStep.value.title).toBe('Dashboard')
    expect(ONBOARDING_TOUR_STEPS.map((step) => step.title)).toContain('Dashboard')
  })

  it('treats completion as one global flag: skip on one page ends the tour everywhere', async () => {
    const tour = useOnboardingTour()
    await tour.setRoute('/alarms')
    tour.open()
    tour.dismiss()
    await tour.setRoute('/connections')
    expect(tour.hasCompleted.value).toBe(true)
    expect(tour.isOpen.value).toBe(false)
    expect(tour.steps.value).toHaveLength(2)
  })

  it('normalizes route URLs before reading and writing completion', async () => {
    const tour = useOnboardingTour()
    await tour.setRoute('/connections?window=24h')
    tour.dismiss()
    await tour.setRoute('/connections')
    expect(tour.hasCompleted.value).toBe(true)
    expect(PAGE_TOUR_STEPS['/operations/detection']?.map((step) => step.title)).toEqual([
      'Bound Review',
      'Cadence Review',
    ])
  })

  describe('global cache merge (OR)', () => {
    it('legacy literal "completed" string counts as completed', async () => {
      window.localStorage.setItem(ONBOARDING_TOUR_STORAGE_KEY, 'completed')
      const tour = useOnboardingTour()
      await tour.load()
      expect(tour.hasCompleted.value).toBe(true)
    })

    it('per-route object with any true entry counts as completed', async () => {
      window.localStorage.setItem(ONBOARDING_TOUR_STORAGE_KEY, JSON.stringify({ '/operations/detection': true }))
      const tour = useOnboardingTour()
      await tour.load()
      expect(tour.hasCompleted.value).toBe(true)
    })

    it('per-route object without a true entry stays incomplete', async () => {
      window.localStorage.setItem(ONBOARDING_TOUR_STORAGE_KEY, JSON.stringify({ '/dashboard': false }))
      const tour = useOnboardingTour()
      await tour.load()
      expect(tour.hasCompleted.value).toBe(false)
    })

    it('server completion wins over empty localStorage', async () => {
      server.use(http.get('*/api/v1/dashboard/tour', () => HttpResponse.json({ completed: true })))
      const tour = useOnboardingTour()
      await tour.load()
      expect(tour.hasCompleted.value).toBe(true)
    })

    it('server completion wins over empty localStorage on setRoute and closes an open dialog', async () => {
      server.use(http.get('*/api/v1/dashboard/tour', () => HttpResponse.json({ completed: true })))
      const tour = useOnboardingTour()
      tour.open()
      expect(tour.isOpen.value).toBe(true)
      await tour.setRoute('/alarms')
      expect(tour.hasCompleted.value).toBe(true)
      expect(tour.isOpen.value).toBe(false)
    })
  })

  describe('server sync failure is non-fatal', () => {
    it('load decides from the cache when the tour endpoint fails', async () => {
      server.use(http.get('*/api/v1/dashboard/tour', () => HttpResponse.json({ detail: 'boom' }, { status: 500 })))
      window.localStorage.setItem(ONBOARDING_TOUR_STORAGE_KEY, 'completed')
      const tour = useOnboardingTour()
      await expect(tour.load()).resolves.not.toThrow()
      expect(tour.hasCompleted.value).toBe(true)
    })

    it('load stays incomplete on server failure with an empty cache', async () => {
      server.use(
        http.get('*/api/v1/dashboard/tour', () => HttpResponse.json({ detail: 'unavailable' }, { status: 503 })),
      )
      const tour = useOnboardingTour()
      await expect(tour.load()).resolves.not.toThrow()
      expect(tour.hasCompleted.value).toBe(false)
    })

    it('complete() swallows a failing PUT and keeps the local completion', async () => {
      server.use(http.put('*/api/v1/dashboard/tour', () => HttpResponse.json({ detail: 'boom' }, { status: 500 })))
      const tour = useOnboardingTour()
      tour.open()
      tour.dismiss()
      expect(tour.hasCompleted.value).toBe(true)
      expect(tour.isOpen.value).toBe(false)
    })
  })

  it('complete() fires PUT /api/v1/dashboard/tour with completed true', async () => {
    let captured: unknown = null
    server.use(
      http.put('*/api/v1/dashboard/tour', async ({ request }) => {
        captured = await request.json()
        return HttpResponse.json({ completed: true })
      }),
    )
    const tour = useOnboardingTour()
    await tour.setRoute('/alarms')
    tour.dismiss()
    await new Promise((resolve) => setTimeout(resolve, 50))
    expect(captured).toEqual({ completed: true })
  })
})
