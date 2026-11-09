/**
 * Tests for the shared frequency store.
 *
 * The store is a singleton consumed by three pages (connections,
 * Assets, Protocols). Its contract is therefore as much about NOT
 * leaking one page's state into another as it is about fetching:
 * `module` must travel with `seriesId`, `matches()` must gate rendering,
 * and a late response must never overwrite a newer selection.
 */
import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'

import { useFrequencyStore } from '~/stores/frequencyStore'
import type { FrequencyProfileResponse } from '~/types/api'

function makeProfile(overrides: Partial<FrequencyProfileResponse> = {}): FrequencyProfileResponse {
  return {
    module: 'conn',
    series_id: 'series-a',
    state: 'normal',
    has_profile: true,
    mean_interval_seconds: 5,
    std_interval_seconds: 0.4,
    tolerance_factor: { value: 2, source: 'global_default', override: null, global_default: 2 },
    absence_factor: { value: 3, source: 'global_default', override: null, global_default: 3 },
    last_seen: '2026-07-26T09:59:55+00:00',
    trained_at: '2026-07-24T01:11:35+00:00',
    now: '2026-07-26T10:00:00+00:00',
    absence_deadline: '2026-07-26T10:00:10+00:00',
    absence_timeout_seconds: 15,
    seconds_until_deadline: 10,
    seconds_since_last_seen: 5,
    active_anomaly_type: null,
    active_anomaly_since: null,
    ...overrides,
  }
}

const fetchMock = vi.fn()

beforeEach(() => {
  setActivePinia(createPinia())
  fetchMock.mockReset()
  vi.stubGlobal('$fetch', fetchMock)
})

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('useFrequencyStore', () => {
  describe('module travels with the series', () => {
    it('sends the requested module to the API', async () => {
      fetchMock.mockResolvedValue(makeProfile({ module: 'mac_traffic' }))
      const store = useFrequencyStore()

      await store.fetchProfile('01:80:c2:00:00:0e', 'mac_traffic')

      expect(fetchMock).toHaveBeenCalledWith('/api/v1/frequency/profile', {
        params: { uci: '01:80:c2:00:00:0e', module: 'mac_traffic' },
      })
    })

    it('defaults to the conn module', async () => {
      fetchMock.mockResolvedValue(makeProfile())
      const store = useFrequencyStore()

      await store.fetchProfile('series-a')

      expect(fetchMock.mock.calls[0]![1].params.module).toBe('conn')
    })

    it('records the module alongside the loaded series', async () => {
      fetchMock.mockResolvedValue(makeProfile({ module: 'proto_traffic' }))
      const store = useFrequencyStore()

      await store.fetchProfile('36545455', 'proto_traffic')

      expect(store.module).toBe('proto_traffic')
      expect(store.seriesId).toBe('36545455')
    })
  })

  describe('matches() gates cross-page rendering', () => {
    it('matches only the module AND series that were loaded', async () => {
      fetchMock.mockResolvedValue(makeProfile({ module: 'mac_traffic' }))
      const store = useFrequencyStore()
      await store.fetchProfile('01:80:c2:00:00:0e', 'mac_traffic')

      expect(store.matches('mac_traffic', '01:80:c2:00:00:0e')).toBe(true)
      // Same id, different module — the Assets page's state must not be
      // rendered by the Protocols page.
      expect(store.matches('proto_traffic', '01:80:c2:00:00:0e')).toBe(false)
      expect(store.matches('mac_traffic', 'other-mac')).toBe(false)
    })

    it('matches nothing while empty', () => {
      const store = useFrequencyStore()

      expect(store.matches('conn', null)).toBe(false)
      expect(store.matches('conn', 'series-a')).toBe(false)
    })

    it('reports the error state as belonging to the attempted series', async () => {
      fetchMock.mockRejectedValue({ status: 503 })
      const store = useFrequencyStore()

      await store.fetchProfile('series-a', 'conn')

      expect(store.matches('conn', 'series-a')).toBe(true)
      expect(store.profile).toBeNull()
      expect(store.error).toContain('Backend is unavailable')
    })
  })

  describe('clear() releases the shared state', () => {
    it('drops profile, series and module', async () => {
      fetchMock.mockResolvedValue(makeProfile({ module: 'mac_traffic' }))
      const store = useFrequencyStore()
      await store.fetchProfile('01:80:c2:00:00:0e', 'mac_traffic')

      store.clear()

      expect(store.profile).toBeNull()
      expect(store.seriesId).toBeNull()
      expect(store.module).toBeNull()
      expect(store.matches('mac_traffic', '01:80:c2:00:00:0e')).toBe(false)
    })

    it('clears when asked to fetch an empty series', async () => {
      fetchMock.mockResolvedValue(makeProfile())
      const store = useFrequencyStore()
      await store.fetchProfile('series-a', 'conn')

      await store.fetchProfile('', 'conn')

      expect(store.seriesId).toBeNull()
      expect(fetchMock).toHaveBeenCalledTimes(1)
    })

    it('stops an in-flight response from repopulating after clear', async () => {
      // Page unmount races the request it started: without the sequence
      // guard the resolved profile would land in a store the next page
      // is already using.
      let resolveFetch: ((value: FrequencyProfileResponse) => void) | undefined
      fetchMock.mockImplementation(
        () =>
          new Promise<FrequencyProfileResponse>((resolve) => {
            resolveFetch = resolve
          }),
      )
      const store = useFrequencyStore()

      const pending = store.fetchProfile('01:80:c2:00:00:0e', 'mac_traffic')
      store.clear()
      resolveFetch!(makeProfile({ module: 'mac_traffic' }))
      await pending

      expect(store.profile).toBeNull()
      expect(store.module).toBeNull()
      expect(store.isLoading).toBe(false)
    })
  })

  describe('late responses never win', () => {
    it('drops a slow first response when a second selection resolved first', async () => {
      const slow = makeProfile({ series_id: 'slow', module: 'mac_traffic' })
      const fast = makeProfile({ series_id: 'fast', module: 'proto_traffic' })
      let resolveSlow: ((value: FrequencyProfileResponse) => void) | undefined
      fetchMock
        .mockImplementationOnce(
          () =>
            new Promise<FrequencyProfileResponse>((resolve) => {
              resolveSlow = resolve
            }),
        )
        .mockResolvedValueOnce(fast)
      const store = useFrequencyStore()

      const slowPending = store.fetchProfile('slow', 'mac_traffic')
      await store.fetchProfile('fast', 'proto_traffic')
      resolveSlow!(slow)
      await slowPending

      expect(store.seriesId).toBe('fast')
      expect(store.module).toBe('proto_traffic')
      expect(store.profile?.series_id).toBe('fast')
    })

    it('drops a late failure so it cannot erase a newer profile', async () => {
      let rejectSlow: ((reason: unknown) => void) | undefined
      fetchMock
        .mockImplementationOnce(
          () =>
            new Promise((_resolve, reject) => {
              rejectSlow = reject
            }),
        )
        .mockResolvedValueOnce(makeProfile({ series_id: 'fast', module: 'proto_traffic' }))
      const store = useFrequencyStore()

      const slowPending = store.fetchProfile('slow', 'mac_traffic')
      await store.fetchProfile('fast', 'proto_traffic')
      rejectSlow!({ status: 500 })
      await slowPending

      expect(store.error).toBeNull()
      expect(store.profile?.series_id).toBe('fast')
    })
  })

  describe('a missing profile is a state, not an error', () => {
    it('stores no_profile without setting error', async () => {
      fetchMock.mockResolvedValue(makeProfile({ state: 'no_profile', has_profile: false }))
      const store = useFrequencyStore()

      await store.fetchProfile('series-a', 'conn')

      expect(store.error).toBeNull()
      expect(store.profile?.state).toBe('no_profile')
    })
  })
})
