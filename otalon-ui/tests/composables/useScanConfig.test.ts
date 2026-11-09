/**
 * Unit tests for the useScanConfig composable.
 *
 * Validates typed fetching of /api/v1/scans/interfaces and
 * /api/v1/scans/modules/{name}/schema via MSW.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { http, HttpResponse } from 'msw'

import { server } from '../mocks/server'

vi.stubGlobal('useRuntimeConfig', () => ({ public: {} }))

const { useScanConfig } = await import('~/composables/useScanConfig')

describe('useScanConfig', () => {
  beforeEach(() => {
    server.resetHandlers()
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  describe('fetchInterfaces()', () => {
    it('returns a typed list of scan interfaces', async () => {
      server.use(
        http.get('*/api/v1/scans/interfaces', () => {
          return HttpResponse.json({
            interfaces: [
              {
                name: 'enp4s0',
                ipv4: '192.168.0.5',
                subnet: '192.168.0.0/24',
                is_up: true,
                role: 'active_scan',
                mac: 'aa:bb:cc:dd:ee:ff',
                is_default: false,
              },
              {
                name: 'enp5s0',
                ipv4: null,
                subnet: null,
                is_up: true,
                role: 'mirror',
                mac: 'aa:bb:cc:dd:ee:00',
                is_default: false,
              },
            ],
          })
        }),
      )

      const { fetchInterfaces } = useScanConfig()
      const result = await fetchInterfaces()

      expect(result).toHaveLength(2)
      expect(result[0].name).toBe('enp4s0')
      expect(result[0].role).toBe('active_scan')
      expect(result[1].role).toBe('mirror')
    })

    it('propagates errors as ApiError on failure', async () => {
      server.use(
        http.get('*/api/v1/scans/interfaces', () => {
          return HttpResponse.json({ detail: 'upstream unreachable' }, { status: 502 })
        }),
      )

      const { fetchInterfaces } = useScanConfig()
      await expect(fetchInterfaces()).rejects.toMatchObject({ status: 502 })
    })
  })

  describe('fetchModuleSchema()', () => {
    it('returns accepted_keys and requires_auth for a known module', async () => {
      server.use(
        http.get('*/api/v1/scans/modules/port_scan/schema', () => {
          return HttpResponse.json({
            module: 'port_scan',
            accepted_keys: [
              { key: 'target_ip', type: 'str', required: true, description: '' },
              { key: 'port_range', type: 'str', required: true, description: '' },
              { key: 'timing_template', type: 'str', required: false, description: '' },
            ],
            requires_auth: false,
            extensible: false,
          })
        }),
      )

      const { fetchModuleSchema } = useScanConfig()
      const result = await fetchModuleSchema('port_scan')

      expect(result.accepted_keys.map((k) => k.key)).toContain('target_ip')
      expect(result.requires_auth).toBe(false)
    })

    it('returns requires_auth true for snmp_scan', async () => {
      server.use(
        http.get('*/api/v1/scans/modules/snmp_scan/schema', () => {
          return HttpResponse.json({
            module: 'snmp_scan',
            accepted_keys: [
              { key: 'target_ip', type: 'str', required: true, description: '' },
              { key: 'network_interface', type: 'str', required: false, description: '' },
            ],
            requires_auth: true,
            extensible: false,
          })
        }),
      )

      const { fetchModuleSchema } = useScanConfig()
      const result = await fetchModuleSchema('snmp_scan')

      expect(result.requires_auth).toBe(true)
    })

    it('propagates 404 as ApiError for unknown modules', async () => {
      server.use(
        http.get('*/api/v1/scans/modules/unknown/schema', () => {
          return HttpResponse.json({ detail: 'module not found' }, { status: 404 })
        }),
      )

      const { fetchModuleSchema } = useScanConfig()
      await expect(fetchModuleSchema('unknown')).rejects.toMatchObject({ status: 404 })
    })
  })
})
