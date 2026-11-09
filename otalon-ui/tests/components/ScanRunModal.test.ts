/**
 * Unit tests for the ScanRunModal component (Variant C+).
 *
 * Validates module-rail rendering, heuristic pre-selection, per-module
 * structured-form prefill, the Form/JSON toggle with schema transparency,
 * client-side JSON-key validation, auth-placeholder visibility, power-user
 * prefs, POST to /api/v1/scans, SSE attach, modal reset, and edge-case
 * degradation.
 *
 * Uses MSW for modules / interfaces / schema / scans endpoints. EventSource
 * is stubbed so the SSE attach is observable but inert.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises } from '@vue/test-utils'
import { http, HttpResponse } from 'msw'

import { mountWithPlugins } from '../helpers/mount'
import { server } from '../mocks/server'

type EventSourceListener = (event: MessageEvent) => void

class MockEventSource {
  static instances: MockEventSource[] = []
  static CLOSED = 2

  url: string
  readyState = 0
  onopen: ((event: Event) => void) | null = null
  onerror: ((event: Event) => void) | null = null
  onmessage: ((event: MessageEvent) => void) | null = null
  private listeners: Map<string, EventSourceListener[]> = new Map()

  constructor(url: string) {
    this.url = url
    MockEventSource.instances.push(this)
  }

  addEventListener(type: string, listener: EventSourceListener): void {
    const existing = this.listeners.get(type) ?? []
    existing.push(listener)
    this.listeners.set(type, existing)
  }

  removeEventListener(): void {
    /* not exercised */
  }

  close(): void {
    this.readyState = 2
  }

  simulateMessage(type: string, data: unknown): void {
    const event = new MessageEvent(type, {
      data: typeof data === 'string' ? data : JSON.stringify(data),
    })
    const listeners = this.listeners.get(type) ?? []
    for (const listener of listeners) listener(event)
  }

  /** Drive the stream into the CLOSED state and fire its ``onerror``. */
  simulateClosedError(): void {
    this.readyState = MockEventSource.CLOSED
    this.onerror?.(new Event('error'))
  }
}

vi.stubGlobal('EventSource', MockEventSource)

const ScanRunModal = (await import('~/components/scan/ScanRunModal.vue')).default

function mountModal(options: Record<string, unknown> = {}) {
  return mountWithPlugins(ScanRunModal, {
    props: {
      modelValue: true,
      targetDevices: [deviceWith({ subnet: '192.168.0.0/24' })],
      ...options,
    },
  })
}

function deviceWith(opts: {
  id?: number
  ipv4?: string | null
  subnet?: string | null
  mac?: string | null
  primaryMac?: string | null
  ports?: { port: number; protocol: string; service?: string | null }[]
}) {
  return {
    id: opts.id ?? 42,
    vendor: null,
    device_family: null,
    device_type: null,
    description: null,
    article_number: null,
    device_role: null,
    firmware_version: null,
    primary_mac: opts.primaryMac ?? null,
    vulnerabilities: null,
    update_available: false,
    last_scan_at: null,
    notes: null,
    created_at: '2026-01-01T00:00:00Z',
    updated_at: null,
    interfaces: [
      {
        id: 1,
        mac_address: opts.mac ?? null,
        ipv4_address: opts.ipv4 ?? null,
        ipv6_address: null,
        subnet: opts.subnet ?? null,
        open_ports_summary: opts.ports ?? null,
        last_scan_at: null,
        notes: null,
      },
    ],
  }
}

describe('ScanRunModal', () => {
  beforeEach(() => {
    MockEventSource.instances = []
    localStorage.clear()
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  // ── Heuristic pre-selection ──────────────────────────────────────────

  describe('heuristic pre-selection', () => {
    it('selects opcua_discover when OPC-UA port 4840 is open', async () => {
      server.use(
        http.get('*/api/v1/modules', () =>
          HttpResponse.json({ modules: ['port_scan', 'opcua_discover', 'snmp_scan'] }),
        ),
        http.get('*/api/v1/scans/interfaces', () => HttpResponse.json({ interfaces: [] })),
      )
      const wrapper = mountModal({
        targetDevices: [deviceWith({ ipv4: '10.0.0.5', ports: [{ port: 4840, protocol: 'tcp' }] })],
      })
      await flushPromises()

      const railItems = wrapper.findAll('[data-testid="scan-modal-module-rail-item"]')
      expect(railItems.length).toBeGreaterThan(0)
      expect(wrapper.text()).toContain('opcua_discover')
    })

    it('selects snmp_scan when SNMP port 161 is open', async () => {
      server.use(
        http.get('*/api/v1/modules', () => HttpResponse.json({ modules: ['port_scan', 'snmp_scan'] })),
        http.get('*/api/v1/scans/interfaces', () => HttpResponse.json({ interfaces: [] })),
      )
      const wrapper = mountModal({
        targetDevices: [deviceWith({ ipv4: '10.0.0.6', ports: [{ port: 161, protocol: 'udp' }] })],
      })
      await flushPromises()

      expect(wrapper.text()).toContain('snmp_scan')
    })

    it('falls back to port_scan when no port signal', async () => {
      server.use(
        http.get('*/api/v1/modules', () => HttpResponse.json({ modules: ['port_scan', 'snmp_scan'] })),
        http.get('*/api/v1/scans/interfaces', () => HttpResponse.json({ interfaces: [] })),
      )
      const wrapper = mountModal({
        targetDevices: [deviceWith({ ipv4: '10.0.0.7', ports: [] })],
      })
      await flushPromises()

      expect(wrapper.text()).toContain('port_scan')
    })

    it('selects arp_scan for multi-target scan-all', async () => {
      server.use(
        http.get('*/api/v1/modules', () => HttpResponse.json({ modules: ['arp_scan', 'port_scan'] })),
        http.get('*/api/v1/scans/interfaces', () => HttpResponse.json({ interfaces: [] })),
      )
      const wrapper = mountModal({
        targetDevices: [deviceWith({ id: 1 }), deviceWith({ id: 2 })],
      })
      await flushPromises()

      expect(wrapper.text()).toContain('arp_scan')
    })

    it('recommends pn_discovery when PROFINET is present in subnet', async () => {
      server.use(
        http.get('*/api/v1/modules', () => HttpResponse.json({ modules: ['arp_scan', 'pn_discovery', 'port_scan'] })),
        http.get('*/api/v1/scans/interfaces', () => HttpResponse.json({ interfaces: [] })),
      )
      const wrapper = mountModal({
        targetDevices: [deviceWith({ id: 1 }), deviceWith({ id: 2 })],
        hasProfinetInSubnet: true,
      })
      await flushPromises()

      expect(wrapper.text()).toContain('pn_discovery')
    })

    it('reactively upgrades arp_scan → pn_discovery when the PROFINET signal arrives late', async () => {
      // UI-016 Cause 1: the parent fetches ``hasProfinetInSubnet`` async; for
      // passive-seeded L2 devices the signal may flip true AFTER the modal has
      // opened and modules have loaded. The recommendation must react to that
      // late change, not be frozen by a one-shot read at module-load time.
      server.use(
        http.get('*/api/v1/modules', () => HttpResponse.json({ modules: ['arp_scan', 'pn_discovery', 'port_scan'] })),
        http.get('*/api/v1/scans/interfaces', () => HttpResponse.json({ interfaces: [] })),
      )
      const wrapper = mountModal({
        targetDevices: [deviceWith({ id: 1 }), deviceWith({ id: 2 })],
        hasProfinetInSubnet: false,
      })
      await flushPromises()

      const vm = wrapper.vm as unknown as {
        recommendedModule: string | null
        selectedModule: string | null
      }
      // One-shot read at module-load saw no PROFINET → arp_scan.
      expect(vm.recommendedModule).toBe('arp_scan')
      expect(vm.selectedModule).toBe('arp_scan')

      // Signal arrives late (async topology fetch resolves).
      await wrapper.setProps({ hasProfinetInSubnet: true })
      await flushPromises()

      // Recommendation reacts and the auto-selection is upgraded.
      expect(vm.recommendedModule).toBe('pn_discovery')
      expect(vm.selectedModule).toBe('pn_discovery')
      expect(wrapper.text()).toContain('pn_discovery')
    })

    it('does not override an operator-chosen module when the PROFINET signal arrives late', async () => {
      // The reactive upgrade must only touch an auto-applied selection. If the
      // operator has manually picked a module, a late PROFINET signal updates
      // the recommendation badge but leaves their selection intact.
      server.use(
        http.get('*/api/v1/modules', () => HttpResponse.json({ modules: ['arp_scan', 'pn_discovery', 'port_scan'] })),
        http.get('*/api/v1/scans/interfaces', () => HttpResponse.json({ interfaces: [] })),
      )
      const wrapper = mountModal({
        targetDevices: [deviceWith({ id: 1 }), deviceWith({ id: 2 })],
        hasProfinetInSubnet: false,
      })
      await flushPromises()

      const vm = wrapper.vm as unknown as {
        recommendedModule: string | null
        selectedModule: string | null
        selectModule: (mod: string) => void
      }
      // Operator manually picks port_scan.
      vm.selectModule('port_scan')
      await flushPromises()
      expect(vm.selectedModule).toBe('port_scan')

      await wrapper.setProps({ hasProfinetInSubnet: true })
      await flushPromises()

      // Recommendation badge updates, but the manual selection is preserved.
      expect(vm.recommendedModule).toBe('pn_discovery')
      expect(vm.selectedModule).toBe('port_scan')
    })

    it('restricts module rail to subnet modules in multi-target mode', async () => {
      server.use(
        http.get('*/api/v1/modules', () =>
          HttpResponse.json({ modules: ['arp_scan', 'pn_discovery', 'port_scan', 'snmp_scan'] }),
        ),
        http.get('*/api/v1/scans/interfaces', () => HttpResponse.json({ interfaces: [] })),
      )
      const wrapper = mountModal({
        targetDevices: [deviceWith({ id: 1 }), deviceWith({ id: 2 })],
      })
      await flushPromises()

      const railItems = wrapper.findAll('[data-testid="scan-modal-module-rail-item"]')
      const labels = railItems.map((item) => item.text())
      expect(labels.some((l) => l.includes('arp_scan'))).toBe(true)
      expect(labels.some((l) => l.includes('pn_discovery'))).toBe(true)
      expect(labels.some((l) => l.includes('port_scan'))).toBe(false)
      expect(labels.some((l) => l.includes('snmp_scan'))).toBe(false)
    })
  })

  // ── Interface default selection ─────────────────────────────────────

  describe('interface selection', () => {
    it('defaults to active_scan role and excludes mirror role', async () => {
      server.use(
        http.get('*/api/v1/modules', () => HttpResponse.json({ modules: ['port_scan'] })),
        http.get('*/api/v1/scans/interfaces', () =>
          HttpResponse.json({
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
          }),
        ),
      )
      const wrapper = mountModal()
      await flushPromises()

      const vm = wrapper.vm as unknown as {
        interfaceNames: string[]
        activeInterfaceDefault: string | null
      }
      expect(vm.interfaceNames).toContain('enp4s0')
      expect(vm.interfaceNames).not.toContain('enp5s0')
      expect(vm.activeInterfaceDefault).toBe('enp4s0')
    })

    it('prefers the interface with is_default === true over first active_scan', async () => {
      server.use(
        http.get('*/api/v1/modules', () => HttpResponse.json({ modules: ['port_scan'] })),
        http.get('*/api/v1/scans/interfaces', () =>
          HttpResponse.json({
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
                ipv4: '192.168.0.6',
                subnet: '192.168.0.0/24',
                is_up: true,
                role: 'active_scan',
                mac: 'aa:bb:cc:dd:ee:00',
                is_default: true,
              },
            ],
          }),
        ),
      )
      const wrapper = mountModal()
      await flushPromises()

      const vm = wrapper.vm as unknown as {
        interfaceNames: string[]
        activeInterfaceDefault: string | null
      }
      expect(vm.interfaceNames).toContain('enp4s0')
      expect(vm.interfaceNames).toContain('enp5s0')
      expect(vm.activeInterfaceDefault).toBe('enp5s0')
    })

    it('prefers enp4s0 over an alphabetically-first Docker bridge (regression UI-025)', async () => {
      server.use(
        http.get('*/api/v1/modules', () => HttpResponse.json({ modules: ['port_scan'] })),
        http.get('*/api/v1/scans/interfaces', () =>
          HttpResponse.json({
            interfaces: [
              {
                name: 'br-40e435523024',
                ipv4: '10.20.0.1',
                subnet: '10.20.0.1/16',
                is_up: true,
                role: 'active_scan',
                mac: '82:e1:aa:ce:a3:1d',
                is_default: false,
              },
              {
                name: 'enp4s0',
                ipv4: '192.168.0.201',
                subnet: '192.168.0.201/24',
                is_up: true,
                role: 'active_scan',
                mac: 'cc:82:7f:a1:8a:36',
                is_default: true,
              },
            ],
          }),
        ),
      )
      const wrapper = mountModal()
      await flushPromises()

      const vm = wrapper.vm as unknown as {
        interfaceNames: string[]
        activeInterfaceDefault: string | null
      }
      expect(vm.interfaceNames).toContain('br-40e435523024')
      expect(vm.interfaceNames).toContain('enp4s0')
      expect(vm.activeInterfaceDefault).toBe('enp4s0')
    })

    it('falls back to the first active_scan when none is marked default', async () => {
      server.use(
        http.get('*/api/v1/modules', () => HttpResponse.json({ modules: ['port_scan'] })),
        http.get('*/api/v1/scans/interfaces', () =>
          HttpResponse.json({
            interfaces: [
              {
                name: 'enp4s0',
                ipv4: '192.168.0.5',
                subnet: '192.168.0.0/24',
                is_up: true,
                role: 'mirror',
                mac: 'aa:bb:cc:dd:ee:ff',
                is_default: false,
              },
              {
                name: 'enp5s0',
                ipv4: '192.168.0.6',
                subnet: '192.168.0.0/24',
                is_up: true,
                role: 'active_scan',
                mac: 'aa:bb:cc:dd:ee:00',
                is_default: false,
              },
              {
                name: 'eno1',
                ipv4: '192.168.0.7',
                subnet: '192.168.0.0/24',
                is_up: true,
                role: 'active_scan',
                mac: 'aa:bb:cc:dd:ee:11',
                is_default: false,
              },
            ],
          }),
        ),
      )
      const wrapper = mountModal()
      await flushPromises()

      const vm = wrapper.vm as unknown as {
        interfaceNames: string[]
        activeInterfaceDefault: string | null
      }
      expect(vm.interfaceNames).not.toContain('enp4s0')
      expect(vm.interfaceNames).toContain('enp5s0')
      expect(vm.interfaceNames).toContain('eno1')
      expect(vm.activeInterfaceDefault).toBe('enp5s0')
    })
  })

  // ── Form / JSON toggle + schema transparency ─────────────────────────

  describe('Form/JSON toggle & schema transparency', () => {
    it('toggles to JSON mode and renders accepted key chips', async () => {
      server.use(
        http.get('*/api/v1/modules', () => HttpResponse.json({ modules: ['port_scan'] })),
        http.get('*/api/v1/scans/interfaces', () => HttpResponse.json({ interfaces: [] })),
        http.get('*/api/v1/scans/modules/port_scan/schema', () =>
          HttpResponse.json({
            module: 'port_scan',
            accepted_keys: [
              { key: 'target_ip', type: 'str', required: true, description: '' },
              { key: 'port_range', type: 'str', required: true, description: '' },
            ],
            requires_auth: false,
            extensible: false,
          }),
        ),
      )
      localStorage.setItem('otalon-scan-prefs-v1', JSON.stringify({ alwaysJson: true }))
      const wrapper = mountModal({ targetDevices: [deviceWith({ ipv4: '10.0.0.1', ports: [] })] })
      await flushPromises()

      expect(wrapper.find('[data-testid="scan-modal-config-text"]').exists()).toBe(true)
      expect(wrapper.text()).toContain('target_ip')
    })

    it('flags an unknown JSON key with a clear message', async () => {
      server.use(
        http.get('*/api/v1/modules', () => HttpResponse.json({ modules: ['port_scan'] })),
        http.get('*/api/v1/scans/interfaces', () => HttpResponse.json({ interfaces: [] })),
        http.get('*/api/v1/scans/modules/port_scan/schema', () =>
          HttpResponse.json({
            module: 'port_scan',
            accepted_keys: [{ key: 'target_ip', type: 'str', required: true, description: '' }],
            requires_auth: false,
            extensible: false,
          }),
        ),
      )
      localStorage.setItem('otalon-scan-prefs-v1', JSON.stringify({ alwaysJson: true }))
      const wrapper = mountModal({ targetDevices: [deviceWith({ ipv4: '10.0.0.1', ports: [] })] })
      await flushPromises()

      const input = wrapper.find('[data-testid="scan-modal-config-text"]').find('input')
      await input.setValue('{ "target_ip": "1.2.3.4", "unknown_key": true }')
      await flushPromises()

      expect(wrapper.text().toLowerCase()).toContain('unknown')
    })

    it('flags SCAN-003 keys amber', async () => {
      server.use(
        http.get('*/api/v1/modules', () => HttpResponse.json({ modules: ['port_scan'] })),
        http.get('*/api/v1/scans/interfaces', () => HttpResponse.json({ interfaces: [] })),
        http.get('*/api/v1/scans/modules/port_scan/schema', () =>
          HttpResponse.json({
            module: 'port_scan',
            accepted_keys: [{ key: 'target_ip', type: 'str', required: true, description: '' }],
            requires_auth: false,
            extensible: false,
          }),
        ),
      )
      localStorage.setItem('otalon-scan-prefs-v1', JSON.stringify({ alwaysJson: true }))
      const wrapper = mountModal({ targetDevices: [deviceWith({ ipv4: '10.0.0.1', ports: [] })] })
      await flushPromises()

      const input = wrapper.find('[data-testid="scan-modal-config-text"]').find('input')
      await input.setValue('{ "target_ip": "1.2.3.4", "udp_scan": true }')
      await flushPromises()

      expect(wrapper.text().toLowerCase()).toContain('not yet configurable')
    })
  })

  // ── Auth placeholder visibility ──────────────────────────────────────

  describe('auth placeholder', () => {
    it('shows disabled placeholder for snmp_scan', async () => {
      server.use(
        http.get('*/api/v1/modules', () => HttpResponse.json({ modules: ['snmp_scan'] })),
        http.get('*/api/v1/scans/interfaces', () => HttpResponse.json({ interfaces: [] })),
        http.get('*/api/v1/scans/modules/snmp_scan/schema', () =>
          HttpResponse.json({
            module: 'snmp_scan',
            accepted_keys: [{ key: 'target_ip', type: 'str', required: true, description: '' }],
            requires_auth: true,
            extensible: false,
          }),
        ),
      )
      const wrapper = mountModal({ presetModule: 'snmp_scan' })
      await flushPromises()

      expect(wrapper.find('[data-testid="scan-modal-auth-placeholder"]').exists()).toBe(true)
    })

    it('shows anonymous note for opcua_discover', async () => {
      server.use(
        http.get('*/api/v1/modules', () => HttpResponse.json({ modules: ['opcua_discover'] })),
        http.get('*/api/v1/scans/interfaces', () => HttpResponse.json({ interfaces: [] })),
        http.get('*/api/v1/scans/modules/opcua_discover/schema', () =>
          HttpResponse.json({
            module: 'port_scan',
            accepted_keys: [{ key: 'target_ip', type: 'str', required: true, description: '' }],
            requires_auth: false,
            extensible: false,
          }),
        ),
      )
      const wrapper = mountModal({ presetModule: 'opcua_discover' })
      await flushPromises()

      expect(wrapper.find('[data-testid="scan-modal-auth-none"]').exists()).toBe(true)
    })
  })

  // ── Power-user prefs ─────────────────────────────────────────────────

  describe('power-user prefs', () => {
    it('showRecommendations OFF removes banner and pre-selection', async () => {
      localStorage.setItem('otalon-scan-prefs-v1', JSON.stringify({ showRecommendations: false }))
      server.use(
        http.get('*/api/v1/modules', () => HttpResponse.json({ modules: ['port_scan', 'opcua_discover'] })),
        http.get('*/api/v1/scans/interfaces', () => HttpResponse.json({ interfaces: [] })),
      )
      const wrapper = mountModal({
        targetDevices: [deviceWith({ ports: [{ port: 4840, protocol: 'tcp' }] })],
      })
      await flushPromises()

      expect(wrapper.find('[data-testid="scan-modal-recommendation-banner"]').exists()).toBe(false)
    })

    it('alwaysJson ON opens directly in JSON mode', async () => {
      localStorage.setItem('otalon-scan-prefs-v1', JSON.stringify({ alwaysJson: true }))
      server.use(
        http.get('*/api/v1/modules', () => HttpResponse.json({ modules: ['arp_scan'] })),
        http.get('*/api/v1/scans/interfaces', () => HttpResponse.json({ interfaces: [] })),
      )
      const wrapper = mountModal()
      await flushPromises()

      expect(wrapper.find('[data-testid="scan-modal-config-text"]').exists()).toBe(true)
    })

    it('expandAdvanced ON expands auth panel', async () => {
      localStorage.setItem('otalon-scan-prefs-v1', JSON.stringify({ expandAdvanced: true }))
      server.use(
        http.get('*/api/v1/modules', () => HttpResponse.json({ modules: ['snmp_scan'] })),
        http.get('*/api/v1/scans/interfaces', () => HttpResponse.json({ interfaces: [] })),
        http.get('*/api/v1/scans/modules/snmp_scan/schema', () =>
          HttpResponse.json({
            module: 'snmp_scan',
            accepted_keys: [{ key: 'target_ip', type: 'str', required: true, description: '' }],
            requires_auth: true,
            extensible: false,
          }),
        ),
      )
      const wrapper = mountModal({ presetModule: 'snmp_scan' })
      await flushPromises()

      expect(wrapper.find('[data-testid="scan-modal-auth-placeholder"]').exists()).toBe(true)
    })
  })

  // ── Edge cases ───────────────────────────────────────────────────────

  describe('edge cases', () => {
    it('device without IP still enables module selection', async () => {
      server.use(
        http.get('*/api/v1/modules', () => HttpResponse.json({ modules: ['opcua_discover'] })),
        http.get('*/api/v1/scans/interfaces', () => HttpResponse.json({ interfaces: [] })),
      )
      const wrapper = mountModal({
        targetDevices: [deviceWith({ ipv4: null, ports: [{ port: 4840, protocol: 'tcp' }] })],
      })
      await flushPromises()

      expect(wrapper.text()).toContain('opcua_discover')
      expect(wrapper.find('[data-testid="scan-modal-field-target_ip"]').exists()).toBe(true)
    })

    it('interface endpoint down shows warning but keeps scan startable', async () => {
      server.use(
        http.get('*/api/v1/modules', () => HttpResponse.json({ modules: ['arp_scan'] })),
        http.get('*/api/v1/scans/interfaces', () => HttpResponse.json({ detail: 'unreachable' }, { status: 502 })),
      )
      const wrapper = mountModal()
      await flushPromises()

      expect(wrapper.text().toLowerCase()).toContain('unavailable')
      expect(wrapper.find('[data-testid="scan-modal-start-btn"]').exists()).toBe(true)
    })

    it('no port signal falls back to port_scan and stays startable', async () => {
      server.use(
        http.get('*/api/v1/modules', () => HttpResponse.json({ modules: ['port_scan'] })),
        http.get('*/api/v1/scans/interfaces', () => HttpResponse.json({ interfaces: [] })),
      )
      const wrapper = mountModal({ targetDevices: [deviceWith({ ipv4: '10.0.0.8', ports: [] })] })
      await flushPromises()
      await flushPromises()

      expect(wrapper.text()).toContain('port_scan')
      expect(wrapper.find('[data-testid="scan-modal-start-btn"]').exists()).toBe(true)
    })

    it('invalid JSON key disables start button in JSON mode', async () => {
      server.use(
        http.get('*/api/v1/modules', () => HttpResponse.json({ modules: ['port_scan'] })),
        http.get('*/api/v1/scans/interfaces', () => HttpResponse.json({ interfaces: [] })),
        http.get('*/api/v1/scans/modules/port_scan/schema', () =>
          HttpResponse.json({
            module: 'port_scan',
            accepted_keys: [{ key: 'target_ip', type: 'str', required: true, description: '' }],
            requires_auth: false,
            extensible: false,
          }),
        ),
      )
      localStorage.setItem('otalon-scan-prefs-v1', JSON.stringify({ alwaysJson: true }))
      const wrapper = mountModal()
      await flushPromises()

      const input = wrapper.find('[data-testid="scan-modal-config-text"]').find('input')
      await input.setValue('{ "bad_key": 1 }')
      await flushPromises()

      expect(wrapper.find('[data-testid="scan-modal-start-btn"]').attributes('data-disabled')).toBe('true')
    })
  })

  // ── Start flow ───────────────────────────────────────────────────────

  describe('start flow', () => {
    it('POSTs the form overrides as JSON and emits started with the scan_id', async () => {
      let capturedBody: unknown = null
      server.use(
        http.get('*/api/v1/modules', () => HttpResponse.json({ modules: ['arp_scan'] })),
        http.get('*/api/v1/scans/interfaces', () => HttpResponse.json({ interfaces: [] })),
        http.post('*/api/v1/scans', async ({ request }) => {
          capturedBody = await request.json()
          return HttpResponse.json({
            scan_id: 'scan-xyz-1',
            run_id: 'run-xyz-1',
            module_name: 'arp_scan',
            status: 'running',
          })
        }),
      )

      const wrapper = mountModal()
      await flushPromises()

      const startBtn = wrapper.find('[data-testid="scan-modal-start-btn"]')
      await startBtn.trigger('click')
      await flushPromises()

      expect(capturedBody).toEqual({
        module_name: 'arp_scan',
        overrides: { target_subnet: '192.168.0.0/24' },
      })
      expect(wrapper.emitted('started')).toBeTruthy()
      expect(wrapper.emitted('started')?.[0]).toEqual(['scan-xyz-1'])

      const badge = wrapper.find('[data-testid="scan-modal-status-badge"]')
      expect(badge.exists()).toBe(true)
      expect(badge.text()).toBe('Running')
    })

    it('renders an upstream-error banner on a 4xx response and stays open', async () => {
      server.use(
        http.get('*/api/v1/modules', () => HttpResponse.json({ modules: ['arp_scan'] })),
        http.get('*/api/v1/scans/interfaces', () => HttpResponse.json({ interfaces: [] })),
        http.post('*/api/v1/scans', () => HttpResponse.json({ detail: 'invalid target_subnet' }, { status: 400 })),
      )

      const wrapper = mountModal()
      await flushPromises()

      await wrapper.find('[data-testid="scan-modal-start-btn"]').trigger('click')
      await flushPromises()

      const banner = wrapper.find('[data-testid="scan-modal-upstream-error"]')
      expect(banner.exists()).toBe(true)
      expect(banner.text()).toContain('invalid target_subnet')
      expect(MockEventSource.instances).toHaveLength(0)
      expect(wrapper.emitted('started')).toBeFalsy()
    })

    it('attaches SSE on success and emits finished on a terminal result event', async () => {
      server.use(
        http.get('*/api/v1/modules', () => HttpResponse.json({ modules: ['arp_scan'] })),
        http.get('*/api/v1/scans/interfaces', () => HttpResponse.json({ interfaces: [] })),
        http.post('*/api/v1/scans', () => HttpResponse.json({ scan_id: 'scan-abc', status: 'running' })),
      )

      const wrapper = mountModal()
      await flushPromises()

      await wrapper.find('[data-testid="scan-modal-start-btn"]').trigger('click')
      await flushPromises()

      expect(MockEventSource.instances).toHaveLength(1)
      const sse = MockEventSource.instances[0]
      expect(sse?.url).toBe('/api/v1/scans/scan-abc/events')

      sse?.simulateMessage('result', { module_name: 'arp_scan', status: 'completed' })
      await flushPromises()

      expect(wrapper.emitted('finished')).toBeTruthy()
      expect(wrapper.emitted('finished')?.[0]).toEqual(['scan-abc', 'completed'])
      const badge = wrapper.find('[data-testid="scan-modal-status-badge"]')
      expect(badge.text()).toBe('Completed')
    })

    it('infers failed status from an SSE error event', async () => {
      server.use(
        http.get('*/api/v1/modules', () => HttpResponse.json({ modules: ['arp_scan'] })),
        http.get('*/api/v1/scans/interfaces', () => HttpResponse.json({ interfaces: [] })),
        http.post('*/api/v1/scans', () => HttpResponse.json({ scan_id: 'scan-fail', status: 'running' })),
      )

      const wrapper = mountModal()
      await flushPromises()
      await wrapper.find('[data-testid="scan-modal-start-btn"]').trigger('click')
      await flushPromises()

      const sse = MockEventSource.instances[0]
      sse?.simulateMessage('error', { reason: 'upstream_disconnected' })
      await flushPromises()

      expect(wrapper.emitted('finished')?.[0]).toEqual(['scan-fail', 'failed'])
      const badge = wrapper.find('[data-testid="scan-modal-status-badge"]')
      expect(badge.text()).toBe('Failed')
    })

    it('L-01 safety net: resolves a stuck modal by polling the persisted scan record', async () => {
      // The SSE stream never delivers a terminal frame (simulating the
      // backend single-subscriber race). The watchdog poller must read the
      // persisted ``status=completed`` and transition the modal anyway.
      vi.useFakeTimers()
      try {
        server.use(
          http.get('*/api/v1/modules', () => HttpResponse.json({ modules: ['arp_scan'] })),
          http.get('*/api/v1/scans/interfaces', () => HttpResponse.json({ interfaces: [] })),
          http.post('*/api/v1/scans', () => HttpResponse.json({ scan_id: 'scan-stuck', status: 'running' })),
          http.get('*/api/v1/scans/scan-stuck', () =>
            HttpResponse.json({
              scan_id: 'scan-stuck',
              module: 'arp_scan',
              status: 'completed',
              finished_at: '2026-06-28T11:00:00Z',
            }),
          ),
        )

        const wrapper = mountModal()
        await vi.advanceTimersByTimeAsync(0)
        await flushPromises()

        await wrapper.find('[data-testid="scan-modal-start-btn"]').trigger('click')
        await flushPromises()
        await vi.advanceTimersByTimeAsync(0)

        expect(wrapper.find('[data-testid="scan-modal-status-badge"]').text()).toBe('Running')

        // No terminal SSE frame is delivered; advance past one watchdog tick.
        await vi.advanceTimersByTimeAsync(4100)
        await flushPromises()
        await vi.advanceTimersByTimeAsync(0)
        await flushPromises()

        expect(wrapper.emitted('finished')?.[0]).toEqual(['scan-stuck', 'completed'])
        expect(wrapper.find('[data-testid="scan-modal-status-badge"]').text()).toBe('Completed')
      } finally {
        vi.useRealTimers()
      }
    })

    it('prefills the OT preset port range visibly for port_scan', async () => {
      server.use(
        http.get('*/api/v1/modules', () => HttpResponse.json({ modules: ['port_scan'] })),
        http.get('*/api/v1/scans/interfaces', () => HttpResponse.json({ interfaces: [] })),
        http.get('*/api/v1/scans/modules/port_scan/schema', () =>
          HttpResponse.json({
            module: 'port_scan',
            accepted_keys: [
              { key: 'target_ip', type: 'str', required: true, description: '' },
              { key: 'port_range', type: 'str', required: true, description: '' },
            ],
            requires_auth: false,
            extensible: false,
          }),
        ),
      )
      const wrapper = mountModal({ targetDevices: [deviceWith({ ipv4: '10.0.0.1', ports: [] })] })
      await flushPromises()

      const input = wrapper.find('[data-testid="scan-modal-field-port_range"]').find('input')
      expect(input.element.value).toContain('4840')
    })

    it('sends the full OT preset in the port_scan start payload', async () => {
      let capturedBody: unknown = null
      server.use(
        http.get('*/api/v1/modules', () => HttpResponse.json({ modules: ['port_scan'] })),
        http.get('*/api/v1/scans/interfaces', () => HttpResponse.json({ interfaces: [] })),
        http.get('*/api/v1/scans/modules/port_scan/schema', () =>
          HttpResponse.json({
            module: 'port_scan',
            accepted_keys: [
              { key: 'target_ip', type: 'str', required: true, description: '' },
              { key: 'port_range', type: 'str', required: true, description: '' },
            ],
            requires_auth: false,
            extensible: false,
          }),
        ),
        http.post('*/api/v1/scans', async ({ request }) => {
          capturedBody = await request.json()
          return HttpResponse.json({ scan_id: 'scan-ps-1', status: 'running' })
        }),
      )
      const wrapper = mountModal({ targetDevices: [deviceWith({ ipv4: '10.0.0.1', ports: [] })] })
      await flushPromises()

      await wrapper.find('[data-testid="scan-modal-start-btn"]').trigger('click')
      await flushPromises()

      const body = capturedBody as Record<string, unknown>
      expect(body.module_name).toBe('port_scan')
      expect((body.overrides as Record<string, unknown>).target_ip).toBe('10.0.0.1')
      expect((body.overrides as Record<string, unknown>).port_range).toContain('4840')
      expect((body.overrides as Record<string, unknown>).timing_template).toBe('3')
    })

    it('prefills target_port 4840 visibly for opcua_discover', async () => {
      server.use(
        http.get('*/api/v1/modules', () => HttpResponse.json({ modules: ['opcua_discover'] })),
        http.get('*/api/v1/scans/interfaces', () => HttpResponse.json({ interfaces: [] })),
        http.get('*/api/v1/scans/modules/opcua_discover/schema', () =>
          HttpResponse.json({
            module: 'opcua_discover',
            accepted_keys: [
              { key: 'target_ip', type: 'str', required: true, description: '' },
              { key: 'target_port', type: 'int', required: false, description: '' },
            ],
            requires_auth: false,
            extensible: false,
          }),
        ),
      )
      const wrapper = mountModal({ presetModule: 'opcua_discover', targetDevices: [deviceWith({ ipv4: '10.0.0.1' })] })
      await flushPromises()

      const input = wrapper.find('[data-testid="scan-modal-field-target_port"]').find('input')
      expect(input.element.value).toBe('4840')
    })

    // ── P8 Welle E (F-11): single-asset parameter targeting ──────────

    it('prefills arp_scan with the device IP as /32 for a single asset', async () => {
      let capturedBody: unknown = null
      server.use(
        http.get('*/api/v1/modules', () => HttpResponse.json({ modules: ['arp_scan'] })),
        http.get('*/api/v1/scans/interfaces', () => HttpResponse.json({ interfaces: [] })),
        http.post('*/api/v1/scans', async ({ request }) => {
          capturedBody = await request.json()
          return HttpResponse.json({ scan_id: 'scan-arp-1', status: 'running' })
        }),
      )
      const wrapper = mountModal({
        targetDevices: [deviceWith({ ipv4: '192.168.0.42', subnet: '192.168.0.0/24' })],
      })
      await flushPromises()

      const input = wrapper.find('[data-testid="scan-modal-field-target_subnet"]').find('input')
      expect(input.element.value).toBe('192.168.0.42/32')

      await wrapper.find('[data-testid="scan-modal-start-btn"]').trigger('click')
      await flushPromises()

      const body = capturedBody as Record<string, unknown>
      expect((body.overrides as Record<string, unknown>).target_subnet).toBe('192.168.0.42/32')
    })

    it('keeps the /24 subnet for a multi-asset arp_scan (scan all)', async () => {
      server.use(
        http.get('*/api/v1/modules', () => HttpResponse.json({ modules: ['arp_scan', 'pn_discovery'] })),
        http.get('*/api/v1/scans/interfaces', () => HttpResponse.json({ interfaces: [] })),
      )
      const wrapper = mountModal({
        targetDevices: [
          deviceWith({ id: 1, ipv4: '192.168.0.42', subnet: '192.168.0.0/24' }),
          deviceWith({ id: 2, ipv4: '192.168.0.43', subnet: '192.168.0.0/24' }),
        ],
      })
      await flushPromises()

      const input = wrapper.find('[data-testid="scan-modal-field-target_subnet"]').find('input')
      expect(input.element.value).toBe('192.168.0.0/24')
    })

    it('prefills pn_discovery target_mac for a single asset', async () => {
      let capturedBody: unknown = null
      server.use(
        http.get('*/api/v1/modules', () => HttpResponse.json({ modules: ['pn_discovery'] })),
        http.get('*/api/v1/scans/interfaces', () => HttpResponse.json({ interfaces: [] })),
        http.get('*/api/v1/scans/modules/pn_discovery/schema', () =>
          HttpResponse.json({
            module: 'pn_discovery',
            accepted_keys: [
              { key: 'network_interface', type: 'str', required: false, description: '' },
              { key: 'target_mac', type: 'str', required: false, description: '' },
            ],
            requires_auth: false,
            extensible: false,
          }),
        ),
        http.post('*/api/v1/scans', async ({ request }) => {
          capturedBody = await request.json()
          return HttpResponse.json({ scan_id: 'scan-pn-1', status: 'running' })
        }),
      )
      const wrapper = mountModal({
        presetModule: 'pn_discovery',
        targetDevices: [deviceWith({ ipv4: '192.168.0.42', primaryMac: 'aa:bb:cc:dd:ee:ff' })],
      })
      await flushPromises()

      const input = wrapper.find('[data-testid="scan-modal-field-target_mac"]').find('input')
      expect(input.element.value).toBe('aa:bb:cc:dd:ee:ff')

      await wrapper.find('[data-testid="scan-modal-start-btn"]').trigger('click')
      await flushPromises()

      const body = capturedBody as Record<string, unknown>
      expect((body.overrides as Record<string, unknown>).target_mac).toBe('aa:bb:cc:dd:ee:ff')
    })
  })

  // ── Structured result display (UI-019) ──────────────────────────────

  describe('structured result display', () => {
    it('renders port findings as chips instead of raw JSON', async () => {
      server.use(
        http.get('*/api/v1/modules', () => HttpResponse.json({ modules: ['port_scan'] })),
        http.get('*/api/v1/scans/interfaces', () => HttpResponse.json({ interfaces: [] })),
        http.post('*/api/v1/scans', () => HttpResponse.json({ scan_id: 'scan-port', status: 'running' })),
      )

      const wrapper = mountModal({ targetDevices: [deviceWith({ ipv4: '10.0.0.1', ports: [] })] })
      await flushPromises()

      await wrapper.find('[data-testid="scan-modal-start-btn"]').trigger('click')
      await flushPromises()

      const sse = MockEventSource.instances[0]
      sse?.simulateMessage('result', {
        module_name: 'T0840/port_scan',
        findings: [
          {
            ipv4: '10.0.0.1',
            open_ports_summary: {
              open: [
                { port: 80, proto: 'tcp' },
                { port: 443, proto: 'tcp' },
              ],
            },
            extra: {
              open_ports: [
                { port: 80, protocol: 'tcp', state: 'open', service_name: 'http', product: 'nginx' },
                { port: 443, protocol: 'tcp', state: 'open', service_name: 'https', product: 'nginx' },
              ],
            },
          },
        ],
      })
      await flushPromises()

      const display = wrapper.find('[data-testid="scan-modal-result-display"]')
      expect(display.exists()).toBe(true)
      expect(display.text()).toContain('10.0.0.1')
      expect(display.text()).toContain('80/tcp')
      expect(display.text()).toContain('443/tcp')
      expect(display.text()).toContain('nginx')
      // Should not contain raw JSON dump indicators
      expect(display.text()).not.toContain('{\n')
      expect(display.text()).not.toContain('"open_ports_summary"')
    })

    it('renders ARP findings with IP and MAC', async () => {
      server.use(
        http.get('*/api/v1/modules', () => HttpResponse.json({ modules: ['arp_scan'] })),
        http.get('*/api/v1/scans/interfaces', () => HttpResponse.json({ interfaces: [] })),
        http.post('*/api/v1/scans', () => HttpResponse.json({ scan_id: 'scan-arp', status: 'running' })),
      )

      const wrapper = mountModal()
      await flushPromises()

      await wrapper.find('[data-testid="scan-modal-start-btn"]').trigger('click')
      await flushPromises()

      const sse = MockEventSource.instances[0]
      sse?.simulateMessage('result', {
        module_name: 'T1018/arp_scan',
        findings: [{ ipv4: '192.168.1.5', mac: 'aa:bb:cc:dd:ee:ff', subnet: '192.168.1.0/24' }],
      })
      await flushPromises()

      const display = wrapper.find('[data-testid="scan-modal-result-display"]')
      expect(display.exists()).toBe(true)
      expect(display.text()).toContain('192.168.1.5')
      expect(display.text()).toContain('aa:bb:cc:dd:ee:ff')
    })
  })

  // ── Stop flow (UI-026) ───────────────────────────────────────────────

  describe('stop flow', () => {
    it('shows stop button only while scan is running', async () => {
      server.use(
        http.get('*/api/v1/modules', () => HttpResponse.json({ modules: ['arp_scan'] })),
        http.get('*/api/v1/scans/interfaces', () => HttpResponse.json({ interfaces: [] })),
        http.post('*/api/v1/scans', () => HttpResponse.json({ scan_id: 'scan-stop-1', status: 'running' })),
      )
      const wrapper = mountModal()
      await flushPromises()

      expect(wrapper.find('[data-testid="scan-modal-stop-btn"]').exists()).toBe(false)

      await wrapper.find('[data-testid="scan-modal-start-btn"]').trigger('click')
      await flushPromises()

      expect(wrapper.find('[data-testid="scan-modal-stop-btn"]').exists()).toBe(true)

      const sse = MockEventSource.instances[0]
      sse?.simulateMessage('result', { status: 'completed' })
      await flushPromises()

      expect(wrapper.find('[data-testid="scan-modal-stop-btn"]').exists()).toBe(false)
    })

    it('POSTs abort to the correct URL when stop is clicked', async () => {
      let abortUrl = ''
      server.use(
        http.get('*/api/v1/modules', () => HttpResponse.json({ modules: ['arp_scan'] })),
        http.get('*/api/v1/scans/interfaces', () => HttpResponse.json({ interfaces: [] })),
        http.post('*/api/v1/scans', () => HttpResponse.json({ scan_id: 'scan-stop-2', status: 'running' })),
        http.post('*/api/v1/scans/scan-stop-2/abort', async ({ request }) => {
          abortUrl = request.url
          return HttpResponse.json({ ok: true })
        }),
      )
      const wrapper = mountModal()
      await flushPromises()

      await wrapper.find('[data-testid="scan-modal-start-btn"]').trigger('click')
      await flushPromises()

      await wrapper.find('[data-testid="scan-modal-stop-btn"]').trigger('click')
      await flushPromises()

      expect(abortUrl).toContain('/api/v1/scans/scan-stop-2/abort')
    })

    it('disables stop button while abort request is in flight', async () => {
      let resolveAbort: (() => void) | null = null
      server.use(
        http.get('*/api/v1/modules', () => HttpResponse.json({ modules: ['arp_scan'] })),
        http.get('*/api/v1/scans/interfaces', () => HttpResponse.json({ interfaces: [] })),
        http.post('*/api/v1/scans', () => HttpResponse.json({ scan_id: 'scan-stop-3', status: 'running' })),
        http.post(
          '*/api/v1/scans/scan-stop-3/abort',
          () =>
            new Promise<HttpResponse>((resolve) => {
              resolveAbort = () => resolve(HttpResponse.json({ ok: true }))
            }),
        ),
      )
      const wrapper = mountModal()
      await flushPromises()

      await wrapper.find('[data-testid="scan-modal-start-btn"]').trigger('click')
      await flushPromises()

      expect(wrapper.find('[data-testid="scan-modal-stop-btn"]').attributes('data-disabled')).toBe('false')

      await wrapper.find('[data-testid="scan-modal-stop-btn"]').trigger('click')
      await flushPromises()

      expect(wrapper.find('[data-testid="scan-modal-stop-btn"]').attributes('data-disabled')).toBe('true')

      resolveAbort?.()
      await flushPromises()

      // After successful abort the scan becomes terminal and the stop button is hidden.
      expect(wrapper.find('[data-testid="scan-modal-stop-btn"]').exists()).toBe(false)
    })

    it('reflects cancelled state and emits finished after successful abort', async () => {
      server.use(
        http.get('*/api/v1/modules', () => HttpResponse.json({ modules: ['arp_scan'] })),
        http.get('*/api/v1/scans/interfaces', () => HttpResponse.json({ interfaces: [] })),
        http.post('*/api/v1/scans', () => HttpResponse.json({ scan_id: 'scan-stop-4', status: 'running' })),
        http.post('*/api/v1/scans/scan-stop-4/abort', () => HttpResponse.json({ ok: true })),
      )
      const wrapper = mountModal()
      await flushPromises()

      await wrapper.find('[data-testid="scan-modal-start-btn"]').trigger('click')
      await flushPromises()

      await wrapper.find('[data-testid="scan-modal-stop-btn"]').trigger('click')
      await flushPromises()

      const badge = wrapper.find('[data-testid="scan-modal-status-badge"]')
      expect(badge.text()).toBe('Aborted')
      expect(wrapper.find('[data-testid="scan-modal-reset-btn"]').exists()).toBe(true)
      expect(wrapper.emitted('finished')?.[0]).toEqual(['scan-stop-4', 'cancelled'])
    })

    it('shows error banner and keeps running state on abort failure', async () => {
      server.use(
        http.get('*/api/v1/modules', () => HttpResponse.json({ modules: ['arp_scan'] })),
        http.get('*/api/v1/scans/interfaces', () => HttpResponse.json({ interfaces: [] })),
        http.post('*/api/v1/scans', () => HttpResponse.json({ scan_id: 'scan-stop-5', status: 'running' })),
        http.post('*/api/v1/scans/scan-stop-5/abort', () =>
          HttpResponse.json({ detail: 'cannot abort' }, { status: 409 }),
        ),
      )
      const wrapper = mountModal()
      await flushPromises()

      await wrapper.find('[data-testid="scan-modal-start-btn"]').trigger('click')
      await flushPromises()

      await wrapper.find('[data-testid="scan-modal-stop-btn"]').trigger('click')
      await flushPromises()

      expect(wrapper.find('[data-testid="scan-modal-upstream-error"]').exists()).toBe(true)
      expect(wrapper.find('[data-testid="scan-modal-upstream-error"]').text()).toContain('cannot abort')
      expect(wrapper.find('[data-testid="scan-modal-status-badge"]').text()).toBe('Running')
      expect(wrapper.find('[data-testid="scan-modal-stop-btn"]').exists()).toBe(true)
    })

    it('infers cancelled status from an SSE status event with aborted', async () => {
      server.use(
        http.get('*/api/v1/modules', () => HttpResponse.json({ modules: ['arp_scan'] })),
        http.get('*/api/v1/scans/interfaces', () => HttpResponse.json({ interfaces: [] })),
        http.post('*/api/v1/scans', () => HttpResponse.json({ scan_id: 'scan-stop-6', status: 'running' })),
      )
      const wrapper = mountModal()
      await flushPromises()

      await wrapper.find('[data-testid="scan-modal-start-btn"]').trigger('click')
      await flushPromises()

      const sse = MockEventSource.instances[0]
      sse?.simulateMessage('status', { status: 'ABORTED' })
      await flushPromises()

      expect(wrapper.find('[data-testid="scan-modal-status-badge"]').text()).toBe('Aborted')
      expect(wrapper.emitted('finished')?.[0]).toEqual(['scan-stop-6', 'cancelled'])
    })
  })

  // ── In-modal reset (UI-018) ─────────────────────────────────────────

  describe('in-modal reset', () => {
    it('shows a New-scan button after completion and resets state without closing', async () => {
      server.use(
        http.get('*/api/v1/modules', () => HttpResponse.json({ modules: ['arp_scan'] })),
        http.get('*/api/v1/scans/interfaces', () => HttpResponse.json({ interfaces: [] })),
        http.post('*/api/v1/scans', () => HttpResponse.json({ scan_id: 'scan-reset', status: 'running' })),
      )

      const wrapper = mountModal()
      await flushPromises()

      await wrapper.find('[data-testid="scan-modal-start-btn"]').trigger('click')
      await flushPromises()

      const sse = MockEventSource.instances[0]
      sse?.simulateMessage('result', { module_name: 'arp_scan', status: 'completed' })
      await flushPromises()

      expect(wrapper.find('[data-testid="scan-modal-status-badge"]').text()).toBe('Completed')
      expect(wrapper.find('[data-testid="scan-modal-start-btn"]').exists()).toBe(false)

      const resetBtn = wrapper.find('[data-testid="scan-modal-reset-btn"]')
      expect(resetBtn.exists()).toBe(true)
      await resetBtn.trigger('click')
      await flushPromises()

      expect(wrapper.find('[data-testid="scan-modal-status-badge"]').exists()).toBe(false)
      expect(wrapper.find('[data-testid="scan-modal-start-btn"]').exists()).toBe(true)
      expect(wrapper.find('[data-testid="scan-modal-reset-btn"]').exists()).toBe(false)
    })
  })

  // ── Modal reset on reopen ────────────────────────────────────────────

  describe('modal reset on reopen', () => {
    it('clears scanId, terminalStatus, terminalResult, events and upstreamError on reopen', async () => {
      server.use(
        http.get('*/api/v1/modules', () => HttpResponse.json({ modules: ['arp_scan'] })),
        http.get('*/api/v1/scans/interfaces', () => HttpResponse.json({ interfaces: [] })),
        http.post('*/api/v1/scans', () => HttpResponse.json({ scan_id: 'scan-001', status: 'running' })),
      )

      const wrapper = mountModal()
      await flushPromises()

      await wrapper.find('[data-testid="scan-modal-start-btn"]').trigger('click')
      await flushPromises()

      const sse = MockEventSource.instances[0]
      sse?.simulateMessage('result', { status: 'completed' })
      await flushPromises()

      expect(wrapper.find('[data-testid="scan-modal-status-badge"]').text()).toBe('Completed')
      expect(wrapper.find('[data-testid="scan-modal-start-btn"]').exists()).toBe(false)
      expect(wrapper.find('[data-testid="scan-modal-result-display"]').exists()).toBe(true)

      const vm = wrapper.vm as unknown as {
        starting: boolean
        terminalResult: unknown
        selectedModule: string | null
      }
      expect(vm.terminalResult).toBeTruthy()

      await wrapper.setProps({ modelValue: false })
      await flushPromises()

      await wrapper.setProps({ modelValue: true })
      await flushPromises()

      const startBtn = wrapper.find('[data-testid="scan-modal-start-btn"]')
      expect(startBtn.exists()).toBe(true)
      expect(wrapper.find('[data-testid="scan-modal-status-badge"]').exists()).toBe(false)
      expect(wrapper.find('[data-testid="scan-modal-result-display"]').exists()).toBe(false)
      expect(vm.starting).toBe(false)
      expect(vm.terminalResult).toBeNull()
      expect(vm.selectedModule).not.toBeNull()
    })

    it('does not reset scanId when reopened in replay mode', async () => {
      server.use(
        http.get('*/api/v1/modules', () => HttpResponse.json({ modules: ['arp_scan'] })),
        http.get('*/api/v1/scans/interfaces', () => HttpResponse.json({ interfaces: [] })),
      )

      const wrapper = mountModal({ replayScanId: 'replay-001' })
      await flushPromises()

      expect(wrapper.find('[data-testid="scan-modal-status-badge"]').exists()).toBe(true)

      await wrapper.setProps({ modelValue: false })
      await flushPromises()
      await wrapper.setProps({ modelValue: true })
      await flushPromises()

      expect(wrapper.find('[data-testid="scan-modal-status-badge"]').exists()).toBe(true)
    })
  })

  // ── Transparency footer ──────────────────────────────────────────────

  describe('transparency footer', () => {
    it('always renders the resolved upstream-URL line', async () => {
      server.use(
        http.get('*/api/v1/modules', () => HttpResponse.json({ modules: ['arp_scan'] })),
        http.get('*/api/v1/scans/interfaces', () => HttpResponse.json({ interfaces: [] })),
      )

      const wrapper = mountModal()
      await flushPromises()

      const line = wrapper.find('[data-testid="scan-modal-upstream-line"]')
      expect(line.exists()).toBe(true)
      expect(line.text()).toContain('OTALON-SCAN')
    })
  })
})
