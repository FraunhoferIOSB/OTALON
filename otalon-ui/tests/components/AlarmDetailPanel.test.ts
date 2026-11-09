/**
 * Component tests for the AlarmDetailPanel alarm component.
 *
 * Validates placeholder rendering, ML prediction display, confidence bar,
 * MITRE ATT&CK label, type statistics, summary info, badges, action
 * buttons (confirm/unconfirm/close), PCAP-download button, and
 * connection list rendering using golden alarm group data.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { flushPromises } from '@vue/test-utils'
import AlarmDetailPanel from '~/components/alarm/AlarmDetailPanel.vue'
import { GOLDEN_ALARM_GROUPS } from '../mocks/golden-data'
import { mountWithPlugins } from '../helpers/mount'

const { fetchAlarmPcapZipMock, triggerBrowserDownloadMock, notifyMock } = vi.hoisted(() => ({
  fetchAlarmPcapZipMock: vi.fn(),
  triggerBrowserDownloadMock: vi.fn(),
  notifyMock: vi.fn(),
}))

vi.mock('~/composables/usePcapDownload', () => ({
  usePcapDownload: () => ({
    fetchAlarmPcapZip: fetchAlarmPcapZipMock,
    triggerBrowserDownload: triggerBrowserDownloadMock,
  }),
}))

vi.mock('quasar', () => ({
  useQuasar: () => ({
    dark: { isActive: false },
    notify: notifyMock,
    dialog: vi.fn(),
  }),
}))

const UNCONFIRMED_GROUP = GOLDEN_ALARM_GROUPS[0]
const CONFIRMED_GROUP = GOLDEN_ALARM_GROUPS[2]

describe('AlarmDetailPanel', () => {
  it('renders placeholder when group is null', () => {
    const wrapper = mountWithPlugins(AlarmDetailPanel, {
      props: { group: null },
    })

    expect(wrapper.text()).toContain('Select an alarm group to view details')
  })

  it('does not render Beta badge', () => {
    const wrapper = mountWithPlugins(AlarmDetailPanel, {
      props: { group: UNCONFIRMED_GROUP },
    })

    const badges = wrapper.findAll('.q-badge')
    const betaBadge = badges.find((b) => b.text() === 'Beta')
    expect(betaBadge).toBeUndefined()
  })

  it('renders anomaly type statistics rows sorted by score_norm', () => {
    const wrapper = mountWithPlugins(AlarmDetailPanel, {
      props: { group: UNCONFIRMED_GROUP },
    })

    const stats = UNCONFIRMED_GROUP.anomaly_type_stats
    const sortedTypes = Object.entries(stats)
      .sort(([, a], [, b]) => b.score_norm - a.score_norm)
      .map(([type]) => type)

    const typeStatRows = wrapper.findAll('.type-stat-row')
    expect(typeStatRows).toHaveLength(sortedTypes.length)

    for (const [index, expectedType] of sortedTypes.entries()) {
      expect(typeStatRows[index].text()).toContain(expectedType)
    }
  })

  it('renders alarm group summary info', () => {
    const wrapper = mountWithPlugins(AlarmDetailPanel, {
      props: { group: UNCONFIRMED_GROUP },
    })

    expect(wrapper.text()).toContain(UNCONFIRMED_GROUP.id)
    expect(wrapper.text()).toContain('Prediction')
    expect(wrapper.text()).toContain('Start Time')
    expect(wrapper.text()).toContain('End Time')
  })

  it('does not render the aggregated affected-feature badge row', () => {
    const wrapper = mountWithPlugins(AlarmDetailPanel, {
      props: { group: { ...UNCONFIRMED_GROUP, affected_features: ['packet_count'] } },
    })

    expect(wrapper.find('[data-testid="alarm-affected-features"]').exists()).toBe(false)
    expect(wrapper.text()).not.toContain('Violated features')
  })

  it('renders active and confirmed badges', () => {
    const wrapper = mountWithPlugins(AlarmDetailPanel, {
      props: { group: CONFIRMED_GROUP },
    })

    const badges = wrapper.findAll('.q-badge')
    const activeBadge = badges.find((b) => b.text() === 'Active')
    expect(activeBadge).toBeDefined()
    expect(activeBadge!.attributes('class')).toContain('bg-negative')

    const confirmedBadge = badges.find((b) => b.text() === 'Confirmed')
    expect(confirmedBadge).toBeDefined()
    expect(confirmedBadge!.attributes('class')).toContain('bg-primary')
  })

  it('renders Confirm button when not confirmed', () => {
    const wrapper = mountWithPlugins(AlarmDetailPanel, {
      props: { group: UNCONFIRMED_GROUP },
    })

    const confirmBtn = wrapper
      .findAll('.action-btn')
      .find((b) => b.text().includes('Confirm') && !b.text().includes('Unconfirm'))
    expect(confirmBtn).toBeDefined()
    expect(wrapper.findAll('.action-btn').find((b) => b.text().includes('Unconfirm'))).toBeUndefined()
  })

  it('renders Unconfirm button when confirmed', () => {
    const wrapper = mountWithPlugins(AlarmDetailPanel, {
      props: { group: CONFIRMED_GROUP },
    })

    const unconfirmBtn = wrapper.findAll('.action-btn').find((b) => b.text().includes('Unconfirm'))
    expect(unconfirmBtn).toBeDefined()
    expect(
      wrapper.findAll('.action-btn').find((b) => b.text().includes('Confirm') && !b.text().includes('Unconfirm')),
    ).toBeUndefined()
  })

  it('emits confirm on Confirm button click', async () => {
    const wrapper = mountWithPlugins(AlarmDetailPanel, {
      props: { group: UNCONFIRMED_GROUP },
    })

    const confirmBtn = wrapper
      .findAll('.action-btn')
      .find((b) => b.text().includes('Confirm') && !b.text().includes('Unconfirm'))!
    await confirmBtn.trigger('click')

    const emitted = wrapper.emitted('confirm')
    expect(emitted).toBeTruthy()
    expect(emitted).toHaveLength(1)
    expect((emitted![0][0] as { id: string }).id).toBe(UNCONFIRMED_GROUP.id)
  })

  it('emits unconfirm on Unconfirm button click', async () => {
    const wrapper = mountWithPlugins(AlarmDetailPanel, {
      props: { group: CONFIRMED_GROUP },
    })

    const unconfirmBtn = wrapper.findAll('.action-btn').find((b) => b.text().includes('Unconfirm'))!
    await unconfirmBtn.trigger('click')

    const emitted = wrapper.emitted('unconfirm')
    expect(emitted).toBeTruthy()
    expect(emitted).toHaveLength(1)
    expect((emitted![0][0] as { id: string }).id).toBe(CONFIRMED_GROUP.id)
  })

  it('emits close on close button click', async () => {
    const wrapper = mountWithPlugins(AlarmDetailPanel, {
      props: { group: UNCONFIRMED_GROUP },
    })

    const closeBtn = wrapper.findAll('.q-btn').find((b) => {
      const icon = b.find('.q-icon')
      return icon.exists() && icon.text() === 'close'
    })
    expect(closeBtn).toBeDefined()
    await closeBtn!.trigger('click')

    expect(wrapper.emitted('close')).toBeTruthy()
  })

  it('renders connection list with series_ids', () => {
    const wrapper = mountWithPlugins(AlarmDetailPanel, {
      props: { group: UNCONFIRMED_GROUP },
    })

    const connectionList = wrapper.find('[data-testid="connection-list"]')
    expect(connectionList.exists()).toBe(true)
  })

  describe('Tab layout (UI-031)', () => {
    it('preserves the active tab when the selected alarm changes', async () => {
      const wrapper = mountWithPlugins(AlarmDetailPanel, {
        props: { group: UNCONFIRMED_GROUP },
      })

      const tabs = wrapper.findComponent({ name: 'QTabs' })
      await tabs.vm.$emit('update:modelValue', 'connections')
      await wrapper.setProps({ group: CONFIRMED_GROUP })

      expect(tabs.props('modelValue')).toBe('connections')
    })

    it('renders all six tabs in the exact order', () => {
      const wrapper = mountWithPlugins(AlarmDetailPanel, {
        props: { group: UNCONFIRMED_GROUP },
      })

      const tabs = wrapper.findAll('.q-tab')
      expect(tabs).toHaveLength(6)

      const expected = ['Meta', 'Prediction Stats', 'AI-Agent Forensics', 'Connections', 'Assets', 'Protocols']
      for (const label of expected) {
        const tab = tabs.find((t) => t.text().includes(label))
        expect(tab).toBeDefined()
      }
    })

    it('routes mixed series_ids to correct tabs for conn alarm', () => {
      const MIXED_GROUP = {
        ...UNCONFIRMED_GROUP,
        module: 'conn',
        series_ids: [
          'aa:bb:cc:dd:ee:ff/11:22:33:44:55:66/0/2048/10.0.0.1/10.0.0.2/502/502/TCP:Modbus',
          'Ethernet:IPv4:TCP:Modbus',
          '00:1b:1b:f8:3a:02',
        ],
        enrichment: {
          schema: 1,
          mac: [],
          proto: [],
        },
      }

      const wrapper = mountWithPlugins(AlarmDetailPanel, {
        props: { group: MIXED_GROUP },
      })

      const connectionList = wrapper.findComponent({ name: 'AlarmConnectionList' })
      expect(connectionList.props('seriesIds')).toEqual([
        'aa:bb:cc:dd:ee:ff/11:22:33:44:55:66/0/2048/10.0.0.1/10.0.0.2/502/502/TCP:Modbus',
      ])

      const macList = wrapper.findComponent({ name: 'AlarmMacAssetList' })
      expect(macList.props('macs')).toEqual(['00:1b:1b:f8:3a:02'])

      const protocolList = wrapper.findComponent({ name: 'AlarmProtocolList' })
      expect(protocolList.props('protos')).toEqual([{ id: 'Ethernet:IPv4:TCP:Modbus', label: 'Modbus' }])
    })

    it('renders Assets and Protocols tabs for enriched conn alarm', () => {
      const ENRICHED_GROUP = {
        ...UNCONFIRMED_GROUP,
        enrichment: {
          schema: 1,
          mac: [
            {
              anomaly_id: 'mac_traffic|a8:74:1d:02:99:8d|2026-04-06T05:55:11+00:00|2026-04-06T05:55:26+00:00',
              module: 'mac_traffic',
              series_id: 'a8:74:1d:02:99:8d',
              anomaly_type: 'BoundViolation',
              confidence: 1.0,
              start_ts: '2026-04-06T05:55:11+00:00',
              end_ts: '2026-04-06T05:55:26+00:00',
            },
          ],
          proto: [
            {
              anomaly_id: 'proto_traffic|1214521437|2026-04-06T05:29:04+00:00|2026-04-06T05:29:10+00:00',
              module: 'proto_traffic',
              series_id: '1214521437',
              protocol: 'Ethernet:IPv4:TCP:HTTPRequest',
              anomaly_type: 'BoundViolation',
              confidence: 1.0,
              start_ts: '2026-04-06T05:29:04+00:00',
              end_ts: '2026-04-06T05:29:10+00:00',
            },
          ],
        },
      }

      const wrapper = mountWithPlugins(AlarmDetailPanel, {
        props: { group: ENRICHED_GROUP },
      })

      expect(wrapper.find('[data-testid="mac-asset-list"]').exists()).toBe(true)
      expect(wrapper.find('[data-testid="protocol-list"]').exists()).toBe(true)
    })

    it('shows readable humanized protocol labels for proto alarm', () => {
      const PROTO_GROUP = {
        ...UNCONFIRMED_GROUP,
        module: 'proto_traffic',
        series_ids: ['Ethernet:ARP', 'Ethernet:IPv4:TCP'],
        protocols: ['Ethernet:ARP', 'Ethernet:IPv4:TCP'],
      }

      const wrapper = mountWithPlugins(AlarmDetailPanel, {
        props: { group: PROTO_GROUP },
      })

      const protocolList = wrapper.findComponent({ name: 'AlarmProtocolList' })
      expect(protocolList.exists()).toBe(true)
      expect((protocolList.props('protos') as { label: string }[]).map((p) => p.label)).toEqual(['ARP', 'TCP'])
    })

    it('resolves numeric hash protocol IDs to their readable names (UI-091)', () => {
      const PROTO_GROUP = {
        ...UNCONFIRMED_GROUP,
        module: 'proto_traffic',
        series_ids: ['309908982', '1435473285'],
        protocols: ['Ethernet:ARP', 'Ethernet:IPv4:TCP'],
      }

      const wrapper = mountWithPlugins(AlarmDetailPanel, {
        props: { group: PROTO_GROUP },
      })

      const protocolList = wrapper.findComponent({ name: 'AlarmProtocolList' })
      expect(protocolList.exists()).toBe(true)
      expect((protocolList.props('protos') as { label: string }[]).map((p) => p.label)).toEqual(['ARP', 'TCP'])
    })

    it('still drops a hash protocol ID that has no readable name (UI-091)', () => {
      const PROTO_GROUP = {
        ...UNCONFIRMED_GROUP,
        module: 'proto_traffic',
        series_ids: ['309908982', '1435473285'],
        protocols: [],
      }

      const wrapper = mountWithPlugins(AlarmDetailPanel, {
        props: { group: PROTO_GROUP },
      })

      const protocolList = wrapper.findComponent({ name: 'AlarmProtocolList' })
      expect(protocolList.exists()).toBe(true)
      expect(protocolList.props('protos') as { label: string }[]).toEqual([])
    })

    it('moves series_ids to Protocols tab for proto alarm and empties Connections tab', () => {
      const PROTO_GROUP = {
        ...UNCONFIRMED_GROUP,
        module: 'proto_traffic',
        series_ids: ['Ethernet:ARP'],
        protocols: ['Ethernet:ARP'],
      }

      const wrapper = mountWithPlugins(AlarmDetailPanel, {
        props: { group: PROTO_GROUP },
      })

      const connectionList = wrapper.findComponent({ name: 'AlarmConnectionList' })
      expect(connectionList.props('seriesIds')).toEqual([])

      const protocolList = wrapper.findComponent({ name: 'AlarmProtocolList' })
      expect(protocolList.props('protos')).toEqual([{ id: 'Ethernet:ARP', label: 'ARP' }])
    })

    it('moves series_ids to MACs tab for mac alarm and empties Connections tab', () => {
      const MAC_GROUP = {
        ...UNCONFIRMED_GROUP,
        module: 'mac_traffic',
        series_ids: ['00:1b:1b:f8:3a:02', '00:1b:1b:f8:3a:03'],
      }

      const wrapper = mountWithPlugins(AlarmDetailPanel, {
        props: { group: MAC_GROUP },
      })

      const connectionList = wrapper.findComponent({ name: 'AlarmConnectionList' })
      expect(connectionList.props('seriesIds')).toEqual([])

      const macList = wrapper.findComponent({ name: 'AlarmMacAssetList' })
      expect(macList.props('macs')).toEqual(['00:1b:1b:f8:3a:02', '00:1b:1b:f8:3a:03'])
    })
  })

  describe('PCAP download button', () => {
    beforeEach(() => {
      fetchAlarmPcapZipMock.mockReset()
      triggerBrowserDownloadMock.mockReset()
      notifyMock.mockReset()
    })

    it('renders the PCAP download button with the expected testid', () => {
      const wrapper = mountWithPlugins(AlarmDetailPanel, {
        props: { group: UNCONFIRMED_GROUP },
      })

      const btn = wrapper.find('[data-testid="alarm-detail-pcap-download-btn"]')
      expect(btn.exists()).toBe(true)
      expect(btn.text()).toContain('PCAP')
    })

    it('fetches the ZIP and triggers a browser download on click', async () => {
      const zipBlob = new Blob([new Uint8Array([0x50, 0x4b])], { type: 'application/zip' })
      fetchAlarmPcapZipMock.mockResolvedValueOnce(zipBlob)

      const wrapper = mountWithPlugins(AlarmDetailPanel, {
        props: { group: UNCONFIRMED_GROUP },
      })

      const btn = wrapper.find('[data-testid="alarm-detail-pcap-download-btn"]')
      await btn.trigger('click')
      await flushPromises()

      expect(fetchAlarmPcapZipMock).toHaveBeenCalledTimes(1)
      expect(fetchAlarmPcapZipMock).toHaveBeenCalledWith(UNCONFIRMED_GROUP.id)
      expect(triggerBrowserDownloadMock).toHaveBeenCalledTimes(1)
      const [downloadBlob, filename] = triggerBrowserDownloadMock.mock.calls[0]
      expect(downloadBlob).toBe(zipBlob)
      expect(filename).toBe(`alarm-${UNCONFIRMED_GROUP.id}-pcap.zip`)
    })

    it('notifies with "No PCAP data available" on a 404 response', async () => {
      fetchAlarmPcapZipMock.mockRejectedValueOnce({ status: 404, message: 'Not Found' })

      const wrapper = mountWithPlugins(AlarmDetailPanel, {
        props: { group: UNCONFIRMED_GROUP },
      })

      const btn = wrapper.find('[data-testid="alarm-detail-pcap-download-btn"]')
      await btn.trigger('click')
      await flushPromises()

      expect(fetchAlarmPcapZipMock).toHaveBeenCalledTimes(1)
      expect(triggerBrowserDownloadMock).not.toHaveBeenCalled()
      expect(notifyMock).toHaveBeenCalledTimes(1)
      const notifyArgs = notifyMock.mock.calls[0][0]
      expect(notifyArgs.type).toBe('negative')
      expect(notifyArgs.message).toBe('No PCAP data available for this alarm')
    })
  })
})
