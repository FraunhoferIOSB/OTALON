import { describe, expect, it } from 'vitest'
import AlarmConnectionList from '~/components/alarm/AlarmConnectionList.vue'
import { mountWithPlugins } from '../helpers/mount'

describe('AlarmConnectionList', () => {
  it('shows collapsed count and one row for many ports in same identity', () => {
    const seriesIds = Array.from(
      { length: 12 },
      (_, index) =>
        `aa:bb/cc:dd//IPv4/10.0.0.1/10.0.0.2/${2000 + index}/4840/Ethernet:IPv4:TCP:OPC_UA`,
    )
    const wrapper = mountWithPlugins(AlarmConnectionList, { props: { seriesIds } })

    expect(wrapper.find('.q-badge').text()).toBe('1')
    expect(wrapper.findAll('.connection-link-item')).toHaveLength(1)
  })
})
