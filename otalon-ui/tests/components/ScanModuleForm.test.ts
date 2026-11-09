/**
 * Component tests for ScanModuleForm.
 *
 * Validates per-module field rendering, two-way binding, and validity
 * emission for the structured scan-config form.
 */
import { describe, expect, it } from 'vitest'
import { flushPromises } from '@vue/test-utils'
import ScanModuleForm from '~/components/scan/ScanModuleForm.vue'
import { mountWithPlugins } from '../helpers/mount'

describe('ScanModuleForm', () => {
  it('renders port_scan fields including network_interface select', () => {
    const wrapper = mountWithPlugins(ScanModuleForm, {
      props: {
        moduleName: 'port_scan',
        modelValue: {},
      },
    })

    expect(wrapper.find('[data-testid="scan-modal-field-target_ip"]').exists()).toBe(true)
    expect(wrapper.find('[data-testid="scan-modal-field-port_range"]').exists()).toBe(true)
    expect(wrapper.find('[data-testid="scan-modal-field-timing_template"]').exists()).toBe(true)
    expect(wrapper.find('[data-testid="scan-modal-field-network_interface"]').exists()).toBe(true)
  })

  it('prefills port_scan network_interface from modelValue (parent default)', async () => {
    const wrapper = mountWithPlugins(ScanModuleForm, {
      props: {
        moduleName: 'port_scan',
        modelValue: { network_interface: 'enp4s0' },
        interfaceOptions: ['enp4s0', 'enp5s0', 'eno1'],
      },
    })
    await flushPromises()

    const select = wrapper.find('[data-testid="scan-modal-field-network_interface"]')
    expect(select.exists()).toBe(true)
    expect((select.element as HTMLSelectElement).value).toBe('enp4s0')
  })

  it('emits update:modelValue when port_scan network_interface changes', async () => {
    const wrapper = mountWithPlugins(ScanModuleForm, {
      props: {
        moduleName: 'port_scan',
        modelValue: {},
        interfaceOptions: ['enp4s0', 'enp5s0', 'eno1'],
      },
    })
    await flushPromises()

    const select = wrapper.find('[data-testid="scan-modal-field-network_interface"]')
    await select.setValue('eno1')

    const emitted = wrapper.emitted('update:modelValue')
    expect(emitted).toHaveLength(1)
    expect((emitted![0] as [Record<string, unknown>])[0]).toEqual({
      network_interface: 'eno1',
    })
  })

  it('removes network_interface key when port_scan select is cleared', async () => {
    const wrapper = mountWithPlugins(ScanModuleForm, {
      props: {
        moduleName: 'port_scan',
        modelValue: { network_interface: 'enp4s0', target_ip: '192.168.1.1' },
        interfaceOptions: ['enp4s0', 'enp5s0', 'eno1'],
      },
    })
    await flushPromises()

    const select = wrapper.find('[data-testid="scan-modal-field-network_interface"]')
    await select.setValue('')

    const emitted = wrapper.emitted('update:modelValue')
    expect(emitted).toHaveLength(1)
    expect((emitted![0] as [Record<string, unknown>])[0]).toEqual({
      target_ip: '192.168.1.1',
    })
  })

  it('emits valid=true for a complete port_scan form', async () => {
    mountWithPlugins(ScanModuleForm, {
      props: {
        moduleName: 'port_scan',
        modelValue: {
          target_ip: '192.168.1.1',
          port_range: '1-1024',
        },
        'onUpdate:valid': (v: boolean) => {
          expect(v).toBe(true)
        },
      },
    })
    await flushPromises()
  })

  it('emits valid=false for an incomplete port_scan form', async () => {
    let lastValid: boolean | undefined
    mountWithPlugins(ScanModuleForm, {
      props: {
        moduleName: 'port_scan',
        modelValue: {},
        'onUpdate:valid': (v: boolean) => {
          lastValid = v
        },
      },
    })
    await flushPromises()
    expect(lastValid).toBe(false)
  })
})
