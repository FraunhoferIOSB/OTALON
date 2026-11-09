/**
 * Shared mount helper for component tests.
 *
 * Pre-configures Vue Test Utils with Quasar component stubs, Pinia, and Nuxt
 * mocks so that individual test files do not duplicate boilerplate setup.
 *
 * Quasar's install() plugin crashes in happy-dom due to missing browser globals,
 * so all Quasar components are provided as lightweight render stubs instead.
 */
import { mount as baseMount, shallowMount as baseShallowMount, type MountingOptions } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import { h, type Component, type SetupContext } from 'vue'

/**
 * Loose-typed alias for stub-component props/setup-context inside this file.
 *
 * The Quasar stubs below mirror Quasar's runtime API only loosely; each stub
 * accepts whatever attributes the real component would, and slot signatures
 * vary widely. Using `Record<string, unknown>` for props keeps `any` out of
 * the surface but still lets the bodies index into props/attrs without a
 * forest of overloads. The trade-off is intentional: these are internal test
 * doubles, not production components, and replicating Quasar's full typings
 * here would be more error-prone than helpful.
 */
type StubProps = Record<string, unknown>

/**
 * Minimal shape of a Quasar q-table column descriptor as consumed by the
 * stub above. Mirrors only the fields the stub actually reads; production
 * components import the full QTableColumn from 'quasar'.
 */
interface QTableColumn {
  name: string
  label: string
  field: string | ((row: Record<string, unknown>) => unknown)
  format?: (value: unknown) => unknown
}
// Vue's SetupContext is generic over the emits map; the Quasar stubs below
// accept any emit signature by design (see StubProps above). Tightening
// this is a larger refactor of the test infrastructure, not in scope here.
// eslint-disable-next-line @typescript-eslint/no-explicit-any -- weakly typed test-stub context, intentional
type StubCtx = SetupContext<any>

const QUASAR_STUBS: Record<string, Component> = {
  'q-card': {
    inheritAttrs: false,
    props: ['flat', 'bordered', 'clickable'],
    setup(_props: StubProps, { slots, attrs }: StubCtx) {
      return () => h('div', { ...attrs, class: ['q-card', attrs.class].filter(Boolean) }, slots.default?.())
    },
  },
  'q-card-section': {
    props: ['horizontal'],
    setup(_props: StubProps, { slots, attrs }: StubCtx) {
      return () => h('div', { ...attrs, class: ['q-card-section', attrs.class].filter(Boolean) }, slots.default?.())
    },
  },
  'q-icon': {
    props: ['name', 'size', 'color'],
    setup(props: StubProps, { attrs }: StubCtx) {
      return () => h('i', { ...attrs, class: ['q-icon', attrs.class].filter(Boolean) }, props.name)
    },
  },
  'q-badge': {
    props: ['color', 'label', 'floating'],
    setup(props: StubProps, { slots, attrs }: StubCtx) {
      return () =>
        h(
          'span',
          {
            ...attrs,
            class: ['q-badge', props.color ? `bg-${props.color}` : '', attrs.class].filter(Boolean),
          },
          slots.default?.() ?? props.label,
        )
    },
  },
  'q-chip': {
    props: ['dense', 'size', 'color', 'textColor', 'outline', 'icon'],
    setup(props: StubProps, { slots, attrs }: StubCtx) {
      return () =>
        h(
          'span',
          {
            ...attrs,
            class: ['q-chip', props.color ? `bg-${props.color}` : '', attrs.class].filter(Boolean),
          },
          slots.default?.(),
        )
    },
  },
  'q-btn': {
    name: 'QBtn',
    props: ['flat', 'round', 'dense', 'icon', 'label', 'color', 'noCaps', 'disable'],
    emits: ['click'],
    setup(props: StubProps, { slots, attrs, emit }: StubCtx) {
      return () =>
        h(
          'button',
          {
            ...attrs,
            class: ['q-btn', props.color ? `text-${props.color}` : '', attrs.class].filter(Boolean),
            onClick: (e: Event) => emit('click', e),
          },
          [props.icon ? h('i', { class: 'q-icon' }, props.icon) : null, props.label ?? '', slots.default?.()],
        )
    },
  },
  'q-table': {
    props: [
      'rows',
      'columns',
      'rowKey',
      'pagination',
      'flat',
      'bordered',
      'dense',
      'noDataLabel',
      'noResultsLabel',
      'tableRowClassFn',
    ],
    emits: ['row-click'],
    setup(props: StubProps, { slots, emit }: StubCtx) {
      return () => {
        const rows = props.rows ?? []
        const columns = props.columns ?? []

        if (rows.length === 0) {
          const noDataSlot = slots['no-data']
          if (noDataSlot) {
            return h('div', { class: 'q-table' }, noDataSlot({ message: props.noDataLabel ?? 'No data' }))
          }
          return h('div', { class: 'q-table' }, props.noDataLabel ?? 'No data')
        }

        const headerCells = columns.map((col: QTableColumn) => h('th', { key: col.name }, col.label))

        const bodyRows = rows.map((row: Record<string, unknown>) => {
          const cells = columns.map((col: QTableColumn) => {
            const slotName = `body-cell-${col.name}`
            if (slots[slotName]) {
              return slots[slotName]({
                row,
                col,
                value: typeof col.field === 'function' ? col.field(row) : row[col.field],
              })
            }
            const rawValue = typeof col.field === 'function' ? col.field(row) : row[col.field]
            const value = col.format ? col.format(rawValue) : rawValue
            return h('td', { class: 'q-td', key: col.name }, String(value ?? ''))
          })
          // Mirrors Quasar's own `tableRowClassFn` handling so row-level
          // styling driven by row data is assertable in component tests.
          const rowClassFn = props.tableRowClassFn as ((row: Record<string, unknown>) => string) | undefined
          const rowClass = rowClassFn ? rowClassFn(row) : ''
          return h(
            'tr',
            {
              key: row[props.rowKey ?? 'id'],
              class: rowClass || undefined,
              onClick: (evt: Event) => emit('row-click', evt, row),
            },
            cells,
          )
        })

        return h('div', { class: 'q-table' }, [h('table', [h('thead', [h('tr', headerCells)]), h('tbody', bodyRows)])])
      }
    },
  },
  'q-markup-table': {
    props: ['flat', 'bordered', 'dense'],
    setup(_props: StubProps, { slots, attrs }: StubCtx) {
      return () => h('table', { ...attrs, class: ['q-markup-table', attrs.class].filter(Boolean) }, slots.default?.())
    },
  },
  'q-td': {
    props: ['props'],
    setup(_props: StubProps, { slots }: StubCtx) {
      return () => h('td', { class: 'q-td' }, slots.default?.())
    },
  },
  'q-separator': {
    props: ['spaced', 'vertical'],
    setup() {
      return () => h('hr', { class: 'q-separator' })
    },
  },
  'q-space': {
    setup() {
      return () => h('div', { class: 'q-space' })
    },
  },
  'q-linear-progress': {
    props: ['value', 'color', 'trackColor', 'rounded', 'size'],
    setup(props: StubProps) {
      return () => h('div', { class: 'q-linear-progress', 'data-value': props.value })
    },
  },
  'q-spinner': {
    props: ['color', 'size'],
    setup() {
      return () => h('div', { class: 'q-spinner' }, '⟳')
    },
  },
  'q-tabs': {
    name: 'QTabs',
    props: ['modelValue', 'dense'],
    emits: ['update:modelValue'],
    setup(_props: StubProps, { slots }: StubCtx) {
      return () => h('div', { class: 'q-tabs' }, slots.default?.())
    },
  },
  'q-tab': {
    props: ['name', 'icon', 'label'],
    setup(props: StubProps, { slots }: StubCtx) {
      // Quasar renders both the `label` prop and the default slot; mirror
      // that so slot-labelled tabs (e.g. the conditional Enrichment tab)
      // expose their text to component tests.
      return () => h('div', { class: 'q-tab' }, [props.label, slots.default?.()])
    },
  },
  'q-tab-panels': {
    props: ['modelValue', 'animated'],
    setup(_props: StubProps, { slots }: StubCtx) {
      return () => h('div', { class: 'q-tab-panels' }, slots.default?.())
    },
  },
  'q-tab-panel': {
    props: ['name'],
    setup(_props: StubProps, { slots }: StubCtx) {
      return () => h('div', { class: 'q-tab-panel' }, slots.default?.())
    },
  },
  'q-page': {
    props: ['padding'],
    setup(_props: StubProps, { slots }: StubCtx) {
      return () => h('div', { class: 'q-page' }, slots.default?.())
    },
  },
  'q-tooltip': {
    props: ['anchor', 'self'],
    setup(_props: StubProps, { slots }: StubCtx) {
      return () => h('span', { class: 'q-tooltip' }, slots.default?.())
    },
  },
  'q-select': {
    name: 'QSelect',
    props: ['modelValue', 'options', 'label', 'outlined', 'dense', 'emitValue', 'mapOptions'],
    emits: ['update:modelValue'],
    setup(props: StubProps, { attrs, emit }: StubCtx) {
      return () =>
        h(
          'select',
          {
            ...attrs,
            class: ['q-select', attrs.class].filter(Boolean),
            value: props.modelValue,
            onChange: (e: Event) => emit('update:modelValue', (e.target as HTMLSelectElement).value),
          },
          ((props.options as { label: string; value: string }[]) ?? []).map((opt: { label: string; value: string }) =>
            h('option', { value: opt.value }, opt.label),
          ),
        )
    },
  },
  'q-input': {
    props: [
      'modelValue',
      'label',
      'dense',
      'outlined',
      'readonly',
      'type',
      'placeholder',
      'autogrow',
      'maxlength',
      'disable',
    ],
    emits: ['update:modelValue'],
    setup(props: StubProps, { slots, attrs, emit }: StubCtx) {
      return () =>
        h('div', { class: 'q-input' }, [
          h('input', {
            ...attrs,
            value: props.modelValue,
            type: props.type,
            readonly: props.readonly,
            disabled: props.disable,
            placeholder: props.placeholder,
            onInput: (e: Event) => emit('update:modelValue', (e.target as HTMLInputElement).value),
          }),
          slots.append?.(),
        ])
    },
  },
  'q-list': {
    props: ['bordered'],
    setup(_props: StubProps, { slots }: StubCtx) {
      return () => h('div', { class: 'q-list' }, slots.default?.())
    },
  },
  'q-expansion-item': {
    props: ['icon', 'label', 'headerClass', 'defaultOpened'],
    setup(props: StubProps, { slots }: StubCtx) {
      return () =>
        h('div', { class: 'q-expansion-item' }, [
          h('div', { class: 'q-expansion-item__header' }, slots.header?.() ?? props.label),
          slots.default?.(),
        ])
    },
  },
  'q-banner': {
    props: ['rounded'],
    setup(_props: StubProps, { slots }: StubCtx) {
      return () => h('div', { class: 'q-banner' }, [slots.avatar?.(), slots.default?.(), slots.action?.()])
    },
  },
  'q-dialog': {
    props: ['modelValue', 'persistent'],
    emits: ['update:modelValue'],
    setup(_props: StubProps, { slots }: StubCtx) {
      return () => h('div', { class: 'q-dialog' }, slots.default?.())
    },
  },
  'q-item': {
    props: ['clickable', 'tag', 'href', 'target', 'rel', 'dense'],
    setup(_props: StubProps, { slots, attrs }: StubCtx) {
      return () => h('div', { ...attrs, class: ['q-item', attrs.class].filter(Boolean) }, slots.default?.())
    },
  },
  'q-item-section': {
    props: ['avatar', 'side'],
    setup(_props: StubProps, { slots, attrs }: StubCtx) {
      return () => h('div', { ...attrs, class: ['q-item-section', attrs.class].filter(Boolean) }, slots.default?.())
    },
  },
  'q-item-label': {
    props: ['header', 'caption', 'lines', 'overline'],
    setup(_props: StubProps, { slots, attrs }: StubCtx) {
      return () => h('div', { ...attrs, class: ['q-item-label', attrs.class].filter(Boolean) }, slots.default?.())
    },
  },
  'q-card-actions': {
    props: ['align'],
    setup(_props: StubProps, { slots, attrs }: StubCtx) {
      return () => h('div', { ...attrs, class: ['q-card-actions', attrs.class].filter(Boolean) }, slots.default?.())
    },
  },
  'q-toggle': {
    props: ['modelValue', 'label', 'disable'],
    emits: ['update:modelValue'],
    setup(props: StubProps, { attrs, emit }: StubCtx) {
      return () =>
        h('label', { ...attrs, class: ['q-toggle', attrs.class].filter(Boolean) }, [
          h('input', {
            type: 'checkbox',
            checked: !!props.modelValue,
            disabled: props.disable,
            onChange: (e: Event) => emit('update:modelValue', (e.target as HTMLInputElement).checked),
          }),
          props.label ?? '',
        ])
    },
  },
  'q-inner-loading': {
    props: ['showing', 'label'],
    setup(_props: StubProps, { slots }: StubCtx) {
      return () => h('div', { class: 'q-inner-loading' }, slots.default?.())
    },
  },
  'q-btn-toggle': {
    props: ['modelValue', 'options', 'dense', 'outline'],
    emits: ['update:modelValue'],
    setup(props: StubProps, { attrs, emit }: StubCtx) {
      return () =>
        h(
          'div',
          { ...attrs, class: ['q-btn-toggle', attrs.class].filter(Boolean) },
          ((props.options as { label: string; value: string }[]) ?? []).map((opt: { label: string; value: string }) =>
            h(
              'button',
              {
                class: opt.value === props.modelValue ? 'on' : '',
                onClick: () => emit('update:modelValue', opt.value),
              },
              opt.label,
            ),
          ),
        )
    },
  },
  'q-menu': {
    props: ['autoClose'],
    setup(_props: StubProps, { slots }: StubCtx) {
      return () => h('div', { class: 'q-menu' }, slots.default?.())
    },
  },
  'q-checkbox': {
    props: ['modelValue', 'val', 'dense'],
    emits: ['update:modelValue'],
    setup(props: StubProps, { attrs, emit }: StubCtx) {
      return () => {
        const values = Array.isArray(props.modelValue) ? props.modelValue : []
        const checked = values.includes(props.val)
        return h('label', { ...attrs, class: ['q-checkbox', attrs.class].filter(Boolean) }, [
          h('input', {
            type: 'checkbox',
            checked,
            onChange: (e: Event) => {
              const next = (e.target as HTMLInputElement).checked
                ? [...values, props.val]
                : values.filter((v: unknown) => v !== props.val)
              emit('update:modelValue', next)
            },
          }),
        ])
      }
    },
  },
  'q-option-group': {
    props: ['modelValue', 'options', 'type', 'dense'],
    emits: ['update:modelValue'],
    setup(props: StubProps, { attrs, emit }: StubCtx) {
      return () =>
        h(
          'div',
          { ...attrs, class: ['q-option-group', attrs.class].filter(Boolean) },
          ((props.options as { label: string; value: string }[]) ?? []).map((opt: { label: string; value: string }) =>
            h('label', { key: opt.value }, [
              h('input', {
                type: props.type === 'checkbox' ? 'checkbox' : 'radio',
                checked: Array.isArray(props.modelValue)
                  ? props.modelValue.includes(opt.value)
                  : props.modelValue === opt.value,
                onChange: (e: Event) => {
                  const checked = (e.target as HTMLInputElement).checked
                  if (props.type === 'checkbox' && Array.isArray(props.modelValue)) {
                    const next = checked
                      ? [...props.modelValue, opt.value]
                      : props.modelValue.filter((v: unknown) => v !== opt.value)
                    emit('update:modelValue', next)
                  } else {
                    emit('update:modelValue', opt.value)
                  }
                },
              }),
              opt.label,
            ]),
          ),
        )
    },
  },
}

/**
 * Build the global configuration object for Vue Test Utils mount.
 *
 * @param options - User-provided mounting options.
 * @returns Merged global config with Quasar stubs, Pinia, and Nuxt mocks.
 */
function buildGlobalConfig(options?: MountingOptions<unknown>) {
  const pinia = createPinia()
  setActivePinia(pinia)

  const userStubs = (options?.global?.stubs ?? {}) as Record<string, unknown>
  const userMocks = (options?.global?.mocks ?? {}) as Record<string, unknown>
  const userPlugins = (options?.global?.plugins ?? []) as unknown[]

  const qMock = {
    dark: { isActive: false },
    dialog: vi.fn().mockImplementation(() => {
      let okCb: (() => void) | undefined
      return {
        onOk: vi.fn((cb: () => void) => {
          okCb = cb
          return { onOk: vi.fn(), onCancel: vi.fn(), onDismiss: vi.fn() }
        }),
        onCancel: vi.fn(),
        onDismiss: vi.fn(),
        __triggerOk: () => okCb?.(),
      }
    }),
    notify: vi.fn(),
  }

  const quasarPlugin = {
    install(app: { provide: (key: symbol | string, value: unknown) => void }) {
      app.provide('$q', qMock)
      // Quasar's useQuasar composable also injects via a private symbol,
      // but the provide key above is the public contract.
    },
  }

  return {
    pinia,
    global: {
      plugins: [pinia, quasarPlugin, ...userPlugins],
      stubs: {
        ...QUASAR_STUBS,
        NuxtLink: { template: '<a><slot /></a>' },
        NuxtPage: { template: '<div />' },
        AlarmConnectionList: {
          name: 'AlarmConnectionList',
          template: '<div data-testid="connection-list" />',
          props: ['seriesIds'],
        },
        AlarmMacAssetList: {
          name: 'AlarmMacAssetList',
          template: '<div data-testid="mac-asset-list" />',
          props: ['macs'],
        },
        AlarmProtocolList: {
          name: 'AlarmProtocolList',
          template: '<div data-testid="protocol-list" />',
          props: ['protos'],
        },
        ...userStubs,
      },
      mocks: {
        $route: { meta: {}, query: {}, params: {}, path: '/' },
        $router: { push: vi.fn(), replace: vi.fn() },
        $q: qMock,
        ...userMocks,
      },
    },
  }
}

/**
 * Mount a component with Quasar stubs, Pinia, and Nuxt mocks pre-configured.
 *
 * @param component - The Vue component to mount.
 * @param options - Optional Vue Test Utils mounting options (merged with defaults).
 * @returns The mounted wrapper instance.
 */
export function mountWithPlugins<T extends Component>(component: T, options?: MountingOptions<unknown>) {
  const { global: globalConfig } = buildGlobalConfig(options)

  return baseMount(component, {
    ...options,
    global: globalConfig,
  })
}

/**
 * Shallow-mount a component with Quasar stubs, Pinia, and Nuxt mocks pre-configured.
 *
 * Use when deep rendering causes issues with child components.
 *
 * @param component - The Vue component to mount.
 * @param options - Optional Vue Test Utils mounting options (merged with defaults).
 * @returns The shallow-mounted wrapper instance.
 */
export function shallowMountWithPlugins<T extends Component>(component: T, options?: MountingOptions<unknown>) {
  const { global: globalConfig } = buildGlobalConfig(options)

  return baseShallowMount(component, {
    ...options,
    global: globalConfig,
  })
}
