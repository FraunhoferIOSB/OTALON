/**
 * Regression test for the alarm-detail context leak (UI-076a).
 *
 * The alarms page shows the alarm detail in a right-side ``<q-dialog>`` on
 * narrow viewports (``useSplitLayout === false``). When that dialog is
 * dismissed (ESC, backdrop click, or programmatic ``v-model = false``) the
 * page must reset both ``alarmDetailOpen`` and ``alarmsStore.selectedGroup``,
 * because the chat-context provider (``buildAlarmsContribution`` in
 * ``app/utils/chatContext.ts``) keeps appending the selected alarm detail to
 * the LLM context for as long as ``detailOpen`` (fed from ``alarmDetailOpen``)
 * is ``true``.
 *
 * Quasar 2.19.0 ``QDialog`` has **no** ``close`` event — its dismiss event is
 * ``hide`` (fires on ESC, backdrop click and programmatic hide). The first
 * UI-076a fix wired ``@close`` on the dialog, which is a dead listener that
 * never fires, so the leak persisted (a false green).
 *
 * These tests mount a harness that mirrors the exact narrow-mode dialog
 * wiring from ``app/pages/alarms.vue`` and dismiss the dialog the way a user
 * does — by driving the dialog's ``hide`` event. The ``QDialog`` stub used
 * here emits the real Quasar ``hide`` event whenever it transitions from
 * open → closed (as ESC, backdrop click and programmatic hide all do),
 * unlike the shared ``mount.ts`` stub, so the test genuinely discriminates
 * between an ``@hide`` binding (fix) and an ``@close`` binding (bug). A
 * source-level assertion additionally pins the fix into ``alarms.vue``.
 */
import { describe, it, expect } from 'vitest'
import { mount } from '@vue/test-utils'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { defineComponent, h, ref, watch, type Component } from 'vue'

/**
 * A ``q-dialog`` test double that mirrors the two Quasar behaviours the
 * real narrow-mode close paths depend on:
 *
 * 1. It respects ``v-model`` (renders its slot only while open), and
 * 2. Whenever it transitions from open → closed it emits the real Quasar
 *    ``hide`` event (fired on ESC, backdrop click and programmatic hide).
 *
 * It deliberately does **not** emit any ``close`` event, because QDialog has
 * none — that is the whole point of the regression.
 */
const HideEmittingDialogStub: Component = defineComponent({
  name: 'QDialog',
  props: { modelValue: { type: Boolean, default: false } },
  emits: ['update:modelValue', 'hide'],
  setup(props, { slots, emit }) {
    watch(
      () => props.modelValue,
      (now, was) => {
        if (was && !now) emit('hide')
      },
    )
    return () => (props.modelValue ? h('div', { class: 'q-dialog' }, slots.default?.()) : null)
  },
})

/**
 * Build a page-fragment harness that reproduces the narrow-mode alarm
 * detail dialog from ``alarms.vue`` including its close handler, wired to
 * the given dialog event name (``hide`` = fix, ``close`` = old bug).
 *
 * ``onCloseDetail`` mirrors the real page handler: clear the store
 * selection and reset both open flags. ``dismiss()`` flips the model to
 * ``false`` exactly as Quasar's ESC/backdrop/programmatic-hide paths do.
 */
function makeHarness(eventName: 'hide' | 'close') {
  const handlerProp = `on${eventName.charAt(0).toUpperCase()}${eventName.slice(1)}`
  return defineComponent({
    name: 'AlarmDialogHarness',
    setup(_props, { expose }) {
      const selectedGroupId = ref<string | null>('alarm-1')
      const detailDialogOpen = ref(true)
      const alarmDetailOpen = ref(true)

      function onCloseDetail(): void {
        selectedGroupId.value = null
        detailDialogOpen.value = false
        alarmDetailOpen.value = false
      }

      function dismiss(): void {
        detailDialogOpen.value = false
      }

      expose({ selectedGroupId, detailDialogOpen, alarmDetailOpen, dismiss })

      return () =>
        h(HideEmittingDialogStub, {
          modelValue: detailDialogOpen.value,
          'onUpdate:modelValue': (v: boolean) => {
            detailDialogOpen.value = v
          },
          // Wire the handler to exactly one event name so the test can prove
          // that only `@hide` reaches onCloseDetail.
          [handlerProp]: onCloseDetail,
        })
    },
  })
}

describe('alarm-detail dialog close wiring (UI-076a)', () => {
  it('resets alarmDetailOpen + selectedGroup when the dialog hides (@hide fix)', async () => {
    const wrapper = mount(makeHarness('hide'))
    const vm = wrapper.vm as unknown as {
      selectedGroupId: string | null
      detailDialogOpen: boolean
      alarmDetailOpen: boolean
      dismiss: () => void
    }

    // Detail is open and an alarm is selected — chat context would leak here.
    expect(vm.alarmDetailOpen).toBe(true)
    expect(vm.selectedGroupId).toBe('alarm-1')

    // Dismiss the dialog the way a user does (ESC / backdrop / programmatic
    // hide all funnel through the QDialog `hide` event).
    vm.dismiss()
    await wrapper.vm.$nextTick()

    expect(vm.alarmDetailOpen).toBe(false)
    expect(vm.selectedGroupId).toBeNull()
    expect(vm.detailDialogOpen).toBe(false)
  })

  it('would LEAK if wired to a non-existent @close event (proves the old bug)', async () => {
    // This harness replicates the pre-fix `@close="onCloseDetail"` binding.
    // Because QDialog never emits `close`, onCloseDetail is never called on
    // dismiss, so the detail state — and thus the chat-context leak —
    // persists. This asserts the failure mode the fix eliminates, which is
    // why an `@hide`-based test is required to catch the real defect.
    const wrapper = mount(makeHarness('close'))
    const vm = wrapper.vm as unknown as {
      selectedGroupId: string | null
      detailDialogOpen: boolean
      alarmDetailOpen: boolean
      dismiss: () => void
    }

    vm.dismiss()
    await wrapper.vm.$nextTick()

    // v-model flips (dialog is visually closed) but state is NOT reset:
    // the leak.
    expect(vm.detailDialogOpen).toBe(false)
    expect(vm.alarmDetailOpen).toBe(true)
    expect(vm.selectedGroupId).toBe('alarm-1')
  })

  it('binds @hide (not the dead @close) on the narrow-mode q-dialog in alarms.vue', () => {
    // Source-level pin: guarantees the running page uses the correct Quasar
    // dismiss event so the behavioural harness above stays representative.
    const alarmsVuePath = resolve(__dirname, '../../app/pages/alarms.vue')
    const source = readFileSync(alarmsVuePath, 'utf-8')

    // Isolate the opening <q-dialog ...> tag (the dialog element's own
    // listeners) — NOT the whole dialog block, which also contains the
    // inner AlarmDetailPanel whose @close emit legitimately routes through
    // onCloseDetail.
    const dialogStart = source.indexOf('<q-dialog')
    const dialogTag = source.slice(dialogStart, source.indexOf('>', dialogStart) + 1)

    // The dialog element must use the real Quasar dismiss event (@hide) and
    // must NOT carry the dead @close listener the false-green fix used.
    expect(dialogTag).toContain('@hide="onCloseDetail"')
    expect(dialogTag).not.toContain('@close')
  })
})
