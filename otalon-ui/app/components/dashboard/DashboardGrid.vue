<template>
  <ClientOnly>
    <template v-if="$q.screen.gt.sm">
      <GridLayout
        v-model:layout="gridLayout"
        :col-num="8"
        :row-height="140"
        :margin="[12, 12]"
        :is-draggable="layoutStore.editMode"
        :is-resizable="layoutStore.editMode"
        :responsive="false"
        :vertical-compact="true"
        :use-css-transforms="true"
        @layout-updated="onLayoutUpdated"
      >
        <GridItem
          v-for="item in gridLayout"
          :key="item.i"
          v-bind="item"
          :min-w="WIDGET_REGISTRY[item.i]?.minW ?? 1"
          :min-h="WIDGET_REGISTRY[item.i]?.minH ?? 1"
          :max-w="8"
          :max-h="8"
          drag-allow-from=".widget-drag-handle"
          class="grid-item"
          :class="{ 'grid-item--editing': layoutStore.editMode }"
        >
          <q-icon
            v-show="layoutStore.editMode"
            name="drag_indicator"
            class="widget-drag-handle"
            :aria-label="`Drag ${item.i}`"
          />
          <component :is="resolveWidget(item.i)" />
        </GridItem>
      </GridLayout>
    </template>
    <template v-else>
      <div class="column q-gutter-md">
        <div v-for="item in mobileItems" :key="item.i">
          <component :is="resolveWidget(item.i)" />
        </div>
      </div>
    </template>
  </ClientOnly>
</template>

<script setup lang="ts">
import { GridLayout, GridItem } from 'grid-layout-plus'
import { useQuasar } from 'quasar'
import { WIDGET_REGISTRY, type WidgetLayoutItem } from '~/components/dashboard/widgets/registry'
import { useDashboardLayoutStore } from '~/stores/dashboardLayoutStore'

const $q = useQuasar()
const layoutStore = useDashboardLayoutStore()

const gridLayout = ref<WidgetLayoutItem[]>(layoutStore.visibleLayout.map((v) => ({ ...v })))

/**
 * Compare two layouts for geometric equality (id, x, y, w, h).
 */
function sameGeometry(a: WidgetLayoutItem[], b: WidgetLayoutItem[]): boolean {
  if (a.length !== b.length) return false
  const index = new Map(b.map((item) => [item.i, item]))
  for (const item of a) {
    const other = index.get(item.i)
    if (!other) return false
    if (other.x !== item.x || other.y !== item.y || other.w !== item.w || other.h !== item.h) {
      return false
    }
  }
  return true
}

watch(
  () => layoutStore.visibleLayout,
  (val) => {
    if (sameGeometry(gridLayout.value, val)) return
    gridLayout.value = val.map((v) => ({ ...v }))
  },
)

const mobileItems = computed(() => {
  return [...layoutStore.visibleLayout].sort((a, b) => {
    if (a.y !== b.y) return a.y - b.y
    return a.x - b.x
  })
})

function resolveWidget(id: string) {
  const def = WIDGET_REGISTRY[id]
  if (!def) {
    return 'div'
  }
  return def.component
}

function onLayoutUpdated(next: WidgetLayoutItem[]): void {
  layoutStore.updateLayout(next)
}
</script>

<style scoped lang="scss">
.grid-item {
  transition: border 0.2s ease;

  &--editing {
    border: 1px dashed var(--q-primary);
    border-radius: 4px;
  }
}

.widget-drag-handle {
  position: absolute;
  top: 6px;
  right: 6px;
  z-index: 2;
  pointer-events: auto;
  cursor: move;
  opacity: 0.6;
  font-size: 20px;
}

:deep(.widget-drag-handle) {
  pointer-events: auto;
  cursor: move;
}
</style>
