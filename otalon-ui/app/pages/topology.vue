<template>
  <q-page class="time-toolbar-page">
    <SharedTimeToolbarRow toolbar-class="col" @update="onTimeUpdate" />

    <SharedErrorBanner :message="topologyStore.error" @retry="reload()" @dismiss="topologyStore.error = null" />

    <q-banner v-if="topologyStore.isTruncated" dense class="bg-warning text-dark q-mb-sm">
      <template #avatar>
        <q-icon name="filter_alt" />
      </template>
      Showing the first {{ topology.nodes.length }} of {{ topologyStore.nodeCount }} nodes. Some devices are not
      displayed.
      <template #action>
        <q-btn flat dense no-caps label="Show more nodes" :disable="topologyStore.isLoading" @click="showMoreNodes()" />
      </template>
    </q-banner>

    <div style="position: relative; min-height: 300px">
      <q-inner-loading :showing="topologyStore.isLoading" label="Loading topology…" />

      <template v-if="!topologyStore.isLoading">
        <TopologyNetworkGraph
          :node-count="topology.nodes.length"
          :edge-count="topology.edges.length"
          @node-click="onNodeClick"
          @edge-click="onEdgeClick"
        />

        <q-card flat bordered class="q-mt-sm legend-card">
          <q-card-section class="q-pa-sm">
            <div class="row q-gutter-sm items-center">
              <q-chip
                v-for="cat in legendItems"
                :key="cat.type"
                dense
                :icon="cat.icon"
                :style="{ backgroundColor: cat.color, color: '#fff' }"
                size="sm"
              >
                {{ cat.type }}
              </q-chip>
              <q-chip dense icon="circle" color="negative" text-color="white" size="sm"> Anomaly </q-chip>
              <q-chip dense icon="remove" color="grey-7" text-color="white" size="sm"> Normal Edge </q-chip>
            </div>
          </q-card-section>
        </q-card>
      </template>
    </div>

    <q-dialog v-model="detailDialogOpen" position="right" full-height seamless>
      <q-card class="topo-detail-dialog">
        <q-card-section class="row items-center q-pb-none">
          <div class="text-h6">{{ dialogTitle }}</div>
          <q-space />
          <q-btn v-close-popup icon="close" flat round dense />
        </q-card-section>

        <q-card-section class="q-pt-sm">
          <template v-if="detailMode === 'node' && selectedNode">
            <div class="node-details">
              <q-list dense>
                <q-item>
                  <q-item-section avatar>
                    <q-icon
                      :name="nodeIcon(selectedNode.type)"
                      :color="selectedNode.isAnomaly ? 'negative' : 'primary'"
                      size="sm"
                    />
                  </q-item-section>
                  <q-item-section>
                    <q-item-label caption>Device Name</q-item-label>
                    <q-item-label class="text-weight-bold">
                      {{ resolveNodeLabel(selectedNode) }}
                    </q-item-label>
                  </q-item-section>
                </q-item>

                <q-separator spaced />

                <q-item>
                  <q-item-section>
                    <q-item-label caption>Type</q-item-label>
                    <q-item-label>
                      <q-chip
                        dense
                        :icon="nodeIcon(selectedNode.type)"
                        :color="typeChipColor(selectedNode.type)"
                        text-color="white"
                        size="sm"
                      >
                        {{ selectedNode.type }}
                      </q-chip>
                    </q-item-label>
                  </q-item-section>
                </q-item>

                <q-item v-if="nodeIp">
                  <q-item-section>
                    <q-item-label caption>IP Address</q-item-label>
                    <q-item-label class="text-mono">{{ nodeIp }}</q-item-label>
                  </q-item-section>
                </q-item>

                <q-item v-if="nodeMac">
                  <q-item-section>
                    <q-item-label caption>MAC Address</q-item-label>
                    <q-item-label class="text-mono">{{ nodeMac }}</q-item-label>
                  </q-item-section>
                </q-item>

                <q-item>
                  <q-item-section>
                    <q-item-label caption>Status</q-item-label>
                    <q-item-label>
                      <SharedStatusBadge
                        :status="selectedNode.isAnomaly ? 'error' : 'running'"
                        :label="selectedNode.isAnomaly ? 'Anomaly' : 'Normal'"
                      />
                    </q-item-label>
                  </q-item-section>
                </q-item>

                <q-separator spaced />

                <q-item>
                  <q-item-section>
                    <q-item-label caption> Connections ({{ connectedEdges.length }}) </q-item-label>
                  </q-item-section>
                </q-item>

                <q-item v-for="edge in connectedEdges" :key="edge.id" dense class="q-pl-md">
                  <q-item-section avatar>
                    <q-icon name="link" :color="edge.isAnomaly ? 'negative' : 'grey-7'" size="xs" />
                  </q-item-section>
                  <q-item-section>
                    <q-item-label class="text-caption">
                      {{ edgePeer(edge) }}
                    </q-item-label>
                    <q-item-label caption>
                      {{ edgeProtocols(edge) }}
                    </q-item-label>
                  </q-item-section>
                  <q-item-section v-if="edge.isAnomaly" side>
                    <q-badge color="negative" label="Anomaly" />
                  </q-item-section>
                </q-item>

                <q-separator spaced />

                <q-item>
                  <q-item-section>
                    <q-btn
                      color="primary"
                      :icon="DOMAIN_ICONS.assets"
                      label="Open in Assets"
                      no-caps
                      outline
                      :disable="!isResolvedDevice(selectedNode)"
                      class="full-width"
                      @click="openInAssets(selectedNode)"
                    >
                      <q-tooltip v-if="!isResolvedDevice(selectedNode)">
                        This node is not in the Asset inventory
                      </q-tooltip>
                      <q-tooltip v-else> Open device #{{ selectedNode.id }} on the Assets page </q-tooltip>
                    </q-btn>
                  </q-item-section>
                </q-item>
              </q-list>
            </div>
          </template>

          <template v-else-if="detailMode === 'edge' && selectedEdgeDetails">
            <div class="connection-details">
              <q-list dense>
                <q-item>
                  <q-item-section avatar>
                    <q-icon name="arrow_forward" color="primary" size="sm" />
                  </q-item-section>
                  <q-item-section>
                    <q-item-label caption>Source Node</q-item-label>
                    <q-item-label class="text-weight-bold">
                      {{ resolveNodeLabel(selectedEdgeDetails.sourceNode) }}
                    </q-item-label>
                    <q-item-label v-if="resolveNodeIp(selectedEdgeDetails.sourceNode)" caption class="text-mono">
                      {{ resolveNodeIp(selectedEdgeDetails.sourceNode) }}
                    </q-item-label>
                  </q-item-section>
                </q-item>

                <q-item>
                  <q-item-section avatar>
                    <q-icon name="arrow_back" color="secondary" size="sm" />
                  </q-item-section>
                  <q-item-section>
                    <q-item-label caption>Target Node</q-item-label>
                    <q-item-label class="text-weight-bold">
                      {{ resolveNodeLabel(selectedEdgeDetails.targetNode) }}
                    </q-item-label>
                    <q-item-label v-if="resolveNodeIp(selectedEdgeDetails.targetNode)" caption class="text-mono">
                      {{ resolveNodeIp(selectedEdgeDetails.targetNode) }}
                    </q-item-label>
                  </q-item-section>
                </q-item>

                <q-separator spaced />

                <q-item>
                  <q-item-section>
                    <q-item-label caption>Protocol(s)</q-item-label>
                    <q-item-label>
                      <q-chip
                        v-for="proto in displayProtocols"
                        :key="proto"
                        dense
                        color="blue-grey-7"
                        text-color="white"
                        size="sm"
                        class="q-mr-xs"
                      >
                        {{ proto }}
                      </q-chip>
                      <span v-if="displayProtocols.length === 0" class="text-grey-6">Unknown</span>
                    </q-item-label>
                  </q-item-section>
                </q-item>

                <q-item>
                  <q-item-section>
                    <q-item-label caption>Anomaly Status</q-item-label>
                    <q-item-label>
                      <SharedStatusBadge
                        :status="selectedEdgeDetails.isAnomaly ? 'error' : 'running'"
                        :label="selectedEdgeDetails.isAnomaly ? 'Anomaly' : 'Normal'"
                      />
                    </q-item-label>
                  </q-item-section>
                </q-item>

                <q-separator spaced />

                <q-item>
                  <q-item-section>
                    <q-btn
                      color="primary"
                      :icon="DOMAIN_ICONS.connections"
                      label="Open in Connections"
                      no-caps
                      unelevated
                      class="full-width"
                      @click="navigateToConnections"
                    />
                  </q-item-section>
                </q-item>
              </q-list>
            </div>
          </template>
        </q-card-section>
      </q-card>
    </q-dialog>
  </q-page>
</template>

<script setup lang="ts">
import type { TopologyNode, TopologyEdge, NodeType } from '~/types/golden-data'
import type { EdgeDetails } from '~/composables/useTopologyGraph'
import type { TopologyGraphResponse } from '~/types/api'
import { provideChatContext, makeVisibleTable } from '~/composables/useChatContext'
import { DOMAIN_ICONS } from '~/composables/useNavigation'
import { useDevicesStore } from '~/stores/devicesStore'
import { getCssVar } from '~/utils/cssVar'

/**
 * Topology page with a full-width interactive ECharts network graph.
 *
 * Node and edge selection opens a detail dialog sliding in from the right.
 * Uses the topologyStore for API data and useTopologyGraph composable for
 * ECharts rendering and selection helpers.
 *
 * In live mode, topology updates are also received via SSE (topic `topology`)
 * so the graph refreshes automatically when the backend emitter fires.
 * Polling continues as a fallback for when the SSE connection is interrupted.
 */

definePageMeta({
  title: 'Topology',
})

const router = useRouter()
const appStore = useAppStore()
const topologyStore = useTopologyStore()
const devicesStore = useDevicesStore()

const {
  topology,
  selectedNode,
  connectedEdges,
  selectNode,
  getEdgeDetails,
  resolveNodeLabel,
  resolveNodeIp,
  resolveNodeMac,
} = useTopologyGraph()

type DetailMode = 'node' | 'edge' | 'none'
const detailMode = ref<DetailMode>('none')
const selectedEdgeDetails = ref<EdgeDetails | null>(null)
const detailDialogOpen = ref(false)

/**
 * Node cap requested from the API.
 *
 * The reload path previously passed no limit at all, so the backend applied
 * its own default and the resulting `meta.truncated` flag had no consumer —
 * the operator silently saw a partial graph (audit UI-11). The limit is now
 * explicit and can be raised from the truncation banner.
 */
const DEFAULT_NODE_LIMIT = 100
const NODE_LIMIT_STEP = 200
const nodeLimit = ref(DEFAULT_NODE_LIMIT)

/**
 * Reload topology data from the API using the current time parameters.
 */
async function reload(): Promise<void> {
  const { start, stop } = appStore.freshApiTimeParams()
  await topologyStore.fetchGraph(start, stop, nodeLimit.value)
  await devicesStore.fetchDevices()
}

/**
 * Raise the node cap and reload, so a truncated graph can be expanded.
 */
async function showMoreNodes(): Promise<void> {
  nodeLimit.value += NODE_LIMIT_STEP
  await reload()
}

onMounted(() => {
  reload()
})

provideChatContext(() => {
  const graph = topologyStore.graph
  const nodes = graph?.nodes ?? []
  const edges = graph?.edges ?? []

  // Surface up to MAX_VISIBLE_ROWS anomalous nodes/edges first because
  // those are usually what the user wants to ask about.
  const anomalousNodes = nodes.filter((n) => n.isAnomaly)
  const sampleNodes = (anomalousNodes.length > 0 ? anomalousNodes : nodes).map((n) => ({
    id: n.id,
    label: n.label ?? null,
    type: n.type ?? null,
    is_anomaly: !!n.isAnomaly,
  }))

  const anomalousEdges = edges.filter((e) => e.isAnomaly)
  const sampleEdges = (anomalousEdges.length > 0 ? anomalousEdges : edges).map((e) => ({
    id: e.id,
    source: e.source,
    target: e.target,
    is_anomaly: !!e.isAnomaly,
  }))

  const selNode = topologyStore.selectedNode
  const selEdge = topologyStore.selectedEdge
  const selection = selNode
    ? {
        kind: 'topology_node',
        id: selNode.id,
        label: selNode.label ?? selNode.id,
        fields: {
          type: selNode.type ?? null,
          is_anomaly: !!selNode.isAnomaly,
        },
      }
    : selEdge
      ? {
          kind: 'topology_edge',
          id: selEdge.id,
          label: `${selEdge.source} ↔ ${selEdge.target}`,
          fields: {
            source: selEdge.source,
            target: selEdge.target,
            is_anomaly: !!selEdge.isAnomaly,
          },
        }
      : undefined

  return {
    selection,
    summary: {
      n_nodes: topologyStore.nodeCount,
      n_edges: topologyStore.edgeCount,
      n_anomalous_nodes: anomalousNodes.length,
      n_anomalous_edges: anomalousEdges.length,
      anomaly_node_count: topologyStore.anomalyNodeCount,
      anomaly_edge_count: topologyStore.anomalyEdgeCount,
    },
    visible_data: [
      makeVisibleTable('topology_nodes', ['id', 'label', 'type', 'is_anomaly'], sampleNodes),
      makeVisibleTable('topology_edges', ['id', 'source', 'target', 'is_anomaly'], sampleEdges),
    ],
  }
})

const liveModeEnabled = computed(() => appStore.liveMode)

usePolling(() => reload(), 60_000, { immediate: false, enabled: liveModeEnabled })

useSse('topology', {
  enabled: liveModeEnabled,
  onEvent: (_topic: string, data: unknown) => {
    topologyStore.handleTopologyUpdate(data as TopologyGraphResponse)
  },
})

watch(
  () => appStore.liveIntervalSeconds,
  () => {
    reload()
  },
)

const NODE_ICONS: Record<NodeType, string> = {
  PLC: 'memory',
  IPC: 'computer',
  IO: 'settings_input_component',
  Other: 'device_hub',
}

const TYPE_CHIP_COLORS: Record<NodeType, string> = {
  PLC: 'blue-6',
  IPC: 'purple-6',
  IO: 'orange-7',
  Other: 'blue-grey-6',
}

const legendItems = computed(() => [
  { type: 'PLC', icon: 'memory', color: getCssVar('--cd-topo-plc', '#42A5F5') },
  { type: 'IPC', icon: 'computer', color: getCssVar('--cd-topo-ipc', '#AB47BC') },
  { type: 'IO', icon: 'settings_input_component', color: getCssVar('--cd-topo-io', '#FFA726') },
  { type: 'Other', icon: 'device_hub', color: getCssVar('--cd-topo-other', '#78909C') },
])

/**
 * Computed dialog title based on the current detail mode.
 */
const dialogTitle = computed(() => {
  if (detailMode.value === 'node') return 'Node Details'
  if (detailMode.value === 'edge') return 'Connection Details'
  return 'Details'
})

const nodeIp = computed(() => {
  if (!selectedNode.value) return ''
  return resolveNodeIp(selectedNode.value)
})

const nodeMac = computed(() => {
  if (!selectedNode.value) return ''
  return resolveNodeMac(selectedNode.value)
})

/**
 * Shortened protocol list for the edge detail panel display.
 */
const displayProtocols = computed<string[]>(() => {
  if (!selectedEdgeDetails.value) return []
  return selectedEdgeDetails.value.protocols.map((p) => {
    const parts = p.split(':')
    return parts.length > 2 ? parts.slice(-2).join(':') : (parts.pop() ?? p)
  })
})

function nodeIcon(type: NodeType): string {
  return NODE_ICONS[type] ?? 'device_hub'
}

function typeChipColor(type: NodeType): string {
  return TYPE_CHIP_COLORS[type] ?? 'blue-grey-6'
}

/**
 * Handle node click — open the detail dialog in node mode.
 */
function onNodeClick(nodeId: string): void {
  selectNode(nodeId)
  selectedEdgeDetails.value = null
  detailMode.value = 'node'
  detailDialogOpen.value = true
}

/**
 * Handle edge click events from the NetworkGraph component.
 *
 * Retrieves enriched edge details and opens the detail dialog in edge mode.
 */
function onEdgeClick(payload: { source: string; target: string; edge: Record<string, unknown> }): void {
  selectNode(null)
  const details = getEdgeDetails(payload.source, payload.target)
  selectedEdgeDetails.value = details
  detailMode.value = details ? 'edge' : 'none'
  if (details) {
    detailDialogOpen.value = true
  }
}

/**
 * Handle time toolbar update events — reload graph data.
 */
function onTimeUpdate(): void {
  reload()
}

/**
 * Test whether a topology node corresponds to a row in the ``devices``
 * inventory.  Resolved nodes carry a numeric ID equal to the device
 * primary key; unresolved nodes use the ``unresolved:...`` prefix.
 */
function isResolvedDevice(node: TopologyNode | null): boolean {
  if (!node) return false
  return /^\d+$/.test(node.id)
}

/**
 * Navigate to the Assets page with a query parameter that auto-selects the
 * matching device row and opens its detail panel.
 */
function openInAssets(node: TopologyNode | null): void {
  if (!isResolvedDevice(node)) return
  detailDialogOpen.value = false
  router.push({ path: '/devices', query: { device: node!.id } })
}

/**
 * Determine the peer node label for a given edge relative to the selected node.
 */
function edgePeer(edge: TopologyEdge): string {
  if (!selectedNode.value) return ''
  const peerId = edge.source === selectedNode.value.id ? edge.target : edge.source
  const peerNode = topology.value.nodes.find((n) => n.id === peerId)
  return peerNode ? resolveNodeLabel(peerNode) : peerId
}

/**
 * Format the protocol list for an edge as a short display string.
 */
function edgeProtocols(edge: TopologyEdge): string {
  const protocols = edge.meta?.protocols ?? []
  if (protocols.length === 0) return 'Unknown'
  return protocols
    .map((p) => {
      const parts = p.split(':')
      return parts.length > 2 ? parts.slice(-2).join(':') : (parts.pop() ?? p)
    })
    .join(', ')
}

/**
 * Navigate to the connections page with the first UCI from the selected edge.
 *
 * When the edge is flagged as anomaly, the UCI is also passed as
 * ``alarmUci`` so the connections page can look up and pre-set the
 * matching alarm group filter.
 */
function navigateToConnections(): void {
  detailDialogOpen.value = false
  if (!selectedEdgeDetails.value) {
    navigateTo('/connections')
    return
  }
  const query: Record<string, string> = {}
  const ucis = selectedEdgeDetails.value.ucis ?? []
  if (ucis.length > 0) {
    query.uci = ucis[0]
  }
  if (selectedEdgeDetails.value.isAnomaly && ucis.length > 0) {
    query.alarmUci = ucis[0]
  }
  navigateTo({ path: '/connections', query })
}
</script>

<style scoped lang="scss">
.legend-card {
  background-color: var(--cd-surface);
  border-color: var(--cd-border);
}

.topo-detail-dialog {
  min-width: 350px;
  max-width: 550px;
  width: 480px;
  margin-top: 50px;
  height: calc(100dvh - var(--cd-header-height, 51px)) !important;
  max-height: calc(100dvh - var(--cd-header-height, 51px)) !important;
  border-radius: 0;
  background-color: var(--cd-surface);
}

.text-mono {
  font-family: $font-family-mono;
  font-size: 0.85rem;
}
</style>
