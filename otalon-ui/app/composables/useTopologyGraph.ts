/**
 * Composable that transforms topology data into ECharts graph format.
 *
 * Renders nodes as colored circles with embedded device-type SVG icons,
 * supports dark/light mode theming, and delegates selection state to the
 * topology Pinia store.
 */

import type { TopologyNode, TopologyEdge, TopologyGraph, NodeType } from '~/types/golden-data'
import { useTopologyStore } from '~/stores/topologyStore'
import { useDeviceLookup } from '~/composables/useDeviceLookup'
import { getCssVar } from '~/utils/cssVar'

/**
 * Escape a value for safe interpolation into tooltip HTML.
 *
 * Node labels, IPs, MACs, and protocol names come from captured device data
 * and must not be able to inject markup into the ECharts tooltip.
 */
export function escapeTooltipHtml(value: unknown): string {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
}

/** ECharts node data element for a graph series. */
export interface GraphNodeData {
  name: string
  symbol: string
  symbolSize: number
  category: number
  itemStyle: { color: string; borderColor: string; borderWidth: number }
  label: { show: boolean; formatter: string; color: string; fontSize: number }
  originalNode: TopologyNode
}

/** ECharts link element for a graph series. */
export interface GraphLinkData {
  source: string
  target: string
  lineStyle: { color: string; width: number; type: string }
  label?: { show: boolean; formatter: string; fontSize: number; color: string }
  originalEdge: TopologyEdge
}

/** Category definition for the ECharts graph legend. */
export interface GraphCategory {
  name: string
  itemStyle: { color: string }
  symbol: string
}

/** Enriched edge details returned by getEdgeDetails(). */
export interface EdgeDetails {
  sourceNode: TopologyNode
  targetNode: TopologyNode
  protocols: string[]
  isAnomaly: boolean
  ucis: string[]
}

/**
 * Inline SVG body templates for each device type.
 *
 * The placeholder %S% is replaced at runtime with the appropriate stroke color
 * (dark strokes for light mode, white strokes for dark mode / anomaly).
 * Each body is wrapped in a group element with shared stroke attributes.
 */
const ICON_BODIES: Record<NodeType, { viewBox: string; body: string }> = {
  PLC: {
    viewBox: '0 0 290 290',
    body:
      '<g fill="none" stroke="%S%" stroke-linecap="round" stroke-linejoin="round" stroke-width="7">' +
      '<rect x="68" y="3.5" width="85" height="283"/>' +
      '<rect x="162" y="3.5" width="56" height="283"/>' +
      '<rect x="172" y="70" width="34" height="56"/>' +
      '<rect x="172" y="180" width="34" height="14"/>' +
      '<rect x="172" y="209" width="34" height="14"/>' +
      '</g>',
  },
  IPC: {
    viewBox: '0 0 290.465 290.465',
    body:
      '<g fill="none" stroke="%S%" stroke-linecap="round" stroke-linejoin="round" stroke-width="7">' +
      '<rect x="3.5" y="3.5" width="283.465" height="283.465"/>' +
      '<rect x="74.366" y="230.272" width="28.346" height="28.346"/>' +
      '<rect x="187.752" y="230.272" width="28.346" height="28.346"/>' +
      '<rect x="187.752" y="31.846" width="28.346" height="141.732"/>' +
      '<rect x="145.232" y="31.846" width="28.346" height="141.732"/>' +
      '<line x1="74.366" y1="173.579" x2="74.366" y2="163.579"/>' +
      '<line stroke-dasharray="0 0 17.39 17.39" x1="74.366" y1="146.188" x2="74.366" y2="50.542"/>' +
      '<line x1="74.366" y1="41.846" x2="74.366" y2="31.846"/>' +
      '<line x1="102.713" y1="31.846" x2="102.713" y2="41.846"/>' +
      '<line stroke-dasharray="0 0 17.39 17.39" x1="102.713" y1="59.237" x2="102.713" y2="154.884"/>' +
      '<line x1="102.713" y1="163.579" x2="102.713" y2="173.579"/>' +
      '</g>',
  },
  IO: {
    viewBox: '0 0 290.465 290.465',
    body:
      '<g fill="none" stroke="%S%" stroke-linecap="round" stroke-linejoin="round" stroke-width="7">' +
      '<rect x="3.5" y="3.5" width="85.039" height="283.465" rx="8.504" ry="8.504"/>' +
      '<path d="m97.043,3.5h49.134c4.693,0,8.504,3.81,8.504,8.504v104.882h-66.142V12.004c0-4.693,3.81-8.504,8.504-8.504Z"/>' +
      '<path d="m220.823,116.886h66.142v161.575c0,4.693-3.81,8.504-8.504,8.504h-49.134c-4.693,0-8.504-3.81-8.504-8.504V116.886h0Z"/>' +
      '<path d="m154.681,116.886h66.142v161.575c0,4.693-3.81,8.504-8.504,8.504h-49.134c-4.693,0-8.504-3.81-8.504-8.504V116.886h0Z"/>' +
      '<path d="m88.539,116.886h66.142v161.575c0,4.693-3.81,8.504-8.504,8.504h-49.134c-4.693,0-8.504-3.81-8.504-8.504V116.886h0Z"/>' +
      '<path d="m163.185,3.5h49.134c4.693,0,8.504,3.81,8.504,8.504v104.882h-66.142V12.004c0-4.693,3.81-8.504,8.504-8.504Z"/>' +
      '<path d="m229.327,3.5h49.134c4.693,0,8.504,3.81,8.504,8.504v104.882h-66.142V12.004c0-4.693,3.81-8.504,8.504-8.504Z"/>' +
      '<line x1="88.539" y1="116.886" x2="3.5" y2="116.886"/>' +
      '<rect x="31.846" y="159.406" width="28.346" height="28.346"/>' +
      '<rect x="31.846" y="216.098" width="28.346" height="28.346"/>' +
      '<rect x="114.524" y="31.846" width="14.173" height="56.693"/>' +
      '<rect x="180.665" y="31.846" width="14.173" height="56.693"/>' +
      '<rect x="246.807" y="31.846" width="14.173" height="56.693"/>' +
      '<line x1="107.437" y1="231.689" x2="135.783" y2="231.689"/>' +
      '<line x1="31.846" y1="31.846" x2="60.193" y2="31.846"/>' +
      '<line x1="173.579" y1="231.689" x2="201.925" y2="231.689"/>' +
      '<line x1="239.72" y1="231.689" x2="268.067" y2="231.689"/>' +
      '</g>',
  },
  Other: {
    viewBox: '0 0 64 64',
    body:
      '<g fill="none" stroke="%S%" stroke-width="3" stroke-linejoin="round">' +
      '<polygon points="32,8 52,20 52,44 32,56 12,44 12,20"/>' +
      '</g>',
  },
}

/**
 * Light-mode circle fill colors per device type.
 *
 * Uses light tints of each type's signature color to provide
 * clear visual distinction on light backgrounds.
 */
const CIRCLE_FILL_LIGHT: Record<NodeType, string> = {
  PLC: '#BBDEFB',
  IPC: '#E1BEE7',
  IO: '#FFE0B2',
  Other: '#CFD8DC',
}

/**
 * Dark-mode circle fill colors per device type.
 *
 * Uses muted dark shades of each type's signature color to provide
 * clear visual distinction on dark backgrounds.
 */
const CIRCLE_FILL_DARK: Record<NodeType, string> = {
  PLC: '#1E3A5F',
  IPC: '#3E1A5F',
  IO: '#5F3A1A',
  Other: '#37474F',
}

const NODE_SIZE = 48

const CATEGORY_INDEX: Record<NodeType, number> = {
  PLC: 0,
  IPC: 1,
  IO: 2,
  Other: 3,
}

const CATEGORY_COLOR_MAP: Record<NodeType, string> = {
  PLC: '--cd-topo-plc',
  IPC: '--cd-topo-ipc',
  IO: '--cd-topo-io',
  Other: '--cd-topo-other',
}

const CATEGORY_FALLBACKS: Record<NodeType, string> = {
  PLC: '#42a5f5',
  IPC: '#ab47bc',
  IO: '#ffa726',
  Other: '#78909c',
}

const symbolCache = new Map<string, string>()

/**
 * Resolve the current topology color palette from CSS custom properties.
 */
function getTopoColors() {
  return {
    plc: getCssVar('--cd-topo-plc', '#42a5f5'),
    ipc: getCssVar('--cd-topo-ipc', '#ab47bc'),
    io: getCssVar('--cd-topo-io', '#ffa726'),
    other: getCssVar('--cd-topo-other', '#78909c'),
    anomaly: getCssVar('--cd-topo-anomaly', '#ef5350'),
    anomalyBorder: getCssVar('--cd-topo-anomaly-border', '#b71c1c'),
    selectionBorder: getCssVar('--cd-topo-selection-border', '#ffd54f'),
    edge: getCssVar('--cd-graph-edge', '#546e7a'),
    edgeActive: getCssVar('--cd-graph-edge-active', '#00838f'),
  }
}

/**
 * Build an SVG data-URI symbol combining a colored circle with a device-type icon.
 *
 * Generates a composite SVG containing a filled circle background and a nested SVG
 * with the device icon scaled to fit inside. Results are cached per combination of
 * type, dark mode, and anomaly status.
 *
 * @param type - Device node type determining the icon shape.
 * @param dark - Whether dark mode is active.
 * @param isAnomaly - Whether the node has an anomaly status.
 * @returns ECharts-compatible image data URI string.
 */
function buildCircleNodeSymbol(type: NodeType, dark: boolean, isAnomaly: boolean): string {
  const key = `${type}-${dark ? 1 : 0}-${isAnomaly ? 1 : 0}`
  const cached = symbolCache.get(key)
  if (cached) return cached

  const colors = getTopoColors()
  const typeBorderMap: Record<NodeType, string> = {
    PLC: colors.plc,
    IPC: colors.ipc,
    IO: colors.io,
    Other: colors.other,
  }

  const circleColor = isAnomaly ? colors.anomaly : dark ? CIRCLE_FILL_DARK[type] : CIRCLE_FILL_LIGHT[type]

  const borderColor = isAnomaly ? colors.anomalyBorder : typeBorderMap[type]
  const strokeColor = dark || isAnomaly ? 'white' : '#263238'

  const icon = ICON_BODIES[type]
  const iconBody = icon.body.replaceAll('%S%', strokeColor)

  const svg =
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100">' +
    `<circle cx="50" cy="50" r="46" fill="${circleColor}" stroke="${borderColor}" stroke-width="2.5"/>` +
    `<svg x="18" y="18" width="64" height="64" viewBox="${icon.viewBox}">` +
    iconBody +
    '</svg></svg>'

  const dataUri = `image://data:image/svg+xml,${encodeURIComponent(svg)}`
  symbolCache.set(key, dataUri)
  return dataUri
}

/**
 * Identifier preference for {@link resolveNodeLabel}.
 *
 * - ``"auto"`` delegates to {@link useDeviceLookup.labelForEndpoint}, giving
 *   hostname → IP → MAC. Only {@link resolveNodeIp} / {@link resolveNodeMac}
 *   are consulted, so the result matches the Connections page.
 * - ``"ip"`` forces an IP-based label, falling back to MAC then label.
 * - ``"mac"`` forces a MAC-based label, falling back to IP then label.
 */
type IdentifierMode = 'auto' | 'ip' | 'mac'

function resolveLabelAuto(node: TopologyNode, deviceLookup: ReturnType<typeof useDeviceLookup>): string {
  const ip = resolveNodeIp(node)
  const mac = resolveNodeMac(node)
  return deviceLookup.labelForEndpoint(ip || null, mac || null) || node.id
}

/**
 * Derive a human-readable display label for a topology node.
 *
 * The optional *mode* parameter influences the fallback order so the user
 * can opt to always see IP or MAC identifiers in the graph instead of
 * mixed labels.
 *
 * This factory needs a live device-lookup instance because the asset-name
 * cache lives in the devices Pinia store.
 */
function buildResolveNodeLabel(deviceLookup: ReturnType<typeof useDeviceLookup>) {
  return function resolveNodeLabel(node: TopologyNode, mode: IdentifierMode = 'auto'): string {
    if (mode === 'ip') {
      const ip = resolveNodeIp(node)
      if (ip) return ip
      const mac = resolveNodeMac(node)
      if (mac) return mac
      return resolveLabelAuto(node, deviceLookup)
    }
    if (mode === 'mac') {
      const mac = resolveNodeMac(node)
      if (mac) return mac
      const ip = resolveNodeIp(node)
      if (ip) return ip
      return resolveLabelAuto(node, deviceLookup)
    }
    return resolveLabelAuto(node, deviceLookup)
  }
}

/**
 * Extract the MAC address from a topology node's meta field.
 *
 * @param node - Topology node to extract MAC from.
 * @returns MAC address string or empty string if unavailable.
 */
export function resolveNodeMac(node: TopologyNode): string {
  const meta = node.meta as unknown as Record<string, unknown>
  if (typeof meta.mac === 'string' && meta.mac.length > 0) {
    return meta.mac
  }
  return ''
}

/**
 * Extract the IP address from a topology node's meta field.
 *
 * Handles both resolved (meta.ip4[]) and unresolved (meta.ip) node formats.
 *
 * @param node - Topology node to extract IP from.
 * @returns IP address string or empty string if unavailable.
 */
export function resolveNodeIp(node: TopologyNode): string {
  const meta = node.meta as unknown as Record<string, unknown>
  if (typeof meta.ip === 'string' && meta.ip.length > 0) {
    return meta.ip
  }
  if (Array.isArray(meta.ip4) && meta.ip4.length > 0) {
    return meta.ip4.join(', ')
  }
  return ''
}

/**
 * Build ECharts graph categories array.
 */
function buildCategories(): GraphCategory[] {
  const types: NodeType[] = ['PLC', 'IPC', 'IO', 'Other']
  return types.map((t) => ({
    name: t,
    itemStyle: { color: getCssVar(CATEGORY_COLOR_MAP[t], CATEGORY_FALLBACKS[t]) },
    symbol: 'circle',
  }))
}

/**
 * Transform a TopologyNode into an ECharts graph node data object.
 *
 * Builds a circle-with-icon symbol via data-URI SVG, applies type-based
 * coloring, and generates a truncated label for display below the node.
 */
function buildNodeData(
  node: TopologyNode,
  dark: boolean,
  resolveLabel: (node: TopologyNode) => string,
  labelFontSize: number = 10,
): GraphNodeData {
  const hasAnomaly = node.isAnomaly
  const colors = getTopoColors()
  const typeBorderMap: Record<NodeType, string> = {
    PLC: colors.plc,
    IPC: colors.ipc,
    IO: colors.io,
    Other: colors.other,
  }
  const typeColor = typeBorderMap[node.type] ?? colors.other
  const nodeColor = hasAnomaly ? colors.anomaly : typeColor
  const label = resolveLabel(node)
  const truncatedLabel = label.length > 27 ? `${label.slice(0, 25)}…` : label

  return {
    name: node.id,
    symbol: buildCircleNodeSymbol(node.type, dark, hasAnomaly),
    symbolSize: NODE_SIZE,
    category: CATEGORY_INDEX[node.type] ?? 3,
    itemStyle: {
      color: nodeColor,
      borderColor: hasAnomaly ? colors.anomalyBorder : typeColor,
      borderWidth: hasAnomaly ? 3 : 1,
    },
    label: {
      show: true,
      formatter: truncatedLabel,
      color: dark ? '#e0e0e0' : '#37474f',
      fontSize: labelFontSize,
    },
    originalNode: node,
  }
}

/**
 * Transform a TopologyEdge into an ECharts graph link data object.
 */
function buildLinkData(edge: TopologyEdge, dark: boolean): GraphLinkData {
  const colors = getTopoColors()
  const hasAnomaly = edge.isAnomaly
  const protocols = edge.meta?.protocols ?? []
  const firstProto = protocols.length > 0 ? protocols[0] : undefined
  const shortProtocol = firstProto ? (firstProto.split(':').pop() ?? '') : ''

  return {
    source: edge.source,
    target: edge.target,
    lineStyle: {
      color: hasAnomaly ? colors.anomaly : dark ? '#455a64' : colors.edge,
      width: hasAnomaly ? 3 : 1.5,
      type: hasAnomaly ? 'solid' : 'solid',
    },
    label: shortProtocol
      ? {
          show: false,
          formatter: shortProtocol,
          fontSize: 9,
          color: getCssVar('--cd-muted', dark ? '#90a4ae' : '#607d8b'),
        }
      : undefined,
    originalEdge: edge,
  }
}

/** Available layout modes for the topology graph. */
export type GraphLayout = 'force' | 'circular'

/** Reactive settings for the topology graph that the user can adjust at runtime. */
export interface TopologyGraphSettings {
  layout: GraphLayout
  friction: number
  hideBroadcast: boolean
  hideMulticast: boolean
  identifierMode: 'auto' | 'ip' | 'mac'
  labelFontSize: number
}

const DEFAULT_SETTINGS: TopologyGraphSettings = {
  layout: 'circular',
  friction: 0.9,
  hideBroadcast: true,
  hideMulticast: true,
  identifierMode: 'auto',
  labelFontSize: 10,
}

const BROADCAST_MAC = 'ff:ff:ff:ff:ff:ff'

/**
 * Determine whether a MAC address is a multicast destination.
 *
 * IEEE 802.3 marks multicast frames by setting the least significant bit of
 * the first MAC octet. This excludes broadcast (``ff:ff:ff:ff:ff:ff``) which
 * is treated as a separate category for filtering purposes.
 *
 * @param mac - MAC address string in colon-separated form.
 * @returns ``true`` when the MAC is a non-broadcast multicast address.
 */
function isMulticastMac(mac: string): boolean {
  if (!mac) return false
  const lower = mac.toLowerCase()
  if (lower === BROADCAST_MAC) return false
  // Common multicast prefixes
  if (lower.startsWith('01:80:c2:') || lower.startsWith('01:00:5e:') || lower.startsWith('33:33:')) {
    return true
  }
  const firstOctet = lower.split(':')[0]
  if (!firstOctet || firstOctet.length !== 2) return false
  const num = parseInt(firstOctet, 16)
  return Number.isFinite(num) && (num & 0x01) === 0x01
}

/**
 * Test whether a node represents the broadcast destination.
 */
function isBroadcastNode(node: TopologyNode): boolean {
  const mac = resolveNodeMac(node).toLowerCase()
  if (mac === BROADCAST_MAC) return true
  const label = (node.label ?? '').toLowerCase()
  return label.includes('broadcast')
}

/**
 * Test whether a node represents a multicast destination.
 */
function isMulticastNode(node: TopologyNode): boolean {
  const mac = resolveNodeMac(node)
  return isMulticastMac(mac)
}

/**
 * Compute a stable signature for the topology graph contents.
 *
 * Two graphs with the same node/edge IDs and anomaly flags produce
 * identical signatures, allowing the consumer to skip unnecessary
 * ECharts re-initializations triggered by SSE pushes that carry the
 * same payload.
 */
export function computeGraphSignature(nodes: TopologyNode[], edges: TopologyEdge[]): string {
  const n = nodes
    .map((x) => `${x.id}:${x.type}:${x.isAnomaly ? 1 : 0}`)
    .sort()
    .join('|')
  const e = edges
    .map((x) => `${x.source}->${x.target}:${x.isAnomaly ? 1 : 0}`)
    .sort()
    .join('|')
  return `${n}#${e}`
}

/**
 * Composable providing ECharts graph data and selection state for the topology page.
 *
 * Uses the topology Pinia store as the data source instead of golden data.
 * Delegates selection state management to the store while keeping the
 * ECharts rendering logic (buildOption, SVG icons, colors) local.
 *
 * @returns Reactive graph data (nodes, links, categories), selected node, and helpers.
 */
export function useTopologyGraph() {
  const topologyStore = useTopologyStore()
  const graphSettings = reactive<TopologyGraphSettings>({ ...DEFAULT_SETTINGS })
  const deviceLookup = useDeviceLookup()
  const resolveNodeLabel = buildResolveNodeLabel(deviceLookup)

  /**
   * Raw topology data straight from the store (unfiltered).
   *
   * Used by the chat-context provider so the LLM sees the complete graph,
   * even when the user is hiding broadcast or multicast nodes in the UI.
   */
  const rawTopology = computed<TopologyGraph>(() => {
    if (!topologyStore.graph) {
      return { nodes: [], edges: [] }
    }
    return {
      nodes: topologyStore.graph.nodes as TopologyNode[],
      edges: topologyStore.graph.edges as TopologyEdge[],
    }
  })

  /**
   * Topology data after applying the user-controlled filter settings:
   * hide broadcast/multicast nodes and keep edges only between remaining nodes.
   */
  const topology = computed<TopologyGraph>(() => {
    const all = rawTopology.value
    if (!graphSettings.hideBroadcast && !graphSettings.hideMulticast) {
      return all
    }
    const keptNodes = all.nodes.filter((n) => {
      if (graphSettings.hideBroadcast && isBroadcastNode(n)) return false
      if (graphSettings.hideMulticast && isMulticastNode(n)) return false
      return true
    })
    const keptIds = new Set(keptNodes.map((n) => n.id))
    const keptEdges = all.edges.filter((e) => keptIds.has(e.source) && keptIds.has(e.target))
    return { nodes: keptNodes, edges: keptEdges }
  })

  /**
   * Stable signature of the currently displayed graph (post-filter).
   *
   * Consumers can watch this string and only trigger expensive ECharts
   * re-initializations when the underlying structure actually changes.
   */
  const topologySignature = computed(() => computeGraphSignature(topology.value.nodes, topology.value.edges))

  /**
   * Signature of the current node labels so the graph can refresh when
   * resolved asset names become available via the devices store.
   */
  const nodeLabelSignature = computed(() => {
    return topology.value.nodes
      .map((n) => `${n.id}=${resolveNodeLabel(n)}`)
      .sort()
      .join('|')
  })

  const selectedNode = computed<TopologyNode | null>(() => {
    const node = topologyStore.selectedNode
    return (node as TopologyNode | undefined) ?? null
  })

  const connectedEdges = computed<TopologyEdge[]>(() => {
    if (!topologyStore.selectedNodeId) return []
    return topologyStore.connectedEdges(topologyStore.selectedNodeId) as TopologyEdge[]
  })

  const categories = computed(() => buildCategories())

  /**
   * Build the complete ECharts option object for the topology graph.
   *
   * Clears the symbol cache before rebuilding to pick up theme changes.
   */
  function buildOption(dark: boolean) {
    symbolCache.clear()

    const idMode = graphSettings.identifierMode
    const labelFontSize = graphSettings.labelFontSize
    const nodes = topology.value.nodes.map((n) =>
      buildNodeData(n, dark, (node) => resolveNodeLabel(node, idMode), labelFontSize),
    )
    const links = topology.value.edges.map((e) => buildLinkData(e, dark))

    return {
      backgroundColor: 'transparent',
      tooltip: {
        trigger: 'item' as const,
        backgroundColor: getCssVar('--cd-surface', dark ? '#1e1e1e' : '#ffffff'),
        borderColor: getCssVar('--cd-plot-grid', dark ? '#37474f' : '#cfd8dc'),
        textStyle: { color: getCssVar('--cd-surface-text', dark ? '#cfd8dc' : '#263238'), fontSize: 12 },
        // ECharts tooltip formatter — shape varies per dataType; loose
        // Record at the boundary, narrowed inside the body.
        formatter(params: Record<string, unknown>): string {
          if (params.dataType === 'node') {
            const original = params.data?.originalNode as TopologyNode | undefined
            if (!original) return escapeTooltipHtml(params.name)
            const ip = resolveNodeIp(original)
            const mac = resolveNodeMac(original)
            const status = original.isAnomaly ? '🔴 Anomaly' : '🟢 Normal'
            let html = `<b>${escapeTooltipHtml(resolveNodeLabel(original))}</b><br/>`
            html += `Type: ${escapeTooltipHtml(original.type)}<br/>`
            if (ip) html += `IP: ${escapeTooltipHtml(ip)}<br/>`
            if (mac) html += `MAC: ${escapeTooltipHtml(mac)}<br/>`
            html += `Status: ${status}`
            return html
          }
          if (params.dataType === 'edge') {
            const original = params.data?.originalEdge as TopologyEdge | undefined
            if (!original) return ''
            const protocols = original.meta?.protocols?.map((p) => escapeTooltipHtml(p)).join(', ') ?? 'Unknown'
            const status = original.isAnomaly ? '🔴 Anomaly' : '🟢 Normal'
            return `<b>Connection</b><br/>Protocols: ${protocols}<br/>Status: ${status}`
          }
          return ''
        },
      },
      legend: { show: false },
      series: [
        {
          type: 'graph',
          layout: graphSettings.layout,
          data: nodes,
          links,
          categories: categories.value,
          roam: true,
          draggable: true,
          ...(graphSettings.layout === 'force'
            ? {
                force: {
                  repulsion: 350,
                  gravity: 0.12,
                  edgeLength: [120, 280],
                  friction: graphSettings.friction,
                },
              }
            : {}),
          ...(graphSettings.layout === 'circular'
            ? {
                circular: {
                  rotateLabel: true,
                },
              }
            : {}),
          emphasis: {
            focus: 'adjacency' as const,
            lineStyle: { width: 4 },
          },
          label: {
            position: 'bottom',
            distance: 5,
          },
          edgeLabel: {
            fontSize: 9,
          },
          lineStyle: {
            curveness: 0.1,
          },
          selectedMode: 'single' as const,
          select: {
            itemStyle: {
              borderColor: getTopoColors().selectionBorder,
              borderWidth: 3,
            },
          },
        },
      ],
    }
  }

  /**
   * Handle a node click from the ECharts event and update the selected node in the store.
   */
  function selectNode(nodeId: string | null): void {
    topologyStore.selectNode(nodeId)
  }

  /**
   * Find a node by its ID in the topology data.
   */
  function findNodeById(nodeId: string): TopologyNode | undefined {
    return topology.value.nodes.find((n) => n.id === nodeId)
  }

  /**
   * Retrieve enriched edge details for a connection between two nodes.
   *
   * Looks up both source and target nodes and combines edge metadata with
   * traffic size data from the API response.
   *
   * @param sourceId - ID of the source node.
   * @param targetId - ID of the target node.
   * @returns EdgeDetails object or null if the edge cannot be resolved.
   */
  function getEdgeDetails(sourceId: string, targetId: string): EdgeDetails | null {
    const edge = topology.value.edges.find(
      (e) => (e.source === sourceId && e.target === targetId) || (e.source === targetId && e.target === sourceId),
    )
    if (!edge) return null

    const sourceNode = findNodeById(edge.source)
    const targetNode = findNodeById(edge.target)
    if (!sourceNode || !targetNode) return null

    const protocols = edge.meta?.protocols ?? []
    const ucis = edge.meta?.ucis ?? []

    return {
      sourceNode,
      targetNode,
      protocols,
      isAnomaly: edge.isAnomaly,
      ucis,
    }
  }

  return {
    topology,
    rawTopology,
    topologySignature,
    nodeLabelSignature,
    selectedNode,
    selectedNodeId: computed(() => topologyStore.selectedNodeId),
    connectedEdges,
    categories,
    graphSettings,
    buildOption,
    selectNode,
    findNodeById,
    getEdgeDetails,
    resolveNodeLabel,
    resolveNodeIp,
    resolveNodeMac,
  }
}
