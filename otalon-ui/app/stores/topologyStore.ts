/**
 * Pinia store for the topology page graph and device state.
 *
 * Manages the topology graph (nodes, edges), device records,
 * node/edge selection, and loading/error indicators.
 *
 * Uses the Options API pattern so that `$reset()` works automatically.
 */
import { defineStore } from 'pinia'

import type {
  DeviceItem,
  DevicesResponse,
  DeviceTypeOverrideResponse,
  TopologyEdgeItem,
  TopologyGraphResponse,
  TopologyNodeItem,
} from '~/types/api'

/**
 * Shape of the topology store reactive state.
 */
export interface TopologyState {
  graph: TopologyGraphResponse | null
  devices: DeviceItem[]
  selectedNodeId: string | null
  selectedEdgeId: string | null
  isLoading: boolean
  error: string | null
}

/**
 * Extract a human-readable error message from an unknown thrown value.
 *
 * @param error - The caught error value.
 * @returns A descriptive error message string.
 */
function extractErrorMessage(error: unknown): string {
  if (!error || typeof error !== 'object') {
    return 'An unknown error occurred'
  }
  const errObj = error as Record<string, unknown>
  const status = errObj.status ?? errObj.statusCode
  if (status === 502 || status === 503 || status === 504) {
    return 'Backend is unavailable — is otalon-api running on :8090?'
  }
  const msg = String(errObj.message ?? errObj.statusMessage ?? '')
  if (msg.includes('fetch failed') || msg.includes('ECONNREFUSED') || msg.includes('NetworkError')) {
    return 'Cannot reach backend — is otalon-api running on :8090?'
  }
  if (msg) return msg
  return 'An unknown error occurred'
}

export const useTopologyStore = defineStore('topology', {
  state: (): TopologyState => ({
    graph: null,
    devices: [],
    selectedNodeId: null,
    selectedEdgeId: null,
    isLoading: false,
    error: null,
  }),

  getters: {
    /**
     * The currently selected topology node.
     *
     * @returns The matching node item, or `undefined` when nothing is selected.
     */
    selectedNode(state): TopologyNodeItem | undefined {
      if (!state.selectedNodeId || !state.graph) return undefined
      return state.graph.nodes.find((n) => n.id === state.selectedNodeId)
    },

    /**
     * The currently selected topology edge.
     *
     * @returns The matching edge item, or `undefined` when nothing is selected.
     */
    selectedEdge(state): TopologyEdgeItem | undefined {
      if (!state.selectedEdgeId || !state.graph) return undefined
      return state.graph.edges.find((e) => e.id === state.selectedEdgeId)
    },

    /**
     * Total number of nodes in the loaded graph.
     *
     * @returns Node count from graph metadata, or `0` when no graph is loaded.
     */
    nodeCount(state): number {
      return state.graph?.meta?.node_count ?? 0
    },

    /**
     * Total number of edges in the loaded graph.
     *
     * @returns Edge count from graph metadata, or `0` when no graph is loaded.
     */
    edgeCount(state): number {
      return state.graph?.meta?.edge_count ?? 0
    },

    /**
     * Whether the backend capped the graph at the requested node limit.
     *
     * The API has always reported this in `meta.truncated`, but nothing
     * consumed it, so an operator silently saw a partial network and could
     * conclude a device was absent (audit UI-11).
     *
     * @returns `true` when nodes were omitted from the response.
     */
    isTruncated(state): boolean {
      return state.graph?.meta?.truncated === true
    },

    /**
     * Number of nodes flagged as anomalous.
     *
     * @returns Count of nodes with `isAnomaly === true`.
     */
    anomalyNodeCount(state): number {
      if (!state.graph) return 0
      return state.graph.nodes.filter((n) => n.isAnomaly).length
    },

    /**
     * Number of edges flagged as anomalous.
     *
     * @returns Count of edges with `isAnomaly === true`.
     */
    anomalyEdgeCount(state): number {
      if (!state.graph) return 0
      return state.graph.edges.filter((e) => e.isAnomaly).length
    },

    /**
     * All edges connected to a given node (as source or target).
     *
     * Returns a function that accepts a nodeId and filters edges accordingly.
     *
     * @returns A function `(nodeId: string) => TopologyEdgeItem[]`.
     */
    connectedEdges(state): (nodeId: string) => TopologyEdgeItem[] {
      return (nodeId: string) => {
        if (!state.graph) return []
        return state.graph.edges.filter((e) => e.source === nodeId || e.target === nodeId)
      }
    },
  },

  actions: {
    /**
     * Fetch the topology graph from the backend for the given time range.
     *
     * Calls `GET /api/v1/topology/graph` with time range and optional parameters.
     *
     * @param start - ISO 8601 UTC start timestamp.
     * @param stop - ISO 8601 UTC stop timestamp.
     * @param nodeLimit - Maximum number of nodes to return (default: 100).
     * @param includeAnomalies - Whether to include anomaly flags (default: true).
     */
    async fetchGraph(start: string, stop: string, nodeLimit?: number, includeAnomalies?: boolean): Promise<void> {
      this.isLoading = true
      this.error = null

      try {
        const params: Record<string, unknown> = { start, stop }
        if (nodeLimit !== undefined) {
          params.node_limit = nodeLimit
        }
        if (includeAnomalies !== undefined) {
          params.include_anomalies = includeAnomalies
        }

        const response = await $fetch<TopologyGraphResponse>('/api/v1/topology/graph', {
          params,
        })
        this.graph = response
      } catch (error: unknown) {
        this.error = `Failed to fetch topology graph: ${extractErrorMessage(error)}`
      } finally {
        this.isLoading = false
      }
    },

    /**
     * Fetch the paginated device list from the backend.
     *
     * Calls `GET /api/v1/topology/devices` with optional pagination parameters.
     *
     * @param limit - Maximum number of devices to return.
     * @param offset - Pagination offset.
     */
    async fetchDevices(limit?: number, offset?: number): Promise<void> {
      this.isLoading = true
      this.error = null

      try {
        const params: Record<string, unknown> = {}
        if (limit !== undefined) {
          params.limit = limit
        }
        if (offset !== undefined) {
          params.offset = offset
        }

        const response = await $fetch<DevicesResponse>('/api/v1/topology/devices', {
          params,
        })
        this.devices = response.devices
      } catch (error: unknown) {
        this.error = `Failed to fetch devices: ${extractErrorMessage(error)}`
      } finally {
        this.isLoading = false
      }
    },

    /**
     * Override the device type for a specific device.
     *
     * Calls `PUT /api/v1/topology/devices/{deviceId}/type` with the new type.
     *
     * @param deviceId - The numeric device ID.
     * @param deviceType - The new device type string.
     * @returns The override response, or `null` on failure.
     */
    async updateDeviceType(deviceId: number, deviceType: string): Promise<DeviceTypeOverrideResponse | null> {
      try {
        const response = await $fetch<DeviceTypeOverrideResponse>(`/api/v1/topology/devices/${deviceId}/type`, {
          method: 'PUT',
          body: { device_type: deviceType },
        })
        return response
      } catch (error: unknown) {
        this.error = `Failed to update device type: ${extractErrorMessage(error)}`
        return null
      }
    },

    /**
     * Set the currently selected node by its ID.
     *
     * Clears the edge selection when a node is selected.
     *
     * @param nodeId - The node ID to select, or `null` to clear selection.
     */
    selectNode(nodeId: string | null): void {
      this.selectedNodeId = nodeId
      if (nodeId !== null) {
        this.selectedEdgeId = null
      }
    },

    /**
     * Set the currently selected edge by its ID.
     *
     * Clears the node selection when an edge is selected.
     *
     * @param edgeId - The edge ID to select, or `null` to clear selection.
     */
    selectEdge(edgeId: string | null): void {
      this.selectedEdgeId = edgeId
      if (edgeId !== null) {
        this.selectedNodeId = null
      }
    },

    /**
     * Clear both node and edge selection.
     */
    clearSelection(): void {
      this.selectedNodeId = null
      this.selectedEdgeId = null
    },

    /**
     * Apply a topology graph update received via SSE.
     *
     * Replaces the current graph with the incoming payload.
     * Called by the `topology` SSE event handler in `topology.vue`.
     *
     * @param data - The full topology graph payload from the backend emitter.
     */
    handleTopologyUpdate(data: TopologyGraphResponse): void {
      this.graph = data
    },
  },
})
