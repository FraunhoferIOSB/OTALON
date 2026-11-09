/**
 * Unit tests for the topology store.
 *
 * Validates graph fetching, device fetching, device type override,
 * selection state, getters, error handling, and $reset().
 */
import { describe, it, expect, beforeEach } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'

import { useTopologyStore } from '~/stores/topologyStore'
import {
  GOLDEN_DEVICES,
  GOLDEN_TOPOLOGY_EDGES,
  GOLDEN_TOPOLOGY_META,
  GOLDEN_TOPOLOGY_NODES,
} from '../mocks/golden-data'
import { errorHandlers } from '../mocks/handlers'
import { server } from '../mocks/server'

describe('topologyStore', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
  })

  describe('fetchGraph', () => {
    it('loads topology graph from API', async () => {
      const store = useTopologyStore()
      await store.fetchGraph('2026-03-06T21:00:00Z', '2026-03-06T22:00:00Z')

      expect(store.graph).not.toBeNull()
      expect(store.graph!.nodes).toHaveLength(GOLDEN_TOPOLOGY_NODES.length)
      expect(store.graph!.edges).toHaveLength(GOLDEN_TOPOLOGY_EDGES.length)
    })

    it('stores graph metadata', async () => {
      const store = useTopologyStore()
      await store.fetchGraph('2026-03-06T21:00:00Z', '2026-03-06T22:00:00Z')

      expect(store.graph!.meta.node_count).toBe(GOLDEN_TOPOLOGY_META.node_count)
      expect(store.graph!.meta.edge_count).toBe(GOLDEN_TOPOLOGY_META.edge_count)
      expect(store.graph!.meta.truncated).toBe(false)
    })

    it('sets isLoading during request', async () => {
      const store = useTopologyStore()
      const promise = store.fetchGraph('2026-03-06T21:00:00Z', '2026-03-06T22:00:00Z')

      expect(store.isLoading).toBe(true)

      await promise

      expect(store.isLoading).toBe(false)
    })

    it('sets error on API failure', async () => {
      server.use(errorHandlers.topologyGraph500)
      const store = useTopologyStore()
      await store.fetchGraph('2026-03-06T21:00:00Z', '2026-03-06T22:00:00Z')

      expect(store.error).toBeTruthy()
      expect(store.error).toContain('Failed to fetch topology graph')
    })

    it('clears error on successful fetch', async () => {
      const store = useTopologyStore()
      store.error = 'previous error'
      await store.fetchGraph('2026-03-06T21:00:00Z', '2026-03-06T22:00:00Z')

      expect(store.error).toBeNull()
    })

    it('preserves node isAnomaly flags', async () => {
      const store = useTopologyStore()
      await store.fetchGraph('2026-03-06T21:00:00Z', '2026-03-06T22:00:00Z')

      const anomalyNode = store.graph!.nodes.find((n) => n.isAnomaly)
      expect(anomalyNode).toBeDefined()
      expect(anomalyNode!.id).toBe('unresolved:cc:82:7f:a1:8a:36')
    })

    it('preserves edge isAnomaly flags', async () => {
      const store = useTopologyStore()
      await store.fetchGraph('2026-03-06T21:00:00Z', '2026-03-06T22:00:00Z')

      const anomalyEdges = store.graph!.edges.filter((e) => e.isAnomaly)
      expect(anomalyEdges.length).toBeGreaterThan(0)
    })
  })

  describe('fetchDevices', () => {
    it('loads device list from API', async () => {
      const store = useTopologyStore()
      await store.fetchDevices()

      expect(store.devices).toHaveLength(GOLDEN_DEVICES.length)
    })

    it('stores device data correctly', async () => {
      const store = useTopologyStore()
      await store.fetchDevices()

      const firstDevice = store.devices[0]
      expect(firstDevice.id).toBe(1)
      expect(firstDevice.description).toBe('OPC UA application 0')
      expect(firstDevice.update_available).toBe(false)
    })

    it('sets error on API failure', async () => {
      server.use(errorHandlers.devices500)
      const store = useTopologyStore()
      await store.fetchDevices()

      expect(store.error).toBeTruthy()
      expect(store.error).toContain('Failed to fetch devices')
    })
  })

  describe('updateDeviceType', () => {
    it('sends PUT request and returns response', async () => {
      const store = useTopologyStore()
      const result = await store.updateDeviceType(1, 'PLC')

      expect(result).not.toBeNull()
      expect(result!.device_id).toBe(1)
      expect(result!.device_type).toBe('PLC')
      expect(result!.previous_type).toBe('Other')
      expect(result!.message).toBe('Device type updated')
    })

    it('sets error on API failure', async () => {
      server.use(errorHandlers.deviceTypePut500)
      const store = useTopologyStore()
      const result = await store.updateDeviceType(1, 'PLC')

      expect(result).toBeNull()
      expect(store.error).toBeTruthy()
      expect(store.error).toContain('Failed to update device type')
    })
  })

  describe('selectNode / selectEdge / clearSelection', () => {
    it('sets selectedNodeId', () => {
      const store = useTopologyStore()
      store.selectNode('1')

      expect(store.selectedNodeId).toBe('1')
    })

    it('clears selectedEdgeId when selecting a node', () => {
      const store = useTopologyStore()
      store.selectEdge('e1')
      store.selectNode('1')

      expect(store.selectedNodeId).toBe('1')
      expect(store.selectedEdgeId).toBeNull()
    })

    it('sets selectedEdgeId', () => {
      const store = useTopologyStore()
      store.selectEdge('e1')

      expect(store.selectedEdgeId).toBe('e1')
    })

    it('clears selectedNodeId when selecting an edge', () => {
      const store = useTopologyStore()
      store.selectNode('1')
      store.selectEdge('e1')

      expect(store.selectedEdgeId).toBe('e1')
      expect(store.selectedNodeId).toBeNull()
    })

    it('clears selectedNodeId with null', () => {
      const store = useTopologyStore()
      store.selectNode('1')
      store.selectNode(null)

      expect(store.selectedNodeId).toBeNull()
    })

    it('clearSelection clears both', () => {
      const store = useTopologyStore()
      store.selectNode('1')
      store.selectEdge('e1')
      store.clearSelection()

      expect(store.selectedNodeId).toBeNull()
      expect(store.selectedEdgeId).toBeNull()
    })
  })

  describe('getters', () => {
    it('nodeCount returns node count from metadata', async () => {
      const store = useTopologyStore()
      expect(store.nodeCount).toBe(0)

      await store.fetchGraph('2026-03-06T21:00:00Z', '2026-03-06T22:00:00Z')
      expect(store.nodeCount).toBe(GOLDEN_TOPOLOGY_META.node_count)
    })

    it('edgeCount returns edge count from metadata', async () => {
      const store = useTopologyStore()
      expect(store.edgeCount).toBe(0)

      await store.fetchGraph('2026-03-06T21:00:00Z', '2026-03-06T22:00:00Z')
      expect(store.edgeCount).toBe(GOLDEN_TOPOLOGY_META.edge_count)
    })

    it('anomalyNodeCount counts anomalous nodes', async () => {
      const store = useTopologyStore()
      expect(store.anomalyNodeCount).toBe(0)

      await store.fetchGraph('2026-03-06T21:00:00Z', '2026-03-06T22:00:00Z')
      const expected = GOLDEN_TOPOLOGY_NODES.filter((n) => n.isAnomaly).length
      expect(store.anomalyNodeCount).toBe(expected)
    })

    it('anomalyEdgeCount counts anomalous edges', async () => {
      const store = useTopologyStore()
      expect(store.anomalyEdgeCount).toBe(0)

      await store.fetchGraph('2026-03-06T21:00:00Z', '2026-03-06T22:00:00Z')
      const expected = GOLDEN_TOPOLOGY_EDGES.filter((e) => e.isAnomaly).length
      expect(store.anomalyEdgeCount).toBe(expected)
    })

    it('selectedNode returns matching node from graph', async () => {
      const store = useTopologyStore()
      await store.fetchGraph('2026-03-06T21:00:00Z', '2026-03-06T22:00:00Z')

      store.selectNode('2')
      expect(store.selectedNode).toBeDefined()
      expect(store.selectedNode!.id).toBe('2')
      expect(store.selectedNode!.type).toBe('PLC')
    })

    it('selectedNode returns undefined when nothing selected', () => {
      const store = useTopologyStore()

      expect(store.selectedNode).toBeUndefined()
    })

    it('selectedEdge returns matching edge from graph', async () => {
      const store = useTopologyStore()
      await store.fetchGraph('2026-03-06T21:00:00Z', '2026-03-06T22:00:00Z')

      store.selectEdge('1-2')
      expect(store.selectedEdge).toBeDefined()
      expect(store.selectedEdge!.source).toBe('1')
      expect(store.selectedEdge!.target).toBe('2')
    })

    it('connectedEdges filters edges for a node', async () => {
      const store = useTopologyStore()
      await store.fetchGraph('2026-03-06T21:00:00Z', '2026-03-06T22:00:00Z')

      const edges = store.connectedEdges('2')
      expect(edges.length).toBe(2)
      expect(edges.every((e) => e.source === '2' || e.target === '2')).toBe(true)
    })

    it('connectedEdges returns empty array for unknown node', async () => {
      const store = useTopologyStore()
      await store.fetchGraph('2026-03-06T21:00:00Z', '2026-03-06T22:00:00Z')

      const edges = store.connectedEdges('nonexistent')
      expect(edges).toEqual([])
    })

    it('connectedEdges returns empty array when no graph loaded', () => {
      const store = useTopologyStore()

      const edges = store.connectedEdges('1')
      expect(edges).toEqual([])
    })
  })

  describe('$reset', () => {
    it('clears all data', async () => {
      const store = useTopologyStore()
      await store.fetchGraph('2026-03-06T21:00:00Z', '2026-03-06T22:00:00Z')
      await store.fetchDevices()
      store.selectNode('1')

      expect(store.graph).not.toBeNull()
      expect(store.devices).not.toHaveLength(0)

      store.$reset()

      expect(store.graph).toBeNull()
      expect(store.devices).toEqual([])
      expect(store.selectedNodeId).toBeNull()
      expect(store.selectedEdgeId).toBeNull()
      expect(store.isLoading).toBe(false)
      expect(store.error).toBeNull()
    })
  })
})
