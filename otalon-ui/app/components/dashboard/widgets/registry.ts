import type { Component } from 'vue'
import SignalKpiWidget from './SignalKpiWidget.vue'
import AssetsKpiWidget from './AssetsKpiWidget.vue'
import ConnectionsKpiWidget from './ConnectionsKpiWidget.vue'
import ProtocolsKpiWidget from './ProtocolsKpiWidget.vue'
import ThroughputWidget from './ThroughputWidget.vue'
import RecentAlarmsWidget from './RecentAlarmsWidget.vue'
import VulnerabilitiesWidget from './VulnerabilitiesWidget.vue'
import SecurityAdvisoriesWidget from './SecurityAdvisoriesWidget.vue'
import TopConnectionsWidget from './TopConnectionsWidget.vue'
import TopAssetsWidget from './TopAssetsWidget.vue'
import TopProtocolsWidget from './TopProtocolsWidget.vue'
import ServiceHealthWidget from './ServiceHealthWidget.vue'

/**
 * Grid layout item matching grid-layout-plus serializable model.
 */
export interface WidgetLayoutItem {
  i: string
  x: number
  y: number
  w: number
  h: number
}

/**
 * Metadata for a single dashboard widget.
 */
export interface WidgetDefinition {
  id: string
  label: string
  component: Component
  minW: number
  minH: number
}

/**
 * Registry of all dashboard widgets keyed by id.
 *
 * Callers must narrow `undefined` when indexing (noUncheckedIndexedAccess).
 */
export const WIDGET_REGISTRY: Record<string, WidgetDefinition> = {
  signal: { id: 'signal', label: 'Signal', component: SignalKpiWidget, minW: 1, minH: 1 },
  assets: { id: 'assets', label: 'Assets', component: AssetsKpiWidget, minW: 1, minH: 1 },
  connections: { id: 'connections', label: 'Connections', component: ConnectionsKpiWidget, minW: 1, minH: 1 },
  protocols: { id: 'protocols', label: 'Protocols', component: ProtocolsKpiWidget, minW: 1, minH: 1 },
  throughput: { id: 'throughput', label: 'Network Throughput', component: ThroughputWidget, minW: 4, minH: 1 },
  recentAlarms: { id: 'recentAlarms', label: 'Recent Alarms', component: RecentAlarmsWidget, minW: 2, minH: 2 },
  vulnerabilities: {
    id: 'vulnerabilities',
    label: 'Vulnerabilities',
    component: VulnerabilitiesWidget,
    minW: 2,
    minH: 2,
  },
  securityAdvisories: {
    id: 'securityAdvisories',
    label: 'Security Advisories',
    component: SecurityAdvisoriesWidget,
    minW: 2,
    minH: 2,
  },
  topConnections: { id: 'topConnections', label: 'Top Connections', component: TopConnectionsWidget, minW: 2, minH: 2 },
  topAssets: { id: 'topAssets', label: 'Top Assets', component: TopAssetsWidget, minW: 2, minH: 2 },
  topProtocols: { id: 'topProtocols', label: 'Top Protocols', component: TopProtocolsWidget, minW: 2, minH: 2 },
  serviceHealth: { id: 'serviceHealth', label: 'Service Health', component: ServiceHealthWidget, minW: 4, minH: 1 },
}

/**
 * Default dashboard layout (8 columns, G6 arrangement scaled).
 *
 * Row 0: KPIs (signal/assets/connections/protocols).
 * Row 1: full-width throughput.
 * Rows 2-7: complex widgets in two right-side columns.
 * Row 8: full-width service health.
 */
export const DEFAULT_LAYOUT: WidgetLayoutItem[] = [
  { i: 'signal', x: 0, y: 0, w: 2, h: 1 },
  { i: 'assets', x: 2, y: 0, w: 2, h: 1 },
  { i: 'connections', x: 4, y: 0, w: 2, h: 1 },
  { i: 'protocols', x: 6, y: 0, w: 2, h: 1 },
  { i: 'throughput', x: 0, y: 1, w: 8, h: 1 },
  { i: 'recentAlarms', x: 4, y: 2, w: 2, h: 2 },
  { i: 'vulnerabilities', x: 4, y: 4, w: 2, h: 2 },
  { i: 'securityAdvisories', x: 4, y: 6, w: 2, h: 2 },
  { i: 'topConnections', x: 6, y: 2, w: 2, h: 2 },
  { i: 'topAssets', x: 6, y: 4, w: 2, h: 2 },
  { i: 'topProtocols', x: 6, y: 6, w: 2, h: 2 },
  { i: 'serviceHealth', x: 0, y: 8, w: 8, h: 1 },
]
