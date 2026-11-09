/**
 * Composable for loading and caching Golden Data JSON files.
 *
 * Provides typed accessors for all golden data sets used in the mockup.
 * Data is imported statically from ~/assets/golden-data/ and cached in refs.
 */

import type {
  KpiData,
  TimeseriesPoint,
  Connection,
  AlarmGroup,
  AlarmGroupData,
  RealAlarmGroup,
  TopologyGraph,
  HealthService,
  Device,
} from '~/types/golden-data'

import gdKpis from '~/assets/golden-data/gd09-kpis.json'
import gdVolume from '~/assets/golden-data/gd05-total-volume.json'
import gdAlarms from '~/assets/golden-data/gd08-alarm-group.json'
import gdRealAlarms from '~/assets/golden-data/gd-alarm-groups-real.json'
import gdTopology from '~/assets/golden-data/gd10-topology.json'
import gdHealth from '~/assets/golden-data/gd12a-health.json'
import gdDevices from '~/assets/golden-data/gd13-devices.json'
import gdConnections from '~/assets/golden-data/gd01-connections.json'

/**
 * Provide typed access to all golden data sets.
 *
 * @returns Object containing all golden data arrays with proper TypeScript types.
 */
export function useGoldenData() {
  const kpis = computed<KpiData>(() => (gdKpis as KpiData[])[0])
  const volume = computed<TimeseriesPoint[]>(() => gdVolume as TimeseriesPoint[])
  const alarmGroups = computed<AlarmGroup[]>(() => (gdAlarms as AlarmGroupData).groups)
  const realAlarmGroups = computed<RealAlarmGroup[]>(() => gdRealAlarms as RealAlarmGroup[])
  const topology = computed<TopologyGraph>(() => (gdTopology as TopologyGraph[])[0])
  const health = computed<HealthService[]>(() => gdHealth as HealthService[])
  const devices = computed<Device[]>(() => gdDevices as Device[])
  const connections = computed<Connection[]>(() => gdConnections as Connection[])

  return {
    kpis,
    volume,
    alarmGroups,
    realAlarmGroups,
    topology,
    health,
    devices,
    connections,
  }
}
