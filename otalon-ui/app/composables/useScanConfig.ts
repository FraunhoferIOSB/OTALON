import { useApi } from '~/composables/useApi'
import type { ModuleSchema, ScanInterface } from '~/types/scans'

/**
 * Return type for {@link useScanConfig}.
 */
export interface UseScanConfigReturn {
  /**
   * Fetch the list of host network interfaces usable for scans.
   *
   * @returns Array of scan interfaces (may be empty on failure — callers
   *   should degrade gracefully).
   */
  fetchInterfaces: () => Promise<ScanInterface[]>
  /**
   * Fetch the override schema for a given module.
   *
   * @param name - Module name (e.g. ``port_scan``).
   * @returns Schema describing accepted override keys and auth requirements.
   */
  fetchModuleSchema: (name: string) => Promise<ModuleSchema>
}

/**
 * Composable wrapping the scan-config endpoints (interfaces + module schema).
 *
 * Both endpoints are thin GET proxies to ``otalon-scan:8091`` via
 * ``otalon-api``.
 *
 * @example
 * ```ts
 * const { fetchInterfaces, fetchModuleSchema } = useScanConfig()
 * const ifaces = await fetchInterfaces()
 * const schema = await fetchModuleSchema('port_scan')
 * ```
 */
export function useScanConfig(): UseScanConfigReturn {
  const api = useApi()

  interface InterfacesResponse {
    interfaces: ScanInterface[]
  }

  async function fetchInterfaces(): Promise<ScanInterface[]> {
    const data = await api.get<InterfacesResponse>('/api/v1/scans/interfaces')
    return data.interfaces ?? []
  }

  async function fetchModuleSchema(name: string): Promise<ModuleSchema> {
    return await api.get<ModuleSchema>(`/api/v1/scans/modules/${encodeURIComponent(name)}/schema`)
  }

  return { fetchInterfaces, fetchModuleSchema }
}
