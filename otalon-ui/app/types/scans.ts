/**
 * UI-side type contracts for the otalon-api scan-proxy endpoints
 * (Wave-C ``api--scans`` proxy → upstream ``otalon-scan``).
 *
 * The shapes here intentionally mirror the **minimum** fields the UI needs.
 * The Wave-C proxy forwards request and response bodies verbatim, so callers
 * may receive additional fields the UI does not yet consume — that is
 * acceptable and forward-compatible.
 *
 * Per the v1.0 design (Decision 1) the scan request body is left untyped
 * (``Record<string, unknown>``). Typed per-module schemas are deferred to
 * v1.1.
 */

/**
 * Response shape for ``GET /api/v1/modules``.
 *
 * The upstream returns ``{"modules": [...]}``; if a later wave switches to a
 * bare array, the caller normalises it on the UI side.
 */
export interface ScanModulesResponse {
  modules: string[]
}

/**
 * Response shape for ``POST /api/v1/scans``.
 *
 * Mirrors the Wave-C documented body ``{run_id, scan_id, module_name, status}``.
 * ``scan_id`` is the field used in subsequent ``/scans/{id}/events`` calls.
 */
export interface ScanStartResponse {
  run_id?: string
  scan_id: string
  module_name?: string
  status?: string
}

/**
 * Single entry in the ``GET /api/v1/scans`` listing.
 *
 * The list endpoint is documented but not yet implemented upstream
 * (Wave-C deviation 4). When it lands, this minimal shape is the agreed
 * contract for the UI.
 */
export interface ScanItem {
  scan_id: string
  module: string
  status: 'running' | 'completed' | 'failed' | string
  started_at?: string
  finished_at?: string
  error_message?: string
  parameters?: Record<string, unknown>
  /**
   * L-02: per-scan findings snapshot (list of DeviceFinding dicts). Only
   * populated on the single-scan detail endpoint (``GET /scans/{id}``);
   * ``null``/absent on listing rows.
   */
  findings?: Record<string, unknown>[] | null
}

/**
 * Body shape posted to ``POST /api/v1/scans``.
 *
 * Today the upstream ``otalon-scan`` accepts ``{module_name, overrides}``
 * (the legacy contract from Wave A/B). A later wave will rename the fields
 * to ``{module, config}`` per the v1 mission §4.3 contract; until then the
 * proxy is pure pass-through (Wave-C philosophy) and the UI posts the
 * upstream-current shape. When the rename lands, this interface flips to
 * the v1 names in a one-line patch — see ``Decision 6`` in design.md of
 * scan--ui-triggers for the mirror of Wave-C Decision 6.
 *
 * ``overrides`` is intentionally a free-form record — Decision 1 defers
 * typed per-module schemas to v1.1.
 */
export interface ScanStartRequest {
  module_name: string
  overrides: Record<string, unknown>
}

/**
 * Single network interface returned by ``GET /api/v1/scans/interfaces``.
 *
 * Mirrors the enriched otalon-scan endpoint shape (Wave B).
 */
export interface ScanInterface {
  name: string
  ipv4: string | null
  subnet: string | null
  is_up: boolean
  role: 'active_scan' | 'mirror' | 'other'
  mac: string | null
  is_default: boolean
}

/**
 * Single descriptor inside ``ModuleSchema.accepted_keys``.
 */
export interface ModuleSchemaKeyItem {
  key: string
  type: string
  required: boolean
  description: string
}

/**
 * Module schema returned by ``GET /api/v1/scans/modules/{name}/schema``.
 *
 * Drives JSON-mode transparency (accepted key chips + live validation).
 */
export interface ModuleSchema {
  module: string
  accepted_keys: ModuleSchemaKeyItem[]
  requires_auth: boolean
  extensible: boolean
}
