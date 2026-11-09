// https://nuxt.com/docs/api/configuration/nuxt-config

/**
 * Backend `/api/v1` first-path segments that are transparently reverse-proxied
 * to otalon-api. The `operations` and `training` subtrees are deliberately
 * absent: both are admin-key-protected on the backend
 * (`otalon-api/src/middleware/auth.py` `PROTECTED_PATH_PREFIXES`) and are
 * driven from the WAVE-D/E Operations pages, so their traffic MUST hit the
 * server-side operator-key proxies (`server/api/v1/{operations,training}/[...path].ts`,
 * SUITE-014) so the operator key is injected server-side and never delivered to
 * the browser. A blanket `/api/v1/**` proxy cannot be used because Nuxt strips a
 * `proxy: false` reset for those sub-paths, which would let the browser reach
 * the protected subtree with no key (HTTP 401).
 *
 * `events` is ALSO deliberately absent: the httpxy pass-through this map
 * generates does not link the upstream connection to the browser connection, so
 * a browser disconnect never reached the SSE endpoint and its connection count
 * leaked to the 50-cap → HTTP 429 (UI-083). The global events feed
 * `/api/v1/events/stream` is therefore served by the dedicated disconnect-aware
 * route `server/api/v1/events/stream.get.ts`. `/api/v1/events` has no other
 * sub-routes on the backend, so no httpxy fallback is needed for it.
 *
 * `frequency` is ALSO deliberately absent: its rhythm-correction routes
 * (`{series_id}/override/{preview,apply,suggest}`, `{series_id}/history`) each
 * declare `Depends(require_operator_api_key)` in `otalon-api/src/api/v1/frequency.py`.
 * A per-route dependency guards the endpoint even though `/api/v1/frequency` is
 * not in the middleware's `PROTECTED_PATH_PREFIXES`, so the transparent proxy
 * delivered UI-101 correction requests with no key (HTTP 401). The subtree is
 * served by the keyed `server/api/v1/frequency/[...path].ts` proxy instead.
 * When adding a prefix here, check the router for per-route operator
 * dependencies, not just the middleware prefix list.
 *
 * `admin` stays here for remaining legacy surfaces. When a new backend router
 * prefix is added, append it here (mirrors `otalon-api/src/main.py` router mounts) — unless it is
 * admin-key-protected AND driven without a client-supplied key, in which case
 * give it a keyed server proxy instead; SSE feeds need the disconnect-aware
 * server proxy (see `server/utils/sseProxy.ts`) rather than this map.
 */
const PROXIED_API_PREFIXES = [
  'admin',
  'auth',
  // 'anomalies' is served by a dedicated keyed proxy (server/api/v1/anomalies/)
  // because PATCH /anomalies/groups/{id} is a mutation requiring the operator key.
  'baselines',
  'dashboard',
  // 'devices' is served by a dedicated keyed proxy (server/api/v1/devices/)
  // because PATCH /devices/{id} is a mutation requiring the operator key.
  'modules',
  'pcap',
  'status',
  'timeseries',
  'topology',
  // 'vulnerabilities' is served by a dedicated keyed proxy (server/api/v1/vulnerabilities/)
  // because POST /vulnerabilities/lookup is a mutation requiring the operator key.
] as const

function buildApiProxyRules(): Record<string, { proxy: string }> {
  const base = process.env.NUXT_API_PROXY_TARGET || 'http://localhost:8090'
  const rules: Record<string, { proxy: string }> = {}
  for (const prefix of PROXIED_API_PREFIXES) {
    rules[`/api/v1/${prefix}/**`] = { proxy: `${base}/api/v1/${prefix}/**` }
    rules[`/api/v1/${prefix}`] = { proxy: `${base}/api/v1/${prefix}` }
  }
  return rules
}

export default defineNuxtConfig({
  compatibilityDate: '2025-05-15',
  ssr: false,
  devtools: { enabled: true },

  modules: ['nuxt-quasar-ui', '@pinia/nuxt', '@vueuse/nuxt'],

  quasar: {
    plugins: ['Notify', 'Dialog', 'Dark'],
    extras: {
      fontIcons: ['material-icons-sharp'],
    },
  },

  css: ['~/assets/styles/global.scss', '~/assets/styles/themes/light.scss', '~/assets/styles/themes/dark.scss'],

  routeRules: buildApiProxyRules(),

  vite: {
    css: {
      preprocessorOptions: {
        scss: {
          additionalData: '@use "~/assets/styles/tokens" as *;',
        },
      },
    },
  },

  app: {
    head: {
      title: 'OTALON',
      meta: [{ name: 'description', content: 'OTALON Security Monitoring for Industrial Control Systems' }],
      link: [
        // SVG first: modern browsers pick it and follow prefers-color-scheme,
        // so the mark stays legible on dark tab bars. The .ico keeps Safari and
        // pinned-tab/legacy surfaces served (16/32/48/64 frames).
        { rel: 'icon', type: 'image/svg+xml', href: '/favicon.svg' },
        { rel: 'icon', type: 'image/x-icon', href: '/favicon.ico' },
        { rel: 'apple-touch-icon', href: '/apple-touch-icon.png' },
      ],
    },
  },
})
