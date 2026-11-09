# OTALON

> **🚧 Under construction**
>
> **Version: pre-release (development snapshot).** OTALON is under active
> development and is not yet a stable release. Features, APIs, and deployment
> configuration may change before the first stable release.

OTALON is a modular network monitoring and anomaly-detection suite for
industrial control system environments. It collects network telemetry, detects
behavioral changes, and provides operator-facing investigation and management
interfaces. Deploy it only on networks and systems you are authorized to
monitor.

| Component | Responsibility |
| --- | --- |
| `otalon-capture` and `netcap++` | Live and imported packet capture and telemetry |
| `otalon-clas` | Bounds, frequency, and classifier-based detection |
| `otalon-scan` | On-demand asset and service discovery |
| `otalon-api` and `otalon-ui` | Product API and operator interface |
| `otalon-mcp` and `otalon-ai` | MCP tools, chat orchestration, and analysis jobs |
| `otalon-common` | Shared configuration, identity, and runtime utilities |
| `tls-proxy` | HTTPS entry point for the application |

Deployment requires Docker Compose, PostgreSQL, InfluxDB 3 Core, and an
operator-provided LiteLLM-compatible endpoint and model aliases for AI features.
Capture and active scanning also require a prepared Linux host and explicit
network-interface/capability decisions. UI development uses Node 22.22.3 or newer
in the Node 22 line and npm 11.6.2 (`npm install --global npm@11.6.2`); the
Docker builder installs that pinned npm resolver. A fresh checkout uses
`npm install`, then `npm run test:run`, `npm run build`, and `npm run typecheck`
from `otalon-ui/`. Local lockfiles are not publication inputs.

Python test collection does not probe PostgreSQL by default. Set
`OTALON_TEST_DB_PROBE=1` only with an explicitly provisioned disposable test
DB and matching `POSTGRES_*`/`POSTGRES_DSN` settings when exercising the
retained scanner SQL/migration cases. The capture CSV fixture is constructed
regression data, not production telemetry or proof of production equivalence.
UI `typecheck` enforces a 149-error ratchet; the raw checker is not clean.

- Prepared-host deployment: [INSTALL.md](INSTALL.md)
- Contributor contract: [AGENTS.md](AGENTS.md)
- MCP usage and endpoint references: [otalon-mcp/docs/](otalon-mcp/docs/)

Licensed under the [MIT License](LICENSE). Third-party components retain their
own license terms and notices.
