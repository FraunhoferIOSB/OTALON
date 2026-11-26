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

Deployment requires rootful Docker/Compose, Git, host Python, PostgreSQL,
InfluxDB 3 Core, and normal authentication, logging, import and evidence paths.
AI features additionally require an operator-provided LiteLLM-compatible
endpoint and model aliases. New installations default to `CAPTURE_TYPE=NONE`
and empty `CAPTURE_SOURCE`: manual import remains available without a capture
NIC/SPAN/TAP or raw-acquisition readiness. Native active-scanner prerequisites
and authorization remain separate; NONE is not a scanner bypass and does not
remove the base deployment's existing capabilities or native image dependencies.

Boot intent is explicitly `NONE` or `LIVE`, not PCAP or AUTO. The base
`docker-compose.yml` selects native; base plus `docker-compose.wsl.yml` selects
the WSL receiver even in NONE. Native LIVE needs an explicitly authorized Linux
source and real readiness/freshness checks. Windows LIVE uses native
Npcap/dumpcap with processing in WSL2/Docker Desktop (test candidate), and loads
exactly base + WSL + `docker-compose.wsl-live.yml`. The installation shell must
export `COMPOSE_CAPTURE_OVERLAY=docker-compose.wsl-live.yml` for consistent
API-owned recreation. WSL NONE uses base + WSL with that export empty, needs no
Windows launcher/Wireshark/Npcap, source-key preparation/export or collector
start, and preserves existing custody without automatic consumption. Stop the
owned Windows collector explicitly before choosing NONE; receiver disabled
status cannot attest remote dumpcap stopped. Mode/source changes need explicit
affected-service rebuild/recreation as relevant, not a runtime toggle.
UI development uses Node 22.22.3 or newer
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

- Native Linux installation: [INSTALL.md](INSTALL.md)
- Windows / WSL2 continuous capture: [INSTALL-WSL.md](INSTALL-WSL.md)
- Contributor contract: [AGENTS.md](AGENTS.md)
- MCP usage and endpoint references: [otalon-mcp/docs/](otalon-mcp/docs/)

## Workshop Candidate

The `workshop-wsl-extension` tag identifies the workshop candidate for operator-led
final acceptance. See [WORKSHOP-WSL.md](WORKSHOP-WSL.md) for checkout instructions,
verified scope and known limitations. This tag is not a stable release or a claim
that the remaining GUI, large-upload, physical Windows or shutdown gates passed.

## Capture And Manual Import

In **Operations / Data Sources**, picker and drop selections append all files
as visible rows and automatically queue one file's upload through persisted
terminal job settlement before the next. This is browser-lifetime ordering,
not a server-global or cross-browser transaction; files are not concatenated
and timestamps are not jittered. The default is **1024 MiB per file (1 GiB)**:
payload `1073741824` bytes plus at most 64 KiB multipart envelope, default
total request `1073807360` bytes. Server configuration is authoritative;
existing smaller limits are preserved and can accurately return 413. Collector
limits remain separate at nginx `32m` / receiver `32000000` bytes.

Progress measures request transfer only: 100% is not acceptance, import or
completion. Conflicts and overwrite confirmation are per named file/window.
Cancellation cannot undo written metrics; accepted cancelling work holds the
queue until authenticated settlement. Lost acceptance identity, authentication
failure, saturated active-job lists or reconciliation-required cancellation
block automatic resend. Same-app navigation retains store ownership; full
reload loses unuploaded `File` bytes and requires re-selection, while persisted
jobs/history remain. Manual history import does not automatically trigger
historical recovery. Detailed ownership and retry contracts are in
[scripts/install/README.md](scripts/install/README.md).

Health/REST liveness is not recording or persistence proof. Source-verified
contracts and isolated small tests are not fresh acceptance of NONE/status,
GUI behavior or the 1024 MiB/RSS boundary. Fresh owned images/consumers,
authenticated HTTPS picker/drop/error/cancel/reload checks, exact persisted
data, and actual 600/1024 MiB PCAP/PCAPNG on both HTTPS routes with UI/API
incremental RSS <=128 MiB, cgroup peaks, no OOM and temporary cleanup remain
required. Physical Windows/NIC acceptance remains a separate evidence gap;
dated smoke observations are historical only. Rollback preserves custody,
spool, checkpoints and metrics, stops owned collectors and rebuilds/recreates
reverted source: the approved old baseline rejects NONE, so never blindly boot
that rollback in NONE or erase configuration/data to make it start.

Licensed under the [MIT License](LICENSE). Third-party components retain their
own license terms and notices.
