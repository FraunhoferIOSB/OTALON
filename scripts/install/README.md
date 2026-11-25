# Local Installer Utilities

Dependency-free Python 3.10+ helpers for Linux and WSL checkouts. Follow [INSTALL.md](../../INSTALL.md) for native Linux or [INSTALL-WSL.md](../../INSTALL-WSL.md) for Windows/WSL. These commands prepare local files only; they do not build images, authorize interfaces or verify external models. Continuous Desktop code is a release candidate until the genuine Windows/Npcap and final fresh-image gates pass.

```sh
python3 scripts/install/setup.py --workspace "$PWD"
python3 scripts/install/check.py --workspace "$PWD"
sudo python3 scripts/install/bootstrap_influx.py --workspace "$PWD"
```

- setup.py creates .env.compose only when absent, fills missing/template local DB, service and callback secrets with cryptographic randomness, and derives the workspace path/build reference. Missing capture keys take the sample defaults: `CAPTURE_TYPE=NONE`, empty `CAPTURE_SOURCE`, `PCAP_IMPORT_MAX_UPLOAD_BYTES=1073741824`. Explicit LIVE/source/smaller budget, credentials, comments, order, inode, owner and mode are retained. External LiteLLM credentials/model aliases are operator inputs only when LLM features are selected; approved LIVE capture and separately authorized scan interfaces remain operator inputs. Generated values are never printed.
- check.py validates local required values, model-alias shapes, PostgreSQL DSNs, credential-derived caller registries and endpoint shapes. `http://host.docker.internal:4000/v1` is a valid Desktop host URL in both modes when credentials/model aliases are configured. Neither mode contacts the endpoint or proves served-model availability. --syntax-only permits explicit `.invalid`/`offline-unconfigured` endpoint markers, still requires configured non-placeholder credentials/model aliases, and is not a deployment-readiness gate. The normal check rejects those actual offline markers. Literal `@url:` prefixes or Markdown backticks are malformed input, not normalized URLs.
- bootstrap_influx.py requires an existing shared/ directory. New files use exclusive no-replace publication and ownership 1500:1500 with mode 0600. Matching existing JSON is preserved, including extra members and formatting. Mismatched tokens, duplicate keys, unsafe links or wrong existing metadata fail without automatic repair. Database credentials/volumes are never accessed or rotated.

The environment parser deliberately accepts only a restricted Compose subset: UTF-8, LF/CRLF, NAME=value, single-quoted literals and bare/double-quoted ${NAME} references to earlier assignments. Unsupported shell-style substitutions, duplicate assignments, malformed quotes, control characters and unsafe links are rejected. Environment input and cumulative expanded values are each limited to 1 MiB; bootstrap JSON is limited to 1 MiB. Parent directories must be readable/searchable by the caller. In-place updates require file write access, not ownership; preservation is not a promise of transactional recovery from disk failure.

## Capture Intent And Deployment

- Boot intent is exactly NONE/LIVE, with absent intent defaulting NONE. `check.py` uses the parsed selected document's resolved values, never process environment for intent, and trims decoded surrounding whitespace. Empty, lowercase, AUTO and unknown modes fail without echoing values. PCAP is retired for startup with exactly: `CAPTURE_TYPE=PCAP is retired for service startup; use CAPTURE_TYPE=NONE and import PCAP/PCAPNG through Operations / Data Sources.` Internal PCAP file processing remains supported.
- Native LIVE source must match exactly `[A-Za-z0-9_][A-Za-z0-9_.:-]{0,14}`; a syntactically safe absent NIC is source-unavailable at runtime, not syntax failure or readiness proof. NONE exempts only unused capture source from capture checks; normal DB/operator/import/evidence/log/selected LLM checks remain. `--desktop` retains original unused Linux capture/scan selection semantics, not scanner authorization bypass; malformed env grammar remains invalid even for unused fields.
- Base `docker-compose.yml` means native. Base + `docker-compose.wsl.yml` means WSL receiver even in NONE. There is no AUTO/backend API/control-plane selection. Keep step 3's platform/AI/service exports, then each guide's step-4 parsed capture-mode block after env preparation and in every new shell before any Compose check/build/start/recreate. The block imports existing dependency-free `scripts.install._common.read_env`, prints only normalized NONE/LIVE on success and never sources an env file or echoes configuration.
- Native uses base only. WSL NONE uses base + WSL with exported `COMPOSE_CAPTURE_OVERLAY=`. WSL LIVE uses exactly base + WSL + `docker-compose.wsl-live.yml` and exports `COMPOSE_CAPTURE_OVERLAY=docker-compose.wsl-live.yml` so API-owned recreation selects the same exact conditional overlay. The runner allows only empty or that exact capture overlay with WSL; it is not a public boot editor. Existing LIVE upgrades must deliberately include the mount overlay; missing key/mount stays explicit failure. Mode/source changes need affected-service rebuild/recreation as relevant, not hidden runtime toggling.
- NONE still needs rootful Docker/Compose/Git/host Python, normal suite DB/auth/log/import/evidence paths, shared group, bootstrap and migrations. It needs no capture NIC/SPAN/TAP, raw-acquisition readiness, Windows launcher/Wireshark/Npcap, source-key prep/export, collector config or dumpcap startup. Native scanner prerequisites/authorization remain separate; no active scan smoke. NONE gates acquisition at runtime and does not remove shared-image native dependencies or the base/native privilege surface.
- Native plain entrypoint defaults to the recorder coordinator, which owns the adapter child only in LIVE; worker `NETCAP_ENTRYPOINT_MODULES=pcap_import.main` is resolved before the automatic gate. NONE retains idle REST/health and explicit authenticated historical text/detail/pinning without automatic capture or evidence eviction. Native legacy recording is current tcpdump truth; `source_state=recording` additionally requires the current ready adapter pair. REST/health or a spawned PID is not acquisition/publication proof.
- Source-unavailable retry policy is five attempts, immediate then 2/4/8/16-second delays, five-second readiness, and 60-second stable recording reset. Exhaustion stays waiting/degraded with explicit retry exhaustion; recreation resets the budget. Auth/config/privilege/checkpoint/integrity/unknown errors are blocked, not source retries. Persistent and console warnings remain distinct from telemetry freshness. The numeric eight-second coordinator teardown is Native-scoped inside the existing outer ten-second grace, not a universal WSL deadline.

## Core installation without an LLM gateway

LiteLLM and upstream models are optional for core OTALON. Keep the default strict gateway checks when enabling LLM features; otherwise explicitly select:

```sh
python3 scripts/install/setup.py --workspace "$PWD" --without-ai
python3 scripts/install/check.py --workspace "$PWD" --without-ai
```

- `--without-ai` preserves all external values exactly and exempts only gateway URL/key/chat/jobs aliases from readiness checks. Full env grammar, local DB/service keys, DSNs, registries and workspace/reference validation remain enforced; `--syntax-only` is not a replacement for this mode.
- The flag prepares/checks local files only; it does not stop services. Use the non-AI service selection in the matching installation guide to exclude `otalon-ai` when starting/recreating. Capture follows the separate NONE/LIVE intent and detection remains enabled; LLM chat/classification/jobs are unavailable. Already running AI containers are not stopped automatically.

## Continuous Desktop preparation

```sh
python3 scripts/install/check.py --workspace "$PWD" --without-ai --desktop
# LIVE only, after the guide's parsed capture selection; skip both prep commands in NONE:
if [ "${CAPTURE_MODE:?Use INSTALL-WSL.md step 3 then step 4 capture selection}" = LIVE ]; then
  sudo python3 scripts/install/prepare_wsl.py --workspace "$PWD" --receiver-uid 10006
fi
```

For new/changed collector source only, after TLS proxy startup and NTFS ACL
review, restore the guide's shell selection before exporting:

```sh
if [ "${CAPTURE_MODE:?Use INSTALL-WSL.md step 3 then step 4 capture selection}" = LIVE ]; then
  sudo python3 scripts/install/prepare_wsl.py --workspace "$PWD" --receiver-uid 10006 --export /mnt/c/OTALON
fi
```

- `--desktop` exempts unused Linux interface fields only; all env grammar, DB and service-key checks remain. It does not validate Windows capture.
- `prepare_wsl.py` is an explicit LIVE-only guide action, not automatic setup. Source-only mode precedes LIVE receiver startup; export requires its public TLS certificate. It never rotates an existing source key or exports suite/DB/operator credentials. Existing differing key/certificate exports refuse. `collector.zip` is rebuilt from current source; `collector.sample.json` is preserved for operator edits. Source stays `shared/continuous-source.key`, target `/run/secrets/continuous-source-key`, single read-only bind with `create_host_path: false`; never move/rotate the key or mount all of shared.
- Windows package uses stdlib only, native `dumpcap`, an exact Npcap device and verified HTTPS. The Windows directory needs reviewed NTFS ACLs; Linux mode bits on `/mnt/c` are not security proof.
- `init_continuous_volume.py --root <mounted-volume> --uid <service-uid>` runs in a one-off container; it initializes only an empty root and preserves a matching populated root. Wrong populated metadata refuses without recursive repair. Use exactly the Compose volume mounts from INSTALL-WSL.md. Initialize continuous ingestion only when LIVE needs a writable processor, not for idle NONE. Keep the independent recovery-volume policy when using existing committed recovery in NONE/LIVE; do not disable `CONTINUOUS_RECOVERY_ENABLED` or Detection.
- Collector receipt means durable custody, not detection completion. Retained-storage caps stop/refuse when full, preserving evidence; no indefinite-retention or zero-loss claim. Final Windows/fresh-image/browser/recovery gates remain open.
- WSL NONE uses a missing-ledger empty read view and preserves existing custody without automatic consumption/checkpoint advance/outbox publication/tail flush/eviction or false ACK. Automatic writes return disabled 503 before consumption/mutation; the collector keeps pending spool unacknowledged. Historical authenticated evidence and committed recovery are not new ingestion; unsafe/corrupt custody is not repaired.
- Receiver `source_state=disabled` is NONE intent only and remote `recording=null` cannot attest Windows dumpcap stopped. LIVE observations expire after six monotonic seconds or restart; stored history cannot restore current recording. Fresh authenticated observation may restore collector presence after waiting/degraded, not remotely start capture. Stop your own collector with Ctrl+C/owner reconciliation before NONE and explicitly start it after LIVE configuration/TLS/auth/authorized NIC readiness; do not terminate unrelated Wireshark processes.
- Unchanged collector source requires no new export/ZIP merely to select receiver mode. Changed collector source requires clean stop/re-export, preserving edited JSON/source key/certificate/spool. Keep verified IPv4 `https://127.0.0.1:9493`, certificate validation, source/operator credential separation and reviewed NTFS ACLs. No physical Windows proof for this feature is established by these helpers or Linux tests.

## Manual Upload And Ownership

- **Operations / Data Sources** manual PCAP/PCAPNG import is independent in NONE/LIVE. Picker/drop append all files as always-visible rows and automatically queue work. One file's upload must reach its persisted terminal job state (completed/failed/cancelled/rejected) before the next upload within browser lifetime. This is not a server-global/cross-browser transaction, durable batch or window lock. There is no concatenation or timestamp jitter.
- Default payload is **1024 MiB per file (1 GiB)**, exactly `1073741824` bytes. At most 64 KiB (`65536` bytes) covers the entire non-file multipart envelope; default total request is `1073807360` bytes. Server configuration is authoritative; preserved smaller payload budgets can accurately return 413. Small-budget arithmetic tests do not measure deployed 1024 MiB/RSS acceptance. Collector limits are unchanged and independent: nginx `32m`, receiver `32000000` bytes.
- Transfer progress is measured request-transfer bytes/total, or indeterminate when unmeasured; 100% is not accepted/imported/completed or written-metric progress. Every file has its own errors/status. 409 retains a row-local conflict; force confirmation names that file, measurement/window and overwrite risk, not a batch force. No timestamps are shifted to hide conflicts.
- Pending/conflict cancellation affects only that row. Upload abort cannot prove no server effects. Accepted queued/running/cancelling work holds the scheduling barrier until authenticated persisted settlement; cancellation cannot undo already written metrics. Identity-bearing cancellation must target that known display ID, never a similar history row or newer worker slot.
- A lost acceptance ID is never guessed from filename/size/time/history position. Uncertain acceptance, authentication failure, query failure, saturated state-domain job lists or reconciliation-required cancelling block automatic resend/new dispatch. Bounded per-state history uses the PCAP-import domain, and saturation is not absence proof; list total is returned-item count, not a global job count.
- After request-based grace, cancellation report-loss reconciliation makes at most three automatic authenticated worker status attempts. Missing/malformed/idle/restarted/different-ID status or health alone does not prove settlement. Inconclusive attempts leave cancelling with `Cancellation needs reconciliation; worker settlement is unverified.` and no automatic resend or input deletion. The row's explicit same-ID cancel/reconcile action can request a fresh bounded episode; a matching authenticated late terminal report still releases the barrier. Cancellation request success alone is not terminal truth.
- Same-app store ownership survives page navigation. Full browser reload loses unuploaded `File` bytes and requires re-selection; persisted server jobs/history remain and known nonterminal jobs must reconcile before fresh local uploads. Browser bytes are not durable server custody. Manual history import does not automatically trigger historical recovery or Detection for arbitrary ranges.

## Source Verification And Fresh Acceptance

The guidance describes source-verified contracts, not a release/live verdict.
Fresh owned images and all affected consumers must be rebuilt/recreated from
the selected source. Required fresh acceptance includes authenticated HTTPS
boot/NONE/status/health/error behavior and picker/drop/conflict/force/limits/
cancel/reload through both manual routes, with exact persisted packet/byte/time/
MAC/protocol data and recreate checks without reupload. Actual structurally
valid 600 MiB and exactly 1024 MiB PCAP/PCAPNG must pass through both 8443 UI
proxy and 8493 API HTTPS routes with measured envelope, identity/digest/count,
cgroup/RSS peaks, <=128 MiB incremental RSS per UI/API intake process, no OOM,
no whole-file growth and temporary cleanup on refusal/cancel. Small tests,
healthy containers and historical dated smoke do not prove these boundaries or
GUI behavior. Physical Windows/NIC availability remains a separate evidence
gap, never synthetic acceptance.

Rollback is parent/operator-owned: stop owned collectors, preserve custody,
spool, checkpoint, jobs, metrics and configuration; rebuild/recreate reverted
selected source and consumers. The approved old baseline rejects NONE and has
a lower upload default; never blindly boot it in NONE, overwrite operator
selections or delete data to make rollback pass. Permanent database
write-authentication failure propagation, exception-safe partial receiver
construction and controlled in-flight shutdown still require targeted repair
and verified acceptance. Authorization to repair is not evidence of completion.
The eight-second clause is Native-scoped, not a WSL deadline. Receiver stop
must join settled work or verify actual module-process termination through the
existing supervisor, never abandon a thread or report late successful work.
Automated technical E2E precedes separate operator acceptance.

Tests use disposable files only. Stdlib unittest covers legacy helpers; pytest is required for continuous package/volume tests. Set INSTALL_TEST_ROOT to an absolute disposable directory to keep fixtures outside the checkout. No application/database fixtures are imported.

```sh
INSTALL_TEST_ROOT="$HOME/.cache/otalon-install-tests" \
  python3 -m unittest discover -s scripts/install/tests -p 'test_*.py' -v
```

Ownership cases require an authorized privileged run against disposable files; an ordinary run reports those skips explicitly. A root test is not a substitute for an actual nonroot supplementary-group writer. These helpers do not establish native/WSL, database-migration, HTTPS/UI-PCAP, detection or provider-tool-loop acceptance.
