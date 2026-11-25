# Install OTALON on Windows / WSL2

- Windows/WSL only. For native Linux capture, use [INSTALL.md](INSTALL.md) instead.
- **Required:** WSL2 Ubuntu, rootful Docker Desktop running with integration enabled for that Ubuntu distribution, Compose 2.24.4+, Git, sudo, Ubuntu Python 3.10+, curl and normal runtime DB/auth/log/import/evidence paths. Keep the checkout on WSL's Linux filesystem, not `/mnt/c`. Only `LIVE` additionally requires native Windows Python 3.10+ with its launcher, Wireshark/Npcap and an authorized NIC/SPAN/TAP feed. NONE requires no collector prerequisites or raw-acquisition readiness.
- **Status:** continuous Desktop test candidate, **not release-qualified**. Linux receiver/HTTPS/recovery tests and a limited physical Windows/Npcap handoff test are recorded; complete processing, browser, cache-free build and recovery/persistence gates remain open (step 14).
- **Capture path:** LIVE uses Windows Npcap/dumpcap → automatic verified HTTPS transfer → Linux receiver/Netcap++ → InfluxDB/CLAS/UI. NONE is idle receiver intent with independent manual imports and retained historical reads, not physical capture inside WSL containers. Boot intent accepts only NONE/LIVE; new/absent intent defaults NONE with empty `CAPTURE_SOURCE`.
- **LLM gateway optional:** core capture/detection/UI work without LiteLLM; LLM chat/classification/jobs do not.
- **Security:** published ports bind to loopback; the overlay removes raw-capture capabilities and host-root mounts. API Docker-socket and writable-checkout access remain root-equivalent. Capture only an authorized NIC/SPAN/TAP feed; no active scans as smoke tests.
- Steps 1-11 run in **Ubuntu Bash**, not Windows PowerShell. Step 13 labels each shell switch and is LIVE-only. Only for LIVE, check `py -3 --version` in Windows PowerShell before collector preparation; if missing, install native Python and reopen PowerShell. Ubuntu's Python is not a replacement. NONE skips Windows launcher/Npcap/key/export/collector configuration and dumpcap startup entirely.
- Run blocks in order and stop on errors. Never print keys, resolved Compose configuration or DSNs. Preserve existing env files, certificates, retained capture and volumes.

## 1. Clone

```sh
git clone --single-branch --branch wsl-compatible \
  https://github.com/FraunhoferIOSB/OTALON.git /home/user/otalon
cd /home/user/otalon
export WORKSPACE_DIR="$PWD"
```

- This candidate installation targets `wsl-compatible`; confirm with `git branch --show-current`. HTTPS does not require a GitHub SSH key. An SSH `Permission denied (publickey)` is an authentication failure, not an installation failure; use HTTPS rather than creating a second checkout.
- Existing checkout: skip clone; enter its actual path and use `git pull --ff-only`. Do not reset local changes or recopy the env sample. Linux paths are case-sensitive: `/home/user/OTALON` and `/home/user/otalon` are different paths. Use your actual path in every later `cd`.

## 2. Join the shared group

- Check `command -v newgrp`. If absent, install your release's suggested package: `util-linux-extra` in the reported WSL setup; Ubuntu 24.04 supplies it with `login`. Check the command again before proceeding.

```sh
getent group 10000 || sudo groupadd -g 10000 otalon-shared
sudo usermod -aG "$(getent group 10000 | cut -d: -f1)" "$USER"
newgrp "$(getent group 10000 | cut -d: -f1)"
```

At the new prompt, restore the checkout and exports:

```sh
cd /home/user/otalon
export WORKSPACE_DIR="$PWD"
id
```

- Confirm supplementary GID 10000. Use your actual checkout if different. Logging out/in instead of `newgrp` is also valid.

## 3. Select Desktop core services

```sh
# Run from the checkout root, including in each new Ubuntu shell.
export WORKSPACE_DIR="$PWD"
INSTALL_PLATFORM=desktop
INSTALL_PLATFORM_ARGS=--desktop
export COMPOSE_FILE="$WORKSPACE_DIR/docker-compose.yml:$WORKSPACE_DIR/docker-compose.wsl.yml"
INSTALL_AI_ARGS=--without-ai
OTALON_SERVICES='tls-proxy postgres influxdb3 otalon-capture otalon-capture-pcap-import otalon-clas otalon-ui otalon-api otalon-scan otalon-scan-passive-seeder otalon-scan-cve-lookup otalon-mcp'
```

- Repeat step 3, then step 4's capture-mode selection in each new shell before any Compose operation. Base + WSL are always required, including NONE; LIVE additionally needs exactly `docker-compose.wsl-live.yml` for every check/build/start/recreate. `--desktop` only changes installer checks, it does not load an overlay or bypass scanner authorization.
- No Docker Desktop host networking is needed for capture or migrations. In LIVE Windows captures the physical NIC; the containers use a Compose bridge.
- Making `CAPTURE_SOURCE` match a WSL NIC can make native containers healthy but does not enable the Windows receiver. Never drop the overlay or add privileges as a workaround.
- Optional LLM: first configure a real container-reachable LiteLLM-compatible `/v1` endpoint, scoped key and exact served chat/jobs aliases. A gateway does not supply provider access. Then set `INSTALL_AI_ARGS=` and append `otalon-ai` to `OTALON_SERVICES`. Excluding it does not stop an already running AI container.

## 4. Prepare local configuration

```sh
if [ ! -e .env.compose ] && [ ! -L .env.compose ]; then
  python3 scripts/install/setup.py --workspace "$WORKSPACE_DIR" ${INSTALL_AI_ARGS:-} &&
  sudo chown 10001:10000 .env.compose && sudo chmod 0660 .env.compose
fi
python3 scripts/install/setup.py --workspace "$WORKSPACE_DIR" ${INSTALL_AI_ARGS:-}
stat -c '%u:%g %a %n' .env.compose
nano .env.compose
```

- New file: `10001:10000 660`. Existing metadata is not automatically repaired. Setup fills only missing/template local credentials and missing capture defaults; explicit LIVE/source/smaller upload budget, credentials, comments, order, inode, ownership and mode are retained.
- Edit the top **EDIT THIS SECTION** only: confirm workspace/build reference and select exactly `CAPTURE_TYPE=NONE` or `CAPTURE_TYPE=LIVE`. Linux `CAPTURE_SOURCE`/`SCAN_SOURCE` selection remains unused under the original desktop checker semantics; LIVE selects the Npcap NIC later on Windows. This is not authorization to scan.
- No LLM: leave its four external fields untouched. With LLM: configure URL/key/chat/jobs aliases and prove a real request separately. `http://host.docker.internal:4000/v1` is a valid Desktop-host address, not a reachability guarantee.
- Nano: Ctrl+O, Enter, Ctrl+X. Never share `.env.compose`. Env edits do not rotate initialized DB credentials.

After environment preparation, select the exact files from decoded intent in
the parsed selected document, not process environment or an AUTO/OS/NIC
heuristic. Run this block after step 3 in each new Ubuntu shell and after mode
edits, before any Compose operation:

```sh
CAPTURE_MODE="$(python3 - "$WORKSPACE_DIR/.env.compose" <<'PY'
from pathlib import Path
import sys
from scripts.install._common import InstallError, read_env

try:
    _, document = read_env(Path(sys.argv[1]))
    mode = document.resolved.get("CAPTURE_TYPE", "NONE").strip()
    if mode == "PCAP":
        raise InstallError("CAPTURE_TYPE=PCAP is retired for service startup; use CAPTURE_TYPE=NONE and import PCAP/PCAPNG through Operations / Data Sources.")
    if mode not in ("NONE", "LIVE"):
        raise InstallError("CAPTURE_TYPE must be NONE or LIVE for service startup.")
except InstallError as exc:
    print(str(exc), file=sys.stderr)
    raise SystemExit(1)
except OSError:
    print("Capture selection file unavailable; run the local checker.", file=sys.stderr)
    raise SystemExit(1)
print(mode)
PY
)" || exit 1
export COMPOSE_CAPTURE_OVERLAY=
export COMPOSE_FILE="$WORKSPACE_DIR/docker-compose.yml:$WORKSPACE_DIR/docker-compose.wsl.yml"
if [ "$CAPTURE_MODE" = LIVE ]; then
  export COMPOSE_CAPTURE_OVERLAY=docker-compose.wsl-live.yml
  export COMPOSE_FILE="$COMPOSE_FILE:$WORKSPACE_DIR/docker-compose.wsl-live.yml"
fi
```

- The dependency-free parser prints only normalized NONE/LIVE on success, trims decoded whitespace and rejects invalid intent without echoing values. Never source an env file or print resolved configuration. Empty/lowercase/AUTO boot values are invalid; PCAP is retired for startup, not internal manual processing.
- NONE uses exactly base + WSL and empty `COMPOSE_CAPTURE_OVERLAY`. LIVE uses exactly base + WSL + `docker-compose.wsl-live.yml`; exporting its exact name also configures API-owned recreation. Existing LIVE upgrades must deliberately include it. Mode/source changes require explicit affected-service rebuild/recreation as relevant, not a hidden runtime toggle or public backend selector.
- Before switching to NONE, cleanly stop your own Windows collector with Ctrl+C and reconcile its owner; do not stop unrelated captures. A receiver cannot remotely stop or attest dumpcap stopped. NONE refuses automatic writes with 503 and retains unacknowledged pending spool/custody.

## 5. Prepare shared paths

```sh
sudo install -d -o root -g root -m 0755 shared
sudo install -d -o root -g 10000 -m 2775 \
  shared/logs shared/models shared/pcap/buffer shared/pcap/archive \
  shared/pcap/baseline shared/operations
sudo install -d -o root -g root -m 0750 shared/tls
```

- Do not recursively change existing data. API-managed config updates need checkout-root create/rename access for GID 10000: `sudo chgrp 10000 "$WORKSPACE_DIR" && sudo chmod g+ws "$WORKSPACE_DIR"`. This grants the group checkout write access.
- Only for LIVE, provision the separate source credential **before** receiver startup; NONE does not prepare or mount a source key:

```sh
if [ "${CAPTURE_MODE:?Repeat step 3 then step 4 capture selection}" = LIVE ]; then
  sudo python3 scripts/install/prepare_wsl.py --workspace "$WORKSPACE_DIR" --receiver-uid 10006
fi
```

- Existing source credentials are not rotated or silently re-owned. Permission mismatch requires explicit inspection, not deletion.
- The LIVE overlay mounts only `shared/continuous-source.key` at `/run/secrets/continuous-source-key`, read-only with `create_host_path: false`; missing key/mount remains an explicit failure. Do not move/rotate the key or mount the whole shared directory. Selecting receiver mode alone needs no fresh export/ZIP when collector source is unchanged; preserve edited JSON, key, certificate and spool.

## 6. Check configuration and bootstrap Influx authentication

```sh
python3 scripts/install/check.py --workspace "$WORKSPACE_DIR" \
  ${INSTALL_AI_ARGS:-} ${INSTALL_PLATFORM_ARGS:-} &&
docker compose --env-file .env.compose --profile all config --quiet &&
sudo python3 scripts/install/bootstrap_influx.py --workspace "$WORKSPACE_DIR" &&
sudo stat -c '%u:%g %a %n' shared/influx-admin-token.json
```

- Expected bootstrap file: `1500:1500 600`. Read denial for ordinary users is intentional. Do not print JSON or loosen permissions.
- Checks validate local shapes only; they do not contact models, authorize a NIC or establish platform readiness. Mismatched existing bootstrap credentials refuse without rotation.
- The Desktop overlay uses a 100 ms Influx WAL flush interval for local storage. Writes still wait for durable WAL acknowledgement; this is not `no-sync`. Continuous publication batches all same-destination measurement lines per chunk before exact readback, rather than waiting for a separate WAL flush for each metric window.

## 7. Build

```sh
DOCKER_GID="$(docker run --rm --network none \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  --entrypoint sh postgres:15@sha256:9b1d34adbce1dd07ee6e94b4a2cf698884b89bd44a6c9c12f5da8f3acbfe4957 \
  -c 'test -S /var/run/docker.sock && stat -c %g /var/run/docker.sock')"
case "$DOCKER_GID" in ''|*[!0-9]*) printf '%s\n' 'Invalid socket GID'; exit 1 ;; esac
docker compose --env-file .env.compose --profile all build \
  --build-arg "DOCKER_GID=$DOCKER_GID" ${OTALON_SERVICES:?Repeat step 3}
```

- First build downloads dependencies and takes several minutes. Socket mounting is not a security boundary; use the actual daemon socket GID. Successful builds do not initialize DBs.

## 8. Initialize new data volumes

```sh
docker compose --env-file .env.compose --profile all run --rm --no-deps \
  --user 0 --entrypoint sh otalon-capture-pcap-import \
  -c 'chown 0:10000 /import && chmod 2770 /import'
```

Initialize the receiver volume only when LIVE needs its writable processor;
NONE starts with an empty read view if its ledger is missing, without continuous
ingestion initialization just for idle:

```sh
if [ "${CAPTURE_MODE:?Repeat step 3 then step 4 capture selection}" = LIVE ]; then
  docker compose --env-file .env.compose --profile all run --rm --no-deps \
    --user 0 --cap-add CHOWN --cap-add FOWNER --entrypoint python \
    -v "$WORKSPACE_DIR/scripts/install/init_continuous_volume.py:/volume-init.py:ro" \
    otalon-capture /volume-init.py --root /app/continuous --uid 10006 || exit 1
fi
```

Keep the independently necessary recovery-volume initializer below when using
existing committed recovery, including in NONE. Do not disable
`CONTINUOUS_RECOVERY_ENABLED` or Detection to make idle startup pass:

```sh
docker compose --env-file .env.compose --profile all run --rm --no-deps \
  --user 0 --cap-add CHOWN --cap-add FOWNER --entrypoint python \
  -v "$WORKSPACE_DIR/scripts/install/init_continuous_volume.py:/volume-init.py:ro" \
  otalon-clas /volume-init.py --root /app/recovery --uid 10004
```

- Initializer changes only an empty volume's root; correctly configured populated volumes are preserved. Wrong populated metadata refuses. Never use `down -v` as a repair.
- NONE preserves existing custody, checkpoint, pending outbox and committed recovery without automatic consumption, checkpoint advance, packet-tail flush, eviction or false ACK. Independently authorized historical evidence/committed recovery reads remain distinct from ingestion; unsafe/corrupt custody is not automatically repaired.

## 9. Start databases

```sh
docker compose --env-file .env.compose --profile core-db up -d --wait postgres influxdb3 &&
docker compose --env-file .env.compose --profile core-db exec -T influxdb3 influxdb3 show databases
```

Only if the successful listing lacks `netcap`:

```sh
docker compose --env-file .env.compose --profile core-db exec -T influxdb3 influxdb3 create database netcap
```

- Repeat the listing and confirm `netcap`. CLI reads the container's auth token; never pass it in argv. PostgreSQL initializes `POSTGRES_DATABASE` only for an empty volume.

## 10. Migrate before consumers

```sh
docker compose --env-file .env.compose --profile all run --rm --no-deps \
  --entrypoint python otalon-scan -m alembic -c /app/alembic.ini upgrade head &&
docker compose --env-file .env.compose --profile core-db exec -T postgres \
  sh -c 'exec psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -v ON_ERROR_STOP=1 -Atc "SELECT version_num FROM alembic_version"'
```

- Stored revision for this source: `0015`. Empty `alembic current` output is not proof. Desktop overlay routes migration to bridged `postgres`; no host-networking toggle required.
- CLAS owns additive continuous progress tables and creates/checks them at startup; existing telemetry is not backfilled or replaced.
- On first startup with an existing continuous recovery spool, CLAS adds and backfills a small batch-time index in one transaction. Payloads, module outcomes and checkpoints are preserved; later bounded context reads exclude impossible old batches before expanding records. Recovery uses a short active-work delay and a longer idle/error delay, not a fixed one-second pause per module task.

## 11. Start services

- **Release gate still open**. The following is the candidate test-install path, not a claim of validated Windows operation. No physical capture starts inside a container.

```sh
docker compose --env-file .env.compose --profile all up -d --wait ${OTALON_SERVICES:?Repeat step 3} &&
docker compose --env-file .env.compose --profile all ps
```

- Expect selected services healthy (12 core / 13 with LLM). Healthy processes do not prove data, learned artifacts or detector coverage. Desktop refuses ARP/PROFINET raw-L2 discovery; routed protocol scans still require explicit authorization.
- NONE status `source_state=disabled` describes only receiver intent; remote Windows `recording=null` is unknown, not stopped. Explicit authenticated retained-evidence text/detail inspection is historical access, not automatic capture. LIVE recording requires fresh authenticated current-process observation and usable processing; observations expire after six monotonic seconds or receiver restart. Receipt, observation, metric publication and recovery completion are separate evidence.
- Source/dependency unavailability uses a finite five-attempt episode with 2/4/8/16-second delays and five-second readiness; after exhaustion remain waiting/degraded rather than restart indefinitely. Stable recording for 60 seconds resets a later episode; explicit receiver recreation resets the budget. Fresh authenticated collector observations may restore presence without remotely starting dumpcap. Auth/config/privilege/checkpoint/integrity/unknown errors remain blocked, not source retries. Console/persistent warnings and live REST do not prove acquisition. Native's numeric eight-second teardown bound is not a WSL shutdown promise. Controlled settlement or termination of in-flight receiver work must be verified against the existing module-process supervisor; an abandoned thread is not a stopped processor.
- Verify the actual container commands and network before exporting or capturing:

```sh
docker inspect --format \
  '{{.Name}} command={{json .Config.Cmd}} entrypoint={{json .Config.Entrypoint}} network={{.HostConfig.NetworkMode}} cap_add={{json .HostConfig.CapAdd}}' \
  otalon-capture otalon-scan
```

- Expect `desktop_ingest.main` for capture, `python -m uvicorn otalon_scan.api.server:app ...` for scan, a Compose bridge network (not `host`) and no added capabilities. A restarting scan process that exits with code 0 is not fixed by changing the capture NIC. Stop, check the source/overlay and rebuild/recreate from the correct branch; do not disable healthchecks or add privileges.

## 12. Browser login

- Open `https://localhost:8443` in the Windows browser. Default certificate covers localhost/127.0.0.1; use organization certificates for remote access.
- First login: `admin`, bootstrap password shown on the login page. Complete password change; log out and sign in again. Keep existing changed passwords. Never expose bootstrap login publicly.

## 13. Start continuous capture on Windows

**LIVE only. For NONE, skip this entire step and continue to step 14's manual-import/historical checks. Candidate path; complete Windows/Npcap/data acceptance remains required. No manual upload loop.**

Start the owned collector explicitly only after LIVE file selection, receiver
startup, verified TLS/source auth and authorized Npcap NIC readiness. If the
collector source and existing export are unchanged, reuse them: receiver mode
selection alone does not require a new export/ZIP. For a new collector or a
changed collector source, follow the export and Windows-only steps below after
cleanly stopping the old collector; preserve edited JSON/key/certificate/spool.

Before exporting credentials, prepare the destination in **Windows PowerShell**. For a new single-user local test directory, the following removes inherited access and grants the current account access. Existing directories may have explicit grants or reparse points: inspect them and follow your organization's ACL policy rather than treating this example as a universal repair. Do not recursively reset existing spool/data permissions.

```powershell
if (-not (Test-Path -LiteralPath 'C:\OTALON')) {
    New-Item -ItemType Directory -Path 'C:\OTALON' | Out-Null
}
$account = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
icacls 'C:\OTALON' /inheritance:r /grant:r "${account}:(OI)(CI)F"
if ($LASTEXITCODE -ne 0) { throw 'Export directory ACL setup failed' }
icacls 'C:\OTALON'
```

For new/changed collector source in **Ubuntu Bash**, after TLS startup and
restoring step 3 then step 4 capture selection, export only the collector,
public certificate and source credential:

```sh
if [ "${CAPTURE_MODE:?Repeat step 3 then step 4 capture selection}" = LIVE ]; then
  sudo python3 scripts/install/prepare_wsl.py --workspace "$WORKSPACE_DIR" \
    --receiver-uid 10006 --export /mnt/c/OTALON
fi
```

- Never copy the suite env file or DB/operator keys to Windows. WSL mode bits are not proof of NTFS confidentiality. Back in **Windows PowerShell**, inspect `icacls 'C:\OTALON\source.key'`; stop if unintended accounts can read it. Existing differing key/certificate exports refuse: investigate without deleting them.
- Export rebuilds `collector.zip` from the checkout and preserves existing `collector.sample.json` and matching key/certificate files. After a collector source update, stop the old collector cleanly and repeat this export before using the new version; pulling/building alone does not update the Windows ZIP. Keep the old spool for reconciliation.
- In **Windows PowerShell**, verify native Python and list approved Npcap interfaces:

```powershell
py -3 --version
if ($LASTEXITCODE -ne 0) { throw 'Native Windows Python is required' }
& 'C:\Program Files\Wireshark\dumpcap.exe' -D
if ($LASTEXITCODE -ne 0) { throw 'Npcap interface listing failed' }
notepad C:\OTALON\collector.sample.json
```

- Replace `interface` with the exact `\Device\NPF_...` device from the listing, not a numeric Linux/WSL adapter. **JSON requires every backslash to be doubled.** The following is an example field only; replace the GUID with your authorized device:

```json
"interface": "\\Device\\NPF_{01234567-0123-0123-0123-012345678901}"
```

- The parsed value has single backslashes, matching dumpcap's device name. Pasting unescaped `\Device\NPF_...` into JSON produces `JSONDecodeError: Invalid \escape` before capture starts. Verify physical Ethernet and the authorized feed. Use URL `https://127.0.0.1:9493`, certificate verification and the source-key file. The Desktop receiver publishes IPv4 loopback only; Windows may try `::1` first for `localhost`, adding seconds to every sequential upload/receipt request and causing backlog. The default certificate covers `127.0.0.1`. Export preserves existing JSON: explicitly update an older `localhost` URL after cleanly stopping its collector; do not disable TLS or replace retained spool files.
- Validate JSON and probe the **protected receiver route**, not just `/health`, before starting capture. This GET deliberately sends no key and creates/uploads nothing:

```powershell
py -3 -m json.tool C:\OTALON\collector.sample.json | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Collector JSON invalid; check escaped backslashes' }
$status = curl.exe --cacert C:\OTALON\otalon.crt --silent --show-error `
    --max-time 10 --output NUL --write-out '%{http_code}' `
    'https://127.0.0.1:9493/ingest/v1/runs/otalon-readonly-probe/chunks/0'
if ($LASTEXITCODE -ne 0) { throw 'Receiver TLS/connection failed' }
if ($status -ne '401') { throw "Expected protected receiver HTTP 401, got $status; stop before capture" }
Get-Process dumpcap -ErrorAction SilentlyContinue
```

- `401` is expected without a source key; it proves the protected route exists, not that the collector's credential works. `404` here means the expected route is absent: verify step 3/11 and the Desktop proxy/receiver. A native recorder can return `/health` 200 while lacking all `/ingest/v1` routes. Do not bypass certificate checks or print keys to diagnose this.
- If dumpcap is already running, identify its owner and cleanly stop your previous collector before starting another. Do not terminate unrelated Wireshark captures.
- Start in PowerShell; elevate only if Npcap policy requires it:

```powershell
py -3 C:\OTALON\collector.zip --config C:\OTALON\collector.sample.json
```

- Keep it running. Closed chunks are sent automatically; receiver outages retain backlog and retry. Ctrl+C requests a clean stop. Next start reconciles the prior process/files and resumes retained work. A malformed final file, unknown owner or storage exhaustion fails closed; do not delete evidence.
- Stop your owned collector before selecting receiver NONE; 503 disabled refusal leaves pending spool unacknowledged. Receiver mode selection never remotely starts/stops Windows dumpcap and disabled receiver status is not process-stop proof.
- `Receiver unavailable` is a general handoff failure, not proof of a DB outage; first repeat the TLS/route/platform checks. An `os.fsync` / `Bad file descriptor` traceback indicates a faulty/old collector build: update to the corrected source and re-export the ZIP. Never remove `fsync`, ignore its failure or delete `spool`, `collector.sqlite3` or `owner.json` to make startup pass.
- Collector limits default to 2 GB pending spool / 1 GB free reserve; receiver custody and recovery have bounded retained storage. These are safeguards, **not** indefinite-retention/zero-loss guarantees. Reaching a limit needs operator attention; do not claim automatic capacity recovery.
- File closure does not seal a logical metric window. Quiet/final tails wait for later packets; original timestamps are retained. Collector receipt, Influx visibility and per-module recovery completion are separate facts.

## 14. Verify real data and persistence

- For LIVE continuous acceptance, without uploading files inspect **Timeseries Data → Connections**, MAC/protocol measurements and **Alarms** at the original capture timestamps. Check real row growth, enabled profiles and persisted recovery outcomes. In NONE verify independent manual import and retained historical reads, not new continuous processing. Missing artifacts/context must remain explicit, never fake coverage.
- Manual import in **Operations / Data Sources** works in NONE/LIVE independently. Picker/drop append all files as visible rows and queue automatically, one file upload through persisted terminal settlement before the next within browser lifetime, not a server-global/cross-browser transaction. No concatenation/jitter. Manual history import does not automatically trigger historical recovery or establish continuous acceptance.
- Default is **1024 MiB per file (1 GiB)**: payload `1073741824` bytes, at most 64 KiB multipart envelope, default request total `1073807360` bytes. Server configuration is authoritative; preserved smaller budgets can return accurate 413. Collector nginx `32m` / receiver `32000000` remain unchanged. Progress measures request transfer only; 100% is not accepted/imported/completed. Row-local 409/force confirmation names the file, window and overwrite risk. Cancel is not undo of written metrics; accepted cancelling holds the barrier until authenticated settlement.
- Lost ID is never inferred from similar history. Uncertainty, auth failures, saturated state-domain lists and reconciliation-required cancellation block automatic resend. After grace, at most three cancellation status attempts precede actionable reconciliation-required state; explicit same-ID retry/late terminal can release it. Same-app navigation keeps store ownership; full reload loses unuploaded File bytes and requires re-selection while persisted jobs/history remain. See [manual ownership details](scripts/install/README.md#manual-upload-and-ownership).
- Test missing/wrong credentials, receiver and DB outages and adjacent flows. Only with LIVE and separately authorized Windows capture, test automatic catch-up and the genuine feed. Record errors with timestamps; redact keys.
- The dated smoke below is historical evidence only, not proof of this new NONE/status/limit/queue implementation or physical Windows acceptance of this feature.
- **Recorded limited smoke test (2026-11-13):** WSL2 Ubuntu 26.04.1, Docker Desktop, native Windows Python 3.15.2 and physical Npcap Ethernet. After correcting scanner startup and Windows file synchronization, 12 Desktop core services were healthy; the collector reconciled retained files, handed off 49 chunks / 6,645 packets and stopped cleanly with no pending Windows files. Matching credentials and existing DB volumes were preserved; NTFS access and verified TLS were checked. The build used caches. This is not full step-14 acceptance: at the recorded snapshot only 3 chunks were consumed and 2 of 3 processing batches committed, with 717 point-visibility checks in the pending batch. Complete processing, browser/detector coverage, outage recovery and a recreate after this captured data remain unverified.
- A receiver receipt means durable custody, **not** completed Influx publication or per-module recovery. If capture custody grows while processing does not, record the timestamps and separate stage counters and investigate; do not infer completion from healthy containers, an empty Windows spool or one visible measurement. A large pending visibility check may take time, but that is not proof it will complete.
- On this acceptance installation only, return to the **Ubuntu Bash** shell in your checkout before recreating. If this is a new shell, enter the actual checkout path and repeat step 3 then step 4's capture selection to restore `WORKSPACE_DIR`, the same platform/AI selection and exact conditional overlay/export first. Recreate and repeat login/data/history checks **without re-uploading**:

```sh
docker compose --env-file .env.compose --profile all up -d --force-recreate --wait ${OTALON_SERVICES:?Repeat step 3} &&
docker compose --env-file .env.compose --profile all ps
```

- Initial ML artifacts are not bundled; training needs real telemetry/labels/reference data. Never disable detection to make startup green. Test LLM loops separately only when selected.
- Updates require build + recreate of affected services/consumers with the same platform selection, plus a fresh Windows collector export if its source changed. Review `OTALON_BUILD_REF` against the checked-out revision; setup preserves an already configured reference. Preserve passwords, checkpoints, raw custody and volumes. Detailed helper contracts: `scripts/install/README.md`.
- Source-verified documentation/small tests are not fresh NONE/status/1024 MiB/RSS/GUI acceptance. Require fresh owned images/consumers, authenticated HTTPS boot/picker/drop/errors/limits/cancel/reload and exact persisted data; real 600/1024 MiB PCAP/PCAPNG on both manual HTTPS routes (8443 UI proxy and 8493 API), cgroup/RSS observations with <=128 MiB incremental UI/API RSS, no OOM and temporary cleanup. Physical Windows/NIC proof for this feature remains unavailable and open, not synthetic acceptance.
- Rollback is parent/operator-owned: stop owned collectors, preserve custody/spool/checkpoint/jobs/metrics and config, rebuild/recreate reverted selected source and consumers. The approved old baseline rejects NONE; never blindly boot rollback in NONE or erase config/data. Keep acquisition stopped until deliberate selection of a baseline-supported path. Permanent database write-authentication failure propagation, exception-safe partial receiver construction and controlled in-flight shutdown still require targeted repair and verified acceptance; authorization alone does not close those gates. Native's eight-second number is not a WSL deadline.
