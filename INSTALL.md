# Install OTALON

- **Linux:** rootful Docker Engine, Compose v2+, Git, sudo, Python 3.10+, curl.
- **Windows:** WSL2 Ubuntu, Docker Desktop with WSL integration, Compose 2.24.4+, native Windows Python 3.10+, Wireshark with Npcap. Keep the checkout on WSL's Linux filesystem.
- **Status:** native isolated builds/DB startup, Linux receiver/HTTPS/recovery tests and a limited physical Windows/Npcap handoff test are recorded. The continuous Desktop path is **not release-qualified**: cache-free builds, complete data processing, browser and recovery/persistence gates remain open. See the acceptance limits in step 14; healthy services and accepted chunks are not full acceptance.
- **LLM gateway optional:** core capture/detection/UI work without LiteLLM; LLM chat/classification/jobs do not.
- **Security:** native DB ports publish on all interfaces; restrict them before startup. Desktop overlay binds published ports to loopback and removes raw-capture privileges/host-root mounts. API Docker-socket and writable-checkout access remain root-equivalent. Capture only an authorized NIC/SPAN/TAP feed; no active scans as smoke tests.
- Run blocks in order in the same shell; stop on errors. Never print keys, resolved Compose configuration or DSNs. Existing env files, certificates and volumes must be preserved.
- Steps 1-11 run in **Ubuntu Bash**, not Windows PowerShell. Step 13 explicitly switches between the two shells. In Windows PowerShell, check `py -3 --version` before starting installation. If `py` is missing, install native Python 3.10+ with its Windows launcher and reopen PowerShell; Ubuntu's Python is not a replacement.

## 1. Clone

```sh
git clone --single-branch --branch wip/suite069-continuous \
  https://github.com/FraunhoferIOSB/OTALON.git /home/user/otalon
cd /home/user/otalon
export WORKSPACE_DIR="$PWD"
```

- This candidate installation targets `wip/suite069-continuous`; confirm with `git branch --show-current`. HTTPS does not require a GitHub SSH key. An SSH `Permission denied (publickey)` is an authentication failure, not an installation failure; use HTTPS rather than creating a second checkout.
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

## 3. Select platform and core services

```sh
# Run from the checkout root, including in each new Ubuntu shell.
export WORKSPACE_DIR="$PWD"
# WSL requires the Desktop receiver; other Linux hosts use native capture.
if grep -qi microsoft /proc/sys/kernel/osrelease; then
  INSTALL_PLATFORM=desktop
else
  INSTALL_PLATFORM=native
fi
INSTALL_PLATFORM_ARGS=
export COMPOSE_FILE="$WORKSPACE_DIR/docker-compose.yml"
case "$INSTALL_PLATFORM" in
  native) ;;
  desktop)
    INSTALL_PLATFORM_ARGS=--desktop
    export COMPOSE_FILE="$COMPOSE_FILE:$WORKSPACE_DIR/docker-compose.wsl.yml"
    ;;
  *) printf '%s\n' 'Invalid platform'; exit 1 ;;
esac
INSTALL_AI_ARGS=--without-ai
OTALON_SERVICES='tls-proxy postgres influxdb3 otalon-capture otalon-capture-pcap-import otalon-clas otalon-ui otalon-api otalon-scan otalon-scan-passive-seeder otalon-scan-cve-lookup otalon-mcp'
```

- Keep this selection for every build/start/recreate. A new terminal needs step 3 again. Desktop does **not** need host networking for capture or migrations; Windows captures the physical NIC.
- On WSL, `COMPOSE_FILE` must include **both** `docker-compose.yml` and `docker-compose.wsl.yml`. Making `CAPTURE_SOURCE` match a WSL NIC can make native containers healthy, but does not enable the Windows receiver. Do not drop the overlay to work around Desktop errors; native mode also changes published-port and raw-capture security boundaries.
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

- New file: `10001:10000 660`. Existing metadata is not automatically repaired. Setup fills only missing/template local credentials; configured values and ownership are retained.
- Edit the top **EDIT THIS SECTION** only: confirm workspace/build reference; on native choose approved Linux `CAPTURE_SOURCE`/`SCAN_SOURCE`. On Desktop those Linux NIC values are unused; select the Npcap NIC later on Windows.
- No LLM: leave its four external fields untouched. With LLM: configure URL/key/chat/jobs aliases and prove a real request separately. `http://host.docker.internal:4000/v1` is a valid Desktop-host address, not a reachability guarantee.
- Nano: Ctrl+O, Enter, Ctrl+X. Never share `.env.compose`. Env edits do not rotate initialized DB credentials.

## 5. Prepare shared paths

```sh
sudo install -d -o root -g root -m 0755 shared
sudo install -d -o root -g 10000 -m 2775 \
  shared/logs shared/models shared/pcap/buffer shared/pcap/archive \
  shared/pcap/baseline shared/operations
sudo install -d -o root -g root -m 0750 shared/tls
```

- Do not recursively change existing data. API-managed config updates need checkout-root create/rename access for GID 10000: `sudo chgrp 10000 "$WORKSPACE_DIR" && sudo chmod g+ws "$WORKSPACE_DIR"`. This grants the group checkout write access.
- Desktop only, provision the separate source credential **before** receiver startup:

```sh
if [ "$INSTALL_PLATFORM" = desktop ]; then
  sudo python3 scripts/install/prepare_wsl.py --workspace "$WORKSPACE_DIR" --receiver-uid 10006
fi
```

- Existing source credentials are not rotated or silently re-owned. Permission mismatch requires explicit inspection, not deletion.

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

Desktop only:

```sh
if [ "$INSTALL_PLATFORM" = desktop ]; then
  docker compose --env-file .env.compose --profile all run --rm --no-deps \
    --user 0 --cap-add CHOWN --cap-add FOWNER --entrypoint python \
    -v "$WORKSPACE_DIR/scripts/install/init_continuous_volume.py:/volume-init.py:ro" \
    otalon-capture /volume-init.py --root /app/continuous --uid 10006 &&
  docker compose --env-file .env.compose --profile all run --rm --no-deps \
    --user 0 --cap-add CHOWN --cap-add FOWNER --entrypoint python \
    -v "$WORKSPACE_DIR/scripts/install/init_continuous_volume.py:/volume-init.py:ro" \
    otalon-clas /volume-init.py --root /app/recovery --uid 10004
fi
```

- Initializer changes only an empty volume's root; correctly configured populated volumes are preserved. Wrong populated metadata refuses. Never use `down -v` as a repair.

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

- Native: confirm interfaces/firewall/approval. Capture/scan use host networking and NET_RAW/NET_ADMIN.
- Desktop: **release gate still open**. The following is the candidate test-install path, not a claim of validated Windows operation. No physical capture starts inside a container.

```sh
docker compose --env-file .env.compose --profile all up -d --wait ${OTALON_SERVICES:?Repeat step 3} &&
docker compose --env-file .env.compose --profile all ps
```

- Expect selected services healthy (12 core / 13 with LLM). Healthy processes do not prove data, learned artifacts or detector coverage. Desktop refuses ARP/PROFINET raw-L2 discovery; routed protocol scans still require explicit authorization.
- On Desktop, verify the actual container commands and network before exporting or capturing:

```sh
if [ "$INSTALL_PLATFORM" = desktop ]; then
  docker inspect --format \
    '{{.Name}} command={{json .Config.Cmd}} entrypoint={{json .Config.Entrypoint}} network={{.HostConfig.NetworkMode}} cap_add={{json .HostConfig.CapAdd}}' \
    otalon-capture otalon-scan
fi
```

- Expect `desktop_ingest.main` for capture, `python -m uvicorn otalon_scan.api.server:app ...` for scan, a Compose bridge network (not `host`) and no added capabilities. A restarting scan process that exits with code 0 is not fixed by changing the capture NIC. Stop, check the source/overlay and rebuild/recreate from the correct branch; do not disable healthchecks or add privileges.

## 12. Browser login

- Open `https://localhost:8443` in the host/Windows browser. Default certificate covers localhost/127.0.0.1; use organization certificates for remote access.
- First login: `admin`, bootstrap password shown on the login page. Complete password change; log out and sign in again. Keep existing changed passwords. Never expose bootstrap login publicly.

## 13. Desktop: start continuous capture on Windows

**Candidate path; complete Windows/Npcap/data acceptance remains required. No manual upload loop.**

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

In **Ubuntu Bash**, after TLS startup, export only the collector, public certificate and source credential:

```sh
sudo python3 scripts/install/prepare_wsl.py --workspace "$WORKSPACE_DIR" \
  --receiver-uid 10006 --export /mnt/c/OTALON
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
- `Receiver unavailable` is a general handoff failure, not proof of a DB outage; first repeat the TLS/route/platform checks. An `os.fsync` / `Bad file descriptor` traceback indicates a faulty/old collector build: update to the corrected source and re-export the ZIP. Never remove `fsync`, ignore its failure or delete `spool`, `collector.sqlite3` or `owner.json` to make startup pass.
- Collector limits default to 2 GB pending spool / 1 GB free reserve; receiver custody and recovery have bounded retained storage. These are safeguards, **not** indefinite-retention/zero-loss guarantees. Reaching a limit needs operator attention; do not claim automatic capacity recovery.
- File closure does not seal a logical metric window. Quiet/final tails wait for later packets; original timestamps are retained. Collector receipt, Influx visibility and per-module recovery completion are separate facts.

## 14. Verify real data and persistence

- Desktop: without uploading files, inspect **Timeseries Data → Connections**, MAC/protocol measurements and **Alarms** at the original capture timestamps. Check real row growth, enabled profiles and persisted recovery outcomes. Missing artifacts/context must remain explicit, never fake coverage.
- Native: use authorized live traffic; manual **PCAP Import & Replay** remains optional diagnostics, not continuous Desktop acceptance. Manual history import does not automatically trigger historical recovery.
- Test missing/wrong credentials, receiver and DB outages, automatic catch-up, adjacent flows and genuine Windows capture. Record errors with timestamps; redact keys.
- **Recorded limited smoke test (2026-11-13):** WSL2 Ubuntu 26.04.1, Docker Desktop, native Windows Python 3.15.2 and physical Npcap Ethernet. After correcting scanner startup and Windows file synchronization, 12 Desktop core services were healthy; the collector reconciled retained files, handed off 49 chunks / 6,645 packets and stopped cleanly with no pending Windows files. Matching credentials and existing DB volumes were preserved; NTFS access and verified TLS were checked. The build used caches. This is not full step-14 acceptance: at the recorded snapshot only 3 chunks were consumed and 2 of 3 processing batches committed, with 717 point-visibility checks in the pending batch. Complete processing, browser/detector coverage, outage recovery and a recreate after this captured data remain unverified.
- A receiver receipt means durable custody, **not** completed Influx publication or per-module recovery. If capture custody grows while processing does not, record the timestamps and separate stage counters and investigate; do not infer completion from healthy containers, an empty Windows spool or one visible measurement. A large pending visibility check may take time, but that is not proof it will complete.
- On this acceptance installation only, return to the **Ubuntu Bash** shell in your checkout before recreating. If this is a new shell, enter the actual checkout path and repeat step 3 to restore `WORKSPACE_DIR` and the same platform and AI selection first. Recreate and repeat login/data/history checks **without re-uploading**:

```sh
docker compose --env-file .env.compose --profile all up -d --force-recreate --wait ${OTALON_SERVICES:?Repeat step 3} &&
docker compose --env-file .env.compose --profile all ps
```

- Initial ML artifacts are not bundled; training needs real telemetry/labels/reference data. Never disable detection to make startup green. Test LLM loops separately only when selected.
- Updates require build + recreate of affected services/consumers with the same platform selection, plus a fresh Windows collector export if its source changed. Review `OTALON_BUILD_REF` against the checked-out revision; setup preserves an already configured reference. Preserve passwords, checkpoints, raw custody and volumes. Detailed helper contracts: `scripts/install/README.md`.
