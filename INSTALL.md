# Install OTALON

- **Linux:** rootful Docker Engine, Compose v2+, Git, sudo, Python 3.10+, curl.
- **Windows:** WSL2 Ubuntu, Docker Desktop with WSL integration, Compose 2.24.4+, native Windows Python 3.10+, Wireshark with Npcap. Keep the checkout on WSL's Linux filesystem.
- **Status:** native isolated builds/DB startup and Linux receiver/HTTPS/recovery tests are recorded. The continuous Desktop path is implemented in source but **not release-qualified**: final fresh-image, Windows/Npcap, browser and recovery/persistence gates remain open. Do not treat Linux fixtures as physical Windows acceptance.
- **LLM gateway optional:** core capture/detection/UI work without LiteLLM; LLM chat/classification/jobs do not.
- **Security:** native DB ports publish on all interfaces; restrict them before startup. Desktop overlay binds published ports to loopback and removes raw-capture privileges/host-root mounts. API Docker-socket and writable-checkout access remain root-equivalent. Capture only an authorized NIC/SPAN/TAP feed; no active scans as smoke tests.
- Run blocks in order in the same shell; stop on errors. Never print keys, resolved Compose configuration or DSNs. Existing env files, certificates and volumes must be preserved.

## 1. Clone

```sh
git clone https://github.com/FraunhoferIOSB/OTALON.git /home/user/otalon
cd /home/user/otalon
export WORKSPACE_DIR="$PWD"
```

- Existing checkout: skip clone; enter its actual path and use `git pull --ff-only`. Do not reset local changes or recopy the env sample.

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
# Choose native OR desktop. On WSL use desktop.
INSTALL_PLATFORM=native
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

## 11. Start services

- Native: confirm interfaces/firewall/approval. Capture/scan use host networking and NET_RAW/NET_ADMIN.
- Desktop: **release gate still open**. The following is the candidate test-install path, not a claim of validated Windows operation. No physical capture starts inside a container.

```sh
docker compose --env-file .env.compose --profile all up -d --wait ${OTALON_SERVICES:?Repeat step 3} &&
docker compose --env-file .env.compose --profile all ps
```

- Expect selected services healthy (12 core / 13 with LLM). Healthy processes do not prove data, learned artifacts or detector coverage. Desktop refuses ARP/PROFINET raw-L2 discovery; routed protocol scans still require explicit authorization.

## 12. Browser login

- Open `https://localhost:8443` in the host/Windows browser. Default certificate covers localhost/127.0.0.1; use organization certificates for remote access.
- First login: `admin`, bootstrap password shown on the login page. Complete password change; log out and sign in again. Keep existing changed passwords. Never expose bootstrap login publicly.

## 13. Desktop: start continuous capture on Windows

**Candidate path; genuine Windows/Npcap acceptance remains required. No manual upload loop.**

In WSL, after TLS startup, export only the collector, public certificate and source credential:

```sh
sudo python3 scripts/install/prepare_wsl.py --workspace "$WORKSPACE_DIR" \
  --receiver-uid 10006 --export /mnt/c/OTALON
```

- Never copy the suite env file or DB/operator keys to Windows. Restrict `C:\OTALON` to the intended account using your organization's Windows ACL policy; WSL mode bits are not proof of NTFS confidentiality.
- In **Windows PowerShell**, verify native Python and list approved Npcap interfaces:

```powershell
py -3 --version
& 'C:\Program Files\Wireshark\dumpcap.exe' -D
if ($LASTEXITCODE -ne 0) { throw 'Npcap interface listing failed' }
notepad C:\OTALON\collector.sample.json
```

- Replace `interface` with the exact `\Device\NPF_...` device from the listing, not a numeric Linux/WSL adapter. Verify physical Ethernet and the authorized feed. Keep URL `https://localhost:9493`, certificate verification and the source-key file.
- Start in PowerShell; elevate only if Npcap policy requires it:

```powershell
py -3 C:\OTALON\collector.zip --config C:\OTALON\collector.sample.json
```

- Keep it running. Closed chunks are sent automatically; receiver outages retain backlog and retry. Ctrl+C requests a clean stop. Next start reconciles the prior process/files and resumes retained work. A malformed final file, unknown owner or storage exhaustion fails closed; do not delete evidence.
- Collector limits default to 2 GB pending spool / 1 GB free reserve; receiver custody and recovery have bounded retained storage. These are safeguards, **not** indefinite-retention/zero-loss guarantees. Reaching a limit needs operator attention; do not claim automatic capacity recovery.
- File closure does not seal a logical metric window. Quiet/final tails wait for later packets; original timestamps are retained. Collector receipt, Influx visibility and per-module recovery completion are separate facts.

## 14. Verify real data and persistence

- Desktop: without uploading files, inspect **Timeseries Data → Connections**, MAC/protocol measurements and **Alarms** at the original capture timestamps. Check real row growth, enabled profiles and persisted recovery outcomes. Missing artifacts/context must remain explicit, never fake coverage.
- Native: use authorized live traffic; manual **PCAP Import & Replay** remains optional diagnostics, not continuous Desktop acceptance. Manual history import does not automatically trigger historical recovery.
- Test missing/wrong credentials, receiver and DB outages, automatic catch-up, adjacent flows and genuine Windows capture. Record errors with timestamps; redact keys.
- On this acceptance installation only, recreate and repeat login/data/history checks **without re-uploading**:

```sh
docker compose --env-file .env.compose --profile all up -d --force-recreate --wait ${OTALON_SERVICES:?Repeat step 3} &&
docker compose --env-file .env.compose --profile all ps
```

- Initial ML artifacts are not bundled; training needs real telemetry/labels/reference data. Never disable detection to make startup green. Test LLM loops separately only when selected.
- Updates require build + recreate of affected services/consumers. Preserve passwords, checkpoints, raw custody and volumes. Detailed helper contracts: `scripts/install/README.md`.
