# Install OTALON on Linux

- Native Linux only. For Windows physical-NIC capture with WSL2/Docker Desktop, use [INSTALL-WSL.md](INSTALL-WSL.md) instead.
- **Required:** rootful Docker Engine, Compose v2+, Git, sudo, Python 3.10+, curl and normal runtime DB/auth/log/import/evidence paths. Rootless Docker is not covered. Only native `LIVE` capture additionally requires an authorized Linux NIC/SPAN/TAP feed and raw-acquisition readiness; `NONE` requires neither. Native scanner prerequisites and authorization remain separate.
- **Status:** development snapshot. Isolated native build/database tests are recorded; healthy services do not certify your capture, detector or persistence setup.
- **LLM gateway optional:** core capture/detection/UI work without LiteLLM; LLM chat/classification/jobs do not.
- **Security:** native database ports publish on all interfaces; restrict them before startup. Capture/scanning use host networking and NET_RAW/NET_ADMIN. API Docker-socket, host-root and writable-checkout access are root-equivalent. Capture only an authorized feed; no active scans as smoke tests.
- Run numbered blocks in order in Linux Bash; stop on errors. Never print keys, resolved Compose configuration or DSNs. Preserve existing env files, certificates and volumes.

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

- Check `command -v newgrp`. If absent, install your release's suggested package: Ubuntu 24.04 supplies it with `login`. Check the command again before proceeding.

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

## 3. Select native core services

```sh
# Run from the checkout root, including in each new shell.
export WORKSPACE_DIR="$PWD"
INSTALL_PLATFORM=native
INSTALL_PLATFORM_ARGS=
export COMPOSE_FILE="$WORKSPACE_DIR/docker-compose.yml"
INSTALL_AI_ARGS=--without-ai
OTALON_SERVICES='tls-proxy postgres influxdb3 otalon-capture otalon-capture-pcap-import otalon-clas otalon-ui otalon-api otalon-scan otalon-scan-passive-seeder otalon-scan-cve-lookup otalon-mcp'
```

- Keep this selection for every check/build/start/recreate. A new terminal needs step 3 and the capture-mode selection in step 4 again before any Compose operation. Only the base Compose file is used for native capture, in both NONE and LIVE.
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
- Edit the top **EDIT THIS SECTION** only: confirm workspace/build reference. New/absent `CAPTURE_TYPE` defaults NONE with empty `CAPTURE_SOURCE`. Select exactly NONE or LIVE; native LIVE requires an approved `CAPTURE_SOURCE`. Keep `SCAN_SOURCE` selection and scanner authorization independent, including in NONE.
- No LLM: leave its four external fields untouched. With LLM: configure URL/key/chat/jobs aliases and prove a real request separately. A URL that passes the checker is not proof of model reachability.
- Nano: Ctrl+O, Enter, Ctrl+X. Never share `.env.compose`. Env edits do not rotate initialized DB credentials.

After environment preparation, select capture intent from the parsed selected
document, not the process environment. Run this block again after step 3 in
each new shell and after mode edits, before any Compose operation:

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
export COMPOSE_FILE="$WORKSPACE_DIR/docker-compose.yml"
```

- The dependency-free parser prints only normalized NONE/LIVE on success, trims decoded whitespace and rejects invalid modes without echoing values. Never source an env file or print resolved configuration. The normal step-6 checker still validates DB/operator/import/evidence/log and selected LLM settings; NONE exempts only the unused capture source.
- Native LIVE source syntax is exactly `[A-Za-z0-9_][A-Za-z0-9_.:-]{0,14}`. A syntactically safe absent NIC is source-unavailable at runtime, not proof of local readiness. Empty/lowercase/AUTO boot intent is invalid; internal PCAP file processing is independent of boot intent.

## 5. Prepare shared paths

```sh
sudo install -d -o root -g root -m 0755 shared
sudo install -d -o root -g 10000 -m 2775 \
  shared/logs shared/models shared/pcap/buffer shared/pcap/archive \
  shared/pcap/baseline shared/operations
sudo install -d -o root -g root -m 0750 shared/tls
```

- Do not recursively change existing data. API-managed config updates need checkout-root create/rename access for GID 10000: `sudo chgrp 10000 "$WORKSPACE_DIR" && sudo chmod g+ws "$WORKSPACE_DIR"`. This grants the group checkout write access.

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

- Only the import-volume root is adjusted; retained files are not recursively modified. Never use `down -v` as a repair.

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

- Stored revision for this source: `0015`. Empty `alembic current` output is not proof. The native migration uses the host-networked scanner configuration.

## 11. Start services

- Before startup, confirm firewall and separate scanner authorization/prerequisites. For LIVE also confirm the authorized capture interface/capabilities. Capture and scanner containers retain host networking and NET_RAW/NET_ADMIN; NONE avoids capture acquisition at runtime, not the existing base privilege surface or native dependencies in the shared image.

```sh
docker compose --env-file .env.compose --profile all up -d --wait ${OTALON_SERVICES:?Repeat step 3} &&
docker compose --env-file .env.compose --profile all ps
```

- Expect selected services healthy (12 core / 13 with LLM). Healthy processes do not prove traffic, learned artifacts or detector coverage. Active scanning is not part of this installation smoke test.
- NONE runs idle REST/health with no live acquisition or automatic evidence eviction; explicit authenticated retained-evidence text/detail reads are historical inspection, not automatic capture. Native NONE recording=false is local producer absence. In LIVE the legacy recording boolean is current tcpdump process truth; `source_state=recording` additionally requires the current ready adapter pair, not a PID or a health response.
- Source-unavailable episodes allow five attempts: immediate, then 2/4/8/16-second delays, each with five-second readiness. Sixty seconds of stable recording resets a later episode; exhaustion stays waiting (never acquired) or degraded (previous acquisition) with `retry_exhausted=true`. Check source/capability configuration and explicitly recreate to reset the budget. Auth/config/privilege/checkpoint/unknown failures are blocked, not source-retry candidates. Warnings go to console and configured persistent logs. The eight-second coordinator teardown bound is Native-scoped within the existing outer ten-second grace.

## 12. Browser login

- Open `https://localhost:8443` in the Linux host browser. Default certificate covers localhost/127.0.0.1; use organization certificates for remote access.
- First login: `admin`, bootstrap password shown on the login page. Complete password change; log out and sign in again. Keep existing changed passwords. Never expose bootstrap login publicly.

## 13. Verify real data and persistence

- In LIVE inspect **Timeseries Data → Connections**, MAC/protocol measurements and **Alarms** using authorized live traffic. In NONE verify independent manual imports and retained historical reads, not live row growth. Confirm exact data and original timestamps; healthchecks alone are insufficient.
- Manual import in **Operations / Data Sources** works in NONE and LIVE. All picker/drop files append visible rows and queue automatically: one file upload through persisted completed/failed/cancelled/rejected settlement before the next within this browser lifetime. This is not a server-global/cross-browser transaction; there is no concatenation or timestamp jitter. Manual history import does not automatically trigger historical recovery or substitute for LIVE acceptance.
- Default upload budget is **1024 MiB per file (1 GiB)**, payload `1073741824` bytes plus at most 64 KiB multipart envelope, default total `1073807360` bytes. Server configuration is authoritative; a preserved smaller budget can return accurate 413. Request-transfer progress, including 100%, is not acceptance/import/completion. Per-file 409/force confirmation names the file, measurement/window and overwrite risk; cancel cannot undo written metrics. Accepted cancelling holds the queue until authenticated settlement.
- Lost job ID is never guessed from similar history. Uncertainty, auth failures, saturated state-domain lists and reconciliation-required cancellation block automatic resend. Cancellation report-loss reconciliation makes at most three status attempts after grace, then shows an actionable blocked state; explicit same-ID retry or late authenticated terminal settlement can release it. Same-app navigation retains store ownership; full reload loses unuploaded File bytes and requires re-selection, but persisted jobs/history remain. See the [manual ownership contract](scripts/install/README.md#manual-upload-and-ownership).
- Check missing/wrong credentials, adjacent UI flows and persisted data. Record errors with timestamps; redact keys. No unauthorized scans or deliberate disruption of a live OT network.
- On an isolated acceptance installation only, repeat login/data checks after recreation. In a new Linux shell, enter the actual checkout and repeat step 3, then step 4's capture-mode selection first:

```sh
docker compose --env-file .env.compose --profile all up -d --force-recreate --wait ${OTALON_SERVICES:?Repeat step 3} &&
docker compose --env-file .env.compose --profile all ps
```

- Initial ML artifacts are not bundled; training needs real telemetry/labels/reference data. Never disable detection to make startup green. Test LLM loops separately only when selected.
- Updates require build + recreate of affected services/consumers using the same native/AI selection. Review `OTALON_BUILD_REF` against the checked-out revision; setup preserves an already configured reference. Preserve passwords, raw data and volumes. Detailed helper contracts: [scripts/install/README.md](scripts/install/README.md).
- Mode/source edits require explicit affected-service rebuild/recreation as relevant; no hidden runtime toggle exists. Source-verified guidance is not fresh acceptance: require fresh owned images/consumers, authenticated HTTPS boot/picker/drop/errors/limits/cancel/reload and exact persisted data, plus real 600/1024 MiB PCAP/PCAPNG through both manual HTTPS routes (8443 UI proxy and 8493 API), cgroup/RSS observations with <=128 MiB incremental UI/API RSS, no OOM and temporary cleanup. Small tests do not measure the 1024 MiB/RSS/GUI boundary; physical NIC acceptance remains separately authorized and unproved here.
- Rollback preserves custody/spool/checkpoints/jobs/metrics and configuration, stops owned acquisition, and rebuilds/recreates reverted selected source and consumers. The approved old baseline rejects NONE; do not blindly boot rollback in NONE or erase data/config to make it start. Keep acquisition stopped until an operator deliberately selects a baseline-supported path.
