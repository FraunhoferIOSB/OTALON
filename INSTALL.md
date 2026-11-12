# Install OTALON

- **Native Linux:** rootful Docker Engine, Compose v2+, `git`, `sudo`, Python 3.10+, `curl`; working Docker access and internet for dependencies.
- **Tested 2026-11-11:** fresh Ubuntu 24.04 VM; 11 images built, databases initialized, migration `0015` stored, 13 services healthy, HTTPS and import-mount checks passed. Offline gateway markers and VM loopback were test adaptations, **not** proof of AI, physical capture or full acceptance.
- **WSL2 + Docker Desktop:** the suite setup below is build/DB testing only on Desktop, not a validated full deployment. For physical traffic, use [Windows capture → manual import](#windows-capture--manual-import) below; automatic continuous ingestion is not implemented. Desktop host networking is TCP/UDP (layer 4), not direct physical-NIC access. Stop before step 12 on WSL. See [Docker limitations](https://docs.docker.com/engine/network/drivers/host/).
- **Security:** DB ports `5432`/`8181` publish on all host interfaces. Restrict access before startup. API has root-equivalent Docker-socket access, read-only host-root mounts and a writable checkout; read-only mounts can still disclose host data.
- Run each block in order; **stop on an error**. Keep the same shell and checkout. Do not print credentials, resolved Compose configuration or connection strings.

## 1. Clone or update

```sh
git clone https://github.com/FraunhoferIOSB/OTALON.git /home/user/otalon
cd /home/user/otalon
export WORKSPACE_DIR="$PWD"
```

- Existing clone: skip `git clone`, enter your actual checkout, run `git pull --ff-only`, and export `WORKSPACE_DIR="$PWD"`. Review local changes if the pull refuses; do not reset them.
- Existing installation: preserve `.env.compose`, bootstrap files and volumes. A fresh clone does not make existing Docker volumes empty.

## 2. Join the shared group

First check `command -v newgrp`. **If missing on Ubuntu/WSL**, install the package suggested by your Ubuntu release (`util-linux-extra` in the reported WSL setup; Ubuntu 24.04 uses [login](https://packages.ubuntu.com/noble/amd64/login/filelist)). For the `util-linux-extra` suggestion:

```sh
sudo apt-get update && sudo apt-get install util-linux-extra && command -v newgrp
```

- Do not proceed until `newgrp` is available. On Ubuntu 24.04, use `sudo apt-get install --reinstall login` instead. Alternatively, add the group below, then log out/in instead of calling `newgrp` and verify `id` in the fresh session.

```sh
getent group 10000 || sudo groupadd -g 10000 otalon-shared
sudo usermod -aG "$(getent group 10000 | cut -d: -f1)" "$USER"
newgrp "$(getent group 10000 | cut -d: -f1)"
```

At the **new shell prompt**, run:

```sh
cd /home/user/otalon
export WORKSPACE_DIR="$PWD"
id
```

- Use your actual checkout path if different. Confirm GID `10000` appears; group members can write shared application files.
- Continue in this shell. `exit` returns to the old shell without refreshed membership. Alternatively, log out/in after `usermod`, then repeat `cd`, export and `id`.

## 3. Create local configuration once

```sh
if [ ! -e .env.compose ] && [ ! -L .env.compose ]; then
  python3 scripts/install/setup.py --workspace "$WORKSPACE_DIR" &&
  sudo chown 10001:10000 .env.compose &&
  sudo chmod 0660 .env.compose
fi
stat -c '%u:%g %a %n' .env.compose
```

- Expected: `10001:10000 660 .env.compose`. Existing files are not overwritten, re-owned or re-moded automatically; review unexpected metadata explicitly.
- Never copy the sample over configured credentials. The helpers reject symlink/hardlinked inputs.

## Before step 4: connect LiteLLM

- **Existing gateway:** reuse its container-reachable `/v1` URL, a scoped access key and the exact served aliases for chat/jobs. Upstream provider credentials are separate; keep your working gateway/configuration.
- **New gateway:** follow the official [LiteLLM Docker quickstart](https://docs.litellm.ai/docs/proxy/docker_quick_start) or [CLI quickstart](https://docs.litellm.ai/docs/proxy/quick_start) **in a separate directory, not this OTALON checkout**. Enable authentication, connect a real provider/model, create an access key allowed to use both aliases and send a successful test request before continuing. Review ports/firewall; do not expose an unauthenticated gateway. No bundled proxy is supplied by OTALON yet.
- **Docker Desktop host service:** `http://host.docker.internal:4000/v1` is a valid address when the gateway is reachable through Desktop's host on port4000 ([Docker routing](https://docs.docker.com/desktop/features/networking/networking-how-tos/)). A proxy running in another WSL distro/container is not automatically that host service; verify its publication/listen address/firewall. Native Linux routing may require a different reachable host/DNS address.
- The checker below validates configuration text, **not connectivity or model access**. A valid URL without a configured gateway/key/models is not AI acceptance.

## 4. Generate secrets; configure gateway and interfaces

```sh
python3 scripts/install/setup.py --workspace "$WORKSPACE_DIR"
```

- Generates only missing/template local DB, service and callback secrets; derives checkout/build reference. Configured values, comments, order, inode, owner and mode remain intact. A repeat can report `Updated 0 keys`; external fields may still be missing.
- Use the LiteLLM URL/key/aliases prepared **before this step**; local secret generation does not provision a gateway or provider subscription.

```sh
nano .env.compose
```

Edit only the top **EDIT THIS SECTION** block:
- `WORKSPACE_DIR`, `OTALON_BUILD_REF`: confirm generated values; review timezone defaults.
- `CAPTURE_SOURCE`, `SCAN_SOURCE`: approved real host interfaces, not sample lab names. Do not select an OT mirror port for active scanning.
- `LITELLM_BASE_URL`, `LITELLM_API_KEY`, `CHAT_LLM_MODEL`, `JOBS_LLM_MODEL`: your gateway and served aliases; a nonempty value is not reachability proof.
- Local DB/service/callback secrets: generated by setup. Keep existing credentials; env edits do not rotate persisted DB passwords/tokens. Caller registries reuse these fields.
- Optional `NVD_API_KEY`; keep reviewed detection/blacklist defaults. Never commit `.env.compose` or send it in chat.

- Nano: `Ctrl+O`, Enter to save; `Ctrl+X` to exit. Use an interactive terminal.
- Helpers accept a restricted env grammar: single quotes are literal; bare/double-quoted `${NAME}` references follow their inputs. Unsupported substitutions/duplicates fail before writing. See [helper reference](scripts/install/README.md).
- **No gateway yet?** The normal checker will refuse. `--syntax-only` with explicit offline markers is only a bounded infrastructure-test adaptation, not full installation or AI readiness. Do not substitute fake credentials for acceptance.

## 5. Prepare shared directories

```sh
sudo install -d -o root -g root -m 0755 shared
sudo install -d -o root -g 10000 -m 2775 \
  shared/logs shared/models shared/pcap/buffer shared/pcap/archive \
  shared/pcap/baseline shared/operations
sudo install -d -o root -g root -m 0750 shared/tls
```

- Do not recursively change existing data. Optional API-saved configuration requires checkout-root create/rename access for GID 10000; this grants every group member checkout-root write access:

```sh
sudo chgrp 10000 "$WORKSPACE_DIR"
sudo chmod g+ws "$WORKSPACE_DIR"
```

- API atomic env updates can set legacy mode `0644`; restore `sudo chmod 0660 .env.compose` after such updates.

## 6. Check configuration

```sh
python3 scripts/install/check.py --workspace "$WORKSPACE_DIR" &&
docker compose --env-file .env.compose --profile all config --quiet
```

- Stop on errors. Both checker modes validate local shapes only, not endpoint/model availability. The Desktop host URL is accepted; real `.invalid`/`offline-unconfigured` markers are still refused by the normal check. Build does not initialize databases.
- For a gateway published on the Desktop host, the literal env line is `LITELLM_BASE_URL=http://host.docker.internal:4000/v1` — no `@url:`, backticks or Markdown. Configured keys and chat/job aliases are still required. Do not use `--syntax-only` to bypass a real configuration error.

## 7. Create InfluxDB's bootstrap token file

```sh
sudo python3 scripts/install/bootstrap_influx.py --workspace "$WORKSPACE_DIR" &&
sudo stat -c '%u:%g %a %n' shared/influx-admin-token.json
```

- Expected: `1500:1500 600 shared/influx-admin-token.json`. Ordinary-user read denial is expected; do not print its JSON or loosen permissions.
- This file must exist **before** starting InfluxDB; Compose mounts it for `--admin-token-file`. `INFLUX_TOKEN` alone does not provision the server.
- Matching existing bytes/metadata are preserved. Mismatched tokens, malformed JSON or incompatible metadata refuse without automatic repair. Do not delete DB volumes to fix credentials.

## 8. Determine Docker socket GID; build

```sh
DOCKER_GID="$(docker run --rm --network none \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  --entrypoint sh postgres:15@sha256:9b1d34adbce1dd07ee6e94b4a2cf698884b89bd44a6c9c12f5da8f3acbfe4957 \
  -c 'test -S /var/run/docker.sock && stat -c %g /var/run/docker.sock')"
case "$DOCKER_GID" in
  ''|*[!0-9]*) printf '%s\n' 'No numeric Docker socket GID; stop here'; exit 1 ;;
esac
docker compose --env-file .env.compose --profile all build \
  --build-arg "DOCKER_GID=$DOCKER_GID"
```

- Use the daemon-mounted socket's GID, not merely a group named `docker`. The probe does not call the socket API; a read-only socket mount is not a general security restriction.
- The first build downloads native/Python/Node dependencies and can take several minutes. Wait for successful completion; a built image is not a running service.

## 9. Prepare the PCAP import volume

```sh
docker compose --env-file .env.compose --profile all run --rm --no-deps \
  --user 0 --entrypoint sh otalon-capture-pcap-import \
  -c 'chown 0:10000 /import && chmod 2770 /import'
```

## 10. Start databases; create Influx database if absent

```sh
docker compose --env-file .env.compose --profile core-db up -d --wait postgres influxdb3 &&
docker compose --env-file .env.compose --profile core-db exec -T influxdb3 influxdb3 show databases
```

If and only if the successful listing does **not** contain `netcap`, run:

```sh
docker compose --env-file .env.compose --profile core-db exec -T influxdb3 influxdb3 create database netcap
```

Then confirm it is present:

```sh
docker compose --env-file .env.compose --profile core-db exec -T influxdb3 influxdb3 show databases
```

- CLI uses the container's `INFLUXDB3_AUTH_TOKEN`; do not put a token in command arguments.
- PostgreSQL initializes the configured `POSTGRES_DATABASE` (sample: `otalon`), not necessarily the maintenance database `postgres`. Password applies only to an empty data volume.

## 11. Migrate before starting consumers

- **Docker Desktop build/DB testing:** enable **Settings → Resources → Network → Enable host networking**, apply/restart Desktop and verify DB connectivity before these host-networked one-offs. This does not enable physical capture.

```sh
docker compose --env-file .env.compose --profile all run --rm --no-deps \
  --entrypoint python otalon-scan -m alembic -c /app/alembic.ini upgrade head &&
docker compose --env-file .env.compose --profile all run --rm --no-deps \
  --entrypoint python otalon-scan -m alembic -c /app/alembic.ini current
```

Read the **stored** revision from the configured database:

```sh
docker compose --env-file .env.compose --profile core-db exec -T postgres \
  sh -c 'exec psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -v ON_ERROR_STOP=1 -Atc "SELECT version_num FROM alembic_version"'
```

- Expected revision for this source: `0015`. `alembic current` returned exit 0 without a printed revision in the test; use the SQL readback rather than treating empty output as proof.
- Stop if upgrade/readback fails. Querying the wrong `postgres` database can report a missing `alembic_version` table even when migration succeeded in `otalon`.

## 12. Start the suite — authorized native Linux host only

- Confirm interfaces, firewall and network-owner approval **before** this block. Capture/scan have host networking and `NET_RAW`/`NET_ADMIN`; do not trigger active scans as smoke tests.
- **WSL/Desktop physical capture: stop before this block.** The Windows collector/receiver and late-data handling remain pending; there is no raw-NIC workaround in this guide.

```sh
docker compose --env-file .env.compose --profile all up -d --wait &&
docker compose --env-file .env.compose --profile all ps
```

- Expected: all 13 services healthy. Healthy capture/AI/classifier processes do not prove packet recording, provider access or detection output.

## 13. Browser login; change bootstrap password

- Open `https://localhost:8443` on the deployment host, or its authorized hostname/IP. Default TLS is self-signed for `localhost`/`127.0.0.1`; use trusted organization certificates for remote access.
- First login: `admin`, bootstrap password displayed on the login page. Complete the required password change; log out and sign in with the new password. Never expose first-start access publicly.
- Existing accounts: keep your changed password. Rerunning setup does not reset it. Browser login/password change were **not exercised** by the native command-only test.

## 14. Operator acceptance — data, not only health

```sh
docker compose --env-file .env.compose --profile all exec -T otalon-api \
  python3 -c 'import os; assert os.access("/import", os.W_OK)' &&
docker compose --env-file .env.compose --profile all exec -T otalon-capture-pcap-import \
  python3 -c 'import os; assert os.access("/import", os.W_OK)' &&
curl -kfsS https://127.0.0.1:8443/ >/dev/null
```

- **Auth:** confirm logged-out protected pages require login; verify protected APIs reject missing/wrong keys and accept the intended role/key. Keep keys out of screenshots/logs.
- **PCAP:** open **Operations → Data Sources → PCAP Import & Replay**. Upload an authorized real PCAP/PCAPNG and wait for `completed`, not just successful upload. Record filename, job ID, capture range and result counts.
- **Data:** click **Set time range**, then inspect **Timeseries Data → Connections** at the capture's original timestamps. Verify persisted measurements; processed metric-record counts are not packet counts. Manual history import does not automatically run historical detection.
- **Persistence:** record the imported range/result first. On this acceptance installation only, perform the planned recreate below, then repeat login, job/history and data checks. Keep the changed password, rows and volumes; do not re-upload to make missing data appear.

```sh
docker compose --env-file .env.compose --profile all up -d --force-recreate --wait &&
docker compose --env-file .env.compose --profile all ps
```

- **AI/detection:** test real chat/jobs using your actual gateway/aliases and enabled profiles/artifacts separately. Initial classifier artifacts are not supplied; retraining needs an existing classifier and real telemetry/labels/reference data. Never disable detection to make startup green.
- **Record failures:** step/command or UI action, error/status, expected vs actual and timestamp; redact credentials. Browser auth, UI PCAP/persistence, real provider loops and physical Windows capture remain unverified until exercised on your target.
- **Updates:** build/recreate affected services after source changes; recreate after env changes, not merely restart. Never use `down -v` or delete volumes to fix credentials. Reference: [MCP docs](otalon-mcp/docs/).

## Windows capture → manual import

**Available route:** physical Windows NIC → Npcap/dumpcap → closed PCAP → manual browser upload. This is **not** continuous WSL monitoring or a validated WSL deployment; the step-12 stop still applies. Upload requires an already running, authorized OTALON UI (a separately verified Linux deployment is also a valid target).

1. On **Windows**, install [Wireshark](https://www.wireshark.org/download.html) with [Npcap](https://npcap.com/guide/npcap-users-guide.html). Follow organization policy; review Npcap licensing separately rather than bundling its installer. Reboot if requested.
2. Use an authorized physical Ethernet NIC; it must actually receive the desired traffic (for other devices, arrange an approved SPAN/mirror or TAP feed). A Windows/WSL virtual adapter is not a substitute. Do not trigger active scans to create test traffic.
3. Open **Windows PowerShell**, not the Ubuntu/WSL shell. Elevate only if your Npcap permissions require it. List interfaces:

```powershell
$dumpcap = Join-Path $env:ProgramFiles 'Wireshark\dumpcap.exe'
$capinfos = Join-Path $env:ProgramFiles 'Wireshark\capinfos.exe'
if (!(Test-Path $dumpcap) -or !(Test-Path $capinfos)) { throw 'Wireshark tools not found; check the installation path' }
& $dumpcap -D
if ($LASTEXITCODE -ne 0) { throw 'Interface listing failed; check Npcap and permissions' }
```

4. In the **same PowerShell session**, enter the exact number or device name from the listing. Capture stops at 60 seconds or the 102400-kB file-size threshold; check free space first (thresholds are not a strict disk quota). Keep captures in an organization-approved private directory; the example uses your local application-data directory.

```powershell
$nic = Read-Host 'Approved physical interface number or device name'
if ([string]::IsNullOrWhiteSpace($nic)) { throw 'No interface selected' }
$dir = Join-Path $env:LOCALAPPDATA 'OTALON\captures'
New-Item -ItemType Directory -Path $dir -Force -ErrorAction Stop | Out-Null
$file = Join-Path $dir ('capture-' + [guid]::NewGuid().ToString('N') + '.pcap')
& $dumpcap -i $nic -F pcap -a duration:60 -a filesize:102400 -w $file
if ($LASTEXITCODE -ne 0) { throw 'Capture failed; retain the error and do not import a partial file' }
& $capinfos -c -a -e $file
if ($LASTEXITCODE -ne 0) { throw 'Capture file validation failed' }
$file
```

5. Wait for dumpcap to exit; inspect the reported **packet count and original capture timestamps**. Zero packets is not acceptance: check the selected NIC/feed. Do not upload a growing file, retime packets or overwrite existing evidence. These Windows commands require validation on your actual Windows/Npcap system; Linux CLI checks are not that proof.
6. In the **Windows browser**, open your already running OTALON UI. Follow step 13, then **Operations → Data Sources → PCAP Import & Replay**; upload the printed Windows file directly. No copy into WSL, host bind mount or container command is needed. Wait for `completed`, use **Set time range**, and perform the data/persistence checks in step 14. Manual imports do not automatically run historical detection.

**Continuous WSL capture — not implemented:** a Windows collector must safely retain/forward closed files to an authenticated receiver; native/Python measurement state must span file boundaries/restarts; delayed data needs durable progress and separate detection recovery. Desktop Compose integration and real Windows → metrics → detection/UI, outage/restart and persistence tests remain required. Do not configure a Windows device name as `CAPTURE_SOURCE`, enable container privileges as a raw-NIC workaround, or automate independent per-file imports and call them equivalent live monitoring. References: [dumpcap options](https://www.wireshark.org/docs/man-pages/dumpcap.html), [capinfos](https://www.wireshark.org/docs/man-pages/capinfos.html), [Desktop limitations](https://docs.docker.com/engine/network/drivers/host/).
