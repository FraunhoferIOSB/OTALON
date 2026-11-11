# Install OTALON

- **Full capture/scanning:** rootful Docker Engine on an authorized native Linux host; Compose v2+.
- **WSL2 + Docker Desktop:** build/development only in this guide. Desktop host networking is TCP/UDP (layer 4), not direct physical-NIC access. Do not run step 12 for physical OT capture/scanning under Desktop. No full WSL installation has been verified. See [Docker host-network limitations](https://docs.docker.com/engine/network/drivers/host/).
- Tools: `git`, `sudo`, `python3`, Docker/Compose; internet access for image/package downloads and pinned native build dependencies.
- Security: PostgreSQL `5432` and InfluxDB `8181` publish on **all host interfaces**. Restrict them with an approved firewall before starting. `HTTP_PLAIN_*` settings do not change this.

## 1. Clone

```sh
git clone https://github.com/FraunhoferIOSB/OTALON.git /home/user/otalon
cd /home/user/otalon
export WORKSPACE_DIR="$PWD"
```

## 2. Join the shared group

```sh
getent group 10000 || sudo groupadd -g 10000 otalon-shared
sudo usermod -aG "$(getent group 10000 | cut -d: -f1)" "$USER"
newgrp "$(getent group 10000 | cut -d: -f1)"
cd /home/user/otalon
export WORKSPACE_DIR="$PWD"
id
```

- Confirm GID `10000` appears. Membership grants write access to shared application files.
- `newgrp` opens a new shell. Run the following `cd`, `export` and `id` lines at its new prompt. Continue the installation in this shell; `exit` returns to the old shell, whose group membership has not changed. Alternatively, log out and log in again after `usermod`, then repeat `cd`, `export` and `id`.

## 3. Create the local configuration once

```sh
if [ ! -e .env.compose ] && [ ! -L .env.compose ]; then
  python3 scripts/install/setup.py --workspace "$WORKSPACE_DIR"
  sudo chown 10001:10000 .env.compose
  sudo chmod 0660 .env.compose
fi
stat -c '%u:%g %a %n' .env.compose
```

- Expected: `10001:10000 660 .env.compose`. Never overwrite a configured file from the sample. Existing files are not re-owned or re-moded automatically; stop if the displayed metadata differs and review it explicitly. Symlinks are rejected by the setup helper.

## 4. Generate local secrets; configure external dependencies

```sh
python3 scripts/install/setup.py --workspace "$WORKSPACE_DIR"
```

- This fills only missing/template local DB, service and callback secrets with cryptographic randomness, and derives the checkout path/build reference. Configured values, comments, order, inode, owner and mode are preserved. It never generates external provider credentials or selects capture/scan interfaces. Output lists variable names only; a successful setup is not deployment readiness.
- The helpers use a restricted environment-file grammar: single quotes are literal, and bare/double-quoted `${NAME}` references must follow their inputs. Shell commands, unsupported substitutions, duplicate assignments and symlink/hardlinked inputs fail before writes. See [Local Installer Utilities](scripts/install/README.md).
- LiteLLM is a gateway between OTALON and your model provider. For this bounded installation path, use an existing reachable LiteLLM-compatible gateway; no gateway, upstream subscription, credentials or models are bundled. A gateway alone does not provide an LLM. Obtain its `/v1` URL, access key and actually served chat/job aliases before proceeding. The optional bundled-gateway and full WSL deployment paths remain separate, unverified work.

```sh
nano .env.compose
```

- Use an interactive terminal. In Nano, press `Ctrl+O`, then Enter to save, and `Ctrl+X` to exit. Do not print the configured file or paste its contents into chat.

Edit only the top EDIT THIS SECTION block:
- `WORKSPACE_DIR`: confirm the derived absolute checkout path; review timezone defaults.
- `CAPTURE_SOURCE`, `SCAN_SOURCE`: approved, real host interfaces, not the sample's lab names. The helper does not authorize them.
- `POSTGRES_PASSWORD`, `INFLUX_TOKEN`, API/service keys and `PCAP_IMPORT_WORKER_TOKEN`: generated locally when missing/template. Keep configured credentials; do not rotate them to fix an existing database. Allow-lists and callback inputs reuse these values automatically.
- `LITELLM_BASE_URL` (ending `/v1`), `LITELLM_API_KEY`, `CHAT_LLM_MODEL`, `JOBS_LLM_MODEL`: configure the external gateway and served aliases manually. The sample endpoint is not proof of availability.
- `OTALON_BUILD_REF`: confirm the derived checkout reference. Optional `NVD_API_KEY`; keep reviewed feature/blacklist defaults unless needed.
- Never send credentials in chat or commit `.env.compose`.

## 5. Prepare shared directories and access

```sh
sudo install -d -o root -g root -m 0755 shared
sudo install -d -o root -g 10000 -m 2775 \
  shared/logs shared/models shared/pcap/buffer shared/pcap/archive \
  shared/pcap/baseline shared/operations
sudo install -d -o root -g root -m 0750 shared/tls
```

- Review before deployment: API mounts the Docker socket (**root-equivalent administration**), `/`, `/home`, `/var` read-only (**host-data disclosure**) and the full checkout read/write. Read-only does not mean confidential.
- Optional, for API-saved configuration: grant GID 10000 create/rename access to the checkout root. This grants every member checkout-root write access:

```sh
sudo chgrp 10000 "$WORKSPACE_DIR"
sudo chmod g+ws "$WORKSPACE_DIR"
```

- Do not recursively change existing data. API atomic env-file updates can set legacy mode `0644`; restore `sudo chmod 0660 .env.compose` after such updates.

## 6. Check configuration without printing secrets

```sh
python3 scripts/install/check.py --workspace "$WORKSPACE_DIR"
docker compose --env-file .env.compose --profile all config --quiet
```

- Stop on errors; do not paste resolved configuration. Both checker modes validate local shapes only and do not contact the gateway or establish served-model availability. `--syntax-only` permits explicit offline/sample endpoint markers and is not an installation readiness gate. Build consumes `DOCKER_GID`; database credentials take effect at initialization/start, not image build.

## 7. Create InfluxDB's bootstrap token file

- `INFLUX_TOKEN` alone does **not** provision the server. Compose mounts this local JSON for `--admin-token-file` (image UID/GID `1500:1500`). Existing tokens are not rotated by env changes.

```sh
sudo python3 scripts/install/bootstrap_influx.py --workspace "$WORKSPACE_DIR"
```

- An existing matching file must already be owned by `1500:1500` with mode `0600`; bytes, inode and metadata are preserved. Mismatched credentials, malformed/duplicate JSON, unsafe links or incompatible metadata fail without automatic repair. Review failures explicitly; never delete persisted database volumes to make a token change work.

## 8. Determine the Docker socket GID; build

- Inspect the **daemon-mounted socket**, not just the WSL group named `docker`. The inspection does not call the socket API; a read-only mount is not a general socket security restriction.

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

## 9. Prepare the PCAP import volume

```sh
docker compose --env-file .env.compose --profile all run --rm --no-deps \
  --user 0 --entrypoint sh otalon-capture-pcap-import \
  -c 'chown 0:10000 /import && chmod 2770 /import'
```

## 10. Start databases; initialize InfluxDB

```sh
docker compose --env-file .env.compose --profile core-db up -d --wait postgres influxdb3
docker compose --env-file .env.compose --profile core-db exec influxdb3 influxdb3 show databases
# Fresh installation only: run the next command if and only if netcap is absent:
docker compose --env-file .env.compose --profile core-db exec influxdb3 influxdb3 create database netcap
docker compose --env-file .env.compose --profile core-db exec influxdb3 influxdb3 show databases
```

- Confirm `netcap`. CLI reads its token from the container environment; no `--token` argument.
- If and only if `netcap` is absent from the first `show databases` output, run `create database netcap`. If it is already listed, skip creation and continue with the final `show databases` check.
- PostgreSQL applies `POSTGRES_PASSWORD` **only when initializing an empty data volume**. Changing `.env.compose` does not rotate a persisted password.

## 11. Apply migrations BEFORE starting consumers

- **Docker Desktop prerequisite:** enable **Settings → Resources → Network → Enable host networking**, apply/restart Desktop and verify database connectivity first. This one-off reaches PostgreSQL at `127.0.0.1`; the setting does not enable physical-NIC capture.

```sh
docker compose --env-file .env.compose --profile all run --rm --no-deps \
  --entrypoint python otalon-scan -m alembic -c /app/alembic.ini upgrade head
docker compose --env-file .env.compose --profile all run --rm --no-deps \
  --entrypoint python otalon-scan -m alembic -c /app/alembic.ini current
```

- Current migration: `0015`. Stop if migration fails.

## 12. Start the full stack — native Linux capture host only

- Confirm interfaces, target scope, firewall and network-owner approval. Capture/scan use host networking, `NET_RAW`/`NET_ADMIN`. Do not use active scans as smoke tests.
- **WSL/Docker Desktop:** stop before this step for physical capture/scanning; this guide supplies no verified alternative deployment.

```sh
docker compose --env-file .env.compose --profile all up -d --wait
docker compose --env-file .env.compose --profile all ps
```

## 13. Open HTTPS; change the bootstrap password

- Open `https://localhost:8443` on the deployment host (or its authorized hostname/IP).
- First login: `admin`; use the bootstrap password shown on the login screen. Immediately complete the required password change; never expose first-start access publicly.
- Default TLS is self-signed for `localhost`/`127.0.0.1`; manage trust or install the organization's certificate for remote access.

## 14. Verify before operational use

```sh
docker compose --env-file .env.compose --profile all exec otalon-api \
  python3 -c 'import os; assert os.access("/import", os.W_OK)'
docker compose --env-file .env.compose --profile all exec otalon-capture-pcap-import \
  python3 -c 'import os; assert os.access("/import", os.W_OK)'
curl -kfsS https://127.0.0.1:8443/ >/dev/null
```

- Check API/scan/MCP health, authorized telemetry in InfluxDB, auth rejection with missing/wrong keys and acceptance with the intended key. `/health` or an HTTP 200 alone is not data-flow proof.
- Complete a real UI PCAP import; verify persisted measurements and successful job completion. Recheck persistence after a planned recreate; preserve database/import volumes.
- Bounds/frequency profiles require observed telemetry. Initial classifier artifacts/bootstrap are **not provided**; retraining requires an already deployed classifier plus real telemetry/labels/reference data. Healthy containers do not prove classification or external model readiness.
- Source changes: build/recreate affected services and verify fresh containers. Env-only changes: recreate, not merely restart. Never delete volumes to fix credentials. Development reference: [MCP documentation](otalon-mcp/docs/).
