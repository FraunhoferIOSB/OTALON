# Install OTALON

- **Full capture/scanning:** rootful Docker Engine on an authorized native Linux host; Compose v2+.
- **WSL2 + Docker Desktop:** build/development only in this guide. Desktop host networking is TCP/UDP (layer 4), not direct physical-NIC access. Do not run step 12 for physical OT capture/scanning under Desktop. No full WSL installation has been verified. See [Docker host-network limitations](https://docs.docker.com/engine/network/drivers/host/).
- Tools: `git`, `sudo`, `python3`, Docker/Compose; internet access for image/package downloads and pinned native build dependencies.
- Security: PostgreSQL `5432` and InfluxDB `8181` publish on **all host interfaces**. Restrict them with an approved firewall before starting. `HTTP_PLAIN_*` settings do not change this.

## 1. Clone

```sh
git clone https://github.com/FraunhoferIOSB/OTALON.git /home/user/otalon-github
cd /home/user/otalon-github
export WORKSPACE_DIR="$PWD"
```

## 2. Join the shared group

```sh
getent group 10000 || sudo groupadd -g 10000 otalon-shared
sudo usermod -aG "$(getent group 10000 | cut -d: -f1)" "$USER"
newgrp "$(getent group 10000 | cut -d: -f1)"
cd /home/user/otalon-github
export WORKSPACE_DIR="$PWD"
id
```

- Confirm GID `10000` appears. Membership grants write access to shared application files.

## 3. Create the local configuration once

```sh
if [ ! -e .env.compose ]; then
  sudo install -o 10001 -g 10000 -m 0660 .env.compose.sample .env.compose
fi
sudo chown 10001:10000 .env.compose
sudo chmod 0660 .env.compose
stat -c '%u:%g %a %n' .env.compose
```

- Expected: `10001:10000 660 .env.compose`. **Never overwrite a configured file from the sample.**

## 4. Configure secrets and dependencies BEFORE building

```sh
nano .env.compose
```

Edit only the top **EDIT THIS SECTION** block:
- `WORKSPACE_DIR`: your absolute checkout path; review timezone defaults.
- `CAPTURE_SOURCE`, `SCAN_SOURCE`: approved, real host interfaces, not the sample's lab names.
- `POSTGRES_PASSWORD`: unique, high-entropy hexadecimal password; reserved URL characters break the derived DSNs. Keep DB name/user/port defaults for initial setup.
- `INFLUX_TOKEN`: unique token starting with `apiv3_`, followed by 64 random hexadecimal characters.
- API/service keys: replace all credential placeholders with distinct random keys. Allow-lists below reuse these fields automatically; do not duplicate key values manually.
- `PCAP_IMPORT_WORKER_TOKEN`: one callback secret shared automatically by API/import worker. Required for imports to complete.
- `LITELLM_BASE_URL` (ending `/v1`), `LITELLM_API_KEY`, `CHAT_LLM_MODEL`, `JOBS_LLM_MODEL`: your reachable external proxy and actually served aliases. **No proxy or models are included.**
- `OTALON_BUILD_REF`: checkout commit (`git rev-parse HEAD`). Optional `NVD_API_KEY`; keep reviewed feature/blacklist defaults unless needed.
- Use a password manager's secure generator (32 random bytes / 64 hex characters). Never send credentials in chat or commit `.env.compose`.

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
python3 - <<'PY'
from pathlib import Path
import re
seen, values = set(), {}
for line in Path('.env.compose').read_text().splitlines():
    if not line.strip() or line.lstrip().startswith('#'):
        continue
    m = re.fullmatch(r'([A-Z][A-Z0-9_]*)=(.*)', line)
    if not m or m[1] in seen or '<SET_' in line or '<git-sha-or-release-ref>' in line:
        raise SystemExit('Invalid, duplicate, or unresolved environment assignment')
    if not set(re.findall(r'\$\{([A-Z][A-Z0-9_]*)\}', m[2])) <= seen:
        raise SystemExit('Environment reference must follow its input assignment')
    seen.add(m[1])
    values[m[1]] = m[2].strip().strip("'\"")
required = [line.split('=', 1)[0] for line in Path('.env.compose.sample').read_text().splitlines()
            if line and not line.startswith('#') and '=<SET_' in line]
missing = [key for key in required if not values.get(key)]
if missing:
    raise SystemExit('Required settings missing: ' + ', '.join(missing))
print('Environment syntax, reference order and required inputs OK')
PY
docker compose --env-file .env.compose --profile all config --quiet
```

- Stop on errors; do not paste resolved configuration. Build consumes `DOCKER_GID`; database credentials take effect at initialization/start, not image build.

## 7. Create InfluxDB's bootstrap token file

- `INFLUX_TOKEN` alone does **not** provision the server. Compose mounts this local JSON for `--admin-token-file` (image UID/GID `1500:1500`). Existing tokens are not rotated by env changes.

```sh
sudo env WORKSPACE_DIR="$WORKSPACE_DIR" python3 - <<'PY'
import json, os, pathlib, secrets
root = pathlib.Path(os.environ['WORKSPACE_DIR'])
values = dict(line.split('=', 1) for line in (root / '.env.compose').read_text().splitlines()
              if line and not line.startswith('#') and '=' in line)
token = values['INFLUX_TOKEN'].strip().strip("'\"")
if not token.startswith('apiv3_') or len(token) != 70 or any(c not in '0123456789abcdef' for c in token[6:]):
    raise SystemExit('INFLUX_TOKEN must be apiv3_ plus 64 random hexadecimal characters')
target = root / 'shared/influx-admin-token.json'
if target.exists() or target.is_symlink():
    if target.is_symlink() or not target.is_file():
        raise SystemExit('Bootstrap target is not a regular file')
    current = json.loads(target.read_text())
    if current.get('token') != token or current.get('name') != '_admin':
        raise SystemExit('Existing token differs; explicit credential rotation required')
else:
    tmp = target.with_name('.influx-token-' + secrets.token_hex(8))
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as f:
        json.dump({'token': token, 'name': '_admin'}, f)
    os.chown(tmp, 1500, 1500)
    os.replace(tmp, target)
os.chown(target, 1500, 1500)
os.chmod(target, 0o600)
PY
```

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
# Fresh installation only; skip creation if netcap already exists:
docker compose --env-file .env.compose --profile core-db exec influxdb3 influxdb3 create database netcap
docker compose --env-file .env.compose --profile core-db exec influxdb3 influxdb3 show databases
```

- Confirm `netcap`. CLI reads its token from the container environment; no `--token` argument.
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
