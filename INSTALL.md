# Linux Deployment

This guide prepares a Linux host for a Docker Compose deployment. It is an
operator procedure (instructions), not measured evidence that a fresh
installation has been verified. Perform it only on an authorized monitoring
host and coordinate capture or scanning with the network owner.

## Requirements

- A supported rootful Linux host with Docker Engine and the Docker Compose v2
  plugin.
- `sudo` rights for the one-time host preparation below, permission to use
  Docker and its daemon socket, plus `getent`, `install`, `groupadd`/`usermod`,
  `python3`, and `openssl`.
- Network access from Docker builds to the configured package sources and to
  GitHub for the pinned Boost and pybind11 FetchContent dependencies.
- Operator-managed PostgreSQL credentials, an InfluxDB token, API/service
  credentials, and a reachable LiteLLM-compatible API with the configured model
  aliases available.
- An approved capture interface and, only if active discovery is authorized,
  an approved scan interface and scope.

## Checkout And Host Directories

Clone the public repository over HTTPS or SSH as a host account that can
operate Docker. The examples use `/home/user/otalon-github`; if that account or
path does not exist, choose another checkout path and use it consistently as
`WORKSPACE_DIR` in `.env.compose` and in the shell environment of every
Compose command (Compose interpolation does not read `env_file` values).

```text
git clone https://github.com/FraunhoferIOSB/OTALON.git /home/user/otalon-github
# or: git clone git@github.com:FraunhoferIOSB/OTALON.git /home/user/otalon-github
cd /home/user/otalon-github
export WORKSPACE_DIR="$PWD"
```

The Compose workspace path must match that checkout exactly. The container
user IDs are API 10001, MCP 10002, UI 10003, CLAS 10004, AI 10005, capture
10006, and scan 10007; all but scan share group GID 10000, and scan joins it
for log writes. InfluxDB runs as UID/GID 1500 in its image.

### Shared group and privileged boundary

Files owned by `10001:10000` cannot be read, changed, or `chmod`-ed by an
ordinary host user without privilege. Choose one of the following and accept its
boundary explicitly:

- **Group membership (recommended).** Make GID 10000 exist on the host and add
  the operator to it. This is a host-wide privileged change and members of the
  group can write the shared application directories:

  ```text
  getent group 10000 || sudo groupadd -g 10000 otalon-shared
  sudo usermod -aG "$(getent group 10000 | cut -d: -f1)" "$USER"
  # Log out and back in (or run `newgrp`) so the membership takes effect.
  ```

- **No membership.** Perform every read/edit/`chmod` of `.env.compose` with
  `sudo` (for example `sudoedit .env.compose`) and run Compose with `sudo`.

Create the local environment file from the single tracked template with its
final owner and mode in one privileged step (an ordinary `chown` is not
available to the operator):

```text
sudo install -o 10001 -g 10000 -m 0660 .env.compose.sample .env.compose
```

Edit it in place with `sudoedit .env.compose`, or directly if you are a member
of GID 10000. Set `WORKSPACE_DIR` in it to the same checkout path. Every
Compose command must pass `--env-file .env.compose` explicitly; the same file
is injected into services through their `env_file` declarations. Do not widen
it to world-readable permissions.

Current API behavior: the API's configuration-management endpoint rewrites
`.env.compose` and its current implementation writes the replacement through a
temporary file in the same directory followed by an atomic rename, with legacy
mode `0644`. Consequently (a) UID 10001 must be able to create files in the
checkout directory that holds `.env.compose`, and (b) after any API-driven
configuration change the file may be world-readable until you restore the mode.
This guide documents that behavior as it is; it does not change the policy.
Grant the directory access through the shared group only if you use that
feature, and re-check the mode afterwards:

```text
sudo chgrp 10000 "$WORKSPACE_DIR"
sudo chmod g+ws "$WORKSPACE_DIR"        # lets GID 10000 create/rename temp files
sudo chmod 0660 "$WORKSPACE_DIR/.env.compose"   # re-run after API config changes
```

This gives every member of GID 10000 write access to the checkout root, which
is a significant privilege grant; skip it if API-driven env editing is not
needed.

### Bind-mounted directories

The bind-mounted directories are relative to the checkout: `shared/logs`,
`shared/models`, `shared/pcap/buffer`, `shared/pcap/archive`,
`shared/pcap/baseline`, `shared/operations`, and `shared/tls`. Prepare an empty
checkout's writable application directories with shared GID 10000 and setgid
group-write permissions:

```text
sudo install -d -o root -g root -m 0755 shared
sudo install -d -o root -g 10000 -m 2775 \
  shared/logs shared/models shared/pcap/buffer shared/pcap/archive \
  shared/pcap/baseline shared/operations
sudo install -d -o root -g root -m 0750 shared/tls
```

Do not recursively change ownership on directories containing existing
operator data. The TLS proxy creates a self-signed certificate on first start
and retains it in `shared/tls`; install a trusted certificate there through
your organization's certificate process when required. The generated
certificate is for `localhost` and `127.0.0.1`; it is not a trusted certificate
for the host's DNS name or address.

The API image accesses `/var/run/docker.sock`. Determine the host socket's
numeric group and pass it while building, without changing the container's
configured privilege model:

```text
docker compose --env-file .env.compose --profile all build \
  --build-arg DOCKER_GID="$(getent group docker | cut -d: -f3)"
```

Build images from the source checkout before applying scanner migrations. The
capture image's build downloads pinned Boost and pybind11 sources, so the host
needs GitHub access during the build.

If the socket uses another group, use that numeric GID instead. This grants the
API's existing Docker integration access to the host daemon and must be treated
as a highly privileged host boundary. The API also receives read-only mounts
of `/`, `/home`, and `/var` for storage inspection and read/write access to the
checkout for its existing operations/configuration functions. Read-only does
not prevent disclosure of host-readable files. Review all these grants before
exposing the API; a disposable isolated test must not mount the live host roots.

## PCAP Import Volume Permissions

The named `pcap-import-data` volume is shared by the API (UID 10001) and
import worker (UID 10006). A new Docker volume defaults to root:root 0755,
which both services can mount but neither can write. Prepare it before the
first upload; health checks alone do not prove this access.

After building the images, run this one-off, explicitly privileged preparation
against this deployment's named volume only:

```text
docker compose --env-file .env.compose --profile all run --rm --no-deps \
  --user 0 --entrypoint sh otalon-capture-pcap-import \
  -c 'chown 0:10000 /import && chmod 2770 /import'
```

The setgid directory grants the two existing shared-group members access.
Do not recursively change existing upload ownership. Verify access from both
normal service users after startup:

```text
docker compose --env-file .env.compose exec otalon-api \
  python3 -c 'import os; assert os.access("/import", os.W_OK)'
docker compose --env-file .env.compose exec otalon-capture-pcap-import \
  python3 -c 'import os; assert os.access("/import", os.W_OK)'
```

A missing grant causes an upload failure even when the API and worker report
healthy. Preserve the same named volume across updates.

## Configure Secrets And Dependencies

Replace every `<SET_...>` and generated-key placeholder in `.env.compose` with
operator-managed values; never use the placeholders as credentials. Set a
strong `POSTGRES_PASSWORD`, `INFLUX_TOKEN`, and service credentials. Use a
high-entropy hexadecimal PostgreSQL password for the DSN interpolation in this
sample; unescaped `@`, `:`, `/`, `#`, or `%` characters break its URL form. The
PostgreSQL DSNs in the template derive their host, port, database, and
credentials from `POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_PORT`, and
`POSTGRES_DATABASE`. The shipped database name is `otalon`; the API initializes
its own application tables there, while scanner-owned tables are created by the
explicit Alembic migration below.

`INFLUX_TOKEN` must begin with `apiv3_` (see the InfluxDB bootstrap below).

Allow-list values use comma-separated `name:role:key` entries. Keep each
consumer credential byte-for-byte equal to the `key` field of its producer's
allow-list entry: `OTALON_AI_UI_KEY` to an AI viewer key,
`OTALON_AI_INTERNAL_KEY` to an AI operator key, `OTALON_MCP_API_KEY` to an MCP
operator key, `OTALON_SCAN_API_KEY` to a scanner operator key, and
`OTALON_API_KEY` to the `mcp:operator` API key entry. `ADMIN_API_KEY` is explicitly registered as `ui:operator` in the API
allow-list because a nonempty registry replaces the legacy single-key fallback.
It is also the existing PCAP recorder/import-worker operator credential; keep
the MCP/API and report-channel credentials separate. Roles
are `viewer` or `operator` as required by the corresponding caller. Names
identify entries and are not credentials.

The template leaves chat and jobs model names as editable placeholders. Set
each to a model alias served by the external LiteLLM endpoint configured by
`LITELLM_BASE_URL` and `LITELLM_API_KEY`. The service code retains its
`azure/gpt-5.4` fallback model name, but the Compose template requires operators
to provide the intended aliases; no LLM provider or model is bundled, and
startup/reachability does not establish that a requested model is available.
Legacy direct-provider fields are optional and are not the runtime path used by
`otalon-ai`.

Configure `CAPTURE_SOURCE` and `SCAN_SOURCE` for the authorized host
interfaces. Live capture uses host networking and the Compose-declared network
capabilities; active scanning also uses host networking and `NET_RAW` plus
`NET_ADMIN`. Do not launch active scans until the interface, target scope, and
authorization have been reviewed. The legacy `HTTP_PLAIN_PORTS_ENABLED` and
`HTTP_PLAIN_PORTS_BIND_ADDRESS` sample variables are not consumed by this
standalone Compose file and do not change any listening address. UI and API
are bridge-internal; capture and scan use host networking, while PostgreSQL
and InfluxDB publish host ports on all interfaces. Restrict these boundaries
with reviewed host firewall rules or a deployment-specific Compose override;
never assume the legacy toggle protects cleartext credentials. Keep
`SESSION_COOKIE_SECURE=true` and use the TLS proxy for normal browser access.
The public sample has no deployment-specific blacklist. Set only exclusions
approved for the monitored network.

`PCAP_IMPORT_WORKER_TOKEN` must be set to the same high-entropy secret for the
API and import worker before PCAP import can complete. `NVD_API_KEY` is
optional and only raises the NVD lookup rate allowance.

## InfluxDB Token Bootstrap

The `INFLUXDB3_AUTH_TOKEN` environment variable that Compose passes to the
server is not what provisions the admin token on first boot. The pinned
InfluxDB 3 Core server is instead started with `--admin-token-file`, reading a
JSON file bind-mounted read-only from `./shared/influx-admin-token.json`. This
file is local runtime input; it is ignored through `/shared/` and is not an
additional tracked template. Its schema is:

```text
{"token": "apiv3_...", "name": "_admin"}
```

Create it from the `INFLUX_TOKEN` you already placed in `.env.compose`, without
printing the token. The script parses the env file in process, validates the
prefix, and writes the JSON atomically with numeric owner 1500:1500 and mode
0600 (the InfluxDB image UID/GID; this assumes a normal rootful Linux host):

```text
sudo env WORKSPACE_DIR="$WORKSPACE_DIR" python3 - <<'PY'
import json, os, pathlib

root = pathlib.Path(os.environ["WORKSPACE_DIR"])
token = None
for line in (root / ".env.compose").read_text(encoding="utf-8").splitlines():
    if line.startswith("INFLUX_TOKEN="):
        token = line.split("=", 1)[1].strip().strip("'\"")
if not token or not token.startswith("apiv3_"):
    raise SystemExit("INFLUX_TOKEN is missing or does not start with apiv3_")

shared = root / "shared"
shared.mkdir(exist_ok=True)
target = shared / "influx-admin-token.json"
tmp = shared / ".influx-admin-token.json.tmp"
fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(fd, "w", encoding="utf-8") as handle:
    json.dump({"token": token, "name": "_admin"}, handle)
os.chown(tmp, 1500, 1500)
os.chmod(tmp, 0o600)
os.replace(tmp, target)
PY
```

The file must exist before InfluxDB starts; otherwise Docker creates a
directory at the mount path. If you prefer not to read the env file as root,
write the same JSON with `getpass.getpass()` instead of parsing it; never put
the token on a command line or in shell history. Note that the Influx CLI's own
offline token-generation output has a leading non-JSON prefix line, so its whole
stdout is not pure JSON; this procedure does not rely on it.

Start InfluxDB and create the capture database. The CLI inside the container
reads `INFLUXDB3_AUTH_TOKEN` from the container environment automatically, so
never pass `--token` on the command line and do not copy source into the
container:

```text
docker compose --env-file .env.compose --profile core-db up -d influxdb3
docker compose --env-file .env.compose exec influxdb3 influxdb3 create database netcap
docker compose --env-file .env.compose exec influxdb3 influxdb3 show databases
```

The `show databases` output must list `netcap`. Then confirm that
unauthenticated queries are rejected while the intended key succeeds (the
`/health` endpoint alone is not evidence of this). Both commands expand the
token inside the container, so it is not printed; the first must report an
HTTP 401 and the second 200:

```text
docker compose --env-file .env.compose exec influxdb3 sh -c \
  'curl -s -o /dev/null -w "%{http_code}\n" -G http://localhost:8181/api/v3/query_sql --data-urlencode "db=netcap" --data-urlencode "q=SELECT 1"'
docker compose --env-file .env.compose exec influxdb3 sh -c \
  'curl -s -o /dev/null -w "%{http_code}\n" -G -H "Authorization: Bearer $INFLUX_TOKEN" http://localhost:8181/api/v3/query_sql --data-urlencode "db=netcap" --data-urlencode "q=SELECT 1"'
```

Do not start the server with `--without-auth`. These steps are instructions;
they have not been recorded here as a passing fresh-install run.

## Database And Startup Order

Start PostgreSQL and wait for its Compose health check:

```text
docker compose --env-file .env.compose --profile core-db up -d postgres
```

Before starting the scanner API, passive seeder, or CVE lookup consumer, apply
the scanner's existing Alembic chain against the service-injected PostgreSQL
DSN. This is a controlled, scanner-only migration; it is not an automatic DDL
runner. The command requires a built scanner image and a reachable database:

```text
docker compose --env-file .env.compose --profile all run --rm --no-deps \
  --entrypoint python otalon-scan -m alembic \
  -c /app/alembic.ini upgrade head
```

Only after the migration succeeds and the InfluxDB `netcap` database is
confirmed, build the remaining images if needed and start the stack:

```text
docker compose --env-file .env.compose --profile all up -d
```

The API creates its product identity tables and, only when the user table is
empty, seeds `admin` with the fixed first-login password `OTALON-Setup!` and
enforces an immediate password change. Reach the UI through HTTPS on port 8443,
log in once, and change that password before normal use. Do not expose this
bootstrap credential on an untrusted network.

## Post-Start Checks

Before operational use, confirm all required services are healthy; verify API,
scanner, MCP, and UI health endpoints from their intended network boundary;
confirm the browser uses the TLS proxy and that the certificate is trusted or
explicitly managed; and confirm PostgreSQL, InfluxDB, logs, models, PCAP, and
operations data persist across container recreation. Check that telemetry flows
from the selected capture interface into InfluxDB and then into detection only
after a safe, authorized observation period. Do not use an active scan as a
smoke test.

Bounds and frequency profiles are learned from observed telemetry; the
operator-facing runtime training endpoints can request a selected UTC time
window after data has accumulated. Classifier artifacts are stored under
`shared/models`; runtime classifier retraining only accepts modules that
already have a deployed classifier artifact. A first-classifier bootstrap
workflow is not established by this guide and must be resolved before claiming
initial ML classification. Existing classifier training also needs appropriate
real telemetry, labels, and any configured MITRE reference data. Never treat
fabricated measurements or an empty database as trained coverage.

## Development

Make and review changes in the source checkout, use the owning module's
documented test configuration, and build images from source before deployment.
The public MCP references are in [otalon-mcp/docs/](otalon-mcp/docs/).
A successful build is not a trained-detection or production-readiness claim;
complete the post-start checks against the actual deployment.
