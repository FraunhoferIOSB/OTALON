# syntax=docker/dockerfile:1
FROM python:3.13-slim@sha256:7ce4b6dfe35e55397b7cda544f8a13f191b7ae28dc5aad71fe664dbc9bc2623f

# PYTHONPATH points at the package root: SUITE-032 moved the sources into
# ``src/otalon_scan/``, so ``/app/src`` (not ``/app``) is the sys.path entry
# that makes ``otalon_scan.*`` resolve — for the API CMD below and for the
# two ``python -m otalon_scan.<mod>`` sidecar commands in docker-compose.yml.
ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONPATH=/app/src

WORKDIR /app

# System packages required by scanner modules (e.g., nmap) and for sniffing support
# - libpcap0.8: packet capture library used by sniffing backends
# - iproute2: optional helpers for network inspection
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    curl \
    libpcap0.8 \
    iproute2 \
    libcap2-bin \
    && rm -rf /var/lib/apt/lists/*

# Shared suite library (runtime-configuration registry + key manifest).
# Installed BEFORE requirements.txt so the exact pin listed there resolves
# against this local distribution instead of an index lookup — otalon-common
# is not published. Same pattern as otalon-clas/Dockerfile. The build context
# is the repository root for every consumer of this Dockerfile
# (docker-compose.yml: otalon-scan, otalon-scan-passive-seeder,
# otalon-scan-cve-lookup), so this path resolves for all three.
COPY otalon-common/ /app/otalon-common/
RUN python -m pip install --upgrade pip \
    && pip install --no-cache-dir /app/otalon-common/

# Python dependencies
COPY otalon-scan/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

# Application code
COPY otalon-scan/src/ /app/src/
COPY otalon-scan/config/ /app/config/
# Ship the existing migration environment and complete Alembic chain so the
# scanner schema can be upgraded explicitly before scanner consumers start.
COPY otalon-scan/alembic.ini /app/alembic.ini
COPY otalon-scan/alembic/ /app/alembic/

# Logs dir
RUN mkdir -p /app/logs

# Run unprivileged (SUITE-042 wave 3). UID/GID 10007 per the design's
# per-service allocation; group 10000 (otalon-shared) grants access to the
# shared ./shared/logs bind-mount, which every suite service writes to.
RUN groupadd -g 10007 otalon \
 && groupadd -g 10000 otalon-shared \
 && useradd -u 10007 -g otalon -G otalon-shared -m otalon \
 && chown -R otalon:otalon /app

# Raw sockets from a NON-ROOT uid need a file capability on the interpreter.
#
# The design assumed compose `cap_add` alone would suffice ("docker applies
# the cap set to the container's process regardless of UID"). Measured: it
# does not. With `--user`, the kernel clears the permitted/effective sets on
# the UID transition and NET_RAW survives only in the BOUNDING set:
#     CapPrm 0000000000000000  CapEff 0000000000000000
#     CapBnd 00000000a80425fb
# so socket(AF_PACKET, SOCK_RAW) fails with EPERM.
#
# The capability is put on a SEPARATE COPY of the interpreter, not on the
# default one. A file-capability binary cannot exec at all when the container
# lacks the matching cap_add ("operation not permitted"), and this image is
# shared by three compose services — otalon-scan (cap_add NET_RAW/NET_ADMIN),
# otalon-scan-passive-seeder and otalon-scan-cve-lookup (NO cap_add). Setting
# the capability on the default python would therefore have broken the two
# capability-less services outright. Verified both paths.
#
# This is not a privilege escalation: a file capability can only raise what
# the bounding set already permits, so python3-cap simply refuses to exec
# where cap_add is absent.
#
# The note below about avoiding file capabilities predates this change and
# refers to setcap on arbitrary binaries; exec of the copy was verified on
# this host's storage driver. If a future host refuses it, fall back to
# `USER root` for this image and record it — a broken scanner is worse than
# a root scanner.
RUN cp "$(readlink -f "$(command -v python3)")" /usr/local/bin/python3-cap \
 && setcap cap_net_raw,cap_net_admin+eip /usr/local/bin/python3-cap

# Expose API port (FastAPI via uvicorn)
EXPOSE 8091

# Docker HEALTHCHECK: F-02 / scan--observability points the liveness
# probe at the *plain* /health endpoint. That handler performs no I/O
# and returns 200 in well under 10 ms — safe to run every interval
# without contending with active scans. The deep dependency probe
# (Postgres availability, module count, active scans) is exposed at
# /health?deep=true and intentionally NOT wired into the Docker
# healthcheck so a transient Postgres outage does not flip the
# container into "unhealthy" state and trigger a restart while the
# orchestrator could otherwise recover on its own.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -fsS http://localhost:8091/health || exit 1

# Runtime notes for pn_discovery (raw sockets):
# - Preferred at runtime: add capabilities to the container (compose/CLI):
#     cap_add:
#       - NET_RAW
#       - NET_ADMIN
#   or:
#     --cap-add=NET_RAW --cap-add=NET_ADMIN
# - Avoid setting file capabilities on binaries in the image, which can trigger
#   "operation not permitted" on exec under certain storage drivers / policies.

USER otalon

# Start API via python -m to avoid exec of console-script shim
# python3-cap (not plain python) so the API process — which opens
# AF_PACKET/SOCK_RAW for pn_discovery and arp_scan — carries NET_RAW/
# NET_ADMIN as a non-root uid. Only this service is started via the image
# default CMD; otalon-scan-passive-seeder and otalon-scan-cve-lookup
# override `command:` with plain `python` in docker-compose.yml and have no
# cap_add, so they are unaffected by the capability-bearing copy.
CMD ["python3-cap","-m","uvicorn","otalon_scan.api.server:app","--host","0.0.0.0","--port","8091","--forwarded-allow-ips","*"]
