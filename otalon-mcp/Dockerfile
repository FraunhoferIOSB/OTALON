# syntax=docker/dockerfile:1
FROM python:3.13-slim@sha256:7ce4b6dfe35e55397b7cda544f8a13f191b7ae28dc5aad71fe664dbc9bc2623f

# PYTHONPATH points at the package root: SUITE-032 moved the sources into
# ``src/otalon_mcp/``, so ``/app/src`` (not ``/app``) is the sys.path entry
# that makes ``python -m otalon_mcp.server`` resolve.
ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONPATH=/app/src

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
 && rm -rf /var/lib/apt/lists/*

COPY otalon-common/ /app/otalon-common/
COPY otalon-mcp/requirements.txt /app/otalon-mcp/requirements.txt
RUN pip install --upgrade pip && \
    pip install --no-cache-dir -r /app/otalon-mcp/requirements.txt

COPY otalon-mcp/src/ /app/src/
COPY otalon-mcp/config/ /app/config/
COPY otalon-mcp/data/ /app/data/
COPY otalon-mcp/scripts/ /app/scripts/

RUN mkdir -p /app/logs

# Run unprivileged (SUITE-042 wave 1). UID/GID 10002 per the design's
# per-service allocation, so host-side ownership stays attributable.
# All five wave-1/2 services share ONE ./shared/logs bind-mount, so no
# single owner UID can satisfy them all. Each user therefore also joins
# the shared group 10000 (otalon-shared); the host migration sets
# shared/logs to root:10000 with g+ws. Per-service UIDs are kept so
# ownership of anything a service writes elsewhere stays attributable.
RUN groupadd -g 10002 otalon \
 && groupadd -g 10000 otalon-shared \
 && useradd -u 10002 -g otalon -G otalon-shared -m otalon \
 && chown -R otalon:otalon /app

USER otalon

EXPOSE 9000

# No compose-level healthcheck exists for this service (SUITE-041 / HC5).
# curl is already installed above. /health needs no credential, so the probe
# works as the non-root runtime user.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS http://localhost:9000/health || exit 1

CMD ["python","-u","-m","otalon_mcp.server"]
