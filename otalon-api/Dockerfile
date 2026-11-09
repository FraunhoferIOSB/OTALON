FROM python:3.13-slim@sha256:7ce4b6dfe35e55397b7cda544f8a13f191b7ae28dc5aad71fe664dbc9bc2623f

# PYTHONPATH points at the package root: SUITE-032 moved the sources into
# ``src/otalon_api/``, so ``/app/src`` (not ``/app``) is the sys.path entry
# that makes ``uvicorn otalon_api.main:app`` resolve.
ENV PYTHONPATH=/app/src

WORKDIR /app

COPY otalon-common/ /app/otalon-common/
RUN pip install --no-cache-dir /app/otalon-common/

COPY otalon-api/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY otalon-api/src/ /app/src/
COPY otalon-api/config/ /app/config/

RUN mkdir -p /app/logs

# Run unprivileged (SUITE-042 wave 1). UID/GID 10001 per the design's
# per-service allocation, so host-side ownership stays attributable.
# All five wave-1/2 services share ONE ./shared/logs bind-mount, so no
# single owner UID can satisfy them all. Each user therefore also joins
# the shared group 10000 (otalon-shared); the host migration sets
# shared/logs to root:10000 with g+ws. Per-service UIDs are kept so
# ownership of anything a service writes elsewhere stays attributable.
# otalon-api manages containers through the mounted /var/run/docker.sock,
# which is root:docker 0660 on the host. The socket's GID is host-specific,
# so it is injected at build time (DOCKER_GID, default 989) rather than
# hard-coded; a wrong value only costs the Docker probe, not startup.
ARG DOCKER_GID=989
RUN groupadd -g 10001 otalon \
 && groupadd -g 10000 otalon-shared \
 && (getent group "$DOCKER_GID" || groupadd -g "$DOCKER_GID" docker-host) \
 && useradd -u 10001 -g otalon -G otalon-shared,"$(getent group "$DOCKER_GID" | cut -d: -f1)" -m otalon \
 && chown -R otalon:otalon /app

USER otalon

EXPOSE 8090

# No compose-level healthcheck exists for this service (SUITE-041 / HC5).
# The image has neither curl nor wget, so the probe uses the interpreter that
# is already present. /health is the unversioned, unauthenticated liveness
# endpoint (SUITE-037) — it needs no credential, so this works as the
# non-root runtime user.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python3 -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://localhost:8090/health', timeout=4).status == 200 else 1)" || exit 1

CMD ["uvicorn", "otalon_api.main:app", "--host", "0.0.0.0", "--port", "8090"]
