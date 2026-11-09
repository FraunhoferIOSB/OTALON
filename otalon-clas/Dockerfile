FROM python:3.13-slim@sha256:7ce4b6dfe35e55397b7cda544f8a13f191b7ae28dc5aad71fe664dbc9bc2623f

WORKDIR /app

COPY otalon-common/ /app/otalon-common/
RUN pip install --no-cache-dir /app/otalon-common/

COPY otalon-clas/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY otalon-clas/ /app/otalon-clas/
RUN pip install --no-cache-dir /app/otalon-clas/

WORKDIR /app/otalon-clas

# Run unprivileged (SUITE-042 wave 1). UID/GID 10004 per the design's
# per-service allocation, so host-side ownership stays attributable.
# /app/logs and /app/models are bind-mounts at runtime; creating them here
# means the image has the right owner if the mount is ever absent.
# All five wave-1/2 services share ONE ./shared/logs bind-mount, so no
# single owner UID can satisfy them all. Each user therefore also joins
# the shared group 10000 (otalon-shared); the host migration sets
# shared/logs to root:10000 with g+ws. Per-service UIDs are kept so
# ownership of anything a service writes elsewhere stays attributable.
RUN mkdir -p /app/logs /app/models \
 && groupadd -g 10004 otalon \
 && groupadd -g 10000 otalon-shared \
 && useradd -u 10004 -g otalon -G otalon-shared -m otalon \
 && chown -R otalon:otalon /app

USER otalon

# otalon-clas is a long-running detection worker with no HTTP port, so the
# probe is a file-mtime liveness marker (SUITE-052): `run_live` touches
# /tmp/otalon-clas-last-tick after every completed tick. A tick that hangs —
# unreachable Postgres/InfluxDB, a wedged query — stops refreshing the marker
# and the container flips to (unhealthy) instead of looking idle. The live
# poll interval is 5 s, so 180 s tolerates a restart of the dependencies
# without a false alarm. The image has no curl/wget, hence the interpreter
# probe. start_period covers config load + first DB connection.
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
    CMD python -c "import os,sys,time; p='/tmp/otalon-clas-last-tick'; sys.exit(0 if os.path.exists(p) and time.time()-os.path.getmtime(p) < 180 else 1)"

CMD ["python", "-m", "otalon_clas.main"]
