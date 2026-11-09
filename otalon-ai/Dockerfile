FROM python:3.13-slim@sha256:7ce4b6dfe35e55397b7cda544f8a13f191b7ae28dc5aad71fe664dbc9bc2623f

# PYTHONPATH points at the package root: SUITE-032 moved the sources into
# ``src/otalon_ai/``, so ``/app/src`` (not ``/app``) is the sys.path entry
# that makes ``uvicorn otalon_ai.main:app`` resolve.
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONPATH=/app/src

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc libpq-dev curl \
    && rm -rf /var/lib/apt/lists/*

COPY otalon-common/ /app/otalon-common/
RUN pip install --no-cache-dir /app/otalon-common/

COPY otalon-ai/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY otalon-ai/src /app/src
COPY otalon-ai/config /app/config
COPY otalon-ai/migrations /app/migrations

RUN mkdir -p /app/logs /app/prompts

# Run unprivileged (SUITE-042 wave 1). UID/GID 10005 per the design's
# per-service allocation, so host-side ownership stays attributable.
# All five wave-1/2 services share ONE ./shared/logs bind-mount, so no
# single owner UID can satisfy them all. Each user therefore also joins
# the shared group 10000 (otalon-shared); the host migration sets
# shared/logs to root:10000 with g+ws. Per-service UIDs are kept so
# ownership of anything a service writes elsewhere stays attributable.
RUN groupadd -g 10005 otalon \
 && groupadd -g 10000 otalon-shared \
 && useradd -u 10005 -g otalon -G otalon-shared -m otalon \
 && chown -R otalon:otalon /app

USER otalon

EXPOSE 9100

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD curl -fs http://localhost:9100/health || exit 1

CMD ["uvicorn", "otalon_ai.main:app", "--host", "0.0.0.0", "--port", "9100"]
