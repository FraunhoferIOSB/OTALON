# syntax=docker/dockerfile:1
FROM python:3.13@sha256:debad600e8d6e754012528dc796488acc52438fea3d28596b87262df9b91c71e AS builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    git \
    libpcap-dev \
    python3-dev \
    libpcre2-dev \
    pkg-config \
    wget \
    ca-certificates \
    tar \
 && rm -rf /var/lib/apt/lists/*

RUN pip install --upgrade pip

COPY netcap++ /src/netcap++
WORKDIR /src/netcap++

RUN pip wheel --no-deps --verbose --wheel-dir /wheels .

FROM python:3.13-slim@sha256:326df678c20c78d465db501563f3492d17c42a4afe33a1f2bf5406a1d56b0e86 AS runtime
ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    DEBIAN_FRONTEND=noninteractive \
    LD_LIBRARY_PATH=/usr/local/lib:${LD_LIBRARY_PATH}

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev \
    ethtool \
    ca-certificates \
    curl \
    tcpdump \
    tshark \
    libcap2-bin \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY otalon-capture/requirements.txt /tmp/requirements.txt
COPY --from=builder /wheels /tmp/wheels

# SUITE-043: installed BEFORE requirements.txt so the `otalon-common==0.1.0`
# pin listed there resolves against this local distribution instead of an
# index lookup — the package is not published. Same pattern as otalon-scan.
COPY otalon-common/ /app/otalon-common/

RUN pip install --upgrade pip && \
    pip install --no-cache-dir /app/otalon-common/ && \
    pip install --no-cache-dir -r /tmp/requirements.txt && \
    pip install --no-cache-dir /tmp/wheels/*.whl && \
    python - <<'PY'
import pathlib
import shutil
import site

lib_name = "libnetwork-capture_lib.so"
lib_target = pathlib.Path("/usr/local/lib") / lib_name
lib_target.parent.mkdir(parents=True, exist_ok=True)
found = False
for pkg_dir in site.getsitepackages():
    candidate = pathlib.Path(pkg_dir) / "lib" / lib_name
    if candidate.exists():
        shutil.copy2(candidate, lib_target)
        found = True
        break
if not found:
    raise SystemExit(f"{lib_name} not found in site-packages")
PY
RUN ldconfig && rm -rf /tmp/requirements.txt /tmp/wheels

# Run unprivileged (SUITE-042 wave 3). UID/GID 10006 per the design's
# per-service allocation; group 10000 (otalon-shared) grants access to the
# shared ./shared/logs bind-mount that every suite service writes to.
#
# NOTE: pcapuser previously had UID 1000. It is referenced by name from
# pcap_recorder/api.py (TSHARK_USER, the tshark privilege drop), so the name
# is kept and only the numeric id changes.
RUN groupadd -g 10006 pcapuser \
 && groupadd -g 10000 otalon-shared \
 && useradd --system --uid 10006 --gid 10006 --groups otalon-shared \
            --create-home --shell /usr/sbin/nologin pcapuser

# NET-006: copy the source tree WHOLESALE, never module by module.
#
# The previous per-module COPY block listed every package and loose module
# under src/ by name. A new top-level module then never reached the image and
# nothing turned red: host-side pytest puts src/ on sys.path via
# `pythonpath = ["src"]` and stayed green. That is exactly how
# src/capture_settings_base.py (SUITE-038 79ca8dd, extended in PCAP-007
# 9d62bbf) slipped through — BOTH containers built from this image crash-looped
# on the first full rebuild with ModuleNotFoundError.
#
# Non-runtime content is kept out by the build context, not by this line:
# __pycache__/, *.py[cod], .mypy_cache/, .pytest_cache/ and tests/ are excluded
# in the REPOSITORY-ROOT .dockerignore. That is the file that matters here —
# compose builds this image with `context: .`, and Docker only honours a
# .dockerignore at the context root, so otalon-capture/.dockerignore is inert
# for this build.
COPY otalon-capture/src/ /app/src/
COPY otalon-capture/config/ /app/config/
COPY otalon-capture/entrypoint.py /app/entrypoint.py
RUN chmod +x /app/entrypoint.py

ENV PYTHONPATH=/app/src:${PYTHONPATH}
RUN mkdir -p logs /app/pcap/buffer /app/pcap/archive \
 && chown -R pcapuser:pcapuser /app

# Live capture from a NON-ROOT uid needs a file capability on tcpdump, which
# pcap_recorder runs as a subprocess to write the ringbuffer chunks.
#
# The design assumed compose `cap_add` alone would suffice regardless of UID.
# Measured: it does not. On the UID transition the kernel clears the
# permitted/effective capability sets and NET_RAW survives only in the
# BOUNDING set, so tcpdump fails with "You don't have permission to perform
# this capture on that device (socket: Operation not permitted)".
#
# TWO binaries need it, for two different capture paths:
#   * tcpdump — pcap_recorder spawns it to write the ringbuffer chunks.
#   * python3-cap — a SEPARATE COPY of the interpreter, because live capture
#     also runs through the netcap++ C extension (NetworkCapture), which
#     opens its own raw socket in-process. Without it the container dies with
#     "RuntimeError: Could not open live reader".
#
# The capability is deliberately NOT put on the default python. This image
# also runs the pcap_import worker (otalon-capture-pcap-import), which has NO
# cap_add; a capability-bearing binary refuses to exec outright when the
# matching cap_add is absent, so that service would break. It keeps using
# plain `python` via ENTRYPOINT. Verified: tcpdump and python3-cap both work
# as uid 10006 with cap_add, both refuse without it, and the import worker's
# plain python still execs normally.
RUN setcap cap_net_raw,cap_net_admin+eip "$(readlink -f "$(command -v tcpdump)")" \
 && cp "$(readlink -f "$(command -v python3)")" /usr/local/bin/python3-cap \
 && setcap cap_net_raw,cap_net_admin+eip /usr/local/bin/python3-cap

# 9090 pcap_recorder REST API, 9092 pcap_import worker (separate container,
# selected via NETCAP_ENTRYPOINT_MODULES — see entrypoint.py).
EXPOSE 9090 9092

# NET-006 / NET-007: the image declares its own import-smoke contract.
#
# Every module named here must be importable inside the BUILT image — that is
# the check host-side pytest cannot make. All three are entrypoint modules of
# this one image: otalon_capture.main + pcap_recorder.main are the live
# adapter's default set (entrypoint.py DEFAULT_MODULES), pcap_import.main is
# what otalon-capture-pcap-import selects via NETCAP_ENTRYPOINT_MODULES.
#
# NET-007 reads this label to drive a suite-wide smoke without hard-coding a
# per-service module list:
#
#   mods=$(docker inspect -f '{{index .Config.Labels "otalon.smoke.modules"}}' <img>)
#   docker run --rm --entrypoint python <img> -c "import ${mods}"
#
# --entrypoint python is REQUIRED for this image: the default entrypoint is
# python3-cap, a setcap copy of the interpreter that refuses to exec without
# the matching cap_add ("operation not permitted"), which would make the smoke
# fail for a reason that has nothing to do with module drift.
LABEL otalon.smoke.modules="otalon_capture.main, pcap_recorder.main, pcap_import.main"

# No compose-level healthcheck exists for otalon-capture (SUITE-041 / HC5).
# pcap_recorder serves an unauthenticated /health on 9090 and curl is
# installed above, so this works as the non-root runtime user (uid 10006).
#
# Scoped to the recorder deliberately: the same image also runs the
# pcap_import worker (otalon-capture-pcap-import), which listens on 9092 and
# already has its own compose-level healthcheck — that one wins for that
# service, so no probe is duplicated.
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD curl -fsS http://localhost:9090/health || exit 1

USER pcapuser

# python3-cap: the live-capture service needs NET_RAW in-process (netcap++).
# otalon-capture-pcap-import overrides this in docker-compose.yml with plain
# `python`, since it has no cap_add and needs no raw access.
ENTRYPOINT ["python3-cap","-u","/app/entrypoint.py"]
CMD []
