FROM nginx:1.27-alpine@sha256:65645c7bb6a0661892a8b03b89d0743208a18dd2f3f17a54ef4b76fb8e2f2a10

RUN apk add --no-cache openssl

COPY nginx.conf /etc/nginx/nginx.conf
COPY generate-cert.sh /usr/local/bin/generate-cert.sh
RUN chmod 0755 /usr/local/bin/generate-cert.sh

ENTRYPOINT ["/bin/sh", "-c", "/usr/local/bin/generate-cert.sh && exec nginx -g 'daemon off;' -c /etc/nginx/nginx.conf"]

# Readiness probe (SUITE-052). The proxy terminates TLS on 8443/8493/9493 and
# deliberately starts without otalon-ui/otalon-api resolvable, so the probe
# must neither speak TLS nor touch an upstream. docker-compose.yml is not the
# place for it either: nginx binds a loopback-only `/healthz` server (see
# `nginx.conf`), which a request against 127.0.0.1:8099 reaches through the
# real worker processes. That proves nginx is accepting requests — `nginx -t`
# would only re-parse the config in a fresh process. Alpine's busybox ships
# `wget`; the image has no curl.
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD wget -q -O /dev/null http://127.0.0.1:8099/healthz || exit 1
