FROM node:22-alpine@sha256:c610fcdfb1d5b4740dd70c284ed3cb16bb857e0f7166196e36a5501df7a3aa32 AS builder
WORKDIR /app
# npm 10's peer resolver crashes on the declared Nuxt/Vitest graph in a clean
# clone. Pin the verified resolver; do not bypass peer checks.
RUN npm install --global npm@11.6.2
COPY package*.json ./
# Local lockfiles and dependencies are excluded from this build context.
RUN npm install
COPY . .
ENV NUXT_API_PROXY_TARGET=http://otalon-api:8090
ENV MCP_SERVER_URL=http://otalon-mcp:9000
RUN npm run build

FROM node:22-alpine@sha256:c610fcdfb1d5b4740dd70c284ed3cb16bb857e0f7166196e36a5501df7a3aa32
WORKDIR /app
COPY --from=builder /app/.output .output
RUN mkdir -p /app/logs

# Run unprivileged (SUITE-042 wave 2). UID/GID 10003 per the design's
# per-service allocation. Alpine's busybox adduser/addgroup differ from
# the Debian tools used by the Python images. Node listens on 8080, which
# is unprivileged, so no capability is required.
# All five wave-1/2 services share ONE ./shared/logs bind-mount, so no
# single owner UID can satisfy them all. Each user therefore also joins
# the shared group 10000 (otalon-shared); the host migration sets
# shared/logs to root:10000 with g+ws. Per-service UIDs are kept so
# ownership of anything a service writes elsewhere stays attributable.
RUN addgroup -g 10003 -S otalon \
 && addgroup -g 10000 -S otalon-shared \
 && adduser -u 10003 -S otalon -G otalon \
 && addgroup otalon otalon-shared \
 && chown -R otalon:otalon /app

USER otalon

ENV HOST=0.0.0.0
ENV PORT=8080
ENV NODE_ENV=production
ENV MCP_SERVER_URL=http://otalon-mcp:9000
ENV LOG_FILE=/app/logs/ui-next.log
ENV LOG_LEVEL=info
EXPOSE 8080

# No compose-level healthcheck exists for this service (SUITE-041 / HC5).
# The alpine runtime image ships busybox wget (no curl). Serving the SPA
# root is the liveness signal; it requires no credential, so the probe works
# as the non-root runtime user.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD wget -q -O /dev/null http://127.0.0.1:8080/ || exit 1
CMD ["node", ".output/server/index.mjs"]
