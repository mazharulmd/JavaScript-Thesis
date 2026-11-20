# Benchmark API image. Build context: repository root (needs the workspace lockfile).
#   docker build -f test-api/Dockerfile -t bac-test-api .
# syntax=docker/dockerfile:1
FROM node:22-alpine

ENV NODE_ENV=production
WORKDIR /app

COPY package.json package-lock.json ./
COPY test-api/package.json test-api/package.json
# Optional: behind a TLS-intercepting proxy, pass its CA bundle as a build secret
#   docker build --secret id=ca,src=/path/ca.crt --build-arg HTTPS_PROXY=... --network host ...
# Without the secret (normal case, e.g. GitHub Actions) nothing changes.
ARG HTTPS_PROXY
RUN --mount=type=secret,id=ca,required=false \
    if [ -f /run/secrets/ca ]; then export npm_config_cafile=/run/secrets/ca; fi; \
    npm ci --omit=dev --workspace test-api --include-workspace-root=false && npm cache clean --force

COPY test-api/ test-api/

USER node
EXPOSE 3000
HEALTHCHECK --interval=5s --timeout=3s --start-period=5s --retries=10 \
  CMD wget -qO- http://127.0.0.1:3000/health || exit 1

CMD ["node", "test-api/src/server.js"]
