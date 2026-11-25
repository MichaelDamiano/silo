# Build from the repository root: docker build -f apps/server/Dockerfile .
# Debian rather than Alpine: libsignal's prebuilt module needs glibc.
# Base images are pinned by digest so a rebuild uses exactly the same bytes; Dependabot proposes updates.
FROM node:25-bookworm-slim@sha256:81db02c4b671288a03915da9534dbd54f96d0e7c24d80ccc54f5b36b2e684370 AS build
WORKDIR /app
ENV ELECTRON_SKIP_BINARY_DOWNLOAD=1
COPY package.json package-lock.json tsconfig.base.json ./
COPY packages/protocol/package.json packages/protocol/
COPY packages/signal/package.json packages/signal/
COPY apps/server/package.json apps/server/
COPY apps/desktop/package.json apps/desktop/
# --ignore-scripts: no dependency gets to run code while installing.
RUN npm ci --ignore-scripts --workspace @silo/protocol --workspace @silo/signal --workspace @silo/server --include-workspace-root
COPY packages/protocol packages/protocol
COPY packages/signal packages/signal
COPY apps/server apps/server
RUN npm run build -w @silo/protocol && npm run build -w @silo/signal && npm run build -w @silo/server

FROM node:25-bookworm-slim@sha256:81db02c4b671288a03915da9534dbd54f96d0e7c24d80ccc54f5b36b2e684370
WORKDIR /app
ENV NODE_ENV=production
COPY package.json package-lock.json ./
COPY packages/protocol/package.json packages/protocol/
COPY packages/signal/package.json packages/signal/
COPY apps/server/package.json apps/server/
COPY apps/desktop/package.json apps/desktop/
RUN npm ci --ignore-scripts --omit=dev --workspace @silo/protocol --workspace @silo/signal --workspace @silo/server && npm cache clean --force
COPY --from=build /app/packages/protocol/dist packages/protocol/dist
COPY --from=build /app/packages/signal/dist packages/signal/dist
COPY --from=build /app/apps/server/dist apps/server/dist
COPY apps/server/migrations apps/server/migrations
# The server identity key lives here, readable only by the server.
RUN mkdir -p /keys && chown node:node /keys && chmod 700 /keys
USER node
EXPOSE 8443
CMD ["node", "apps/server/dist/main.js"]
