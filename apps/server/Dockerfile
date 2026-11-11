# Build from the repository root: docker build -f apps/server/Dockerfile .
# Debian rather than Alpine: libsignal's prebuilt module needs glibc.
# Base images are pinned by digest so a rebuild uses exactly the same bytes; Dependabot proposes updates.
FROM node:26-bookworm-slim@sha256:add5c17c14752c54d2f3d519ec46a3815684d41c33f198bcb09fb998f7dcbf68 AS build
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

FROM node:26-bookworm-slim@sha256:add5c17c14752c54d2f3d519ec46a3815684d41c33f198bcb09fb998f7dcbf68
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
