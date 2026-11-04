# Build from the repository root: docker build -f apps/server/Dockerfile .
# Base images are pinned by digest so a rebuild uses exactly the same bytes; Dependabot proposes updates.
FROM node:22-alpine@sha256:fe4f6d74e20370acb04ad889077d14d0f64a9c8ea6a42bc60cddf1e844699914 AS build
WORKDIR /app
ENV ELECTRON_SKIP_BINARY_DOWNLOAD=1
COPY package.json package-lock.json tsconfig.base.json ./
COPY packages/protocol/package.json packages/protocol/
COPY packages/signal/package.json packages/signal/
COPY apps/server/package.json apps/server/
COPY apps/desktop/package.json apps/desktop/
# --ignore-scripts: no dependency gets to run code while installing.
RUN npm ci --ignore-scripts --workspace @silo/protocol --workspace @silo/server --include-workspace-root
COPY packages/protocol packages/protocol
COPY apps/server apps/server
RUN npm run build -w @silo/protocol && npm run build -w @silo/server

FROM node:22-alpine@sha256:fe4f6d74e20370acb04ad889077d14d0f64a9c8ea6a42bc60cddf1e844699914
WORKDIR /app
ENV NODE_ENV=production
COPY package.json package-lock.json ./
COPY packages/protocol/package.json packages/protocol/
COPY packages/signal/package.json packages/signal/
COPY apps/server/package.json apps/server/
COPY apps/desktop/package.json apps/desktop/
RUN npm ci --ignore-scripts --omit=dev --workspace @silo/protocol --workspace @silo/server && npm cache clean --force
COPY --from=build /app/packages/protocol/dist packages/protocol/dist
COPY --from=build /app/apps/server/dist apps/server/dist
COPY apps/server/migrations apps/server/migrations
# The server identity key lives here, readable only by the server.
RUN mkdir -p /keys && chown node:node /keys && chmod 700 /keys
USER node
EXPOSE 8443
CMD ["node", "apps/server/dist/main.js"]
