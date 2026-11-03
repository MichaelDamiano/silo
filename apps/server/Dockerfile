# Build from the repository root: docker build -f apps/server/Dockerfile .
FROM node:22-alpine AS build
WORKDIR /app
ENV ELECTRON_SKIP_BINARY_DOWNLOAD=1
COPY package.json package-lock.json tsconfig.base.json ./
COPY packages/protocol/package.json packages/protocol/
COPY apps/server/package.json apps/server/
COPY apps/desktop/package.json apps/desktop/
RUN npm ci --workspace @silo/protocol --workspace @silo/server --include-workspace-root
COPY packages/protocol packages/protocol
COPY apps/server apps/server
RUN npm run build -w @silo/protocol && npm run build -w @silo/server

FROM node:22-alpine
WORKDIR /app
ENV NODE_ENV=production
COPY package.json package-lock.json ./
COPY packages/protocol/package.json packages/protocol/
COPY apps/server/package.json apps/server/
COPY apps/desktop/package.json apps/desktop/
RUN npm ci --omit=dev --workspace @silo/protocol --workspace @silo/server && npm cache clean --force
COPY --from=build /app/packages/protocol/dist packages/protocol/dist
COPY --from=build /app/apps/server/dist apps/server/dist
COPY apps/server/migrations apps/server/migrations
USER node
EXPOSE 8443
CMD ["node", "apps/server/dist/main.js"]
