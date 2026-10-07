# syntax=docker/dockerfile:1
FROM node:24-alpine AS builder

WORKDIR /app

# Install dependencies first so the layer cache survives source edits.
COPY package.json package-lock.json ./
RUN npm ci

COPY tsconfig*.json ./
COPY src ./src
RUN npm run build

FROM node:24-alpine AS runtime

ENV NODE_ENV=production

ENV SQLITE_PATH=/data/nvd.sqlite
ENV CACHE_DIRECTORY=/data/cache

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force

COPY --from=builder /app/dist ./dist
COPY migrations ./migrations
COPY .env.example ./.env.example

# Non-root user; it owns /data so SQLite and the file cache can be written.
RUN addgroup -S nvd && adduser -S -G nvd nvd \
    && mkdir -p /data \
    && chown -R nvd:nvd /data /app

USER nvd

# Run with -i, not -t: stdout is reserved for MCP JSON-RPC frames.
CMD ["node", "dist/main.js"]
