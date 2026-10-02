# syntax=docker/dockerfile:1
#
# Multi-stage build for the NVD/NIST MCP server.
#
# Base image: node:24-alpine. Node 24 is the current LTS line and satisfies the
# project's Node >= 22.5 requirement (the server uses the built-in node:sqlite
# module). If your registry or CI does not offer node:24-alpine yet, switch both
# stages to node:22-alpine.

# ---------------------------------------------------------------------------
# Builder — installs dev dependencies and compiles TypeScript to dist/.
# ---------------------------------------------------------------------------
FROM node:24-alpine AS builder

WORKDIR /app

# Install dependencies first so the layer cache survives source edits.
COPY package.json package-lock.json ./
RUN npm ci

# tsconfig*.json matches tsconfig.json and tsconfig.build.json.
COPY tsconfig*.json ./
COPY src ./src
RUN npm run build

# ---------------------------------------------------------------------------
# Runtime — production dependencies, compiled output and migrations only.
# ---------------------------------------------------------------------------
FROM node:24-alpine AS runtime

ENV NODE_ENV=production

# Keep the SQLite database and the JSON disk cache on a writable location.
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

# This is a stdio MCP server: it speaks JSON-RPC over stdin/stdout and is meant
# to be started by an MCP client, for example:
#
#   docker run -i --rm -e NVD_API_KEY=... -v nvd-data:/data nist-nvd-mcp-server
#
# Use -i (not -t) so stdin stays open. Logs are written to stderr; stdout must
# stay clean for JSON-RPC frames. No ports are exposed because there is no
# network listener.
#
# The server installs its own SIGINT/SIGTERM handlers and shuts down in a few
# milliseconds, so `docker stop` terminates cleanly without `--init`. The client
# closing the pipe (or dying) is detected as well and stops the process, which
# keeps a shared volume free of a stale SQLite lock.
CMD ["node", "dist/main.js"]
