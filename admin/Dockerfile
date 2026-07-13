# Base image (G4). Pin to a patch-level tag for reproducibility; for full
# supply-chain integrity this SHOULD be pinned to a digest, e.g.
#   FROM node:22.13.1-alpine@sha256:<digest> AS base
# The digest is intentionally omitted here because it cannot be resolved in this
# offline build environment. Dependabot's `docker` ecosystem (see
# .github/dependabot.yml) tracks updates to this base image.
FROM node:26.3.1-alpine AS base
# Refresh corepack first: the version bundled in pinned Node images can fail
# pnpm signature verification ("Cannot find matching keyid") after pnpm key
# rotation; corepack@latest ships current keys.
RUN npm install -g corepack@latest && corepack enable && corepack prepare pnpm@10 --activate

FROM base AS deps
WORKDIR /app
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
RUN pnpm install --frozen-lockfile

FROM base AS builder
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .
# Contracts (src/lib/schemas/*.ts) are committed and kept in sync with
# form/schemas-json by CI (`make contracts-check`). Do NOT regenerate them
# here: the generator reads ../form/schemas-json, which is outside the admin
# build context (compose `context: ./admin`), so it would ENOENT and break
# `docker compose build`.
RUN pnpm build

FROM base AS runner
WORKDIR /app
ENV NODE_ENV=production
RUN addgroup --system --gid 1001 nodejs && adduser --system --uid 1001 nextjs
COPY --from=builder --chown=nextjs:nodejs /app/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/.next/static ./.next/static
USER nextjs
EXPOSE 10063
ENV PORT=10063
ENV HOSTNAME=0.0.0.0
# FORM_BASE_URL and FORM_API_TOKEN are server-only runtime configuration. Inject
# them when starting the container; they are deliberately not build arguments.
CMD ["node", "server.js"]
