FROM node:22-alpine AS base
RUN corepack enable && corepack prepare pnpm@10 --activate

FROM base AS deps
WORKDIR /app
COPY package.json pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile

FROM base AS builder
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .
ARG NEXT_PUBLIC_FUSION_BASE_URL=http://localhost:8000
ENV NEXT_PUBLIC_FUSION_BASE_URL=$NEXT_PUBLIC_FUSION_BASE_URL
# Contracts (src/lib/schemas/*.ts) are committed and kept in sync with
# fusion/schemas-json by CI (`make contracts-check`). Do NOT regenerate them
# here: the generator reads ../fusion/schemas-json, which is outside the portal
# build context (compose `context: ./portal`), so it would ENOENT and break
# `docker compose build`.
RUN pnpm build

FROM base AS runner
WORKDIR /app
ENV NODE_ENV=production
RUN addgroup --system --gid 1001 nodejs && adduser --system --uid 1001 nextjs
COPY --from=builder /app/public ./public
COPY --from=builder --chown=nextjs:nodejs /app/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/.next/static ./.next/static
USER nextjs
EXPOSE 3000
ENV PORT=3000
ENV HOSTNAME=0.0.0.0
CMD ["node", "server.js"]
