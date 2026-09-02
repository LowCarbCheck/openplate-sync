# openplate-sync — self-hostable account + E2EE blob-sync service.
#
# Builds from tracked source and public npm only. There is no build secret,
# no private `.npmrc` and no `@sprqvntrs/*` dependency anywhere in the tree —
# that is a release invariant of this repo, not an accident of the current
# dependency list, and it is what makes this image reproducible by anyone.
#
# The runtime layer carries the esbuild bundle plus exactly three real
# dependencies (`express`, `pg`, `dotenv` — see `scripts/build.ts` for why
# those are external), and the committed migrations, which the service applies
# itself at boot. A self-hoster pulling a newer tag never runs a second
# command.

FROM node:22-alpine AS base
RUN npm i -g pnpm@11
WORKDIR /app

FROM base AS deps
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
RUN pnpm install --frozen-lockfile

FROM base AS prod-deps
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
RUN pnpm install --prod --frozen-lockfile

FROM base AS build
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml tsconfig.json ./
COPY --from=deps /app/node_modules ./node_modules
COPY src ./src
COPY scripts ./scripts
RUN pnpm build

FROM node:22-alpine AS runtime
ENV NODE_ENV=production
WORKDIR /app

COPY package.json ./
COPY --from=prod-deps /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
# Data, not code: read by the migrator at boot (`src/main.ts`).
COPY drizzle ./drizzle

# Never run as root. `node` exists in the base image with uid 1000.
USER node

EXPOSE 3000

# `/health` is unauthenticated by design (PROTOCOL.md §5.6) precisely so a
# healthcheck can use it without holding a credential.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||3000)+'/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

CMD ["node", "dist/server.js"]
