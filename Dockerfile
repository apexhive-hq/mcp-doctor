FROM node:22-slim AS builder

WORKDIR /build

RUN corepack enable

COPY cli/package.json cli/pnpm-lock.yaml cli/tsconfig.json ./
COPY cli/src ./src

RUN pnpm install --frozen-lockfile --ignore-scripts && pnpm run build

FROM node:22-slim

WORKDIR /app

RUN corepack enable

COPY cli/package.json cli/pnpm-lock.yaml cli/mcp-tools.example.json cli/mcp-doctor.policy.example.json ./
COPY --from=builder /build/dist ./dist

RUN pnpm install --prod --frozen-lockfile --ignore-scripts && chown -R node:node /app

USER node

ENTRYPOINT ["node", "dist/src/cli.js"]
CMD ["audit", "--tools-file", "mcp-tools.example.json"]
