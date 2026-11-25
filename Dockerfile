FROM node:24-slim

WORKDIR /app

RUN corepack enable

COPY cli/package.json cli/pnpm-lock.yaml cli/tsconfig.json cli/mcp-doctor.config.example.json cli/mcp-tools.example.json ./
COPY cli/src ./src
COPY cli/tests ./tests

RUN pnpm install --frozen-lockfile --ignore-scripts && pnpm run build

RUN chown -R node:node /app
USER node

ENTRYPOINT ["node", "dist/src/cli.js"]
CMD ["audit", "--config", "mcp-doctor.config.example.json"]
