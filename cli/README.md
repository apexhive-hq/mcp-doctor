# `apexhive-mcp-doctor` CLI (`mcp-doctor`)

> 100% Free MIT static linter for Model Context Protocol (MCP) tool catalogs: prompt-injection pattern checks, secret-leak scanning, schema linting, context-tax measurement, CI policy gates, and SARIF 2.1.0 output (`Node.js >= 20`).

---

## Quickstart (`Node.js >= 20.0.0`)

### Instant Run via npm (`npx`)

```bash
npx -y apexhive-mcp-doctor --version
npx -y apexhive-mcp-doctor status
npx -y apexhive-mcp-doctor audit --tools-file ./tools.json
npx -y apexhive-mcp-doctor audit --config ./mcp-servers.json
```

### Build from Source

```bash
git clone https://github.com/apexhive-hq/mcp-doctor.git
cd mcp-doctor/cli
pnpm install --ignore-scripts
pnpm run build

# Audit a static tools/list JSON fixture
node dist/src/cli.js audit --tools-file mcp-tools.example.json

# Audit live stdio MCP servers from config & emit JSON
node dist/src/cli.js audit --config mcp-doctor.config.example.json --json

# Enforce CI threshold & emit SARIF 2.1.0 (all free MIT)
node dist/src/cli.js audit --tools-file mcp-tools.example.json --policy mcp-doctor.policy.example.json --sarif
node dist/src/cli.js audit --tools-file mcp-tools.example.json --ci --min-score 80
```

---

License: MIT · Support: `apexhive.hq@proton.me`.
