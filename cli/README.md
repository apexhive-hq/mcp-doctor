# `apexhive-mcp-doctor` CLI (`mcp-doctor`)

> Audit Model Context Protocol (MCP) tool catalogs for prompt-injection poisoning, secret leaks, schema defects, and context-window bloat (`Node.js >= 24`, MIT Open Source).

---

## Quickstart (`Node.js >= 24.0.0`)

### Instant Run via npm (`npx`)

```bash
npx -y apexhive-mcp-doctor status
npx -y apexhive-mcp-doctor audit --tools-file mcp-tools.example.json
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

# Enforce CI threshold (exits non-zero if score < min-score)
node dist/src/cli.js audit --tools-file mcp-tools.example.json --ci --min-score 80
```

## Policy & License Activation

Optional policy guardrails (`mcp-doctor.policy.json`), SARIF 2.1.0 export (`--sarif`), and offline Ed25519 licenses (`MCPDOC-PRO-v1...`) are supported locally without cloud telemetry:

```bash
node dist/src/cli.js activate --token "MCPDOC-PRO-v1.<payload>.<signature>"
node dist/src/cli.js audit --tools-file mcp-tools.example.json --sarif
```

## License & Support

- Source Code: MIT License
- Storefront & Live Web Auditor: https://mcp-doctor-store.apexhive-hq.workers.dev
- Support: `apexhive.hq@proton.me`
