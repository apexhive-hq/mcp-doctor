# `mcp-doctor` — Static MCP Security & Context-Tax Linter

> **100% Free & Open Source (MIT)** CLI linter for Model Context Protocol (`MCP`) `tools/list` catalogs: detects regex-based prompt-injection patterns, leaked credentials, missing descriptions, weak JSON schemas, and prompt context-window bloat (`Node.js >= 24`), with built-in `--policy`, `--ci`, and **SARIF 2.1.0** output.

---

## Architecture Overview

```text
+-------------------------------------------------------------------+
|  mcp-doctor CLI (Node >= 24, 100% Free MIT)                       |
|  1. Static Rules           -> Prompt-injection patterns, hidden   |
|                               XML tags, stealth URIs, exfil flags |
|  2. Secret & Schema Audit  -> AWS/GitHub/Stripe/JWT/PEM leaks,    |
|                               missing descriptions & JSON types   |
|  3. Context-Tax Meter      -> UTF-8 bytes, tokens (~4 B/tok),     |
|                               top 5 heaviest tool schemas         |
|  4. Policy & SARIF 2.1.0   -> --policy, --ci --min-score, --json, |
|                               and SARIF 2.1.0 CI reports          |
+---------------------------------+---------------------------------+
                                  |  stdio (JSON-RPC 2.0) or JSON
                                  v
+-------------------------------------------------------------------+
|  Upstream stdio MCP Servers (--config) or Static JSON (--tools)   |
+-------------------------------------------------------------------+
```

---

## Grading Rubric (`0–100`, `A–F`)

| Grade | Score | Meaning |
|---|---|---|
| **A** | `90–100` | Clean tool descriptions, strong schemas, low context tax, zero poisoning/secret findings |
| **B** | `80–89` | Minor schema/description warnings; safe defaults |
| **C** | `70–79` | Noticeable schema bloat or missing metadata |
| **D** | `55–69` | Heavy context tax or security flags (any `CRITICAL` finding caps grade at `<= D`) |
| **F** | `< 55` | Critical injection pattern, secret exposure, or severe schema bloat |

---

## Quickstart (`Node.js >= 24.0.0`, Zero Docker)

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

# Enforce CI policy & emit SARIF 2.1.0 (100% free MIT)
node dist/src/cli.js audit --tools-file mcp-tools.example.json --policy mcp-doctor.policy.example.json --sarif
node dist/src/cli.js audit --tools-file mcp-tools.example.json --ci --min-score 80

# Run full unit & real-stdio integration tests
pnpm test
```

---

If `mcp-doctor` helped harden your CI pipeline, Base USDC tips are welcome at `0x32eceaC45DBED9E555dAb80346aBd4Ab9C676206`. Support: `apexhive.hq@proton.me`.
