# `mcp-doctor` — MCP Security, Prompt-Injection & Context-Tax Auditor

> **Audit Model Context Protocol (MCP) tool catalogs for prompt-injection poisoning, secret leaks, schema defects, and context-window bloat in seconds (`Node.js >= 24`, MIT Open Source).**

- **Live Web Auditor, GitHub Readiness Scanner & `x402` API:** https://mcp-doctor-store.apexhive-hq.workers.dev
- **Packages:** [`cli/`](./cli/) (`Node >=24`, zero native C++ addons) &bull; [`storefront/`](./storefront/) (Cloudflare Workers live auditor, SVG score badges, `x402 v2` audit API, and Ed25519 license issuer)

---

## Architecture Overview

```text
+-------------------------------------------------------------------+
|  mcp-doctor CLI (Node >= 24) / Edge Auditor Worker                |
|  1. Context-Tax Meter      -> UTF-8 bytes, tokens (~4 B/tok),     |
|                               top 5 heaviest schemas, savings est |
|  2. Poisoning Scanner      -> Prompt injection, hidden XML tags,  |
|                               exfiltration, suspicious URIs       |
|  3. Secret & Schema Audit  -> AWS/GitHub/Stripe/JWT/PEM leaks,    |
|                               missing descriptions & JSON types   |
|  4. Score & Grade (A-F)    -> Human, --json, --ci --min-score,    |
|                               SARIF 2.1.0, & XML-safe SVG badges  |
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
| **D** | `55–69` | Heavy context tax or security/poisoning flags (any `CRITICAL` finding caps grade at `<= D`) |
| **F** | `< 55` | Critical poisoning, secret exposure, or severe schema bloat |

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

# Enforce CI threshold (exits non-zero if score < min-score)
node dist/src/cli.js audit --tools-file mcp-tools.example.json --ci --min-score 80

# Run full unit & real-stdio integration tests
pnpm test
```

---

## Live SVG Badges & `x402 v2` Edge API

- **Web Auditor (`0` Setup):** Visit `https://mcp-doctor-store.apexhive-hq.workers.dev` to audit MCP JSON catalogs or scan public GitHub MCP repositories (`GET /badge/repo/:owner/:repo.svg`).
- **Agent `x402 v2` Endpoint:** `POST /api/x402/audit` discovers cleanly via `GET /.well-known/x402` and `GET /openapi.json`.

---

## License & Commercial Support

MIT Open Source (`$0`). Organizational policy packs (`mcp-doctor.policy.json`), multi-server SARIF CI exports, optional community sponsorship, and offline Ed25519 license tokens are available on the [ApexHive Labs Storefront](https://mcp-doctor-store.apexhive-hq.workers.dev). Support: `apexhive.hq@proton.me`.
