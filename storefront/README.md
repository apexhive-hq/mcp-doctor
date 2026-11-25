# `mcp-doctor` Edge Auditor, SVG Badges & `x402 v2` API

Cloudflare Workers + Workers KV application powering:

1. **Web Catalog Auditor (`POST /api/audit/catalog`):** Zero-KV-write prompt-injection, secret-leak, schema-quality, and context-tax analyzer.
2. **GitHub Readiness Scanner & SVG Badges (`POST /api/audit/github`, `GET /badge`, `GET /badge/repo/:owner/:repo.svg`):** SSRF-safe public GitHub repository checker with XML-escaped dynamic SVG badges.
3. **Agent `x402 v2` Micro-Pay API (`POST /api/x402/audit`):** Pay-per-call Base USDC (`eip155:8453`, `$0.005 USDC` / `5000` atomic) audit endpoint authenticated via EIP-191 (`X-Payment`, `X-Payment-Signature`, `X-Payment-Address`).
4. **Non-Custodial License Issuer:** Issues offline-verifiable Ed25519 Team & Supporter tokens via Base Mainnet USDC (`0x32eceaC45DBED9E555dAb80346aBd4Ab9C676206`).

## Local Verification

```bash
pnpm run typecheck
pnpm test
```
