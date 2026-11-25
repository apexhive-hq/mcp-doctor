import { createPrivateKey, sign as nodeEd25519Sign } from 'node:crypto';
import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { verifyMessage } from 'viem';
import {
  auditCatalogPayload,
  MAX_AUDIT_BYTES,
  parseSafeGithubRepo,
  renderScoreBadgeSvg,
  scanPublicGithubRepo
} from './auditor.ts';

export interface Env {
  ASSETS: Fetcher;
  LICENSES_KV: KVNamespace;
  GLOBAL_CLAIMED_TX_KV: KVNamespace;
  BRAND_NAME: string;
  PRODUCT_ID: string;
  TOKEN_PREFIX: string;
  PAY_TO_EVM_ADDRESS: string;
  BASE_USDC_CONTRACT: string;
  BASE_CHAIN_ID: string;
  BASE_RPC_URL: string;
  BASE_RPC_URLS?: string;
  SUPPORTER_PRICE_USDC_ATOMIC?: string;
  TEAM_PRICE_USDC_ATOMIC: string;
  MIN_CONFIRMATIONS: string;
  CHALLENGE_TTL_SECONDS: string;
  DOWNLOAD_TTL_SECONDS: string;
  SOLANA_RECEIVE_ADDRESS: string;
  BTC_RECEIVE_ADDRESS: string;
  TRON_RECEIVE_ADDRESS: string;
  LICENSE_SIGNING_PRIVATE_JWK?: string;
  LICENSE_SIGNING_PUBLIC_SPKI_B64?: string;
  DOWNLOAD_HMAC_SECRET?: string;
}

type Tier = 'supporter' | 'team';

const ERC20_TRANSFER_TOPIC =
  '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef';
const TX_HASH_RE = /^0x[0-9a-fA-F]{64}$/;
const EVM_ADDR_RE = /^0x[0-9a-fA-F]{40}$/;
const SIG_RE = /^0x[0-9a-fA-F]{130}$/;
const STRICT_HEX_RE = /^0x[0-9a-fA-F]+$/;
const X402_PRICE_ATOMIC = 5000n;
const SCOPE_STOREFRONT = 'storefront:mcp-doctor';
const SCOPE_X402 = 'x402:mcp-doctor';

const DEFAULT_BASE_RPC_URLS = [
  'https://mainnet.base.org',
  'https://base-rpc.publicnode.com',
  'https://1rpc.io/base'
];

const FAVICON_SVG = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32"><rect width="32" height="32" rx="7" fill="#0b1020"/><path d="M16 7v18M7 16h18" stroke="#10b981" stroke-width="3.5" stroke-linecap="round"/></svg>`;

interface ChallengeRecord {
  nonce: string;
  txHash: string;
  tier: Tier;
  ts: number;
  message: string;
}

interface GlobalClaimRecord {
  scope: string;
  payer: string;
  tier: string;
  txHash: string;
  claimedAt: number;
}

interface DownloadGrantRecord {
  txHash: string;
  payer: string;
  tier: Tier;
  remainingDownloads: number;
  createdAt: number;
  licenseToken: string;
}

interface RpcLog {
  address: string;
  topics: string[];
  data: string;
}

interface RpcReceipt {
  status: string;
  blockNumber: string;
  logs: RpcLog[];
}

function parseStrictHexBigInt(val: unknown): bigint | null {
  if (typeof val !== 'string' || !STRICT_HEX_RE.test(val)) return null;
  return BigInt(val);
}

function base64UrlEncode(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i += 1) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function randomHex(byteCount = 16): string {
  const bytes = new Uint8Array(byteCount);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

function constantTimeEqualHex(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

async function hmacSha256Hex(secret: string, message: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(message));
  return toHex(new Uint8Array(sig));
}

function normalizeAddressFromTopic(topic: string): string {
  return `0x${topic.slice(-40).toLowerCase()}`;
}

function getTierPriceAtomic(env: Env, tier: Tier): bigint {
  if (tier === 'team') return BigInt(env.TEAM_PRICE_USDC_ATOMIC || '49000000');
  return BigInt(env.SUPPORTER_PRICE_USDC_ATOMIC || '5000000');
}

function getBaseRpcUrls(env: Env): string[] {
  if (env.BASE_RPC_URLS && env.BASE_RPC_URLS.trim()) {
    const parsed = env.BASE_RPC_URLS.split(',')
      .map((u) => u.trim())
      .filter(Boolean);
    if (parsed.length > 0) return parsed;
  }
  if (env.BASE_RPC_URL && env.BASE_RPC_URL.trim()) {
    return [env.BASE_RPC_URL.trim()];
  }
  return DEFAULT_BASE_RPC_URLS;
}

async function rpcCallSingle<T>(rpcUrl: string, method: string, params: unknown[]): Promise<T> {
  const res = await fetch(rpcUrl, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
    signal: AbortSignal.timeout(6000)
  });
  if (!res.ok) throw new Error(`RPC HTTP ${res.status}`);
  const json = (await res.json()) as { result?: T; error?: { message?: string } };
  if (json.error) throw new Error(`RPC error: ${json.error.message ?? 'unknown'}`);
  return json.result as T;
}

async function rpcCallWithFailover<T>(urls: string[], method: string, params: unknown[]): Promise<T> {
  let lastError: unknown;
  for (const url of urls) {
    try {
      return await rpcCallSingle<T>(url, method, params);
    } catch (err) {
      lastError = err;
    }
  }
  throw new Error(
    `All Base RPC endpoints failed: ${lastError instanceof Error ? lastError.message : 'unknown'}`
  );
}

function sumBaseUsdcTransfers(
  logs: RpcLog[] | undefined,
  expectedUsdcContract: string,
  expectedPayTo: string
): Map<string, bigint> {
  const expectedUsdc = expectedUsdcContract.toLowerCase();
  const expectedTo = expectedPayTo.toLowerCase();
  const payerTotals = new Map<string, bigint>();
  for (const log of logs ?? []) {
    if (log.address?.toLowerCase() !== expectedUsdc) continue;
    if (!log.topics || log.topics.length < 3) continue;
    if (log.topics[0]?.toLowerCase() !== ERC20_TRANSFER_TOPIC) continue;
    const from = normalizeAddressFromTopic(log.topics[1]);
    const to = normalizeAddressFromTopic(log.topics[2]);
    if (to !== expectedTo) continue;
    const value = parseStrictHexBigInt(log.data);
    if (value === null) continue;
    payerTotals.set(from, (payerTotals.get(from) ?? 0n) + value);
  }
  return payerTotals;
}

function buildChallengeMessage(params: {
  brand: string;
  product: string;
  tier: Tier;
  txHash: string;
  nonce: string;
  ts: number;
}): string {
  return [
    `${params.brand} MCP-Doctor Ownership Proof`,
    `product=${params.product}`,
    `tier=${params.tier}`,
    `tx=${params.txHash.toLowerCase()}`,
    `nonce=${params.nonce}`,
    `ts=${params.ts}`
  ].join('\n');
}

async function signDoctorLicense(
  env: Env,
  payload: {
    v: 1;
    product: string;
    tier: Tier;
    payer: string;
    txHash: string;
    issuedAt: number;
    expiresAt: null;
  }
): Promise<string> {
  const rawJwk = env.LICENSE_SIGNING_PRIVATE_JWK!.trim().replace(/^'(.*)'$/, '$1');
  const jwk = JSON.parse(rawJwk) as JsonWebKey;
  const prefix = env.TOKEN_PREFIX || 'MCPDOC-PRO-v1.';
  const payloadB64Url = base64UrlEncode(new TextEncoder().encode(JSON.stringify(payload)));
  const signingInput = new TextEncoder().encode(`${prefix}${payloadB64Url}`);

  try {
    const key = await crypto.subtle.importKey('jwk', jwk, { name: 'Ed25519' }, false, ['sign']);
    const sigBuf = await crypto.subtle.sign('Ed25519', key, signingInput);
    return `${prefix}${payloadB64Url}.${base64UrlEncode(new Uint8Array(sigBuf))}`;
  } catch {
    const privKey = createPrivateKey({ key: jwk as Record<string, unknown>, format: 'jwk' });
    const sigBuf = nodeEd25519Sign(null, Buffer.from(signingInput), privKey);
    return `${prefix}${payloadB64Url}.${base64UrlEncode(new Uint8Array(sigBuf))}`;
  }
}

function buildX402PaymentRequiredV2(env: Env, origin: string) {
  return {
    x402Version: 2,
    error: 'PAYMENT_REQUIRED',
    resource: {
      url: `${origin}/api/x402/audit`,
      description:
        'Audit MCP tool catalogs for prompt-injection poisoning, secret leaks, and context bloat ($0.005 USDC on Base Mainnet; include X-Payment, X-Payment-Signature, X-Payment-Address).',
      mimeType: 'application/json'
    },
    accepts: [
      {
        scheme: 'exact',
        network: 'eip155:8453',
        amount: X402_PRICE_ATOMIC.toString(),
        payTo: env.PAY_TO_EVM_ADDRESS,
        maxTimeoutSeconds: 300,
        asset: env.BASE_USDC_CONTRACT,
        extra: {
          name: 'USD Coin',
          version: '2',
          signatureRequired: true,
          signatureHeaders: ['X-Payment', 'X-Payment-Signature', 'X-Payment-Address'],
          signatureMessageTemplate: 'ApexHive x402 mcp-doctor-audit\ntxHash:<txHash_lowercase>'
        }
      }
    ],
    extensions: {
      bazaar: {
        info: {
          input: {
            type: 'http',
            method: 'POST',
            bodyType: 'json',
            body: {
              tools: [
                {
                  name: 'search_docs',
                  description: 'Search workspace documentation by keyword.',
                  inputSchema: {
                    type: 'object',
                    properties: { query: { type: 'string' } },
                    required: ['query']
                  }
                }
              ]
            }
          },
          output: {
            type: 'json',
            example: {
              ok: true,
              score: 100,
              grade: 'A',
              totalTools: 1,
              rawBytes: 175,
              estimatedTokens: 44,
              findings: []
            }
          }
        },
        schema: {
          $schema: 'https://json-schema.org/draft/2020-12/schema',
          type: 'object',
          required: ['input'],
          properties: {
            input: {
              type: 'object',
              required: ['type', 'method', 'bodyType', 'body'],
              properties: {
                type: { type: 'string', const: 'http' },
                method: { type: 'string', const: 'POST' },
                bodyType: { type: 'string', const: 'json' },
                body: {
                  type: 'object',
                  required: ['tools'],
                  properties: {
                    tools: {
                      type: 'array',
                      maxItems: 500,
                      items: {
                        type: 'object',
                        required: ['name'],
                        properties: {
                          server: { type: 'string' },
                          name: { type: 'string' },
                          description: { type: 'string' },
                          inputSchema: { type: 'object' }
                        }
                      }
                    }
                  }
                }
              }
            },
            output: {
              type: 'object',
              properties: {
                type: { type: 'string', const: 'json' },
                example: {
                  type: 'object',
                  properties: {
                    ok: { type: 'boolean' },
                    score: { type: 'number' },
                    grade: { type: 'string' },
                    totalTools: { type: 'number' },
                    rawBytes: { type: 'number' },
                    estimatedTokens: { type: 'number' },
                    findings: { type: 'array' }
                  }
                }
              }
            }
          }
        }
      }
    }
  };
}

// ─── App ─────────────────────────────────────────────────────────────────────
const app = new Hono<{ Bindings: Env }>();

app.onError((err, c) => {
  console.error('[mcp-doctor-store unhandled]', err instanceof Error ? err.stack || err.message : String(err));
  return c.json({ error: 'INTERNAL_ERROR' }, 500);
});

const apiCors = cors({
  origin: '*',
  allowMethods: ['GET', 'POST', 'OPTIONS'],
  allowHeaders: [
    'Content-Type',
    'X-Payment',
    'X-Payment-Signature',
    'X-Payment-Address',
    'X-ApexHive-License'
  ],
  exposeHeaders: ['X-Payment-Required']
});

app.use('/api/*', apiCors);
app.use('/.well-known/*', apiCors);
app.use('/openapi.json', apiCors);
app.use('/badge*', apiCors);

app.use('*', async (c, next) => {
  await next();
  const ct = c.res.headers.get('content-type');
  if (ct && (ct.startsWith('application/json') || ct.startsWith('text/html')) && !/charset=/i.test(ct)) {
    c.res.headers.set('content-type', `${ct}; charset=utf-8`);
  }
});

app.get('/favicon.svg', () => {
  return new Response(FAVICON_SVG, {
    status: 200,
    headers: { 'content-type': 'image/svg+xml; charset=utf-8', 'cache-control': 'public, max-age=86400' }
  });
});

app.get('/favicon.ico', () => {
  return new Response(FAVICON_SVG, {
    status: 200,
    headers: { 'content-type': 'image/svg+xml; charset=utf-8', 'cache-control': 'public, max-age=86400' }
  });
});

app.get('/badge', (c) => {
  const svg = renderScoreBadgeSvg({
    grade: c.req.query('grade'),
    score: c.req.query('score'),
    label: c.req.query('label')
  });
  return new Response(svg, {
    status: 200,
    headers: {
      'content-type': 'image/svg+xml; charset=utf-8',
      'cache-control': 'public, max-age=300'
    }
  });
});

app.get('/badge/repo/:owner/:repo', async (c) => {
  const owner = c.req.param('owner') ?? '';
  const rawRepo = c.req.param('repo') ?? '';
  const repo = rawRepo.endsWith('.svg') ? rawRepo.slice(0, -4) : rawRepo;
  const parsed = parseSafeGithubRepo(`${owner}/${repo}`);
  if (!parsed) {
    return c.json(
      { error: 'INVALID_REPO', message: 'Provide valid public owner/repo identifier.' },
      400
    );
  }
  const scan = await scanPublicGithubRepo(parsed.owner, parsed.repo);
  if (!scan.ok) {
    return c.json({ error: scan.error, message: scan.message }, scan.status);
  }
  const svg = renderScoreBadgeSvg({
    grade: scan.grade,
    score: scan.score,
    label: `${parsed.owner}/${parsed.repo}`
  });
  return new Response(svg, {
    status: 200,
    headers: {
      'content-type': 'image/svg+xml; charset=utf-8',
      'cache-control': 'public, max-age=300'
    }
  });
});

app.get('/.well-known/x402', (c) => {
  const origin = new URL(c.req.url).origin;
  return c.json({
    ...buildX402PaymentRequiredV2(c.env, origin),
    name: 'mcp-doctor Edge Security Auditor & x402 API',
    provider: c.env.BRAND_NAME || 'ApexHive Labs',
    contact: 'apexhive.hq@proton.me',
    homepage: origin,
    openapi: `${origin}/openapi.json`,
    freeEndpoints: [
      { method: 'POST', path: '/api/audit/catalog', url: `${origin}/api/audit/catalog` },
      { method: 'POST', path: '/api/audit/github', url: `${origin}/api/audit/github` },
      { method: 'GET', path: '/badge', url: `${origin}/badge?grade=A&score=100` }
    ]
  });
});

app.get('/openapi.json', (c) => {
  const origin = new URL(c.req.url).origin;
  const payTo = c.env.PAY_TO_EVM_ADDRESS;
  const usdc = c.env.BASE_USDC_CONTRACT;
  return c.json({
    openapi: '3.1.0',
    info: {
      title: 'mcp-doctor MCP Security Auditor & x402 API',
      version: '1.0.0',
      description:
        'Audit MCP tool catalogs for prompt-injection, secret leaks, schema gaps, and context-window bloat; generate safe SVG score badges.',
      'x-guidance':
        "Use POST /api/audit/catalog or POST /api/audit/github for free diagnostics, or call POST /api/x402/audit for paid agent scanning ($0.005 USDC = 5000 atomic on Base eip155:8453). Transfer >= 5000 atomic USDC to payTo and sign 'ApexHive x402 mcp-doctor-audit\\ntxHash:<txHash_lowercase>' via EIP-191 in X-Payment, X-Payment-Signature, and X-Payment-Address.",
      contact: {
        name: 'ApexHive Labs',
        email: 'apexhive.hq@proton.me'
      }
    },
    servers: [{ url: origin }],
    paths: {
      '/api/audit/catalog': {
        post: {
          summary: 'Free MCP tool catalog prompt-injection, secret & context-tax audit',
          security: [],
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  required: ['tools'],
                  properties: { tools: { type: 'array', maxItems: 500, items: { type: 'object' } } }
                }
              }
            }
          },
          responses: {
            '200': {
              description: 'Audit score, grade, severity counts, and SVG badge URL',
              content: {
                'application/json': {
                  schema: {
                    type: 'object',
                    properties: {
                      ok: { type: 'boolean' },
                      score: { type: 'number' },
                      grade: { type: 'string' },
                      findings: { type: 'array' }
                    }
                  }
                }
              }
            },
            '400': { description: 'Invalid JSON or nesting depth exceeded' },
            '413': { description: 'Payload exceeds 262,144 bytes or 500 tools' }
          }
        }
      },
      '/api/audit/github': {
        post: {
          summary: 'Free public GitHub MCP repository readiness audit',
          security: [],
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  required: ['repo'],
                  properties: { repo: { type: 'string', example: 'apexhive-hq/slimmcp-proxy' } }
                }
              }
            }
          },
          responses: {
            '200': { description: 'Readiness checklist, score, grade, and SVG badge path' },
            '400': { description: 'Invalid owner/repo format' },
            '404': { description: 'Repository not found' }
          }
        }
      },
      '/api/x402/audit': {
        post: {
          summary: 'x402 v2 paid MCP tool catalog audit ($0.005 USDC on Base)',
          description: `Pay 5000 atomic Base USDC (${usdc}, eip155:8453) to ${payTo} and sign "ApexHive x402 mcp-doctor-audit\\ntxHash:<txHash_lowercase>" via EIP-191.`,
          'x-payment-info': {
            price: { mode: 'fixed', currency: 'USD', amount: '0.005' },
            protocols: [{ x402: {} }]
          },
          parameters: [
            { name: 'X-Payment', in: 'header', required: true, schema: { type: 'string' } },
            { name: 'X-Payment-Signature', in: 'header', required: true, schema: { type: 'string' } },
            { name: 'X-Payment-Address', in: 'header', required: true, schema: { type: 'string' } }
          ],
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  required: ['tools'],
                  properties: { tools: { type: 'array', maxItems: 500, items: { type: 'object' } } }
                }
              }
            }
          },
          responses: {
            '200': {
              description: 'Audit report + settled Base payment receipt',
              content: {
                'application/json': {
                  schema: {
                    type: 'object',
                    properties: {
                      ok: { type: 'boolean' },
                      score: { type: 'number' },
                      grade: { type: 'string' },
                      payment: { type: 'object' }
                    }
                  }
                }
              }
            },
            '401': { description: 'Missing EIP-191 signature headers' },
            '402': { description: 'Payment Required' },
            '403': { description: 'Invalid signature, underpayment, or replayed txHash' },
            '413': { description: 'Payload exceeds 262,144 bytes or 500 tools' }
          }
        }
      },
      '/badge': {
        get: {
          summary: 'Render XML-safe SVG score badge',
          security: [],
          responses: { '200': { description: 'image/svg+xml' } }
        }
      },
      '/api/health': {
        get: { summary: 'Service health and KV bindings', security: [], responses: { '200': { description: 'OK' } } }
      },
      '/api/config': {
        get: { summary: 'Public checkout config and tiers', security: [], responses: { '200': { description: 'OK' } } }
      }
    }
  });
});

app.get('/api/health', (c) => {
  return c.json({
    ok: true,
    service: 'mcp-doctor-store',
    brand: c.env.BRAND_NAME || 'ApexHive Labs',
    chainId: Number(c.env.BASE_CHAIN_ID || '8453'),
    kvBound: Boolean(c.env.LICENSES_KV),
    globalKvBound: Boolean(c.env.GLOBAL_CLAIMED_TX_KV),
    openSourceLicense: 'MIT',
    supportEmail: 'apexhive.hq@proton.me'
  });
});

app.get('/api/config', (c) => {
  const supAtomic = getTierPriceAtomic(c.env, 'supporter');
  const teamAtomic = getTierPriceAtomic(c.env, 'team');
  return c.json({
    brand: c.env.BRAND_NAME || 'ApexHive Labs',
    product: c.env.PRODUCT_ID || 'mcp-doctor',
    tokenPrefix: c.env.TOKEN_PREFIX || 'MCPDOC-PRO-v1.',
    openSourceLicense: 'MIT',
    chainId: Number(c.env.BASE_CHAIN_ID || '8453'),
    network: 'Base Mainnet',
    usdcContract: c.env.BASE_USDC_CONTRACT,
    payToAddress: c.env.PAY_TO_EVM_ADDRESS,
    publicKeySpkiB64: c.env.LICENSE_SIGNING_PUBLIC_SPKI_B64 ?? null,
    tiers: {
      supporter: {
        label: 'Supporter / Sponsor (Optional MIT Backing)',
        usdc: String(Number(supAtomic) / 1_000_000),
        atomic: supAtomic.toString()
      },
      team: {
        label: 'Team Commercial CI (Org Policy + SARIF)',
        usdc: String(Number(teamAtomic) / 1_000_000),
        atomic: teamAtomic.toString()
      }
    },
    supportEmail: 'apexhive.hq@proton.me',
    optionalRails: {
      solanaUsdc: c.env.SOLANA_RECEIVE_ADDRESS,
      bitcoin: c.env.BTC_RECEIVE_ADDRESS,
      tronTrxUsdt: c.env.TRON_RECEIVE_ADDRESS
    },
    selfCustodyWarning:
      'SELF-CUSTODY WALLET ONLY: Send Base USDC ONLY from a wallet you control (MetaMask, Rabby, Coinbase Wallet). NEVER send directly from a centralized exchange (CEX) withdrawal—exchange hot wallets cannot sign the EIP-191 ownership challenge. Need recovery help? Contact apexhive.hq@proton.me.'
  });
});

app.post('/api/audit/catalog', async (c) => {
  const rawText = await c.req.text();
  const result = auditCatalogPayload(rawText);
  if (!result.ok) {
    return c.json({ error: result.error, message: result.message }, result.status);
  }
  return c.json(result, 200);
});

app.post('/api/audit/github', async (c) => {
  let body: { repo?: string };
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: 'INVALID_JSON' }, 400);
  }
  const parsed = parseSafeGithubRepo(String(body.repo ?? ''));
  if (!parsed) {
    return c.json(
      { error: 'INVALID_REPO', message: 'Expected valid public GitHub "owner/repo" slug.' },
      400
    );
  }
  const scan = await scanPublicGithubRepo(parsed.owner, parsed.repo);
  if (!scan.ok) {
    return c.json({ error: scan.error, message: scan.message }, scan.status);
  }
  return c.json(scan, 200, { 'Cache-Control': 'public, max-age=300' });
});

app.post('/api/x402/audit', async (c) => {
  if (!c.env.GLOBAL_CLAIMED_TX_KV) {
    return c.json({ error: 'SERVER_MISCONFIGURED', message: 'Missing GLOBAL_CLAIMED_TX_KV.' }, 500);
  }

  const rawText = await c.req.text();
  if (new TextEncoder().encode(rawText).length > MAX_AUDIT_BYTES) {
    return c.json(
      { error: 'PAYLOAD_TOO_LARGE', message: `Payload exceeds ${MAX_AUDIT_BYTES} bytes limit.` },
      413
    );
  }

  const xPayment = (c.req.header('X-Payment') ?? c.req.header('x-payment') ?? '').trim();
  const xSig = (c.req.header('X-Payment-Signature') ?? c.req.header('x-payment-signature') ?? '').trim();
  const xAddr = (c.req.header('X-Payment-Address') ?? c.req.header('x-payment-address') ?? '').trim();

  if (!xPayment) {
    const origin = new URL(c.req.url).origin;
    return c.json(buildX402PaymentRequiredV2(c.env, origin), 402, {
      'X-Payment-Required': 'true'
    });
  }
  if (!TX_HASH_RE.test(xPayment)) {
    return c.json({ error: 'INVALID_TX_HASH', message: 'Expected 0x-prefixed 64-hex txHash.' }, 400);
  }
  if (!xSig || !xAddr) {
    return c.json(
      {
        error: 'SIGNATURE_REQUIRED',
        message: 'Provide X-Payment-Signature and X-Payment-Address EIP-191 ownership proof.'
      },
      401
    );
  }
  if (!SIG_RE.test(xSig) || !EVM_ADDR_RE.test(xAddr)) {
    return c.json({ error: 'INVALID_PAYMENT_SIGNATURE' }, 403);
  }

  const txLower = xPayment.toLowerCase();
  const payerLower = xAddr.toLowerCase();
  const sigOk = await verifyMessage({
    address: payerLower as `0x${string}`,
    message: `ApexHive x402 mcp-doctor-audit\ntxHash:${txLower}`,
    signature: xSig as `0x${string}`
  }).catch(() => false);
  if (!sigOk) {
    return c.json({ error: 'INVALID_PAYMENT_SIGNATURE', message: 'EIP-191 signature mismatch.' }, 403);
  }

  const auditRes = auditCatalogPayload(rawText);
  if (!auditRes.ok) {
    return c.json({ error: auditRes.error, message: auditRes.message }, auditRes.status);
  }

  const globalKey = `global_tx:${txLower}`;
  const existingGlobalRaw = await c.env.GLOBAL_CLAIMED_TX_KV.get(globalKey);
  if (existingGlobalRaw) {
    const existing = JSON.parse(existingGlobalRaw) as GlobalClaimRecord;
    return c.json(
      {
        error: existing.scope === SCOPE_X402 ? 'TX_ALREADY_CLAIMED' : 'TX_ALREADY_CLAIMED_ELSEWHERE',
        message: 'Transaction hash already redeemed.'
      },
      403
    );
  }

  const x402Key = `x402_claimed:${txLower}`;
  if (await c.env.LICENSES_KV.get(x402Key)) {
    return c.json({ error: 'TX_ALREADY_CLAIMED', message: 'x402 txHash already used.' }, 403);
  }

  const rpcUrls = getBaseRpcUrls(c.env);
  let receipt: RpcReceipt | null;
  let latestBlockHex: string;
  try {
    [receipt, latestBlockHex] = await Promise.all([
      rpcCallWithFailover<RpcReceipt | null>(rpcUrls, 'eth_getTransactionReceipt', [txLower]),
      rpcCallWithFailover<string>(rpcUrls, 'eth_blockNumber', [])
    ]);
  } catch (err) {
    return c.json(
      { error: 'RPC_UNAVAILABLE', message: err instanceof Error ? err.message : 'Base RPC error' },
      502
    );
  }

  if (!receipt || receipt.status !== '0x1') {
    return c.json({ error: 'TX_NOT_CONFIRMED', message: 'Receipt missing or reverted.' }, 403);
  }
  const txBlock = parseStrictHexBigInt(receipt.blockNumber);
  const headBlock = parseStrictHexBigInt(latestBlockHex);
  if (txBlock === null || headBlock === null) {
    return c.json({ error: 'TX_NOT_CONFIRMED', message: 'Malformed hex blockNumber from RPC.' }, 403);
  }
  const minConf = Math.max(1, Number(c.env.MIN_CONFIRMATIONS || '2'));
  const confirmations = headBlock >= txBlock ? Number(headBlock - txBlock) + 1 : 0;
  if (confirmations < minConf) {
    return c.json({ error: 'INSUFFICIENT_CONFIRMATIONS', message: `Need >= ${minConf} confirmations.` }, 403);
  }

  const payerTotals = sumBaseUsdcTransfers(
    receipt.logs,
    c.env.BASE_USDC_CONTRACT,
    c.env.PAY_TO_EVM_ADDRESS
  );
  const paidAtomic = payerTotals.get(payerLower) ?? 0n;
  if (paidAtomic < X402_PRICE_ATOMIC) {
    return c.json({ error: 'PAYMENT_INSUFFICIENT', message: 'Expected >= 5000 atomic Base USDC.' }, 403);
  }

  const verifiedAt = Date.now();
  await Promise.all([
    c.env.LICENSES_KV.put(x402Key, JSON.stringify({ txHash: txLower, payer: payerLower, verifiedAt })),
    c.env.GLOBAL_CLAIMED_TX_KV.put(
      globalKey,
      JSON.stringify({ scope: SCOPE_X402, payer: payerLower, tier: 'x402', txHash: txLower, claimedAt: verifiedAt })
    )
  ]);

  return c.json({
    ...auditRes,
    payment: {
      settled: true,
      txHash: txLower,
      payer: payerLower,
      paidAtomic: paidAtomic.toString(),
      confirmations,
      network: 'base',
      chainId: Number(c.env.BASE_CHAIN_ID || '8453')
    }
  });
});

app.post('/api/challenge', async (c) => {
  let body: { txHash?: string; tier?: string };
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: 'INVALID_JSON' }, 400);
  }

  const txHash = (body.txHash ?? '').trim();
  const tierRaw = (body.tier ?? '').trim();
  if (!TX_HASH_RE.test(txHash)) {
    return c.json({ error: 'INVALID_TX_HASH', message: 'Expected 0x-prefixed 64-hex txHash.' }, 400);
  }
  if (tierRaw !== 'supporter' && tierRaw !== 'team') {
    return c.json({ error: 'INVALID_TIER', message: 'Tier must be supporter or team.' }, 400);
  }
  const tier = tierRaw as Tier;

  const ttl = Math.max(60, Number(c.env.CHALLENGE_TTL_SECONDS || '300'));
  const nonce = randomHex(16);
  const ts = Math.floor(Date.now() / 1000);
  const message = buildChallengeMessage({
    brand: c.env.BRAND_NAME || 'ApexHive Labs',
    product: c.env.PRODUCT_ID || 'mcp-doctor',
    tier,
    txHash,
    nonce,
    ts
  });

  const record: ChallengeRecord = { nonce, txHash: txHash.toLowerCase(), tier, ts, message };
  await c.env.LICENSES_KV.put(`challenge:${nonce}`, JSON.stringify(record), { expirationTtl: ttl });
  return c.json({ nonce, ts, expiresInSeconds: ttl, message });
});

app.post('/api/verify', async (c) => {
  if (
    !c.env.LICENSE_SIGNING_PRIVATE_JWK ||
    !c.env.DOWNLOAD_HMAC_SECRET ||
    c.env.DOWNLOAD_HMAC_SECRET.length < 16 ||
    !c.env.GLOBAL_CLAIMED_TX_KV
  ) {
    return c.json(
      {
        error: 'SERVER_MISCONFIGURED',
        message: 'Missing LICENSE_SIGNING_PRIVATE_JWK, DOWNLOAD_HMAC_SECRET, or GLOBAL_CLAIMED_TX_KV.'
      },
      500
    );
  }

  let body: { txHash?: string; nonce?: string; signature?: string; tier?: string };
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: 'INVALID_JSON' }, 400);
  }

  const txHash = (body.txHash ?? '').trim();
  const nonce = (body.nonce ?? '').trim();
  const signature = (body.signature ?? '').trim();
  const tierRaw = (body.tier ?? '').trim();

  if (!TX_HASH_RE.test(txHash) || !nonce || !SIG_RE.test(signature)) {
    return c.json({ error: 'INVALID_REQUEST', message: 'Provide valid txHash, nonce, and EIP-191 signature.' }, 400);
  }
  if (tierRaw !== 'supporter' && tierRaw !== 'team') {
    return c.json({ error: 'INVALID_TIER', message: 'Tier must be supporter or team.' }, 400);
  }
  const tier = tierRaw as Tier;

  const txLower = txHash.toLowerCase();
  const challengeKey = `challenge:${nonce}`;
  const challengeRaw = await c.env.LICENSES_KV.get(challengeKey);
  if (!challengeRaw) {
    return c.json({ error: 'CHALLENGE_EXPIRED_OR_MISSING', message: 'Challenge expired (>300s) or unknown.' }, 403);
  }

  const challenge = JSON.parse(challengeRaw) as ChallengeRecord;
  const ttl = Math.max(60, Number(c.env.CHALLENGE_TTL_SECONDS || '300'));
  const nowSec = Math.floor(Date.now() / 1000);
  if (challenge.txHash !== txLower || challenge.tier !== tier || nowSec - challenge.ts > ttl) {
    await c.env.LICENSES_KV.delete(challengeKey);
    return c.json({ error: 'CHALLENGE_MISMATCH_OR_EXPIRED', message: 'Challenge mismatch or expired.' }, 403);
  }

  const rpcUrls = getBaseRpcUrls(c.env);
  let receipt: RpcReceipt | null;
  let latestBlockHex: string;
  try {
    [receipt, latestBlockHex] = await Promise.all([
      rpcCallWithFailover<RpcReceipt | null>(rpcUrls, 'eth_getTransactionReceipt', [txLower]),
      rpcCallWithFailover<string>(rpcUrls, 'eth_blockNumber', [])
    ]);
  } catch (err) {
    return c.json(
      { error: 'RPC_UNAVAILABLE', message: err instanceof Error ? err.message : 'Base RPC error' },
      502
    );
  }

  if (!receipt || receipt.status !== '0x1') {
    return c.json({ error: 'TX_NOT_CONFIRMED', message: 'Receipt missing or reverted.' }, 403);
  }
  const txBlock = parseStrictHexBigInt(receipt.blockNumber);
  const headBlock = parseStrictHexBigInt(latestBlockHex);
  if (txBlock === null || headBlock === null) {
    return c.json({ error: 'TX_NOT_CONFIRMED', message: 'Malformed hex blockNumber from RPC.' }, 403);
  }

  const minConf = Math.max(1, Number(c.env.MIN_CONFIRMATIONS || '2'));
  const confirmations = headBlock >= txBlock ? Number(headBlock - txBlock) + 1 : 0;
  if (confirmations < minConf) {
    // Preserve challenge nonce so immediate retry at >= minConf succeeds
    return c.json({ error: 'INSUFFICIENT_CONFIRMATIONS', message: `Need >= ${minConf} confirmations.` }, 403);
  }

  const requiredAmount = getTierPriceAtomic(c.env, tier);
  const payerTotals = sumBaseUsdcTransfers(
    receipt.logs,
    c.env.BASE_USDC_CONTRACT,
    c.env.PAY_TO_EVM_ADDRESS
  );

  let matchedPayer: string | null = null;
  let paidAtomic = 0n;
  for (const [fromAddr, totalPaid] of payerTotals.entries()) {
    if (totalPaid < requiredAmount) continue;
    const sigOk = await verifyMessage({
      address: fromAddr as `0x${string}`,
      message: challenge.message,
      signature: signature as `0x${string}`
    }).catch(() => false);
    if (sigOk) {
      matchedPayer = fromAddr;
      paidAtomic = totalPaid;
      break;
    }
  }

  if (!matchedPayer) {
    await c.env.LICENSES_KV.delete(challengeKey);
    return c.json(
      { error: 'PAYMENT_OR_SIGNATURE_INVALID', message: 'Transfer or EIP-191 signature verification failed.' },
      403
    );
  }

  const globalKey = `global_tx:${txLower}`;
  const globalRaw = await c.env.GLOBAL_CLAIMED_TX_KV.get(globalKey);
  if (globalRaw) {
    const globalRec = JSON.parse(globalRaw) as GlobalClaimRecord;
    if (globalRec.scope !== SCOPE_STOREFRONT) {
      await c.env.LICENSES_KV.delete(challengeKey);
      return c.json(
        { error: 'TX_ALREADY_CLAIMED_ELSEWHERE', message: `Already claimed on ${globalRec.scope}.` },
        403
      );
    }
    if (globalRec.payer?.toLowerCase() !== matchedPayer.toLowerCase() || globalRec.tier !== tier) {
      await c.env.LICENSES_KV.delete(challengeKey);
      return c.json({ error: 'TX_ALREADY_CLAIMED', message: 'Transaction already claimed.' }, 403);
    }
  }

  await c.env.LICENSES_KV.delete(challengeKey);

  const claimedKey = `claimed_tx:${txLower}`;
  const existingRaw = await c.env.LICENSES_KV.get(claimedKey);
  let reclaimed = false;
  if (existingRaw) {
    const existing = JSON.parse(existingRaw) as { payer?: string; tier?: Tier };
    if (existing.payer?.toLowerCase() === matchedPayer.toLowerCase() && existing.tier === tier) {
      reclaimed = true;
    } else {
      return c.json({ error: 'TX_ALREADY_CLAIMED', message: 'Transaction already claimed.' }, 403);
    }
  }

  const issuedAt = Date.now();
  const licenseToken = await signDoctorLicense(c.env, {
    v: 1,
    product: c.env.PRODUCT_ID || 'mcp-doctor',
    tier,
    payer: matchedPayer,
    txHash: txLower,
    issuedAt,
    expiresAt: null
  });

  const grantId = randomHex(16);
  const sigHex = await hmacSha256Hex(c.env.DOWNLOAD_HMAC_SECRET, grantId);
  const downloadToken = `${grantId}.${sigHex}`;
  const downloadTtl = Math.max(120, Number(c.env.DOWNLOAD_TTL_SECONDS || '600'));

  const grant: DownloadGrantRecord = {
    txHash: txLower,
    payer: matchedPayer,
    tier,
    remainingDownloads: 3,
    createdAt: issuedAt,
    licenseToken
  };

  const writes: Array<Promise<void>> = [
    c.env.LICENSES_KV.put(`dl:${grantId}`, JSON.stringify(grant), { expirationTtl: downloadTtl })
  ];
  if (!reclaimed) {
    writes.push(
      c.env.LICENSES_KV.put(
        claimedKey,
        JSON.stringify({ txHash: txLower, payer: matchedPayer, tier, paidAtomic: paidAtomic.toString(), issuedAt })
      ),
      c.env.GLOBAL_CLAIMED_TX_KV.put(
        globalKey,
        JSON.stringify({ scope: SCOPE_STOREFRONT, payer: matchedPayer, tier, txHash: txLower, claimedAt: issuedAt })
      )
    );
  }
  await Promise.all(writes);

  return c.json({
    ok: true,
    reclaimed,
    tier,
    payer: matchedPayer,
    txHash: txLower,
    paidAtomic: paidAtomic.toString(),
    licenseToken,
    downloadToken,
    downloadUrl: `/api/download?token=${encodeURIComponent(downloadToken)}`,
    activationCommand: `node dist/src/cli.js activate --token "${licenseToken}"`
  });
});

app.get('/api/download', async (c) => {
  if (!c.env.DOWNLOAD_HMAC_SECRET || c.env.DOWNLOAD_HMAC_SECRET.length < 16) {
    return c.json({ error: 'SERVER_MISCONFIGURED', message: 'Missing DOWNLOAD_HMAC_SECRET.' }, 500);
  }

  const token = (c.req.query('token') ?? '').trim();
  const match = /^([0-9a-f]{32})\.([0-9a-f]{64})$/.exec(token);
  if (!match) {
    return c.json({ error: 'INVALID_DOWNLOAD_TOKEN' }, 403);
  }

  const [, grantId, sigHex] = match;
  const expectedSig = await hmacSha256Hex(c.env.DOWNLOAD_HMAC_SECRET, grantId);
  if (!constantTimeEqualHex(sigHex, expectedSig)) {
    return c.json({ error: 'INVALID_DOWNLOAD_TOKEN' }, 403);
  }

  const dlKey = `dl:${grantId}`;
  const raw = await c.env.LICENSES_KV.get(dlKey);
  if (!raw) {
    return c.json({ error: 'DOWNLOAD_TOKEN_EXPIRED', message: 'Download grant expired or exhausted.' }, 403);
  }

  const grant = JSON.parse(raw) as DownloadGrantRecord;
  if (grant.remainingDownloads <= 0) {
    await c.env.LICENSES_KV.delete(dlKey);
    return c.json({ error: 'DOWNLOAD_LIMIT_REACHED' }, 403);
  }

  const nextRemaining = grant.remainingDownloads - 1;
  const downloadTtl = Math.max(120, Number(c.env.DOWNLOAD_TTL_SECONDS || '600'));
  if (nextRemaining <= 0) {
    await c.env.LICENSES_KV.delete(dlKey);
  } else {
    await c.env.LICENSES_KV.put(
      dlKey,
      JSON.stringify({ ...grant, remainingDownloads: nextRemaining }),
      { expirationTtl: downloadTtl }
    );
  }

  const bundle = {
    ok: true,
    product: 'mcp-doctor',
    openSourceLicense: 'MIT',
    mitRepoUrl: 'https://github.com/apexhive-hq/mcp-doctor',
    tier: grant.tier,
    payer: grant.payer,
    txHash: grant.txHash,
    issuedAt: grant.createdAt,
    licenseToken: grant.licenseToken,
    recommendedTeamPolicy: {
      minScore: 80,
      failOnSeverity: 'HIGH',
      blockPromptInjection: true,
      maxTotalTokens: 12000,
      denyTools: ['*:delete_*', '*:exec_*']
    }
  };

  return new Response(JSON.stringify(bundle, null, 2), {
    status: 200,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'content-disposition': 'attachment; filename="mcp-doctor-entitlement-policy.json"',
      'cache-control': 'no-store'
    }
  });
});

app.all('*', async (c) => {
  if (c.env.ASSETS) {
    return c.env.ASSETS.fetch(c.req.raw);
  }
  return c.text('Not Found', 404);
});

export default app;
