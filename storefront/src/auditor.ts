export type AuditSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
export type AuditGrade = 'A' | 'B' | 'C' | 'D' | 'F';

export interface CatalogToolInput {
  server?: unknown;
  name?: unknown;
  description?: unknown;
  inputSchema?: unknown;
}

export interface AuditFinding {
  ruleId: string;
  severity: AuditSeverity;
  category: 'prompt-injection' | 'secret-leak' | 'schema-quality' | 'context-tax' | 'readiness';
  server: string;
  tool: string;
  message: string;
  evidence?: string;
}

export interface CatalogAuditResult {
  ok: true;
  score: number;
  grade: AuditGrade;
  totalTools: number;
  rawBytes: number;
  estimatedTokens: number;
  slimProxyTokens: number;
  tokensSavedWithSlimMcp: number;
  estimatedSavingsPct: number;
  severityCounts: Record<AuditSeverity, number>;
  topHeaviestTools: Array<{ server: string; name: string; bytes: number; tokens: number }>;
  findings: AuditFinding[];
  badgePath: string;
}

export const MAX_AUDIT_BYTES = 262_144;
export const MAX_AUDIT_TOOLS = 500;
const MAX_JSON_DEPTH = 32;
const SLIM_META_BYTES = 1279;
const SLIM_META_TOKENS = 320;
const VALID_GRADES = new Set<AuditGrade>(['A', 'B', 'C', 'D', 'F']);
const REPO_SEGMENT_RE = /^[A-Za-z0-9_.-]{1,100}$/;

interface PatternRule {
  ruleId: string;
  severity: AuditSeverity;
  category: 'prompt-injection' | 'secret-leak';
  regex: RegExp;
  message: string;
}

const RULES: PatternRule[] = [
  {
    ruleId: 'MCP_PI_IGNORE_INSTRUCTIONS',
    severity: 'CRITICAL',
    category: 'prompt-injection',
    regex: /\b(ignore|disregard|forget|override)\s+(all\s+)?(previous|prior|above|system)\s+(instructions|prompts?|rules?)\b/i,
    message: 'Prompt-injection directive attempting to override prior system instructions.'
  },
  {
    ruleId: 'MCP_PI_HIDDEN_TAG',
    severity: 'CRITICAL',
    category: 'prompt-injection',
    regex: /<\s*\/?\s*(?:system|instructions|important|developer|tool_override)\b[^>]*>|\[SYSTEM\]/i,
    message: 'Suspicious hidden XML/bracket system tag inside tool metadata.'
  },
  {
    ruleId: 'MCP_PI_EXFILTRATION',
    severity: 'CRITICAL',
    category: 'prompt-injection',
    regex: /\b(exfiltrate|steal|leak)\b|(?:~\/\.ssh|id_rsa|\.env\b|private[_ -]?key|seed\s*phrase).*\b(send|post|upload|curl|fetch|http)\b|\b(curl|wget)\b.*\|\s*(?:sh|bash)\b/i,
    message: 'Tool poisoning pattern instructing sensitive file/secret exfiltration.'
  },
  {
    ruleId: 'MCP_PI_STEALTH_URI_OR_ZW',
    severity: 'HIGH',
    category: 'prompt-injection',
    regex: /(?:data:text\/html|javascript:|[\u200B-\u200D\uFEFF])/i,
    message: 'Suspicious script/data URI or hidden zero-width Unicode characters.'
  },
  {
    ruleId: 'MCP_PI_SHELL_DANGER',
    severity: 'HIGH',
    category: 'prompt-injection',
    regex: /\b(?:rm\s+-rf\s+\/|powershell\s+-enc|child_process\.exec)\b/i,
    message: 'Dangerous shell execution directive embedded in tool schema or description.'
  },
  {
    ruleId: 'MCP_SEC_AWS_KEY',
    severity: 'CRITICAL',
    category: 'secret-leak',
    regex: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/,
    message: 'Exposed AWS Access Key ID detected in tool metadata.'
  },
  {
    ruleId: 'MCP_SEC_GITHUB_TOKEN',
    severity: 'CRITICAL',
    category: 'secret-leak',
    regex: /\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})\b/,
    message: 'Exposed GitHub Personal Access Token detected in tool metadata.'
  },
  {
    ruleId: 'MCP_SEC_API_KEY',
    severity: 'CRITICAL',
    category: 'secret-leak',
    regex: /\b(?:sk_live_[0-9A-Za-z]{16,}|sk-(?:proj-|ant-)?[A-Za-z0-9_-]{20,}|xox[baprs]-[0-9A-Za-z-]{10,})\b/,
    message: 'Exposed API token (Stripe/OpenAI/Anthropic/Slack) detected in tool metadata.'
  },
  {
    ruleId: 'MCP_SEC_PEM_OR_JWT',
    severity: 'CRITICAL',
    category: 'secret-leak',
    regex: /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----|eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/,
    message: 'Exposed PEM private key or JWT token detected in tool metadata.'
  }
];

function gradeFromScore(score: number): AuditGrade {
  if (score >= 90) return 'A';
  if (score >= 80) return 'B';
  if (score >= 70) return 'C';
  if (score >= 55) return 'D';
  return 'F';
}

function exceedsJsonDepth(text: string, maxDepth: number): boolean {
  let depth = 0;
  let inString = false;
  let escaped = false;
  for (let i = 0; i < text.length; i += 1) {
    const ch = text.charCodeAt(i);
    if (inString) {
      if (escaped) escaped = false;
      else if (ch === 92) escaped = true;
      else if (ch === 34) inString = false;
      continue;
    }
    if (ch === 34) inString = true;
    else if (ch === 123 || ch === 91) {
      depth += 1;
      if (depth > maxDepth) return true;
    } else if (ch === 125 || ch === 93) {
      depth -= 1;
    }
  }
  return false;
}

function collectStrings(val: unknown, out: string[] = []): string[] {
  if (typeof val === 'string') out.push(val);
  else if (Array.isArray(val)) for (const item of val) collectStrings(item, out);
  else if (val && typeof val === 'object') {
    for (const [k, v] of Object.entries(val)) {
      out.push(k);
      collectStrings(v, out);
    }
  }
  return out;
}

export function auditCatalogPayload(
  rawBodyText: string
): CatalogAuditResult | { ok: false; status: 400 | 413; error: string; message: string } {
  const encoder = new TextEncoder();
  const bodyBytes = encoder.encode(rawBodyText).length;
  if (bodyBytes > MAX_AUDIT_BYTES) {
    return {
      ok: false,
      status: 413,
      error: 'PAYLOAD_TOO_LARGE',
      message: `Payload exceeds ${MAX_AUDIT_BYTES} bytes limit.`
    };
  }
  if (exceedsJsonDepth(rawBodyText, MAX_JSON_DEPTH)) {
    return {
      ok: false,
      status: 400,
      error: 'NESTING_DEPTH_EXCEEDED',
      message: `JSON nesting exceeds ${MAX_JSON_DEPTH} levels.`
    };
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(rawBodyText);
  } catch {
    return { ok: false, status: 400, error: 'INVALID_JSON', message: 'Expected valid JSON payload.' };
  }

  let toolsRaw: unknown = null;
  if (Array.isArray(parsed)) toolsRaw = parsed;
  else if (parsed && typeof parsed === 'object') {
    const obj = parsed as { tools?: unknown; result?: { tools?: unknown } };
    if (Array.isArray(obj.tools)) toolsRaw = obj.tools;
    else if (obj.result && Array.isArray(obj.result.tools)) toolsRaw = obj.result.tools;
  }

  if (!Array.isArray(toolsRaw) || toolsRaw.length === 0) {
    return {
      ok: false,
      status: 400,
      error: 'INVALID_TOOLS_PAYLOAD',
      message: 'Provide a non-empty array or { tools: [...] } MCP catalog JSON payload.'
    };
  }
  if (toolsRaw.length > MAX_AUDIT_TOOLS) {
    return {
      ok: false,
      status: 413,
      error: 'TOO_MANY_TOOLS',
      message: `Maximum ${MAX_AUDIT_TOOLS} tools allowed per audit call.`
    };
  }

  const tools = toolsRaw as CatalogToolInput[];
  for (const t of tools) {
    if (!t || typeof t !== 'object' || typeof t.name !== 'string' || !t.name.trim()) {
      return {
        ok: false,
        status: 400,
        error: 'INVALID_TOOL_ENTRY',
        message: 'Every tool entry must be an object with a non-empty string name.'
      };
    }
  }

  const findings: AuditFinding[] = [];
  const weights: Array<{ server: string; name: string; bytes: number; tokens: number }> = [];
  let missingDescPenalty = 0;
  let weakSchemaPenalty = 0;
  let securityPenalty = 0;

  for (const tool of tools) {
    const server = typeof tool.server === 'string' && tool.server.trim() ? tool.server.trim() : 'default';
    const name = String(tool.name).trim();
    const serialized = JSON.stringify({
      name,
      description: tool.description ?? '',
      inputSchema: tool.inputSchema ?? {}
    });
    const bytes = encoder.encode(serialized).length;
    weights.push({ server, name, bytes, tokens: Math.ceil(bytes / 4) });

    const seen = new Set<string>();
    for (const txt of collectStrings({ name, description: tool.description ?? '', inputSchema: tool.inputSchema ?? {} })) {
      for (const rule of RULES) {
        if (seen.has(rule.ruleId)) continue;
        rule.regex.lastIndex = 0;
        const m = txt.match(rule.regex);
        if (m) {
          seen.add(rule.ruleId);
          findings.push({
            ruleId: rule.ruleId,
            severity: rule.severity,
            category: rule.category,
            server,
            tool: name,
            message: rule.message,
            evidence: m[0].slice(0, 64)
          });
          securityPenalty += rule.severity === 'CRITICAL' ? 35 : 15;
        }
      }
    }

    const desc = typeof tool.description === 'string' ? tool.description.trim() : '';
    if (desc.length < 12) {
      findings.push({
        ruleId: 'MCP_SCHEMA_MISSING_DESCRIPTION',
        severity: 'MEDIUM',
        category: 'schema-quality',
        server,
        tool: name,
        message: 'Tool description is missing or shorter than 12 characters.'
      });
      missingDescPenalty = Math.min(20, missingDescPenalty + 5);
    }

    const schema = tool.inputSchema as Record<string, unknown> | undefined;
    const hasProps =
      schema &&
      typeof schema === 'object' &&
      (schema.type !== 'object' ||
        (schema.properties &&
          typeof schema.properties === 'object' &&
          Object.keys(schema.properties as Record<string, unknown>).length > 0));
    if (!schema || !hasProps) {
      findings.push({
        ruleId: 'MCP_SCHEMA_UNTYPED',
        severity: 'LOW',
        category: 'schema-quality',
        server,
        tool: name,
        message: 'Tool inputSchema lacks typed properties.'
      });
      weakSchemaPenalty = Math.min(12, weakSchemaPenalty + 3);
    }
  }

  const rawBytes = encoder.encode(JSON.stringify({ tools })).length;
  const estimatedTokens = Math.ceil(rawBytes / 4);
  const tokensSaved = Math.max(0, estimatedTokens - SLIM_META_TOKENS);
  const estimatedSavingsPct =
    rawBytes > SLIM_META_BYTES
      ? Number((((rawBytes - SLIM_META_BYTES) / rawBytes) * 100).toFixed(2))
      : 0;

  let bloatPenalty = 0;
  if (estimatedTokens > 25_000) bloatPenalty = 35;
  else if (estimatedTokens > 15_000) bloatPenalty = 25;
  else if (estimatedTokens > 8_000) bloatPenalty = 15;
  if (bloatPenalty > 0) {
    findings.push({
      ruleId: 'MCP_CONTEXT_TAX_BLOAT',
      severity: bloatPenalty >= 25 ? 'HIGH' : 'MEDIUM',
      category: 'context-tax',
      server: '*',
      tool: '*',
      message: `Catalog consumes ~${estimatedTokens.toLocaleString('en-US')} tokens/turn (${rawBytes.toLocaleString('en-US')} bytes). Wrapping with slimmcp-proxy saves ~${tokensSaved.toLocaleString('en-US')} tokens (${estimatedSavingsPct}%).`
    });
  }

  const severityCounts: Record<AuditSeverity, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  for (const f of findings) severityCounts[f.severity] += 1;

  let score = Math.max(0, 100 - securityPenalty - bloatPenalty - missingDescPenalty - weakSchemaPenalty);
  if (severityCounts.CRITICAL > 0) score = Math.min(score, 55);
  const grade = gradeFromScore(score);

  return {
    ok: true,
    score,
    grade,
    totalTools: tools.length,
    rawBytes,
    estimatedTokens,
    slimProxyTokens: SLIM_META_TOKENS,
    tokensSavedWithSlimMcp: tokensSaved,
    estimatedSavingsPct,
    severityCounts,
    topHeaviestTools: [...weights].sort((a, b) => b.bytes - a.bytes).slice(0, 5),
    findings,
    badgePath: `/badge?grade=${grade}&score=${score}&label=mcp-doctor`
  };
}

// ─── Strict XML-Safe Dynamic SVG Badge Generator (Zero XSS Possible) ──────────

function xmlEscape(raw: string): string {
  return raw
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

export function sanitizeBadgeLabel(raw: string | undefined): string {
  const safe = (raw ?? 'mcp-doctor').replace(/[^A-Za-z0-9_./ -]/g, '').trim().slice(0, 42);
  return safe || 'mcp-doctor';
}

export function renderScoreBadgeSvg(input: {
  grade?: string;
  score?: number | string;
  label?: string;
}): string {
  const gradeCandidate = String(input.grade ?? 'F').trim().toUpperCase() as AuditGrade;
  const parsedScore = Number(input.score);
  const safeScore = Number.isFinite(parsedScore)
    ? Math.max(0, Math.min(100, Math.round(parsedScore)))
    : 0;
  const safeGrade = VALID_GRADES.has(gradeCandidate)
    ? gradeCandidate
    : gradeFromScore(safeScore);
  const safeLabel = xmlEscape(sanitizeBadgeLabel(input.label));
  const valueText = xmlEscape(`${safeGrade} (${safeScore}/100)`);

  const colorMap: Record<AuditGrade, string> = {
    A: '#10b981',
    B: '#22c55e',
    C: '#eab308',
    D: '#f97316',
    F: '#ef4444'
  };
  const badgeColor = colorMap[safeGrade];

  const leftWidth = Math.max(78, Math.round(safeLabel.length * 6.8) + 18);
  const rightWidth = 86;
  const totalWidth = leftWidth + rightWidth;

  return `<svg xmlns="http://www.w3.org/2000/svg" width="${totalWidth}" height="20" role="img" aria-label="${safeLabel}: ${valueText}">
  <title>${safeLabel}: ${valueText}</title>
  <rect width="${leftWidth}" height="20" rx="3" fill="#1e293b"/>
  <rect x="${leftWidth}" width="${rightWidth}" height="20" rx="3" fill="${badgeColor}"/>
  <rect x="${leftWidth}" width="4" height="20" fill="${badgeColor}"/>
  <g fill="#ffffff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="11">
    <text x="${Math.round(leftWidth / 2)}" y="14">${safeLabel}</text>
    <text x="${leftWidth + Math.round(rightWidth / 2)}" y="14" font-weight="bold">${valueText}</text>
  </g>
</svg>`;
}

// ─── SSRF-Safe Public GitHub MCP Readiness Scanner ───────────────────────────

const OWNER_SEGMENT_RE = /^[A-Za-z0-9](?:[A-Za-z0-9]|-(?=[A-Za-z0-9])){0,38}$/;

export function parseSafeGithubRepo(repoSlug: string): { owner: string; repo: string } | null {
  const trimmed = repoSlug.trim();
  const parts = trimmed.split('/');
  if (parts.length !== 2) return null;
  const [owner, repo] = parts;
  if (!OWNER_SEGMENT_RE.test(owner) || !REPO_SEGMENT_RE.test(repo)) return null;
  if (repo === '.' || repo === '..' || repo === '.git' || trimmed.includes('..')) {
    return null;
  }
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(repo)) return null;
  return { owner, repo };
}

export interface GithubReadinessReport {
  ok: true;
  repo: string;
  defaultBranch: string;
  score: number;
  grade: AuditGrade;
  badgePath: string;
  checks: {
    hasMitOrOpenSourceLicense: boolean;
    licenseSpdx: string | null;
    hasReadme: boolean;
    hasGlamaJson: boolean;
    hasSmitheryYaml: boolean;
    hasDockerfile: boolean;
    cleanInstallHygiene: boolean;
  };
  notes: string[];
}

function detectLicenseSpdxFromText(licenseText: string | null): string | null {
  if (!licenseText) return null;
  const trimmed = licenseText.trim();
  if (trimmed.length < 20) return null;
  if (/MIT License|Permission is hereby granted, free of charge/i.test(trimmed)) return 'MIT';
  if (/Apache License/i.test(trimmed)) return 'Apache-2.0';
  if (/GNU GENERAL PUBLIC LICENSE/i.test(trimmed)) return 'GPL-3.0';
  if (/BSD (2|3)-Clause|Redistribution and use in source and binary forms/i.test(trimmed)) return 'BSD';
  if (/ISC License/i.test(trimmed)) return 'ISC';
  return 'OPEN_SOURCE';
}

export async function scanPublicGithubRepo(
  owner: string,
  repo: string
): Promise<GithubReadinessReport | { ok: false; status: 404 | 502 | 503; error: string; message: string }> {
  const slug = `${owner}/${repo}`;
  const repoApiUrl = `https://api.github.com/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}`;

  let branch = 'HEAD';
  let licenseSpdx: string | null = null;
  let apiSucceeded = false;

  try {
    const repoRes = await fetch(repoApiUrl, {
      headers: {
        Accept: 'application/vnd.github+json',
        'User-Agent': 'ApexHive-MCP-Doctor/1.0'
      },
      signal: AbortSignal.timeout(5000)
    });

    if (repoRes.status === 404) {
      return { ok: false, status: 404, error: 'REPO_NOT_FOUND', message: `Public GitHub repo ${slug} not found.` };
    }
    if (repoRes.ok) {
      const meta = (await repoRes.json()) as {
        default_branch?: string;
        license?: { spdx_id?: string } | null;
      };
      if (typeof meta.default_branch === 'string' && /^[A-Za-z0-9_.-]+$/.test(meta.default_branch)) {
        branch = meta.default_branch;
      } else {
        branch = 'main';
      }
      licenseSpdx = meta.license?.spdx_id ?? null;
      apiSucceeded = true;
    }
    // Note: on 403/429 (Cloudflare shared IP rate limit) or 5xx, fall through cleanly to raw.githubusercontent.com
  } catch {
    // Network/timeout on api.github.com — fall through cleanly to raw.githubusercontent.com
  }

  async function fetchRawFile(ref: string, filePath: string): Promise<string | null> {
    const rawUrl = `https://raw.githubusercontent.com/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/${encodeURIComponent(ref)}/${filePath}`;
    try {
      const r = await fetch(rawUrl, {
        headers: { 'User-Agent': 'ApexHive-MCP-Doctor/1.0' },
        signal: AbortSignal.timeout(4000)
      });
      return r.ok ? await r.text() : null;
    } catch {
      return null;
    }
  }

  async function fetchBundleForRef(ref: string) {
    const [readmeText, licenseText, glamaText, smitheryText, dockerText, pkgText] = await Promise.all([
      fetchRawFile(ref, 'README.md'),
      fetchRawFile(ref, 'LICENSE'),
      fetchRawFile(ref, 'glama.json'),
      fetchRawFile(ref, 'smithery.yaml'),
      fetchRawFile(ref, 'Dockerfile'),
      fetchRawFile(ref, 'package.json')
    ]);
    const anyFound = Boolean(
      readmeText !== null ||
      licenseText !== null ||
      glamaText !== null ||
      smitheryText !== null ||
      dockerText !== null ||
      pkgText !== null
    );
    return { ref, readmeText, licenseText, glamaText, smitheryText, dockerText, pkgText, anyFound };
  }

  const candidateRefs = apiSucceeded ? [branch] : ['HEAD', 'main', 'master'];
  let bundle = await fetchBundleForRef(candidateRefs[0]);
  if (!bundle.anyFound) {
    for (let i = 1; i < candidateRefs.length; i += 1) {
      const nextBundle = await fetchBundleForRef(candidateRefs[i]);
      if (nextBundle.anyFound) {
        bundle = nextBundle;
        break;
      }
    }
  }

  if (!apiSucceeded && !bundle.anyFound) {
    // Verify whether the repository actually exists on github.com before reporting 404 vs 502
    try {
      const htmlRes = await fetch(`https://github.com/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}`, {
        method: 'HEAD',
        headers: { 'User-Agent': 'ApexHive-MCP-Doctor/1.0' },
        signal: AbortSignal.timeout(4000)
      });
      if (htmlRes.status === 404) {
        return { ok: false, status: 404, error: 'REPO_NOT_FOUND', message: `Public GitHub repo ${slug} not found.` };
      }
      if (!htmlRes.ok && htmlRes.status !== 403 && htmlRes.status !== 429) {
        return {
          ok: false,
          status: 502,
          error: 'GITHUB_UNAVAILABLE',
          message: `GitHub returned HTTP ${htmlRes.status}.`
        };
      }
    } catch (err) {
      return {
        ok: false,
        status: 502,
        error: 'GITHUB_UNAVAILABLE',
        message: err instanceof Error ? err.message : 'GitHub request failed.'
      };
    }
  }

  branch = bundle.ref;
  if (!licenseSpdx || licenseSpdx === 'NOASSERTION') {
    const inferred = detectLicenseSpdxFromText(bundle.licenseText);
    if (inferred) licenseSpdx = inferred;
  }

  const { readmeText, glamaText, smitheryText, dockerText } = bundle;
  const hasMitOrOpenSourceLicense = Boolean(licenseSpdx && licenseSpdx !== 'NOASSERTION');

  const hasReadme = Boolean(readmeText && readmeText.trim().length > 40);
  let hasGlamaJson = false;
  if (glamaText) {
    try {
      const g = JSON.parse(glamaText) as { $schema?: unknown; maintainers?: unknown };
      hasGlamaJson = Boolean(g && typeof g.$schema === 'string' && Array.isArray(g.maintainers) && g.maintainers.length > 0);
    } catch {
      hasGlamaJson = false;
    }
  }
  const hasSmitheryYaml = Boolean(smitheryText && smitheryText.includes('startCommand'));
  const hasDockerfile = Boolean(dockerText && /FROM\s+/i.test(dockerText));
  const cleanInstallHygiene = !readmeText || !/\bnpx\s+-y\s+@[a-z0-9-]+\/slimmcp|\bnpx\s+mcp-doctor/i.test(readmeText);

  let score = 0;
  const notes: string[] = [];
  if (hasMitOrOpenSourceLicense) score += 25;
  else notes.push('Missing root Open-Source LICENSE detected by GitHub API.');

  if (hasReadme) score += 20;
  else notes.push('Missing or minimal root README.md.');

  if (cleanInstallHygiene) score += 15;
  else notes.push('README references unverified package CLI shims.');

  if (hasGlamaJson) score += 15;
  else notes.push('Missing valid root glama.json ($schema + maintainers).');

  if (hasSmitheryYaml) score += 15;
  else notes.push('Missing root smithery.yaml manifest.');

  if (hasDockerfile) score += 10;
  else notes.push('Missing root Dockerfile for container registry checks.');

  const grade = gradeFromScore(score);
  return {
    ok: true,
    repo: slug,
    defaultBranch: branch,
    score,
    grade,
    badgePath: `/badge/repo/${owner}/${repo}.svg`,
    checks: {
      hasMitOrOpenSourceLicense,
      licenseSpdx,
      hasReadme,
      hasGlamaJson,
      hasSmitheryYaml,
      hasDockerfile,
      cleanInstallHygiene
    },
    notes
  };
}
