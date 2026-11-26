import { z } from 'zod';
import type {
  AuditFinding,
  AuditGrade,
  AuditReport,
  AuditSeverity,
  McpToolInput,
  ServerAuditSummary,
  TeamPolicyConfig,
  ToolWeight
} from './types.js';
import { MCP_DOCTOR_VERSION } from './version.js';

export const MAX_COLLECT_DEPTH = 32;
export const MAX_COLLECTED_STRINGS = 10_000;

const SEVERITY_RANK: Record<AuditSeverity, number> = {
  LOW: 1,
  MEDIUM: 2,
  HIGH: 3,
  CRITICAL: 4
};

export const TeamPolicySchema = z
  .object({
    minScore: z.number().finite().min(0).max(100).optional(),
    failOnSeverity: z.enum(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']).optional(),
    blockPromptInjection: z.boolean().optional(),
    maxTotalTokens: z.number().int().positive().optional(),
    denyTools: z.array(z.string().min(1)).optional()
  })
  .strict();

export function parseTeamPolicy(raw: unknown): TeamPolicyConfig {
  const result = TeamPolicySchema.safeParse(raw);
  if (!result.success) {
    const details = result.error.issues
      .map((issue) => `${issue.path.join('.') || '<root>'}: ${issue.message}`)
      .join('; ');
    throw new Error(`Invalid TeamPolicyConfig: ${details}`);
  }
  return result.data;
}

interface PatternRule {
  ruleId: string;
  severity: AuditSeverity;
  category: 'prompt-injection' | 'secret-leak';
  regex?: RegExp;
  match?: (text: string) => string | null;
  message: string;
}

const EXFIL_DIRECT_RE = /\b(exfiltrate|steal|leak)\b/i;
const EXFIL_TARGET_RE = /(?:~\/\.ssh|id_rsa|\.env\b|private[_ -]?key|seed\s*phrase)/i;
const EXFIL_VERB_RE = /\b(send|post|upload|curl|fetch|http)\b/i;
const EXFIL_PIPE_SHELL_RE = /\b(?:curl|wget)\b[^\r\n|]{0,200}\|\s*(?:sh|bash)\b/i;

const SECRET_RULES: PatternRule[] = [
  {
    ruleId: 'MCP_SEC_AWS_KEY',
    severity: 'CRITICAL',
    category: 'secret-leak',
    regex: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/,
    message: 'Exposed AWS Access Key ID detected in tool catalog metadata.'
  },
  {
    ruleId: 'MCP_SEC_GITHUB_TOKEN',
    severity: 'CRITICAL',
    category: 'secret-leak',
    regex: /\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})\b/,
    message: 'Exposed GitHub Personal Access Token detected in tool catalog metadata.'
  },
  {
    ruleId: 'MCP_SEC_API_KEY',
    severity: 'CRITICAL',
    category: 'secret-leak',
    regex: /\b(?:sk_live_[0-9A-Za-z]{16,}|sk-(?:proj-|ant-)?[A-Za-z0-9_-]{20,}|xox[baprs]-[0-9A-Za-z-]{10,})\b/,
    message: 'Exposed API token (Stripe/OpenAI/Anthropic/Slack) detected in tool catalog metadata.'
  },
  {
    ruleId: 'MCP_SEC_PEM_OR_JWT',
    severity: 'CRITICAL',
    category: 'secret-leak',
    regex: /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----|eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/,
    message: 'Exposed PEM private key or JWT token detected in tool catalog metadata.'
  }
];

const INJECTION_AND_SECRET_RULES: PatternRule[] = [
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
    regex: /<\s*(?:\/\s*)?(?:system|instructions|important|developer|tool_override)\b[^>]*>|\[SYSTEM\]/i,
    message: 'Suspicious hidden XML/bracket system tag inside tool metadata.'
  },
  {
    ruleId: 'MCP_PI_EXFILTRATION',
    severity: 'CRITICAL',
    category: 'prompt-injection',
    match: (text: string): string | null => {
      const direct = text.match(EXFIL_DIRECT_RE);
      if (direct) return direct[0];
      const piped = text.match(EXFIL_PIPE_SHELL_RE);
      if (piped) return piped[0];
      const target = text.match(EXFIL_TARGET_RE);
      if (target && EXFIL_VERB_RE.test(text)) {
        return target[0];
      }
      return null;
    },
    message: 'Tool poisoning pattern instructing sensitive file/secret exfiltration.'
  },
  {
    ruleId: 'MCP_PI_STEALTH_URI_OR_ZW',
    severity: 'HIGH',
    category: 'prompt-injection',
    regex: /(?:data:text\/html|javascript:|[\u200B-\u200F\u202A-\u202E\u2060-\u2069\uFEFF\u{E0000}-\u{E007F}])/iu,
    message: 'Suspicious script/data URI or hidden zero-width/BiDi/tag Unicode characters in tool metadata.'
  },
  {
    ruleId: 'MCP_PI_SHELL_DANGER',
    severity: 'HIGH',
    category: 'prompt-injection',
    regex: /\b(?:rm\s+-rf\s+\/|powershell\s+-enc|child_process\.exec)\b/i,
    message: 'Dangerous shell execution directive embedded in tool schema or description.'
  },
  ...SECRET_RULES
];

const EXTRA_RULE_METADATA: Array<{
  ruleId: string;
  severity: AuditSeverity;
  category: AuditFinding['category'];
  message: string;
}> = [
  {
    ruleId: 'MCP_SCHEMA_MISSING_DESCRIPTION',
    severity: 'MEDIUM',
    category: 'schema-quality',
    message: 'Tool description is missing or shorter than 12 characters.'
  },
  {
    ruleId: 'MCP_SCHEMA_UNTYPED',
    severity: 'LOW',
    category: 'schema-quality',
    message: 'Tool inputSchema lacks typed properties.'
  },
  {
    ruleId: 'MCP_SCAN_TRUNCATED',
    severity: 'HIGH',
    category: 'schema-quality',
    message: 'Tool schema inspection exceeded depth or string limits and was truncated fail-closed.'
  },
  {
    ruleId: 'MCP_POLICY_DENIED_TOOL',
    severity: 'HIGH',
    category: 'policy',
    message: 'Tool matched a Team policy denyTools glob pattern.'
  },
  {
    ruleId: 'MCP_CONTEXT_TAX_BLOAT',
    severity: 'MEDIUM',
    category: 'context-tax',
    message: 'Tool catalog consumes excessive prompt context tokens.'
  },
  {
    ruleId: 'MCP_POLICY_TOKEN_BUDGET',
    severity: 'HIGH',
    category: 'policy',
    message: 'Estimated catalog tokens exceed policy maxTotalTokens.'
  }
];

export function maskSecret(secret: string): string {
  if (secret.length <= 8) {
    return '[REDACTED]';
  }
  return `${secret.slice(0, 4)}***REDACTED***`;
}

function sanitizePromptEvidence(text: string): string {
  let sanitized = text;
  for (const rule of SECRET_RULES) {
    if (!rule.regex) continue;
    const globalRe = new RegExp(
      rule.regex.source,
      rule.regex.flags.includes('g') ? rule.regex.flags : `${rule.regex.flags}g`
    );
    sanitized = sanitized.replace(globalRe, (match) => maskSecret(match));
  }
  return sanitized.slice(0, 64);
}

const INVISIBLE_OBFUSCATION_RE =
  /[\u200B-\u200F\u202A-\u202E\u2060-\u2069\uFEFF\u{E0000}-\u{E007F}]/gu;

function stripInvisibleObfuscation(text: string): string {
  return text.replace(INVISIBLE_OBFUSCATION_RE, '');
}

function matchRule(rule: PatternRule, text: string): string | null {
  const normalized = stripInvisibleObfuscation(text);
  const candidates = normalized !== text ? [text, normalized] : [text];

  for (const candidate of candidates) {
    if (rule.match) {
      const m = rule.match(candidate);
      if (m !== null) return m;
    } else if (rule.regex) {
      rule.regex.lastIndex = 0;
      const m = candidate.match(rule.regex);
      if (m) return m[0];
    }
  }
  return null;
}

export interface CollectStringsState {
  truncated: boolean;
  reasons: Set<'max-depth' | 'max-strings'>;
}

export function collectStrings(
  value: unknown,
  out: string[] = [],
  depth = 0,
  visited: WeakSet<object> = new WeakSet<object>(),
  state?: CollectStringsState
): string[] {
  if (out.length >= MAX_COLLECTED_STRINGS) {
    if (state) {
      state.truncated = true;
      state.reasons.add('max-strings');
    }
    return out;
  }
  if (typeof value === 'string') {
    out.push(value);
    return out;
  }
  if (value === null || typeof value !== 'object') {
    return out;
  }
  if (visited.has(value)) {
    return out;
  }
  if (depth >= MAX_COLLECT_DEPTH) {
    if (state) {
      state.truncated = true;
      state.reasons.add('max-depth');
    }
    return out;
  }
  visited.add(value);

  if (Array.isArray(value)) {
    for (const item of value) {
      if (out.length >= MAX_COLLECTED_STRINGS) {
        if (state) {
          state.truncated = true;
          state.reasons.add('max-strings');
        }
        break;
      }
      collectStrings(item, out, depth + 1, visited, state);
    }
  } else {
    for (const [k, v] of Object.entries(value)) {
      if (out.length >= MAX_COLLECTED_STRINGS) {
        if (state) {
          state.truncated = true;
          state.reasons.add('max-strings');
        }
        break;
      }
      out.push(k);
      collectStrings(v, out, depth + 1, visited, state);
    }
  }
  return out;
}

function safeJsonStringify(value: unknown): string {
  try {
    return JSON.stringify(value) ?? '';
  } catch {
    const seen = new WeakSet<object>();
    const sanitize = (v: unknown, depth: number): unknown => {
      if (v === null || typeof v !== 'object') {
        return typeof v === 'bigint' ? v.toString() : v;
      }
      if (depth >= MAX_COLLECT_DEPTH) return '[MaxDepth]';
      if (seen.has(v)) return '[Circular]';
      seen.add(v);
      if (Array.isArray(v)) {
        return v.map((item) => sanitize(item, depth + 1));
      }
      const obj: Record<string, unknown> = {};
      for (const [k, val] of Object.entries(v)) {
        obj[k] = sanitize(val, depth + 1);
      }
      return obj;
    };
    return JSON.stringify(sanitize(value, 0)) ?? '';
  }
}

export function gradeFromScore(score: number): AuditGrade {
  if (score >= 90) return 'A';
  if (score >= 80) return 'B';
  if (score >= 70) return 'C';
  if (score >= 55) return 'D';
  return 'F';
}

function matchesGlob(pattern: string, input: string): boolean {
  const p = pattern.toLowerCase();
  const s = input.toLowerCase();
  let pi = 0;
  let si = 0;
  let starIdx = -1;
  let matchIdx = 0;

  while (si < s.length) {
    if (pi < p.length && (p[pi] === '?' || p[pi] === s[si])) {
      pi++;
      si++;
    } else if (pi < p.length && p[pi] === '*') {
      starIdx = pi;
      matchIdx = si;
      pi++;
    } else if (starIdx !== -1) {
      pi = starIdx + 1;
      matchIdx++;
      si = matchIdx;
    } else {
      return false;
    }
  }

  while (pi < p.length && p[pi] === '*') {
    pi++;
  }
  return pi === p.length;
}

export function auditMcpTools(
  tools: McpToolInput[],
  options?: { policy?: TeamPolicyConfig }
): AuditReport {
  const policy = options?.policy ? parseTeamPolicy(options.policy) : undefined;
  const encoder = new TextEncoder();
  const findings: AuditFinding[] = [];
  const weights: ToolWeight[] = [];
  const serverMap = new Map<string, { tools: McpToolInput[]; bytes: number }>();

  let missingDescPenalty = 0;
  let weakSchemaPenalty = 0;
  let securityPenalty = 0;
  let hasTruncatedScan = false;

  for (const tool of tools) {
    const server = (tool.server || 'default').trim() || 'default';
    const name = String(tool.name || '').trim() || '<unnamed>';
    const serialized = safeJsonStringify({
      name,
      description: tool.description ?? '',
      inputSchema: tool.inputSchema ?? {}
    });
    const bytes = encoder.encode(serialized).length;
    const tokens = Math.ceil(bytes / 4);
    weights.push({ server, name, bytes, tokens });

    const entry = serverMap.get(server) ?? { tools: [], bytes: 0 };
    entry.tools.push(tool);
    entry.bytes += bytes;
    serverMap.set(server, entry);

    // 1. Scan all text inside name, description, and inputSchema for prompt injection & secrets
    const scanState: CollectStringsState = {
      truncated: false,
      reasons: new Set<'max-depth' | 'max-strings'>()
    };
    const allTexts = collectStrings(
      {
        name,
        description: tool.description ?? '',
        inputSchema: tool.inputSchema ?? {}
      },
      [],
      0,
      new WeakSet<object>(),
      scanState
    );
    const seenRules = new Set<string>();
    for (const txt of allTexts) {
      for (const rule of INJECTION_AND_SECRET_RULES) {
        if (seenRules.has(rule.ruleId)) continue;
        const matched = matchRule(rule, txt);
        if (matched !== null) {
          seenRules.add(rule.ruleId);
          const evidence =
            rule.category === 'secret-leak' ? maskSecret(matched) : sanitizePromptEvidence(matched);
          findings.push({
            ruleId: rule.ruleId,
            severity: rule.severity,
            category: rule.category,
            server,
            tool: name,
            message: rule.message,
            evidence
          });
          securityPenalty += rule.severity === 'CRITICAL' ? 35 : 15;
        }
      }
    }

    if (scanState.truncated) {
      hasTruncatedScan = true;
      findings.push({
        ruleId: 'MCP_SCAN_TRUNCATED',
        severity: 'HIGH',
        category: 'schema-quality',
        server,
        tool: name,
        message: `Tool schema inspection truncated (${[...scanState.reasons].join(', ')}); deeper fields could not be scanned.`
      });
      securityPenalty += 35;
    }

    // 2. Schema & description quality checks
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

    const schema = tool.inputSchema;
    const hasNonEmptyProps =
      Boolean(schema?.properties) &&
      typeof schema?.properties === 'object' &&
      !Array.isArray(schema?.properties) &&
      Object.keys(schema!.properties as Record<string, unknown>).length > 0;
    const hasExplicitNonObjectType =
      typeof schema?.type === 'string' && schema.type.trim() !== '' && schema.type !== 'object';
    const hasProps =
      Boolean(schema) &&
      typeof schema === 'object' &&
      !Array.isArray(schema) &&
      (hasNonEmptyProps || hasExplicitNonObjectType);
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

    // 3. Optional Team Policy denyTools rules
    if (policy?.denyTools) {
      for (const pattern of policy.denyTools) {
        if (matchesGlob(pattern, `${server}:${name}`) || matchesGlob(pattern, name)) {
          findings.push({
            ruleId: 'MCP_POLICY_DENIED_TOOL',
            severity: 'HIGH',
            category: 'policy',
            server,
            tool: name,
            message: `Tool matches Team policy deny pattern "${pattern}".`
          });
          securityPenalty += 15;
        }
      }
    }
  }

  const rawBytes = encoder.encode(safeJsonStringify({ tools })).length;
  const estimatedTokens = Math.ceil(rawBytes / 4);

  // Context-tax bloat penalties
  let bloatPenalty = 0;
  if (estimatedTokens > 25_000) {
    bloatPenalty = 35;
  } else if (estimatedTokens > 15_000) {
    bloatPenalty = 25;
  } else if (estimatedTokens > 8_000) {
    bloatPenalty = 15;
  }
  if (bloatPenalty > 0) {
    findings.push({
      ruleId: 'MCP_CONTEXT_TAX_BLOAT',
      severity: bloatPenalty >= 25 ? 'HIGH' : 'MEDIUM',
      category: 'context-tax',
      server: '*',
      tool: '*',
      message: `Catalog consumes ~${estimatedTokens.toLocaleString('en-US')} tokens/turn (${rawBytes.toLocaleString('en-US')} UTF-8 bytes), exceeding recommended prompt context budgets.`
    });
  }

  if (policy?.maxTotalTokens && estimatedTokens > policy.maxTotalTokens) {
    findings.push({
      ruleId: 'MCP_POLICY_TOKEN_BUDGET',
      severity: 'HIGH',
      category: 'policy',
      server: '*',
      tool: '*',
      message: `Estimated tokens (${estimatedTokens}) exceed policy maxTotalTokens (${policy.maxTotalTokens}).`
    });
    securityPenalty += 15;
  }

  const severityCounts: Record<AuditSeverity, number> = {
    CRITICAL: 0,
    HIGH: 0,
    MEDIUM: 0,
    LOW: 0
  };
  for (const f of findings) {
    severityCounts[f.severity] += 1;
  }

  let score = Math.max(
    0,
    100 - securityPenalty - bloatPenalty - missingDescPenalty - weakSchemaPenalty
  );
  // Any CRITICAL poisoning or secret finding caps grade at <= D (score <= 55)
  if (severityCounts.CRITICAL > 0) {
    score = Math.min(score, 55);
  }
  // Truncated scans fail-closed (never silently return Grade A / passing score)
  if (hasTruncatedScan) {
    score = Math.min(score, 65);
  }

  const grade = gradeFromScore(score);
  const topHeaviestTools = [...weights].sort((a, b) => b.bytes - a.bytes).slice(0, 5);
  const servers: ServerAuditSummary[] = [...serverMap.entries()].map(([server, info]) => ({
    server,
    toolCount: info.tools.length,
    rawBytes: info.bytes,
    estimatedTokens: Math.ceil(info.bytes / 4)
  }));

  const minScoreThreshold = policy?.minScore ?? 70;
  const failSeverity = policy?.failOnSeverity ?? 'CRITICAL';
  const failRank = SEVERITY_RANK[failSeverity];
  const hasPolicyViolation = findings.some((f) => f.category === 'policy');
  const hasDisallowedSeverity = findings.some((f) => SEVERITY_RANK[f.severity] >= failRank);
  const hasBlockedInjection =
    policy?.blockPromptInjection === true &&
    findings.some((f) => f.category === 'prompt-injection');

  const ok =
    !hasTruncatedScan &&
    !hasPolicyViolation &&
    !hasDisallowedSeverity &&
    !hasBlockedInjection &&
    severityCounts.CRITICAL === 0 &&
    score >= minScoreThreshold;

  return {
    ok,
    score,
    grade,
    totalServers: servers.length,
    totalTools: tools.length,
    rawBytes,
    estimatedTokens,
    severityCounts,
    topHeaviestTools,
    servers,
    findings
  };
}

export function toSarifReport(report: AuditReport) {
  const levelMap: Record<AuditSeverity, 'error' | 'warning' | 'note'> = {
    CRITICAL: 'error',
    HIGH: 'error',
    MEDIUM: 'warning',
    LOW: 'note'
  };

  const ruleDescriptors = [
    ...INJECTION_AND_SECRET_RULES.map((r) => ({
      id: r.ruleId,
      name: r.ruleId,
      shortDescription: { text: r.message },
      defaultConfiguration: { level: levelMap[r.severity] },
      properties: { severity: r.severity, category: r.category }
    })),
    ...EXTRA_RULE_METADATA.map((r) => ({
      id: r.ruleId,
      name: r.ruleId,
      shortDescription: { text: r.message },
      defaultConfiguration: { level: levelMap[r.severity] },
      properties: { severity: r.severity, category: r.category }
    }))
  ];

  return {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'mcp-doctor',
            version: MCP_DOCTOR_VERSION,
            informationUri: 'https://github.com/apexhive-hq/mcp-doctor',
            rules: ruleDescriptors
          }
        },
        results: report.findings.map((f) => ({
          ruleId: f.ruleId,
          level: levelMap[f.severity],
          message: { text: `[${f.server}:${f.tool}] ${f.message}` },
          locations: [
            {
              physicalLocation: {
                artifactLocation: {
                  uri:
                    f.server === '*'
                      ? 'mcp-catalog.json'
                      : `mcp-servers/${encodeURIComponent(f.server)}.json`
                },
                region: { startLine: 1 }
              },
              logicalLocations: [
                {
                  name: `${f.server}:${f.tool}`,
                  fullyQualifiedName: `${f.server}:${f.tool}`,
                  kind: 'function'
                }
              ]
            }
          ],
          properties: {
            severity: f.severity,
            category: f.category,
            server: f.server,
            tool: f.tool
          }
        }))
      }
    ]
  };
}
