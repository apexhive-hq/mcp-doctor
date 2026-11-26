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

interface PatternRule {
  ruleId: string;
  severity: AuditSeverity;
  category: 'prompt-injection' | 'secret-leak';
  regex: RegExp;
  message: string;
}

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
    message: 'Suspicious script/data URI or hidden zero-width Unicode characters in tool metadata.'
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

function collectStrings(value: unknown, out: string[] = []): string[] {
  if (typeof value === 'string') {
    out.push(value);
  } else if (Array.isArray(value)) {
    for (const item of value) collectStrings(item, out);
  } else if (value && typeof value === 'object') {
    for (const [k, v] of Object.entries(value)) {
      out.push(k);
      collectStrings(v, out);
    }
  }
  return out;
}

export function gradeFromScore(score: number): AuditGrade {
  if (score >= 90) return 'A';
  if (score >= 80) return 'B';
  if (score >= 70) return 'C';
  if (score >= 55) return 'D';
  return 'F';
}

function globToRegex(glob: string): RegExp {
  const escaped = glob
    .replace(/[.+^${}()|[\]\\]/g, '\\$&')
    .replace(/\*/g, '.*')
    .replace(/\?/g, '.');
  return new RegExp(`^${escaped}$`, 'i');
}

export function auditMcpTools(
  tools: McpToolInput[],
  options?: { policy?: TeamPolicyConfig }
): AuditReport {
  const encoder = new TextEncoder();
  const findings: AuditFinding[] = [];
  const weights: ToolWeight[] = [];
  const serverMap = new Map<string, { tools: McpToolInput[]; bytes: number }>();

  let missingDescPenalty = 0;
  let weakSchemaPenalty = 0;
  let securityPenalty = 0;

  for (const tool of tools) {
    const server = (tool.server || 'default').trim() || 'default';
    const name = String(tool.name || '').trim() || '<unnamed>';
    const serialized = JSON.stringify({
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
    const allTexts = collectStrings({
      name,
      description: tool.description ?? '',
      inputSchema: tool.inputSchema ?? {}
    });
    const seenRules = new Set<string>();
    for (const txt of allTexts) {
      for (const rule of INJECTION_AND_SECRET_RULES) {
        if (seenRules.has(rule.ruleId)) continue;
        rule.regex.lastIndex = 0;
        const m = txt.match(rule.regex);
        if (m) {
          seenRules.add(rule.ruleId);
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

    // 3. Optional Team Policy denyTools rules
    if (options?.policy?.denyTools) {
      for (const pattern of options.policy.denyTools) {
        const re = globToRegex(pattern);
        if (re.test(`${server}:${name}`) || re.test(name)) {
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

  const rawBytes = encoder.encode(JSON.stringify({ tools })).length;
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

  if (options?.policy?.maxTotalTokens && estimatedTokens > options.policy.maxTotalTokens) {
    findings.push({
      ruleId: 'MCP_POLICY_TOKEN_BUDGET',
      severity: 'HIGH',
      category: 'policy',
      server: '*',
      tool: '*',
      message: `Estimated tokens (${estimatedTokens}) exceed policy maxTotalTokens (${options.policy.maxTotalTokens}).`
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

  const grade = gradeFromScore(score);
  const topHeaviestTools = [...weights].sort((a, b) => b.bytes - a.bytes).slice(0, 5);
  const servers: ServerAuditSummary[] = [...serverMap.entries()].map(([server, info]) => ({
    server,
    toolCount: info.tools.length,
    rawBytes: info.bytes,
    estimatedTokens: Math.ceil(info.bytes / 4)
  }));

  return {
    ok: severityCounts.CRITICAL === 0 && score >= (options?.policy?.minScore ?? 70),
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
  return {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'mcp-doctor',
            version: '1.0.1',
            informationUri: 'https://github.com/apexhive-hq/mcp-doctor'
          }
        },
        results: report.findings.map((f) => ({
          ruleId: f.ruleId,
          level: levelMap[f.severity],
          message: { text: `[${f.server}:${f.tool}] ${f.message}` },
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
