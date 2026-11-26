#!/usr/bin/env node
import { readFileSync } from 'node:fs';
import { auditMcpTools, parseTeamPolicy, toSarifReport } from './auditor.js';
import { introspectStdioServers, loadServerSpecsFromConfig } from './stdio-client.js';
import type { AuditReport, McpToolInput, TeamPolicyConfig } from './types.js';
import { MCP_DOCTOR_VERSION } from './version.js';

function getRequiredFlagValue(args: string[], flag: string): string | undefined {
  const idx = args.indexOf(flag);
  if (idx < 0) return undefined;
  const val = args[idx + 1];
  if (val === undefined || val.startsWith('--')) {
    throw new Error(`${flag} requires a value.`);
  }
  return val;
}

function loadToolsFile(filePath: string): McpToolInput[] {
  const parsed = JSON.parse(readFileSync(filePath, 'utf8')) as
    | McpToolInput[]
    | { tools?: McpToolInput[]; result?: { tools?: McpToolInput[] } };
  if (Array.isArray(parsed)) return parsed;
  if (parsed && Array.isArray(parsed.tools)) return parsed.tools;
  if (parsed && parsed.result && Array.isArray(parsed.result.tools)) return parsed.result.tools;
  throw new Error('Tools JSON must be an array or { tools: [...] } object.');
}

function formatHumanReport(report: AuditReport): string {
  const lines = [
    `=== mcp-doctor Static MCP Audit (MIT Open Source) ===`,
    `Score:       ${report.score}/100 (Grade ${report.grade})`,
    `Servers:     ${report.totalServers} | Tools: ${report.totalTools}`,
    `Context Tax: ${report.rawBytes.toLocaleString('en-US')} bytes (~${report.estimatedTokens.toLocaleString('en-US')} tokens)`,
    `Findings:    CRITICAL=${report.severityCounts.CRITICAL} HIGH=${report.severityCounts.HIGH} MEDIUM=${report.severityCounts.MEDIUM} LOW=${report.severityCounts.LOW}`
  ];
  if (report.findings.length > 0) {
    lines.push('', 'Alerts:');
    for (const f of report.findings.slice(0, 15)) {
      lines.push(`- [${f.severity}] (${f.server}:${f.tool}) ${f.ruleId}: ${f.message}`);
    }
  }
  return lines.join('\n');
}

function printHelp(): void {
  console.log(`mcp-doctor v${MCP_DOCTOR_VERSION} — Free MIT MCP Security, Secret-Leak & Context-Tax Linter

Usage:
  mcp-doctor audit (--config <mcp-servers.json> | --tools-file <tools.json>) [options]
  mcp-doctor status
  mcp-doctor --version
  mcp-doctor --help

Options:
  --policy <policy.json>   Apply TeamPolicyConfig thresholds & deny globs
  --sarif                  Emit SARIF 2.1.0 JSON report
  --json                   Emit AuditReport JSON
  --ci                     Exit non-zero if policy fails, score < min-score, or CRITICAL findings exist
  --min-score <0-100>      Minimum passing score for --ci (default: 70)
  --version, -v            Print CLI version
`);
}

async function main() {
  const [, , cmd = 'help', ...args] = process.argv;

  if (cmd === 'help' || cmd === '--help' || cmd === '-h' || args.includes('--help') || args.includes('-h')) {
    printHelp();
    return;
  }

  if (cmd === '--version' || cmd === '-v' || cmd === '-V' || args.includes('--version') || args.includes('-v')) {
    console.log(MCP_DOCTOR_VERSION);
    return;
  }

  if (cmd === 'status') {
    console.log(
      JSON.stringify(
        {
          mode: 'open-source-mit',
          license: 'MIT',
          version: MCP_DOCTOR_VERSION,
          features: ['audit', 'sarif', 'policy', 'ci-gate']
        },
        null,
        2
      )
    );
    return;
  }

  if (cmd !== 'audit') {
    console.error('Usage: mcp-doctor <audit|status|--version|--help> [options]');
    process.exit(1);
  }

  const configPath = getRequiredFlagValue(args, '--config');
  const toolsFile = getRequiredFlagValue(args, '--tools-file');
  const policyPath = getRequiredFlagValue(args, '--policy');
  const isJson = args.includes('--json');
  const isSarif = args.includes('--sarif');
  const isCi = args.includes('--ci');
  const minScoreRaw = getRequiredFlagValue(args, '--min-score');

  let minScoreProvided = false;
  let minScore = 70;
  if (minScoreRaw !== undefined) {
    minScoreProvided = true;
    const parsedScore = Number(minScoreRaw.trim());
    if (minScoreRaw.trim() === '' || !Number.isFinite(parsedScore) || parsedScore < 0 || parsedScore > 100) {
      console.error('--min-score must be a finite number between 0 and 100.');
      process.exit(1);
    }
    minScore = parsedScore;
  }

  if (!configPath && !toolsFile) {
    console.error('Provide either --config <mcp-servers.json> or --tools-file <tools.json>.');
    process.exit(1);
  }

  const policy: TeamPolicyConfig | undefined = policyPath
    ? parseTeamPolicy(JSON.parse(readFileSync(policyPath, 'utf8')))
    : undefined;

  const effectiveMinScore =
    policy?.minScore !== undefined
      ? minScoreProvided
        ? Math.max(policy.minScore, minScore)
        : policy.minScore
      : minScore;

  const effectivePolicy: TeamPolicyConfig | undefined =
    policy || minScoreProvided ? { ...(policy ?? {}), minScore: effectiveMinScore } : undefined;

  const tools = configPath
    ? await introspectStdioServers(loadServerSpecsFromConfig(configPath))
    : loadToolsFile(toolsFile!);

  const report = auditMcpTools(tools, { policy: effectivePolicy });
  if (isSarif) {
    console.log(JSON.stringify(toSarifReport(report), null, 2));
  } else if (isJson) {
    console.log(JSON.stringify(report, null, 2));
  } else {
    console.log(formatHumanReport(report));
  }

  if (isCi) {
    if (!report.ok || report.score < effectiveMinScore || report.severityCounts.CRITICAL > 0) {
      process.exit(1);
    }
  }
}

main().catch((err) => {
  console.error(err instanceof Error ? err.message : String(err));
  process.exit(1);
});
