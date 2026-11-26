#!/usr/bin/env node
import { readFileSync } from 'node:fs';
import { auditMcpTools, toSarifReport } from './auditor.js';
import { introspectStdioServers, loadServerSpecsFromConfig } from './stdio-client.js';
import type { AuditReport, McpToolInput, TeamPolicyConfig } from './types.js';

function getFlagValue(args: string[], flag: string): string | undefined {
  const idx = args.indexOf(flag);
  if (idx >= 0 && idx + 1 < args.length) return args[idx + 1];
  return undefined;
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
  console.log(`mcp-doctor v1.0.1 — Free MIT MCP Security, Secret-Leak & Context-Tax Linter

Usage:
  mcp-doctor audit (--config <mcp-servers.json> | --tools-file <tools.json>) [options]
  mcp-doctor status
  mcp-doctor --help

Options:
  --policy <policy.json>   Apply TeamPolicyConfig thresholds & deny globs
  --sarif                  Emit SARIF 2.1.0 JSON report
  --json                   Emit AuditReport JSON
  --ci                     Exit non-zero if score < min-score or CRITICAL findings exist
  --min-score <0-100>      Minimum passing score for --ci (default: 70)
`);
}

async function main() {
  const [, , cmd = 'help', ...args] = process.argv;

  if (cmd === 'help' || cmd === '--help' || cmd === '-h' || args.includes('--help') || args.includes('-h')) {
    printHelp();
    return;
  }

  if (cmd === 'status') {
    console.log(
      JSON.stringify(
        {
          mode: 'open-source-mit',
          license: 'MIT',
          version: '1.0.1',
          features: ['audit', 'sarif', 'policy', 'ci-gate']
        },
        null,
        2
      )
    );
    return;
  }

  if (cmd !== 'audit') {
    console.error('Usage: mcp-doctor <audit|status|--help> [options]');
    process.exit(1);
  }

  const configPath = getFlagValue(args, '--config');
  const toolsFile = getFlagValue(args, '--tools-file');
  const policyPath = getFlagValue(args, '--policy');
  const isJson = args.includes('--json');
  const isSarif = args.includes('--sarif');
  const isCi = args.includes('--ci');
  const minScoreRaw = getFlagValue(args, '--min-score');
  const minScore = minScoreRaw !== undefined ? Number(minScoreRaw) : 70;

  if (!configPath && !toolsFile) {
    console.error('Provide either --config <mcp-servers.json> or --tools-file <tools.json>.');
    process.exit(1);
  }

  const policy = policyPath
    ? (JSON.parse(readFileSync(policyPath, 'utf8')) as TeamPolicyConfig)
    : undefined;

  const tools = configPath
    ? await introspectStdioServers(loadServerSpecsFromConfig(configPath))
    : loadToolsFile(toolsFile!);

  const report = auditMcpTools(tools, { policy });
  if (isSarif) {
    console.log(JSON.stringify(toSarifReport(report), null, 2));
  } else if (isJson) {
    console.log(JSON.stringify(report, null, 2));
  } else {
    console.log(formatHumanReport(report));
  }

  if (isCi) {
    const threshold = policy?.minScore ?? minScore;
    if (report.score < threshold || report.severityCounts.CRITICAL > 0) {
      process.exit(1);
    }
  }
}

main().catch((err) => {
  console.error(err instanceof Error ? err.message : String(err));
  process.exit(1);
});
