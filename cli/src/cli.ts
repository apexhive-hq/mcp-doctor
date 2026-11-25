#!/usr/bin/env node
import { readFileSync } from 'node:fs';
import { auditMcpTools, toSarifReport } from './auditor.js';
import { loadActivatedLicense, saveActivatedLicense } from './license.js';
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
    `=== ApexHive Labs mcp-doctor Audit ===`,
    `Score:       ${report.score}/100 (Grade ${report.grade})`,
    `Servers:     ${report.totalServers} | Tools: ${report.totalTools}`,
    `Context Tax: ${report.rawBytes.toLocaleString('en-US')} bytes (~${report.estimatedTokens.toLocaleString('en-US')} tokens)`,
    `SlimMCP Est: ~${report.slimProxyTokens} tokens (${report.estimatedSavingsPct}% reduction, saves ~${report.tokensSavedWithSlimMcp.toLocaleString('en-US')} tok/turn)`,
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

async function main() {
  const [, , cmd = 'audit', ...args] = process.argv;

  if (cmd === 'activate') {
    const token = getFlagValue(args, '--token');
    if (!token) {
      console.error('Usage: node dist/src/cli.js activate --token "<MCPDOC-PRO-v1...>"');
      process.exit(1);
    }
    const { filePath, verification } = saveActivatedLicense(token);
    console.log(
      JSON.stringify(
        {
          ok: true,
          filePath,
          tier: verification.payload?.tier,
          payer: verification.payload?.payer
        },
        null,
        2
      )
    );
    return;
  }

  if (cmd === 'status') {
    const status = loadActivatedLicense();
    console.log(
      JSON.stringify(
        {
          mode: status.valid ? status.payload?.tier : 'open-source-mit',
          valid: status.valid,
          reason: status.reason ?? null,
          payload: status.payload ?? null
        },
        null,
        2
      )
    );
    return;
  }

  if (cmd !== 'audit') {
    console.error('Usage: node dist/src/cli.js <audit|activate|status> [options]');
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

  let policy: TeamPolicyConfig | undefined;
  if (policyPath || isSarif) {
    const lic = loadActivatedLicense();
    if (!lic.valid || lic.payload?.tier !== 'team') {
      console.error(
        `Team Commercial License required for --policy/--sarif (Open-Core MIT audit/--json/--ci stays free at $0). Activate via https://mcp-doctor-store.apexhive-hq.workers.dev. (${lic.reason ?? 'no license'})`
      );
      process.exit(2);
    }
    if (policyPath) {
      policy = JSON.parse(readFileSync(policyPath, 'utf8')) as TeamPolicyConfig;
    }
  }

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
