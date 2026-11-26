import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';
import { auditMcpTools, toSarifReport } from '../src/auditor.js';
import { introspectStdioServers } from '../src/stdio-client.js';

const CLI_DIR = process.cwd();
const FIXTURE_JS = resolve(CLI_DIR, 'dist', 'tests', 'fixtures', 'mock-doctor-mcp.js');
const CLI_JS = resolve(CLI_DIR, 'dist', 'src', 'cli.js');

test('Real stdio clean 3-tool MCP server achieves Grade A (score >= 90)', async () => {
  const tools = await introspectStdioServers([
    { name: 'clean-srv', command: 'node', args: [FIXTURE_JS, '--mode=clean'] }
  ]);
  const report = auditMcpTools(tools);
  assert.equal(report.totalTools, 3);
  assert.equal(report.grade, 'A');
  assert.ok(report.score >= 90, `Expected >=90, got ${report.score}`);
  assert.equal(report.severityCounts.CRITICAL, 0);
});

test('Real stdio bloated 60-tool MCP server detects MCP_CONTEXT_TAX_BLOAT without promo strings', async () => {
  const tools = await introspectStdioServers([
    { name: 'bloated-srv', command: 'node', args: [FIXTURE_JS, '--mode=bloated'] }
  ]);
  const report = auditMcpTools(tools);
  assert.equal(report.totalTools, 60);
  assert.ok(report.estimatedTokens > 8000, `Expected >8000 tokens, got ${report.estimatedTokens}`);
  assert.ok(report.score < 90, `Bloated catalog must score < 90, got ${report.score}`);
  const bloatFinding = report.findings.find((f) => f.ruleId === 'MCP_CONTEXT_TAX_BLOAT');
  assert.ok(bloatFinding);
  assert.equal(bloatFinding.message.includes('slimmcp'), false);
});

test('Real stdio poisoned MCP server detects prompt-injection + secret leak as CRITICAL & caps grade <= D', async () => {
  const tools = await introspectStdioServers([
    { name: 'poisoned-srv', command: 'node', args: [FIXTURE_JS, '--mode=poisoned'] }
  ]);
  const report = auditMcpTools(tools);
  assert.ok(report.severityCounts.CRITICAL >= 2, 'Expected CRITICAL findings for injection + secret');
  assert.ok(report.score <= 55, `Score must cap <= 55 on CRITICAL finding, got ${report.score}`);
  assert.ok(report.findings.some((f) => f.ruleId === 'MCP_PI_IGNORE_INSTRUCTIONS'));
  assert.ok(report.findings.some((f) => f.ruleId === 'MCP_PI_HIDDEN_TAG'));
  assert.ok(report.findings.some((f) => f.ruleId === 'MCP_SEC_GITHUB_TOKEN'));

  const sarif = toSarifReport(report);
  assert.equal(sarif.version, '2.1.0');
  assert.ok(sarif.runs[0].results.length >= 2);
});

test('CLI --help, status, free --policy, free --sarif, and --ci threshold gates all work cleanly under MIT', () => {
  const helpOut = execFileSync(process.execPath, [CLI_JS, '--help'], { encoding: 'utf8' });
  assert.ok(helpOut.includes('mcp-doctor audit'));

  const statusOut = execFileSync(process.execPath, [CLI_JS, 'status'], { encoding: 'utf8' });
  const statusParsed = JSON.parse(statusOut);
  assert.equal(statusParsed.mode, 'open-source-mit');
  assert.equal(statusParsed.license, 'MIT');

  const tmpHome = mkdtempSync(join(tmpdir(), 'mcp-doctor-mit-'));
  const tmpCfg = join(tmpHome, 'poisoned-config.json');
  const tmpPolicy = join(tmpHome, 'policy.json');
  writeFileSync(
    tmpCfg,
    JSON.stringify({ servers: [{ name: 'p', command: 'node', args: [FIXTURE_JS, '--mode=poisoned'] }] }),
    'utf8'
  );
  writeFileSync(
    tmpPolicy,
    JSON.stringify({ minScore: 80, denyTools: ['*:delete_*'] }),
    'utf8'
  );

  try {
    // --policy and --sarif work 100% free with zero license tokens
    const sarifOut = execFileSync(
      process.execPath,
      [CLI_JS, 'audit', '--tools-file', resolve(CLI_DIR, 'mcp-tools.example.json'), '--policy', tmpPolicy, '--sarif'],
      { encoding: 'utf8' }
    );
    const sarifParsed = JSON.parse(sarifOut);
    assert.equal(sarifParsed.version, '2.1.0');

    // --ci on poisoned config exits non-zero (1)
    assert.throws(() => {
      execFileSync(
        process.execPath,
        [CLI_JS, 'audit', '--config', tmpCfg, '--ci', '--min-score', '70'],
        { stdio: 'pipe' }
      );
    });
  } finally {
    if (existsSync(tmpHome)) rmSync(tmpHome, { recursive: true, force: true });
  }
});
