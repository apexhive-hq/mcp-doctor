import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { generateKeyPairSync, sign } from 'node:crypto';
import { existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';
import { auditMcpTools, toSarifReport } from '../src/auditor.js';
import { loadActivatedLicense, saveActivatedLicense, verifyDoctorLicenseToken } from '../src/license.js';
import { introspectStdioServers } from '../src/stdio-client.js';

const CLI_DIR = process.cwd();
const FIXTURE_JS = resolve(CLI_DIR, 'dist', 'tests', 'fixtures', 'mock-doctor-mcp.js');
const CLI_JS = resolve(CLI_DIR, 'dist', 'src', 'cli.js');

function mintTeamToken(privateKey: ReturnType<typeof generateKeyPairSync>['privateKey'], tier: 'supporter' | 'team' = 'team') {
  const payload = {
    v: 1,
    product: 'mcp-doctor',
    tier,
    payer: '0x1111111111111111111111111111111111111111',
    txHash: '0x' + 'aa'.repeat(32),
    issuedAt: Date.now(),
    expiresAt: null
  };
  const payloadB64 = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
  const signingInput = Buffer.from(`MCPDOC-PRO-v1.${payloadB64}`, 'utf8');
  const sigB64 = sign(null, signingInput, privateKey).toString('base64url');
  return `MCPDOC-PRO-v1.${payloadB64}.${sigB64}`;
}

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

test('Real stdio bloated 60-tool MCP server incurs context-tax bloat penalty & high SlimMCP savings', async () => {
  const tools = await introspectStdioServers([
    { name: 'bloated-srv', command: 'node', args: [FIXTURE_JS, '--mode=bloated'] }
  ]);
  const report = auditMcpTools(tools);
  assert.equal(report.totalTools, 60);
  assert.ok(report.estimatedTokens > 8000, `Expected >8000 tokens, got ${report.estimatedTokens}`);
  assert.ok(report.estimatedSavingsPct >= 85, `Expected >=85% savings, got ${report.estimatedSavingsPct}%`);
  assert.ok(report.score < 90, `Bloated catalog must score < 90, got ${report.score}`);
  assert.ok(report.findings.some((f) => f.ruleId === 'MCP_CONTEXT_TAX_BLOAT'));
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

test('Ed25519 Team license verification, tamper rejection, disk persistence & CLI --ci/--policy/--sarif gates', () => {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const spkiB64 = publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
  const teamToken = mintTeamToken(privateKey, 'team');
  const supporterToken = mintTeamToken(privateKey, 'supporter');

  const ok = verifyDoctorLicenseToken(teamToken, { publicKeySpkiB64: spkiB64 });
  assert.equal(ok.valid, true);
  assert.equal(ok.payload?.tier, 'team');

  const parts = teamToken.split('.');
  const forged = `${parts[0]}.${Buffer.from(JSON.stringify({ v: 1, product: 'mcp-doctor', tier: 'team' })).toString('base64url')}.${parts[2]}`;
  assert.equal(verifyDoctorLicenseToken(forged, { publicKeySpkiB64: spkiB64 }).valid, false);

  const tmpHome = mkdtempSync(join(tmpdir(), 'mcp-doctor-home-'));
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
    saveActivatedLicense(teamToken, { homeDir: tmpHome, publicKeySpkiB64: spkiB64 });
    const loaded = loadActivatedLicense({ homeDir: tmpHome, publicKeySpkiB64: spkiB64 });
    assert.equal(loaded.valid, true);

    // Supporter token must NOT unlock --policy
    assert.throws(() => {
      execFileSync(
        'node',
        [CLI_JS, 'audit', '--tools-file', resolve(CLI_DIR, 'mcp-tools.example.json'), '--policy', tmpPolicy],
        {
          env: { ...process.env, MCP_DOCTOR_PUBLIC_KEY: spkiB64, MCP_DOCTOR_LICENSE: supporterToken },
          stdio: 'pipe'
        }
      );
    });

    // Team token unlocks --policy + --sarif cleanly
    const sarifOut = execFileSync(
      'node',
      [CLI_JS, 'audit', '--tools-file', resolve(CLI_DIR, 'mcp-tools.example.json'), '--policy', tmpPolicy, '--sarif'],
      {
        env: { ...process.env, MCP_DOCTOR_PUBLIC_KEY: spkiB64, MCP_DOCTOR_HOME: tmpHome },
        encoding: 'utf8'
      }
    );
    const sarifParsed = JSON.parse(sarifOut);
    assert.equal(sarifParsed.version, '2.1.0');

    // --ci on poisoned config exits non-zero (1)
    assert.throws(() => {
      execFileSync(
        'node',
        [CLI_JS, 'audit', '--config', tmpCfg, '--ci', '--min-score', '70'],
        { stdio: 'pipe' }
      );
    });
  } finally {
    if (existsSync(tmpHome)) rmSync(tmpHome, { recursive: true, force: true });
  }
});
