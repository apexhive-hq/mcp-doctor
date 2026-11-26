import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { readFileSync } from 'node:fs';
import { dirname, isAbsolute, resolve } from 'node:path';
import type { McpToolInput } from './types.js';
import { MCP_DOCTOR_VERSION } from './version.js';

export const DEFAULT_SAFE_ENV_KEYS = [
  'PATH',
  'HOME',
  'USERPROFILE',
  'SYSTEMROOT',
  'COMSPEC',
  'TMP',
  'TEMP',
  'NODE_ENV'
] as const;

export const DEFAULT_STDIO_TIMEOUT_MS = 15_000;

export interface StdioServerSpec {
  name: string;
  command: string;
  args: string[];
  env?: Record<string, string>;
  envAllowlist?: string[];
  cwd?: string;
}

export interface IntrospectStdioOptions {
  timeoutMs?: number;
  envAllowlist?: string[];
}

export function buildSafeSubprocessEnv(
  specEnv?: Record<string, string>,
  allowlist: readonly string[] = DEFAULT_SAFE_ENV_KEYS,
  sourceEnv: NodeJS.ProcessEnv = process.env
): Record<string, string> {
  const safeEnv: Record<string, string> = {};
  const canonicalByUpper = new Map<string, string>();
  for (const key of allowlist) {
    canonicalByUpper.set(key.toUpperCase(), key);
  }

  for (const [key, val] of Object.entries(sourceEnv)) {
    if (val === undefined || val.startsWith('()')) continue;
    if (process.platform === 'win32') {
      const canonical = canonicalByUpper.get(key.toUpperCase());
      if (canonical) {
        safeEnv[canonical] = val;
      }
    } else if (allowlist.includes(key)) {
      safeEnv[key] = val;
    }
  }

  if (specEnv) {
    for (const [key, val] of Object.entries(specEnv)) {
      if (val !== undefined) {
        safeEnv[key] = val;
      }
    }
  }

  return safeEnv;
}

export function loadServerSpecsFromConfig(configPath: string): StdioServerSpec[] {
  const absPath = isAbsolute(configPath) ? configPath : resolve(process.cwd(), configPath);
  const configDir = dirname(absPath);
  const parsed = JSON.parse(readFileSync(absPath, 'utf8')) as {
    servers?: StdioServerSpec[];
    mcpServers?: Record<
      string,
      { command: string; args?: string[]; env?: Record<string, string>; envAllowlist?: string[]; cwd?: string }
    >;
  };

  if (Array.isArray(parsed.servers)) {
    return parsed.servers.map((s) => ({
      ...s,
      cwd: s.cwd ? (isAbsolute(s.cwd) ? s.cwd : resolve(configDir, s.cwd)) : configDir
    }));
  }

  if (parsed.mcpServers && typeof parsed.mcpServers === 'object') {
    return Object.entries(parsed.mcpServers).map(([name, cfg]) => ({
      name,
      command: cfg.command,
      args: cfg.args ?? [],
      env: cfg.env,
      envAllowlist: cfg.envAllowlist,
      cwd: cfg.cwd ? (isAbsolute(cfg.cwd) ? cfg.cwd : resolve(configDir, cfg.cwd)) : configDir
    }));
  }

  throw new Error('Config JSON must define either "servers" array or "mcpServers" object.');
}

export async function introspectStdioServers(
  specs: StdioServerSpec[],
  options?: IntrospectStdioOptions
): Promise<McpToolInput[]> {
  const allTools: McpToolInput[] = [];
  const timeoutMs = options?.timeoutMs ?? DEFAULT_STDIO_TIMEOUT_MS;

  for (const spec of specs) {
    const mergedAllowlist = [
      ...DEFAULT_SAFE_ENV_KEYS,
      ...(options?.envAllowlist ?? []),
      ...(spec.envAllowlist ?? [])
    ];
    const client = new Client(
      { name: 'mcp-doctor-inspector', version: MCP_DOCTOR_VERSION },
      { capabilities: {} }
    );
    const transport = new StdioClientTransport({
      command: spec.command,
      args: spec.args,
      env: buildSafeSubprocessEnv(spec.env, mergedAllowlist),
      cwd: spec.cwd,
      stderr: 'ignore'
    });

    let timer: NodeJS.Timeout | undefined;
    const runPromise = (async () => {
      await client.connect(transport);
      return await client.listTools();
    })();
    runPromise.catch(() => {});

    const timeoutPromise = new Promise<never>((_, reject) => {
      timer = setTimeout(() => {
        reject(new Error(`Timed out after ${timeoutMs}ms initializing stdio MCP server "${spec.name}".`));
      }, timeoutMs);
      timer.unref?.();
    });

    try {
      const res = await Promise.race([runPromise, timeoutPromise]);
      for (const tool of res.tools ?? []) {
        allTools.push({
          server: spec.name,
          name: tool.name,
          description: tool.description,
          inputSchema: tool.inputSchema as Record<string, unknown> | undefined
        });
      }
    } finally {
      if (timer) clearTimeout(timer);
      await client.close().catch(() => {});
    }
  }
  return allTools;
}
