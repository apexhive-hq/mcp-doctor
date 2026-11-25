import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { readFileSync } from 'node:fs';
import { dirname, isAbsolute, resolve } from 'node:path';
import type { McpToolInput } from './types.js';

export interface StdioServerSpec {
  name: string;
  command: string;
  args: string[];
  env?: Record<string, string>;
  cwd?: string;
}

export function loadServerSpecsFromConfig(configPath: string): StdioServerSpec[] {
  const absPath = isAbsolute(configPath) ? configPath : resolve(process.cwd(), configPath);
  const configDir = dirname(absPath);
  const parsed = JSON.parse(readFileSync(absPath, 'utf8')) as {
    servers?: StdioServerSpec[];
    mcpServers?: Record<
      string,
      { command: string; args?: string[]; env?: Record<string, string>; cwd?: string }
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
      cwd: cfg.cwd ? (isAbsolute(cfg.cwd) ? cfg.cwd : resolve(configDir, cfg.cwd)) : configDir
    }));
  }

  throw new Error('Config JSON must define either "servers" array or "mcpServers" object.');
}

export async function introspectStdioServers(specs: StdioServerSpec[]): Promise<McpToolInput[]> {
  const allTools: McpToolInput[] = [];
  for (const spec of specs) {
    const client = new Client({ name: 'mcp-doctor-inspector', version: '1.0.0' }, { capabilities: {} });
    const transport = new StdioClientTransport({
      command: spec.command,
      args: spec.args,
      env: { ...process.env, ...spec.env } as Record<string, string>,
      cwd: spec.cwd,
      stderr: 'ignore'
    });
    await client.connect(transport);
    try {
      const res = await client.listTools();
      for (const tool of res.tools ?? []) {
        allTools.push({
          server: spec.name,
          name: tool.name,
          description: tool.description,
          inputSchema: tool.inputSchema as Record<string, unknown> | undefined
        });
      }
    } finally {
      await client.close();
    }
  }
  return allTools;
}
