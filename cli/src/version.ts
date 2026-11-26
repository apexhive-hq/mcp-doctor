import { existsSync, readFileSync } from 'node:fs';

function resolvePackageVersion(): string {
  const candidates = [
    new URL('../../package.json', import.meta.url),
    new URL('../package.json', import.meta.url)
  ];

  for (const url of candidates) {
    try {
      if (!existsSync(url)) continue;
      const pkg = JSON.parse(readFileSync(url, 'utf8')) as { name?: string; version?: string };
      if (pkg.name === 'apexhive-mcp-doctor' && typeof pkg.version === 'string' && pkg.version.trim()) {
        return pkg.version.trim();
      }
    } catch {
      // Ignore unreadable candidate and continue to fallback
    }
  }

  return '1.0.1';
}

export const MCP_DOCTOR_VERSION = resolvePackageVersion();
