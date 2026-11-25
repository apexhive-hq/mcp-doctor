import { createPublicKey, verify } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { z } from 'zod';
import type { DoctorLicensePayload, LicenseVerificationResult } from './types.js';

export const DEFAULT_MCP_DOCTOR_PUBLIC_KEY_SPKI_B64 =
  'MCowBQYDK2VwAyEAAnpWI5VSnokNaHchhXTKTGh2cFmOcuMKnzYqhMq5SUE=';

const TOKEN_PREFIX = 'MCPDOC-PRO-v1.';

const LicensePayloadSchema = z.object({
  v: z.literal(1),
  product: z.literal('mcp-doctor'),
  tier: z.enum(['supporter', 'team']),
  payer: z.string().regex(/^0x[0-9a-fA-F]{40}$/),
  txHash: z.string().regex(/^0x[0-9a-fA-F]{64}$/),
  issuedAt: z.number().int().positive(),
  expiresAt: z.number().int().positive().nullable()
});

function toPublicKeyObject(spkiB64: string) {
  const der = Buffer.from(spkiB64.trim(), 'base64');
  return createPublicKey({ key: der, format: 'der', type: 'spki' });
}

export function verifyDoctorLicenseToken(
  token: string,
  options?: { publicKeySpkiB64?: string; nowMs?: number }
): LicenseVerificationResult {
  const trimmed = token.trim();
  if (!trimmed.startsWith(TOKEN_PREFIX)) {
    return { valid: false, reason: 'Invalid license token prefix (expected MCPDOC-PRO-v1.).' };
  }

  const parts = trimmed.slice(TOKEN_PREFIX.length).split('.');
  if (parts.length !== 2 || !parts[0] || !parts[1]) {
    return { valid: false, reason: 'Malformed license token structure.' };
  }

  const [payloadB64Url, sigB64Url] = parts;
  const spkiB64 =
    options?.publicKeySpkiB64 ||
    process.env.MCP_DOCTOR_PUBLIC_KEY ||
    DEFAULT_MCP_DOCTOR_PUBLIC_KEY_SPKI_B64;

  let sigVerified = false;
  try {
    const pubKey = toPublicKeyObject(spkiB64);
    const signingInput = Buffer.from(`${TOKEN_PREFIX}${payloadB64Url}`, 'utf8');
    const sigBytes = Buffer.from(sigB64Url, 'base64url');
    sigVerified = verify(null, signingInput, pubKey, sigBytes);
  } catch (err) {
    return {
      valid: false,
      reason: `Ed25519 verification error: ${err instanceof Error ? err.message : String(err)}`
    };
  }

  if (!sigVerified) {
    return { valid: false, reason: 'Invalid Ed25519 signature.' };
  }

  let parsedJson: unknown;
  try {
    parsedJson = JSON.parse(Buffer.from(payloadB64Url, 'base64url').toString('utf8'));
  } catch {
    return { valid: false, reason: 'Malformed JSON payload in license token.' };
  }

  const parsed = LicensePayloadSchema.safeParse(parsedJson);
  if (!parsed.success) {
    return { valid: false, reason: `Invalid license payload fields: ${parsed.error.message}` };
  }

  const payload: DoctorLicensePayload = parsed.data;
  const now = options?.nowMs ?? Date.now();
  if (payload.expiresAt !== null && now > payload.expiresAt) {
    return { valid: false, reason: 'License token has expired.', payload };
  }

  return { valid: true, payload };
}

export function resolveDoctorHome(customHome?: string): string {
  if (customHome) return customHome;
  if (process.env.MCP_DOCTOR_HOME) return process.env.MCP_DOCTOR_HOME;
  const base = process.env.APPDATA || homedir();
  return join(base, '.mcp-doctor');
}

export function saveActivatedLicense(
  token: string,
  options?: { homeDir?: string; publicKeySpkiB64?: string }
): { filePath: string; verification: LicenseVerificationResult } {
  const verification = verifyDoctorLicenseToken(token, {
    publicKeySpkiB64: options?.publicKeySpkiB64
  });
  if (!verification.valid) {
    throw new Error(verification.reason || 'License verification failed.');
  }
  const home = resolveDoctorHome(options?.homeDir);
  mkdirSync(home, { recursive: true });
  const filePath = join(home, 'license.json');
  writeFileSync(
    filePath,
    JSON.stringify(
      {
        token: token.trim(),
        activatedAt: new Date().toISOString(),
        payload: verification.payload
      },
      null,
      2
    ),
    'utf8'
  );
  return { filePath, verification };
}

export function loadActivatedLicense(options?: {
  homeDir?: string;
  publicKeySpkiB64?: string;
}): LicenseVerificationResult {
  const envToken = process.env.MCP_DOCTOR_LICENSE;
  if (envToken && envToken.trim()) {
    return verifyDoctorLicenseToken(envToken, {
      publicKeySpkiB64: options?.publicKeySpkiB64
    });
  }
  const filePath = join(resolveDoctorHome(options?.homeDir), 'license.json');
  if (!existsSync(filePath)) {
    return { valid: false, reason: 'No local license found (Open-Core MIT mode active).' };
  }
  try {
    const raw = JSON.parse(readFileSync(filePath, 'utf8')) as { token?: string };
    if (!raw.token) {
      return { valid: false, reason: 'License file missing token field.' };
    }
    return verifyDoctorLicenseToken(raw.token, {
      publicKeySpkiB64: options?.publicKeySpkiB64
    });
  } catch (err) {
    return {
      valid: false,
      reason: `Failed reading license file: ${err instanceof Error ? err.message : String(err)}`
    };
  }
}
