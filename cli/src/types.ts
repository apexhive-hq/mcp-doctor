export type AuditSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
export type AuditGrade = 'A' | 'B' | 'C' | 'D' | 'F';
export type AuditCategory = 'prompt-injection' | 'secret-leak' | 'schema-quality' | 'context-tax' | 'policy';

export interface McpToolInput {
  server?: string;
  name: string;
  description?: string;
  inputSchema?: Record<string, unknown>;
}

export interface AuditFinding {
  ruleId: string;
  severity: AuditSeverity;
  category: AuditCategory;
  server: string;
  tool: string;
  message: string;
  evidence?: string;
}

export interface ToolWeight {
  server: string;
  name: string;
  bytes: number;
  tokens: number;
}

export interface ServerAuditSummary {
  server: string;
  toolCount: number;
  rawBytes: number;
  estimatedTokens: number;
}

export interface AuditReport {
  ok: boolean;
  score: number;
  grade: AuditGrade;
  totalServers: number;
  totalTools: number;
  rawBytes: number;
  estimatedTokens: number;
  slimProxyBytes: number;
  slimProxyTokens: number;
  tokensSavedWithSlimMcp: number;
  estimatedSavingsPct: number;
  severityCounts: Record<AuditSeverity, number>;
  topHeaviestTools: ToolWeight[];
  servers: ServerAuditSummary[];
  findings: AuditFinding[];
}

export interface TeamPolicyConfig {
  minScore?: number;
  failOnSeverity?: AuditSeverity;
  blockPromptInjection?: boolean;
  maxTotalTokens?: number;
  denyTools?: string[];
}

export interface DoctorLicensePayload {
  v: 1;
  product: 'mcp-doctor';
  tier: 'supporter' | 'team';
  payer: string;
  txHash: string;
  issuedAt: number;
  expiresAt: number | null;
}

export interface LicenseVerificationResult {
  valid: boolean;
  reason?: string;
  payload?: DoctorLicensePayload;
}
