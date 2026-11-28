/** Mirrors `bugfound-desktop-core::dto`. Never add a secret field here. */

export interface BudgetSnapshot {
  maxSteps: number;
  maxToolCalls: number;
  maxNetworkCalls: number;
  requestsPerMinute: number;
  maxTokens: number;
}

export interface SettingsSnapshot {
  mode: string;
  workspace: string;
  baseUrlConfigured: boolean;
  /** `env` | `literal` | `missing` — never the value. */
  apiKeySource: string;
  defaultModel: string | null;
  storagePath: string;
  budgets: BudgetSnapshot;
}

export interface SessionSummary {
  id: string;
  title: string;
  state: string;
  model: string | null;
  createdAt: string;
  updatedAt: string | null;
}

export interface AppSnapshot {
  product: string;
  version: string;
  status: string;
  /** Non-empty when config or DB startup degraded to a safe fallback. */
  startupWarnings: string[];
  sessions: SessionSummary[];
  settings: SettingsSnapshot;
}

export interface TimelineItem {
  id: string;
  role: string;
  text: string;
}

export interface ApprovalSummary {
  id: string;
  sessionId: string;
  tool: string;
  risk: string;
  reason: string | null;
  argsRedacted: string;
  expiresAt: string | null;
}

export interface FindingSummary {
  id: string;
  title: string;
  severity: string;
  status: string;
  verdict: string;
  confidence: string;
  catalogVersion: string;
  tlpLabel: string;
}

export interface InvestigationView {
  engagementId: string;
  revision: number;
  phase: string;
  catalogVersion: string;
  tlpLabel: string;
  planSteps: number;
  openHypotheses: number;
  coverageRows: number;
  reflections: number;
}

export interface AuditEventView {
  kind: string;
  actor: string;
  stepId: string;
  payloadJson: string;
}

export interface ReportView {
  path: string;
  text: string;
}

export type RuntimeEvent =
  | { kind: "started"; sessionId: string }
  | { kind: "delta"; sessionId: string; text: string }
  | { kind: "finished"; sessionId: string; text: string }
  /** `sessionId` is optional because backend errors are not always scoped. */
  | { kind: "error"; text: string; sessionId?: string }
  | { kind: "status"; state: string };

export interface RuntimeStatus {
  activeSession: string | null;
  busy: boolean;
}

export interface AppError {
  kind: "config" | "storage" | "invalidInput" | "internal";
  message: string;
}

export function isAppError(value: unknown): value is AppError {
  return (
    typeof value === "object" &&
    value !== null &&
    "kind" in value &&
    "message" in value &&
    typeof (value as AppError).message === "string"
  );
}
