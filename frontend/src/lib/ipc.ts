import { Channel, invoke } from "@tauri-apps/api/core";
import {
  isAppError,
  type AppSnapshot,
  type ApprovalSummary,
  type AuditEventView,
  type FindingSummary,
  type InvestigationView,
  type ReportView,
  type RuntimeEvent,
  type RuntimeStatus,
  type TimelineItem,
} from "./types";

/**
 * The webview's only door to Rust. Add commands here as the phases progress;
 * never open a DB connection or call a network API from the renderer.
 */
async function call<T>(command: string, args?: Record<string, unknown>): Promise<T> {
  try {
    return await invoke<T>(command, args);
  } catch (error) {
    if (isAppError(error)) {
      throw new Error(error.message);
    }
    throw new Error(String(error));
  }
}

export function appReady(): Promise<AppSnapshot> {
  return call<AppSnapshot>("app_ready");
}

export function sessionsList(): Promise<AppSnapshot["sessions"]> {
  return call<AppSnapshot["sessions"]>("sessions_list");
}

export function sessionHistory(sessionId: string): Promise<TimelineItem[]> {
  return call<TimelineItem[]>("session_history", { sessionId });
}

export function approvalsList(sessionId: string): Promise<ApprovalSummary[]> {
  return call<ApprovalSummary[]>("approvals_list", { sessionId });
}

export function findingsList(sessionId: string): Promise<FindingSummary[]> {
  return call<FindingSummary[]>("findings_list", { sessionId });
}

export function investigationView(engagementId: string): Promise<InvestigationView | null> {
  return call<InvestigationView | null>("investigation_view", { engagementId });
}

export function auditEvents(engagementId: string, limit = 50): Promise<AuditEventView[]> {
  return call<AuditEventView[]>("audit_events", { engagementId, limit });
}

export function reportRead(engagementId: string): Promise<ReportView> {
  return call<ReportView>("report_read", { engagementId });
}

export function runtimeStatus(): Promise<RuntimeStatus> {
  return call<RuntimeStatus>("runtime_status");
}

export function pendingApprovals(): Promise<ApprovalSummary[]> {
  return call<ApprovalSummary[]>("pending_approvals");
}

export function engagementStart(
  url: string,
  cwd: string,
  onEvent: (event: RuntimeEvent) => void,
): Promise<void> {
  return call<void>("engagement_start", {
    url,
    cwd,
    channel: runtimeChannel(onEvent),
  });
}

function runtimeChannel(onEvent: (event: RuntimeEvent) => void): Channel<RuntimeEvent> {
  const channel = new Channel<RuntimeEvent>();
  channel.onmessage = onEvent;
  return channel;
}

export function runtimeChat(text: string, onEvent: (event: RuntimeEvent) => void): Promise<void> {
  return call<void>("runtime_chat", { text, channel: runtimeChannel(onEvent) });
}

export function runtimeChatSend(
  session: string,
  text: string,
  cwd: string,
  onEvent: (event: RuntimeEvent) => void,
): Promise<void> {
  return call<void>("runtime_chat_send", {
    session,
    text,
    cwd,
    channel: runtimeChannel(onEvent),
  });
}

export function runtimeSteer(session: string, text: string): Promise<void> {
  return call<void>("runtime_steer", { session, text });
}

export function runtimeStop(session: string): Promise<void> {
  return call<void>("runtime_stop", { session });
}

export function runtimeDecide(
  session: string,
  decision: string,
  onEvent: (event: RuntimeEvent) => void,
): Promise<void> {
  return call<void>("runtime_decide", {
    session,
    decision,
    channel: runtimeChannel(onEvent),
  });
}
