import type { RuntimeEvent, RuntimeStatus } from "./types";

/** Pure, testable core of the runtime event handler in `App.tsx`. */
export interface RuntimeUiState {
  status: RuntimeStatus;
  events: RuntimeEvent[];
}

const HISTORY_LIMIT = 40;

export function applyRuntimeEvent(state: RuntimeUiState, event: RuntimeEvent): RuntimeUiState {
  let status = state.status;

  switch (event.kind) {
    case "started":
    case "delta":
      status = { activeSession: event.sessionId, busy: true };
      break;
    case "finished":
      // An empty session id means an unscoped terminal event (e.g. an
      // engagement summary). A late event from a *different* real session must
      // not clear a newly started session's busy state.
      if (!event.sessionId || event.sessionId === status.activeSession) {
        status = { activeSession: null, busy: false };
      }
      break;
    case "error":
      // Local failures may carry the session that caused them. Only clear that
      // session; an unattributed error is treated as a terminal command error.
      if (!event.sessionId || event.sessionId === status.activeSession) {
        status = { activeSession: null, busy: false };
      }
      break;
    case "status":
    default:
      break;
  }

  const last = state.events[state.events.length - 1];
  const repeatedError =
    event.kind === "error" && last?.kind === "error" && last.text === event.text;

  return {
    status,
    events: repeatedError ? state.events : [...state.events.slice(-HISTORY_LIMIT), event],
  };
}

/** Human-readable message for anything thrown across IPC or by the renderer. */
export function errorMessage(error: unknown): string {
  if (error instanceof Error && error.message) return error.message;
  if (typeof error === "string" && error.trim()) return error;
  if (typeof error === "object" && error !== null && "message" in error) {
    const message = (error as { message: unknown }).message;
    if (typeof message === "string" && message.trim()) return message;
  }
  try {
    return JSON.stringify(error) ?? String(error);
  } catch {
    return String(error);
  }
}

/** Replaces the old raw `JSON.stringify(event)` line in the event feed. */
export function describeEvent(event: RuntimeEvent): string {
  switch (event.kind) {
    case "started":
      return `started · ${event.sessionId.slice(0, 8)}`;
    case "delta":
      return `delta · ${event.sessionId.slice(0, 8)} · ${event.text}`;
    case "finished":
      return `finished · ${event.sessionId.slice(0, 8) || "engagement"} · ${event.text}`;
    case "error":
      return `error · ${event.text}`;
    case "status":
      return `status · ${event.state}`;
    default:
      return `event · ${String((event as { kind?: string }).kind ?? "unknown")}`;
  }
}
