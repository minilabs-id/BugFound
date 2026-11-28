import { describe, expect, it } from "vitest";
import { applyRuntimeEvent, errorMessage } from "./runtimeEvents";
import type { RuntimeUiState } from "./runtimeEvents";

const state = (activeSession: string | null = null, busy = false): RuntimeUiState => ({
  status: { activeSession, busy },
  events: [],
});

describe("applyRuntimeEvent", () => {
  it("sets the active session and busy flag on started/delta", () => {
    const started = applyRuntimeEvent(state(), { kind: "started", sessionId: "a" });
    expect(started.status).toEqual({ activeSession: "a", busy: true });
    const delta = applyRuntimeEvent(started, { kind: "delta", sessionId: "a", text: "x" });
    expect(delta.status).toEqual({ activeSession: "a", busy: true });
  });

  it("clears on a matching finished event", () => {
    const next = applyRuntimeEvent(state("a", true), {
      kind: "finished",
      sessionId: "a",
      text: "done",
    });
    expect(next.status).toEqual({ activeSession: null, busy: false });
  });

  it("ignores a late finished event from a different session", () => {
    const next = applyRuntimeEvent(state("b", true), {
      kind: "finished",
      sessionId: "a",
      text: "late",
    });
    expect(next.status).toEqual({ activeSession: "b", busy: true });
  });

  it("only clears for an error attributed to the active session", () => {
    const stale = applyRuntimeEvent(state("b", true), {
      kind: "error",
      sessionId: "a",
      text: "old failure",
    });
    expect(stale.status).toEqual({ activeSession: "b", busy: true });
    const current = applyRuntimeEvent(state("b", true), {
      kind: "error",
      sessionId: "b",
      text: "failure",
    });
    expect(current.status).toEqual({ activeSession: null, busy: false });
  });

  it("deduplicates consecutive identical errors and renders readable messages", () => {
    const first = applyRuntimeEvent(state(), { kind: "error", text: "boom" });
    const second = applyRuntimeEvent(first, { kind: "error", text: "boom" });
    expect(second.events).toHaveLength(1);
    expect(errorMessage(new Error("bad config"))).toBe("bad config");
    expect(errorMessage({ message: "ipc failed" })).toBe("ipc failed");
  });
});
