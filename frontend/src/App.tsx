import { useCallback, useEffect, useState } from "react";
import { applyTheme, useAppStore, type Theme } from "./state/appStore";
import {
  engagementStart,
  findingsList,
  pendingApprovals,
  runtimeChat,
  runtimeChatSend,
  runtimeDecide,
  runtimeStatus,
  runtimeStop,
  runtimeSteer,
} from "./lib/ipc";
import type { RuntimeEvent } from "./lib/types";
import type { ApprovalSummary, FindingSummary } from "./lib/types";
import {
  applyRuntimeEvent,
  describeEvent,
  errorMessage,
  type RuntimeUiState,
} from "./lib/runtimeEvents";
import { formatBudget } from "./lib/format";
import "./styles/tokens.css";
import "./styles/global.css";

const THEMES: Theme[] = ["system", "light", "dark"];

export default function App() {
  const connection = useAppStore((s) => s.connection);
  const snapshot = useAppStore((s) => s.snapshot);
  const error = useAppStore((s) => s.error);
  const theme = useAppStore((s) => s.theme);
  const initialize = useAppStore((s) => s.initialize);
  const setTheme = useAppStore((s) => s.setTheme);

  useEffect(() => {
    void initialize();
  }, [initialize]);

  useEffect(() => {
    applyTheme(theme);
    const media = window.matchMedia("(prefers-color-scheme: dark)");
    const onChange = () => applyTheme(theme);
    media.addEventListener("change", onChange);
    return () => media.removeEventListener("change", onChange);
  }, [theme]);

  const budgets = snapshot?.settings.budgets;
  const workspace = snapshot?.settings.workspace ?? ".";
  const firstSession = snapshot?.sessions[0]?.id ?? null;

  const [findings, setFindings] = useState<FindingSummary[]>([]);
  const [input, setInput] = useState("");
  const [selectedSession, setSelectedSession] = useState<string | null>(null);
  const [runtime, setRuntime] = useState<RuntimeUiState>({
    status: { activeSession: null, busy: false },
    events: [],
  });
  const [approvals, setApprovals] = useState<ApprovalSummary[]>([]);
  const [settingsOpen, setSettingsOpen] = useState(false);

  const { status: runStatus, events } = runtime;
  const activeSession = selectedSession ?? runStatus.activeSession ?? firstSession;
  const latestError = events
    .slice()
    .reverse()
    .find(
      (event): event is Extract<RuntimeEvent, { kind: "error" }> =>
        event.kind === "error",
    );

  const handleEvent = useCallback((event: RuntimeEvent) => {
    setRuntime((current) => applyRuntimeEvent(current, event));
  }, []);

  /** All renderer-side failures surface as a visible, deduplicated error event. */
  const reportError = useCallback(
    (
      error: unknown,
      options: { sessionId?: string | null; preserveStatus?: boolean } = {},
    ) => {
      const event: RuntimeEvent = {
        kind: "error",
        text: errorMessage(error),
        ...(options.sessionId ? { sessionId: options.sessionId } : {}),
      };
      setRuntime((current) => {
        const last = current.events[current.events.length - 1];
        if (last?.kind === "error" && last.text === event.text) return current;
        return options.preserveStatus
          ? { ...current, events: [...current.events.slice(-40), event] }
          : applyRuntimeEvent(current, event);
      });
    },
    [],
  );

  useEffect(() => {
    const timer = window.setInterval(() => {
      runtimeStatus()
        .then((status) => setRuntime((current) => ({ ...current, status })))
        .catch((error: unknown) => reportError(error, { preserveStatus: true }));
      pendingApprovals()
        .then(setApprovals)
        .catch((error: unknown) => reportError(error, { preserveStatus: true }));
    }, 1500);
    return () => window.clearInterval(timer);
  }, [reportError]);

  useEffect(() => {
    let active = true;
    if (!activeSession) {
      setFindings([]);
      return;
    }
    findingsList(activeSession)
      .then((items) => {
        if (active) setFindings(items);
      })
      .catch((error: unknown) => {
        if (active) {
          setFindings([]);
          reportError(error, { preserveStatus: true });
        }
      });
    return () => {
      active = false;
    };
  }, [activeSession, reportError]);

  const dismissError = () => {
    setRuntime((current) => {
      const index = current.events.map((event) => event.kind).lastIndexOf("error");
      return index < 0
        ? current
        : { ...current, events: current.events.filter((_, i) => i !== index) };
    });
  };

  const newSession = () => {
    setSelectedSession(null);
    setInput("");
    setRuntime({ status: { activeSession: null, busy: false }, events: [] });
  };

  const submit = () => {
    const text = input.trim();
    if (!text || runStatus.busy) return;
    setInput("");
    // Optimistic busy: runtime commands are queued, so the Started event may
    // arrive a tick later and the composer must not accept a second command.
    setRuntime((current) => ({
      ...current,
      status: { ...current.status, busy: true },
    }));
    const request = activeSession
      ? runtimeChatSend(activeSession, text, workspace, handleEvent)
      : runtimeChat(text, handleEvent);
    request.catch((error: unknown) => reportError(error, { sessionId: activeSession }));
  };

  const decide = (approval: ApprovalSummary, decision: "approve" | "deny") => {
    setRuntime((current) => ({
      ...current,
      status: { activeSession: approval.sessionId, busy: true },
    }));
    runtimeDecide(approval.sessionId, decision, handleEvent).catch((error: unknown) =>
      reportError(error, { sessionId: approval.sessionId }),
    );
  };

  return (
    <div className="app-shell">
      <aside className="sidebar" aria-label="Sessions">
        <div className="brand">
          <span className="brand-mark" aria-hidden="true" />
          <span className="brand-name">BugFound</span>
        </div>

        <button className="new-session" type="button" onClick={newSession}>
          <span aria-hidden="true">＋</span> New session
        </button>

        <div className="sidebar-section">
          <div className="section-label">Recents</div>
          {snapshot?.sessions.length ? (
            <ul className="session-list">
              {snapshot.sessions.map((session) => {
                const selected = session.id === activeSession;
                return (
                  <li key={session.id}>
                    <button
                      type="button"
                      className={`session-item${selected ? " is-selected" : ""}`}
                      aria-current={selected ? "true" : undefined}
                      onClick={() => setSelectedSession(session.id)}
                    >
                      <span
                        className={`state-dot state-${session.state}`}
                        aria-hidden="true"
                      />
                      <span className="session-title" title={session.title}>
                        {session.title}
                      </span>
                      <span className="session-id">{session.id.slice(0, 8)}</span>
                    </button>
                  </li>
                );
              })}
            </ul>
          ) : (
            <p className="sidebar-empty">No sessions yet.</p>
          )}
        </div>

        <div className="sidebar-footer">
          <label className="theme-select">
            <span>Theme</span>
            <select value={theme} onChange={(e) => setTheme(e.target.value as Theme)}>
              {THEMES.map((option) => (
                <option key={option} value={option}>
                  {option}
                </option>
              ))}
            </select>
          </label>
          <button
            className="text-button"
            type="button"
            onClick={() => setSettingsOpen(true)}
          >
            Settings
          </button>
        </div>
      </aside>

      <main className="workspace">
        <header className="session-header">
          <div className="header-titles">
            <span className="header-title">Workspace</span>
            <span className="header-subtitle">Phase 0 — IPC connected</span>
          </div>
          <ConnectionPill connection={connection} />
        </header>

        {snapshot?.startupWarnings.map((warning, index) => (
          <div className="storage-warning" role="alert" key={index}>
            <strong>Startup warning.</strong> {warning}
          </div>
        ))}

        {latestError && (
          <div className="runtime-error-banner" role="alert">
            <strong>Error.</strong> {latestError.text}
            <button
              type="button"
              className="banner-dismiss"
              aria-label="Dismiss error"
              onClick={dismissError}
            >
              ×
            </button>
          </div>
        )}

        <section className="timeline" aria-live="polite">
          {connection === "error" ? (
            <div className="empty-state error-state">
              <h1>Could not reach the desktop core</h1>
              <p>{error}</p>
            </div>
          ) : (
            <div className="empty-state">
              <h1>BugFound</h1>
              <p>
                A supervision console for scoped security engagements. The
                conversation, approvals, findings and report will live here.
              </p>
              <div className="phase-note">
                Scaffolding is ready. The composer, sessions and engagement flow
                arrive in phases 1–3.
              </div>
            </div>
          )}
        </section>

        <footer className="composer">
          <div className="control-row">
            <span className="chip">{snapshot?.settings.mode ?? "—"}</span>
            <span className="chip mono">{workspace}</span>
            <span className="chip mono">
              {snapshot?.settings.defaultModel ?? "model: auto"}
            </span>
            <span className="chip">key: {snapshot?.settings.apiKeySource ?? "—"}</span>
          </div>
          <div className="composer-box">
            <input
              className="composer-input"
              value={input}
              onChange={(event) => setInput(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === "Enter") submit();
              }}
              placeholder="Message BugFound…"
              aria-label="Message BugFound"
            />
            <button type="button" onClick={submit} disabled={runStatus.busy}>
              Send
            </button>
            <button
              type="button"
              onClick={() => {
                const url = input.trim();
                if (!url || runStatus.busy) return;
                setInput("");
                setRuntime((current) => ({
                  ...current,
                  status: { ...current.status, busy: true },
                }));
                engagementStart(url, workspace, handleEvent).catch((error: unknown) =>
                  reportError(error),
                );
              }}
              disabled={runStatus.busy}
            >
              Engage
            </button>
            <button
              type="button"
              onClick={() => {
                const session = activeSession;
                const text = input.trim();
                if (!session || !text) return;
                runtimeSteer(session, text).catch((error: unknown) =>
                  reportError(error, { sessionId: session }),
                );
                setInput("");
              }}
              disabled={!activeSession}
            >
              Steer
            </button>
            <button
              type="button"
              onClick={() => {
                const session = activeSession;
                if (session) {
                  runtimeStop(session).catch((error: unknown) =>
                    reportError(error, { sessionId: session }),
                  );
                }
              }}
              disabled={!activeSession}
            >
              Stop
            </button>
            <span className="composer-hint">
              {activeSession ? `session ${activeSession.slice(0, 8)}` : "new session"}
            </span>
          </div>
          {events.length > 0 && (
            <div className="runtime-events" aria-live="polite">
              {events.slice(-6).map((event, index) => (
                <div
                  key={index}
                  className={`runtime-event${event.kind === "error" ? " is-error" : ""}`}
                >
                  {describeEvent(event)}
                </div>
              ))}
            </div>
          )}
        </footer>
      </main>

      <aside className="rail" aria-label="Session details">
        <RailCard title="Connection">
          <Row label="Core" value={connection} />
          <Row label="Version" value={snapshot?.version ?? "—"} />
          <Row label="Sessions" value={String(snapshot?.sessions.length ?? 0)} />
        </RailCard>
        <RailCard title="Budgets">
          {budgets ? (
            <>
              <Row label="Steps" value={formatBudget(budgets.maxSteps)} />
              <Row label="Tools" value={formatBudget(budgets.maxToolCalls)} />
              <Row label="Network" value={formatBudget(budgets.maxNetworkCalls)} />
              <Row label="RPM" value={formatBudget(budgets.requestsPerMinute)} />
              <Row label="Tokens" value={formatBudget(budgets.maxTokens)} />
            </>
          ) : (
            <p className="rail-empty">Waiting for core…</p>
          )}
        </RailCard>
        {approvals.length > 0 && (
          <RailCard title="Needs your decision">
            {approvals.map((approval) => (
              <div className="approval-card" key={approval.id}>
                <div className="approval-tool">
                  {approval.tool} · {approval.risk}
                </div>
                <div className="approval-args">{approval.argsRedacted}</div>
                <div className="approval-actions">
                  <button type="button" onClick={() => decide(approval, "approve")}>
                    Approve
                  </button>
                  <button type="button" onClick={() => decide(approval, "deny")}>
                    Deny
                  </button>
                </div>
              </div>
            ))}
          </RailCard>
        )}

        <RailCard title="Findings">
          {findings.length === 0 ? (
            <p className="rail-empty">Findings appear here as the agent works.</p>
          ) : (
            findings.map((finding) => (
              <div className="finding-row" key={finding.id}>
                <span className="finding-title">{finding.title}</span>
                <span className="finding-verdict">
                  {finding.verdict} · {finding.confidence}
                </span>
                {finding.tlpLabel && (
                  <span className="finding-tlp">{finding.tlpLabel}</span>
                )}
              </div>
            ))
          )}
        </RailCard>
      </aside>

      {settingsOpen && (
        <div
          className="dialog-backdrop"
          role="presentation"
          onClick={() => setSettingsOpen(false)}
        >
          <section
            className="settings-dialog"
            role="dialog"
            aria-modal="true"
            aria-label="Settings"
            onClick={(event) => event.stopPropagation()}
          >
            <div className="dialog-header">
              <h2>Settings</h2>
              <button
                type="button"
                aria-label="Close settings"
                onClick={() => setSettingsOpen(false)}
              >
                ×
              </button>
            </div>
            <p className="dialog-note">
              Read-only projection of the active desktop-core configuration.
              Edit the config file and restart the app to change these values.
            </p>
            {snapshot ? (
              <>
                <Row label="Mode" value={snapshot.settings.mode} />
                <Row label="Workspace" value={workspace} />
                <Row label="Storage" value={snapshot.settings.storagePath} />
                <Row
                  label="Base URL"
                  value={
                    snapshot.settings.baseUrlConfigured ? "configured" : "not configured"
                  }
                />
                <Row label="API key" value={snapshot.settings.apiKeySource} />
                <Row label="Default model" value={snapshot.settings.defaultModel ?? "auto"} />
                <Row
                  label="Steps"
                  value={formatBudget(snapshot.settings.budgets.maxSteps)}
                />
                <Row
                  label="Tool calls"
                  value={formatBudget(snapshot.settings.budgets.maxToolCalls)}
                />
                <Row
                  label="Network calls"
                  value={formatBudget(snapshot.settings.budgets.maxNetworkCalls)}
                />
                <Row
                  label="Requests/min"
                  value={formatBudget(snapshot.settings.budgets.requestsPerMinute)}
                />
                <Row
                  label="Tokens"
                  value={formatBudget(snapshot.settings.budgets.maxTokens)}
                />
              </>
            ) : (
              <p className="rail-empty">Waiting for core…</p>
            )}
            <label className="theme-select dialog-theme">
              <span>Theme</span>
              <select value={theme} onChange={(event) => setTheme(event.target.value as Theme)}>
                {THEMES.map((option) => (
                  <option key={option} value={option}>
                    {option}
                  </option>
                ))}
              </select>
            </label>
          </section>
        </div>
      )}
    </div>
  );
}

function ConnectionPill({ connection }: { connection: string }) {
  const label =
    connection === "connected"
      ? "connected"
      : connection === "error"
        ? "disconnected"
        : "connecting";
  return (
    <span className={`pill pill-${label}`}>
      <span className="pill-dot" aria-hidden="true" /> {label}
    </span>
  );
}

function RailCard({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="rail-card">
      <h2 className="rail-title">{title}</h2>
      {children}
    </section>
  );
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div className="rail-row">
      <span>{label}</span>
      <span className="mono">{value}</span>
    </div>
  );
}
