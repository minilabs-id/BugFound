# ADR-009: Replace the egui desktop shell with Tauri 2 + React

- Status: **Accepted** (2026-11-26 — operator approved; Phase 0 complete and audited)
- Date: 2026-11-26

**Resolved choices:** English UI copy; Windows + Linux CI (macOS later); pnpm;
Zustand for frontend state; parallel sessions stay P3; keep the existing logo
for now; TUI is a later surface.
- Supersedes: the egui/eframe surface described in `README.md` → Interfaces
- Related: ADR-001 (kernel/domain separation), `docs/research/19_desktop_ui_ux_benchmark.md`, `docs/roadmap/DESKTOP_UI_OVERHAUL.md`

## Context

`crates/bugfound-desktop` is a single-window egui/eframe app: a top bar, a
single-line composer, one flat `Vec<ChatLine>`, an approval block, a collapsible
raw-text report box, and a settings form of raw config fields
(`crates/bugfound-desktop/src/main.rs:406-619`). The audit in
`docs/roadmap/DESKTOP_UI_OVERHAUL.md` §2 records 15 concrete defects, including
an unreachable engagement path (`engage_url` is never assigned by any widget),
no persisted conversation history in the UI, no markdown, no themes, no
keyboard map, and blocking SQLite I/O on the UI thread.

The target quality bar is the public desktop experience of ChatGPT/Codex and
Claude Code: a session sidebar, a control row under the composer, collapsed
tool activity, inline approval cards, a findings/evidence rail, diff and
report viewers, and a real design system (§2–§3 of research note 19).

egui is an immediate-mode toolkit with no DOM, no CSS, no real text layout for
rich markdown, no webview, and no practical pane/tab system. Reaching the target
bar in egui would mean writing a text layout engine, a markdown renderer, a
widget library and a theme system from scratch — work that would be discarded
the moment a web UI is introduced.

Tauri 2 supplies the missing pieces without moving agent logic out of Rust:
`invoke` commands for request/response, events for state changes, and
**Channels** for ordered streaming (`https://v2.tauri.app/develop/calling-rust/`).
The engine stays in Rust; only presentation moves to the webview.

## Decision

1. **Replace** `crates/bugfound-desktop` (egui/eframe) with a Tauri 2 shell.
   The desktop crate becomes a thin adapter; all reusable logic moves into a
   new `bugfound-desktop-core` library crate so the CLI and future surfaces can
   share it.
2. **Frontend:** React + TypeScript + Vite, plain CSS with design tokens
   (no component framework locked in for v1). Built assets are embedded by
   Tauri; no remote origin is loaded at runtime.
3. **IPC contract:**
   - `#[tauri::command]` functions mirror `ChatCommand` (`chat_send`,
     `approval_decide`, `engagement_start`, `engagement_control`,
     `settings_get/save`, `sessions_list`, `session_history`, `findings_list`,
     `report_open`). Phase 0 implements `app_ready` synchronously; commands
     become `async` when they start doing heavy work. All return typed
     `Serialize` results / a serializable error enum.
   - Rust → frontend state changes go through **typed events** tied to the
     existing `ChatWorkerEvent` / `EngagementEvent` variants.
   - Streaming assistant deltas use a Tauri **Channel**, not high-frequency
     events, to preserve ordering (Tauri docs recommend Channels for ordered,
     high-throughput data).
4. **State ownership stays in Rust.** The webview holds a disposable projection
   of the store (sessions, timeline, approvals, findings, budgets). It never
   writes the DB directly and never holds a second SQLite connection.
5. **Security boundary:** minimal Tauri ACL (no arbitrary shell, no arbitrary
   filesystem plugin, no HTTP plugin in the webview), strict CSP, no remote
   URLs, no Node runtime in the webview. Secrets remain `env:VAR` references;
   the UI never renders a raw API key. All redaction stays on the Rust side.
6. **CLI is unaffected** and remains a first-class surface. This ADR does not
   change agent behavior, budgets, policy, or the local-report-only rule.
7. **Deletion path:** if the overhaul is cancelled before Phase 1, the old egui
   crate is removed outright and the CLI becomes the only interface. See
   roadmap §11 for the exact deletion list.

## Consequences

### Positive

- Achieves the target visual/UX bar with standard web layout, typography, CSS
  theming, accessibility primitives and markdown rendering.
- Fixes the audit defects structurally: state projection is derived from the
  store, all DB I/O is async in Rust, history is loadable, input/steer and stop
  become real controls.
- One engine, many surfaces (ADR-001 and S4): desktop core is shared, CLI and
  future web/mobile shells can reuse it.
- Tauri's native webview keeps the binary small and avoids shipping Chromium.

### Negative / costs

- Adds a frontend toolchain (Node/pnpm, Vite, React, TS) and a webview build
  step to CI. Rust-only contributors need to context-switch.
- Webview security configuration (ACL, CSP, capability files) becomes a new
  review surface and must be kept minimal.
- A full rewrite of the view layer is a larger change than patching egui;
  phases must be incremental so the app stays buildable throughout.
- Tauri IPC is JSON-serialized; large evidence payloads should be passed as
  paths/read on demand rather than shipped wholesale across the bridge.

## Alternatives considered

| Alternative | Why not |
| --- | --- |
| **Overhaul egui in place** (custom visuals, markdown crate, tables) | Low cost but low ceiling: no CSS/DOM, weak rich-text layout, no pane system. Would approximate a chat log, not the target products. |
| **CLI / TUI only (Claude Code style)** | Cleanest and cheapest, but the operator asked for a ChatGPT/Codex-class visual surface. Keep as the fallback deletion path, not the decision. |
| **Local HTTP server + system browser (no native shell)** | Avoids Tauri packaging, but loses native window integration, OS shortcuts, deep links and a reliable single-app experience; security origin handling is harder. |
| **Electron** | Ships Chromium, much larger binary and memory footprint; no benefit over Tauri when the backend is already Rust. |

## Compliance checks before merge

- `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings`,
  `cargo test --workspace`, and the ADR-001 domain-boundary check still pass.
- Frontend: `pnpm lint`, `pnpm typecheck`, `pnpm test`, production build.
- Tauri ACL review: webview cannot reach shell/fs/http plugins directly.
- Manual smoke: start engagement, answer an approval, steer while running,
  stop, reopen app and reload history, open report, switch theme, use keyboard
  shortcuts.

## References

- <https://v2.tauri.app/> — Tauri 2 overview.
- <https://v2.tauri.app/develop/calling-rust/> — commands, events, channels, managed state.
- <https://v2.tauri.app/concept/inter-process-communication/> — message-passing model.
- `docs/research/19_desktop_ui_ux_benchmark.md` — UI benchmark and sources.
