# 19 — Desktop Agent UI/UX Benchmark (ChatGPT / Codex / Claude Code)

> **About these notes.** Point-in-time research (2026-11-26) into the public
> surfaces of ChatGPT desktop, OpenAI Codex, and Claude Code. It is design
> input for the desktop UI overhaul, not a claim about BugFound's current code.
> Verify current behavior in `crates/`. No code was changed for this document.

Status: research only. Consumed by `docs/adr/ADR-009-tauri-react-desktop-ui.md`
and `docs/roadmap/DESKTOP_UI_OVERHAUL.md`.

## Sources

| # | Source | What it establishes |
| --- | --- | --- |
| S1 | <https://developers.openai.com/codex/app> and <https://developers.openai.com/codex/app.md> | ChatGPT desktop: projects, parallel work, files/artifacts in the same workspace, chat vs. Work vs. Codex modes, quick chat. |
| S2 | <https://developers.openai.com/codex/permission-modes.md> | Permissions live **under the composer**; sandbox and approvals are separate controls; "approve for me" does not widen the sandbox. |
| S3 | <https://developers.openai.com/codex/permissions> and `/codex/prompting`, `/codex/model-selection`, `/codex/skills-and-plugins` | Codex foundations: permissions, model selection, skills/plugins as first-class UI objects. |
| S4 | <https://docs.claude.com/en/docs/claude-code/overview> | One engine, many surfaces (terminal, IDE, desktop, web, mobile). Sessions/portability are a product feature, not an afterthought. |
| S5 | <https://code.claude.com/docs/en/desktop.md> | The most detailed public description of an agent desktop UI: sidebar sessions, environment/project/permission/model row under the prompt, panes, diff review, view modes, shortcuts, context usage. |
| S6 | <https://www.anthropic.com/claude-code> | Marketing screenshots confirm the visual grammar: left sidebar with Pinned / Scheduled / Recents, conversation cards with activity summaries (`Read 3 files`), diff chips (`+9 -3`), inline code blocks, status pills (`Auto`, `Opus`, `Extra high`). |
| S7 | <https://v2.tauri.app/>, `/develop/calling-rust/`, `/concept/inter-process-communication/` | Tauri 2 architecture: `invoke` commands for request/response, events for state changes, **Channels** for ordered streaming, managed state, async commands, ACL-based permissions. |
| S8 | <https://developers.openai.com/codex/security-administration> and Claude Code permission docs | Enterprise/security posture: mode availability can be restricted by policy; UI must degrade gracefully when a mode is disabled. |
| S9 | `docs/research/17_ideal_workflow.md` (local) | BugFound's nine engagement phases and zero-submit boundary — the domain workflow the UI must expose. |

---

## 1. The shared mental model

All three products converge on the same shape:

```
┌─────────────┬──────────────────────────────────┬──────────────────┐
│             │  session header / breadcrumb     │  session rail    │
│  sidebar    ├──────────────────────────────────┤  (context, diffs, │
│  sessions   │  conversation / activity stream  │   tasks, files)  │
│  projects   │  - user turn                     │                  │
│  pinned     │  - assistant text (markdown)     │  optional panes: │
│  scheduled  │  - collapsed tool activity       │  diff, browser,  │
│  recents    │  - approval / diff / finding     │  terminal, plan   │
│             ├──────────────────────────────────┤                  │
│             │  control row (mode/model/scope)  │                  │
│             │  composer (multiline + attach)   │                  │
└─────────────┴──────────────────────────────────┴──────────────────┘
```

The important insight is **not** the visual style; it is that an agent UI is a
*supervision console*. The human's job is to set boundaries, watch progress,
review evidence, and intervene. The interface is organized around those jobs.

## 2. Patterns worth copying

| Pattern | Evidence | BugFound translation |
| --- | --- | --- |
| **Session list in a left sidebar** with pinned / scheduled / recents, grouping and search (S5, S6, S1) | "Keep every chat in view" | List engagements and chat sessions from `Store::list_sessions`; group by status (running / needs-decision / done / archived). |
| **Multiple sessions in parallel**, switch with `Ctrl+Tab`, split view (S5) | Long-running work is the norm | One worker per active session; sidebar shows live status badges. Phase 2+ feature. |
| **Control row beneath the composer**: environment, project folder, permission mode, model, effort (S5) | Controls belong where the action is | Replace the hidden `show_settings` screen: mode selector, workspace picker, model, budget usage sit directly under the composer. |
| **Permission mode as a visible, switchable control** (S2, S5) | "Permissions control below the composer" | Ask vs. Full-auto becomes a segmented control with an explicit risk explanation, not a buried radio in Settings. |
| **Collapsed tool activity** with progressive disclosure, plus Normal / Thinking / Verbose view modes (S5) | Default calm, detail on demand | `EngagementEvent::Action` becomes a compact row (`tool · ok · detail`) expandable to raw args/bytes; add Transcript / Verbose toggle. |
| **Inline approval cards with concrete context** (S2, S5) | Approve once / always / deny | Approval card shows tool, risk, redacted args, "why this needs approval", and Approve / Deny / Always allow for this tool. |
| **Diff and evidence as first-class panes** (S5, S6) | Review before accept | A "Findings" rail: finding cards with severity, status (candidate / validated / ruled_out / open_proof_gap), captured-evidence links, and the report viewer. |
| **Context / budget usage indicator** (S5) | Avoid surprise stops | Show steps, tool calls, network calls and estimated tokens against configured budgets — BugFound already persists these. |
| **Keyboard-first shortcuts** (`Ctrl+N`, `Ctrl+Tab`, `Esc` to stop, `Ctrl+/` help) (S5) | Power-user throughput | Define a shortcut map and a help overlay from day one. |
| **Surfaces share one engine** (S4) | Don't fork the agent for the UI | Keep all agent logic in existing crates; the desktop shell is a thin adapter over `bugfound-desktop-core` commands. |
| **Suggested next prompt** as gray placeholder, accept with Tab (S5) | Reduces blank-page friction | For BugFound: suggested next step based on engagement phase ("review scope", "inspect finding 2"). Phase 2. |
| **Stop / steer while running** (S5) | Interrupt is a first-class action | Wire `Esc` to cancel and keep the composer usable for steering messages at step boundaries (the core already has `steer`). |

## 3. Visual grammar (what "sekelas" actually means)

Derived from S6 screenshots and S5 descriptions; these are the details that
separate a prototype from a product:

- **Three-zone layout** with a fixed 240–280 px sidebar, a max-width (~720 px)
  centered conversation column, and an optional right rail. Nothing stretches
  to full width.
- **Quiet surfaces**: one background for the app, one slightly raised surface
  for cards, one subtle border. No colored panel chrome, no bevels.
- **Typography hierarchy** with a real font stack, 13–14 px body, 11–12 px
  metadata, tabular numbers for counters, and monospace for tool/evidence data.
- **Semantic color used sparingly**: severity and status are small colored pills
  (critical/high/medium/low, validated/blocked/ruled_out), not whole panels.
- **Generous rhythm**: 8 px spacing scale, 16–24 px card padding, consistent
  radii, 150–200 ms transitions, reduced-motion support.
- **Light + dark themes** with system-follow default and a persisted override.
- **Progressive disclosure**: default view is summaries; raw tool JSON, HTTP
  bytes and diffs are one click away.
- **Empty states that teach**: the first screen explains the workflow and
  offers one primary action, instead of a bare input box.

## 4. What NOT to copy

- **Auto-submit / autonomous external action.** The UI must never present a
  path that files a report or contacts a platform. `docs/research/17` makes
  local-report-only a non-negotiable boundary.
- **Trusting model-supplied severity/risk.** Labels in the UI must be derived
  from the deterministic verifier / store, with model values marked advisory.
- **Enterprise-only surface sprawl** (cloud, SSH, iOS simulator, computer use).
  Out of scope for v1; the ADR lists them as explicitly deferred.
- **"Bypass permissions" as a default.** BugFound's default stays policy-bounded;
  any dangerous opt-in requires an explicit, labeled confirmation.
- **Infinite scroll timelines.** Engagements are long; use paginated history
  and jump-to-latest, otherwise the DOM and the operator both drown.

## 5. Gap summary against the current egui surface

The current `crates/bugfound-desktop/src/main.rs` has: a top bar, a single-line
composer, one flat chat vector, an approval block, a collapsing raw report
text area, and a settings form of raw config fields. It has none of the
patterns above: no session list, no control row, no markdown, no collapsed
activity, no theme, no keyboard map, no evidence viewer, no budget display, no
conversation persistence in the UI, and no progressive disclosure. The
detailed audit and file references live in
`docs/roadmap/DESKTOP_UI_OVERHAUL.md` §2.
