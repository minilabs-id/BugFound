# MiniBug Architecture (Phase 1: Universal Core)

## Overview
MiniBug is a Rust, LLM-agnostic universal agent core. The design borrows proven ideas from OpenCode while simplifying for performance and maintainability:

- **Session**: unit of work with persistent state (id, goal, state, model, history).
- **Runner loop**: bounded step loop — load history → LLM chat (with tool schemas) → if tool calls: policy-evaluate & execute (or pause for approval/deny) → append results → continue; else finalize.
- **Tool runtime**: typed tools with schema, risk label, validated args, timeout/capture, truncated outputs.
- **Policy/Permission**: `ask` vs `full_auto` modes, allow/ask/deny decisions, target allow/deny hooks, default-deny for destructive/intrusive actions.
- **LLM layer**: OpenAI-compatible `/v1/chat/completions` + tool calling; `base_url` normalization; model auto-discovery via `GET /v1/models` with `default_model` fallback.
- **Store**: SQLite (WAL) for sessions/messages/approvals (minimal in MVP).

## Execution & control (target model, inspired by OpenCode)
- Cooperative `resume/wake/interrupt/await_idle` with wake coalescing and durable **run claim** for crash recovery.
- Continuations and inbox (steer vs queued input) to avoid losing control/state.
- Classified outcomes: `completed | interrupted | failed | waiting_approval | blocked`.
- Strict error taxonomy (retryable vs blocked/declined/corrected vs fatal) and transactional state transitions.

## Policy modes
- **ask**: auto-allow safe/read actions; require approval for exec/network/write/intrusive/unknown; deny out-of-scope/forbidden.
- **full_auto**: autonomous **only within policy envelope** (scope/allowlist, rate/budget, non-destructive). Guardrails remain active even for broad/"no-scope" events unless explicitly configured.

## Token & performance strategy
- Keep prompts/history compact (compaction/summaries), store large tool outputs as artifacts and pass references/summaries to the LLM.
- Bounded steps/tool-calls, timeouts, dedupe/cache of deterministic results, streaming/capture limits.
- Async I/O, minimal dependencies, explicit state machine.

## Phase 2 (Bug Bounty layer, on stable core)
- Scope engine (in/out-of-scope parsing & enforcement), engagement profiles.
- Tool adapters: httpx, subfinder, dnsx, katana, nuclei, ffuf, naabu/nmap (gated), Playwright, etc., with structured parsing and per-tool risk/rate profiles.
- Asset graph/store, prioritized scheduler, hypothesis-driven playbooks.
- Safe validation/PoC, evidence redaction, dedupe, and report drafting — always policy-gated.

## Implemented hardening
- Interactive approval/resume flow with durable claims, lease renewal and stale-run recovery.
- Tool-result interception persists findings/assets/artifacts; reports are redacted.
- Rate/tool/network budgets are enforced in the runner and audited as events.
- HTTP egress is DNS-pinned with private/reserved-range blocking and no redirects;
  shell commands have a destructive-pattern guardrail and secret-scrubbed env.
- Path confinement for filesystem tools, output truncation, fail-fast API keys,
  deterministic tool registry, and mock-LLM integration tests for the runner loop.

## Remaining gaps (deployment, not code)
OS-level isolation (container/VM with restricted egress), context compaction for
very long sessions, concurrency/clustering beyond process-local claims, and
additional tool adapters (nuclei/ffuf/nmap/Playwright) with per-tool risk and
rate profiles.
