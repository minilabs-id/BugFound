# AgentBug Architecture

## Overview

AgentBug is a Rust, LLM-agnostic agent core with a local bug-bounty engagement
layer. The design borrows the durable-session idea from OpenCode but keeps the
execution model deliberately simple: one bounded Runner step loop, typed tools,
a typed policy, and SQLite as the single source of truth. Every feature advertised
in `README.md` resolves to a call site in the evidence matrix at
`docs/PRODUCTION_PLAN.md` §2; if it is not in that matrix, it is not a claim.

- **Session**: unit of work with persistent state (id, goal, state, model, history)
  in `agentbug-store` (`create_session`, `claim_session`, `transition_state_owned`).
- **Runner loop** (`agentbug-core::Runner::run_goal` / `run_loop`): load history →
  LLM chat with tool schemas → policy-evaluate tool calls → execute or park for
  approval → append results → continue; otherwise finalize. Each step is one LLM
  call; there is no in-memory tool loop.
- **Tool runtime** (`agentbug-tools`): typed tools with schema, risk label,
  validated args, timeout/capture and truncated output; deterministic registry
  via `try_default_registry_with_options`.
- **Policy** (`agentbug-policy`): `ask` vs `full_auto`, allow/ask/deny decisions,
  scope parsing from a program brief (`parse_scope_brief`), default-deny for
  destructive/intrusive actions.
- **LLM layer** (`agentbug-llm`): OpenAI-compatible `/v1/chat/completions` with
  tool calling, `base_url` normalization, `GET /v1/models` discovery with
  `default_model` fallback, retries with backoff.
- **Store** (`agentbug-store`): SQLite (WAL) for sessions, messages, approvals,
  events, budgets, findings, assets, artifacts, coverage, hypotheses, reports and
  `trace_events`. Redaction (`redact`) is applied at report and CLI egress.

## Execution & control

- **Bounded steps, durable budgets.** `session_budgets` plus `ensure_budget` /
  `budget_usage` persist steps, tool/network calls and the RPM window across
  `resume` and restarts (`budget_survives_resume_with_a_new_runner`).
- **Approval is a DB transaction.** Risky tool calls park the session in
  `waiting_approval`; `resolve_approval` resolves once under a `status='pending'`
  predicate, and `claim_session` / `transition_state_owned` guard ownership and
  lease so two processes cannot both run an approved action.
- **Engagement control is process-local and ID-based.** `agentbug-engagement`
  owns a control center (`pause` / `resume` / `abort`) keyed by engagement id;
  abort is terminal. Pause/resume/abort are surfaced by the CLI `engagement`
  command and the desktop Engagement tab.
- **Classified outcomes** are recorded in session/engagement state
  (`completed | interrupted | failed | waiting_approval | blocked`, plus
  `brief_only` for the read-only ingestion path).

### Modules that are NOT production-wired

`agentbug-core` retains `inbox`, `execution`, `event`, `step`, `compaction` and
`error` modules (re-exported at the crate root). `subagent`, `skill` and `usage`
were removed during hardening. The retained modules are unit-tested in isolation
but have **no production call site from `agentbug-engagement`**. They are therefore
not advertised as agent features: there is no steer queue, no wake coalescing, no
skill loader and no subagent job execution in the shipping engagement flow. If a
hardening item wires one of them, add a feature → call site → test row in
`PRODUCTION_PLAN.md` §2 first.

## Policy modes

- **ask**: auto-allow safe/read actions; require approval for exec/network/write/
  intrusive/unknown; deny out-of-scope or forbidden targets.
- **full_auto**: autonomous **only within the policy envelope** (scope/allowlist,
  rate/budget, non-destructive, tool risk labels). Guardrails remain active; the
  engagement runner still refuses out-of-scope targets and destructive actions.

## Token & performance strategy

- Prompts/history are compacted in `Runner::build_llm_messages` once they grow
  large (`compaction_summarizes_old_turns_and_keeps_recent_tail`); tool outputs are
  truncated and large artifacts are stored, not replayed verbatim.
- Bounded steps/tool-calls, timeouts, deterministic dedupe, and per-session
  budgets keep cost predictable. Token/cost figures come from API usage in the
  replay (`token_usage`, `agentbug tokens`), never from a `len/4` estimate.

## Bug-bounty layer (on the core)

- **Brief ingestion** (`fetch_brief` → `extract_profile_from_text` or LLM-assisted
  extraction): scope and ROE are parsed from the **whole** brief; missing in-scope
  targets or login/404 pages fail closed. `engage_brief_only` performs this path
  without executing any tool.
- **Planner** (`wstg_playbooks`, `prioritize_targets`): nine WSTG playbooks become
  durable tasks and hypotheses; coverage is recorded per target (`record_coverage`).
- **Verifier & report**: the deterministic verifier replays tool-captured
  request/response bytes, requiring reflection of the canary that
  `HttpRequestTool` injected into the real outbound request
  (`attach_capture` / `get_capture`; ADR-008);
  `validate_poc` is a helper tool, **not** an authoritative acceptance gate, and
  is filtered when the ROE forbids state changes. Findings carry evidence bytes
  and SHA-256 hashes; the canonical Markdown renderer emits Executive Summary,
  Scope & ROE, Methodology, Findings, Coverage, Timeline and Appendices. Reports
  are local only — there is no submission path to any platform.
- **Trace & eval**: `append_trace` writes `trace_events` (`run_start`, `action`,
  `finding`, `usage`, `verifier`); `eval/export_trace.py` exports them and joins
  the engagement replay into `replay.jsonl`, and `eval/score.py` computes recall,
  precision, FPR, reproducibility and tokens-per-finding. Evaluation is
  operator-recorded scaffolding; no results are asserted.

## Implemented hardening

Durable claims/leases and guarded transitions; atomic approval resolution; persistent
budgets; redaction at report, CLI and tool-output egress boundaries; deterministic
PoC verifier;
SHA-256 evidence; tamper-evident event chain (`verify-log`); shell allowlist with
scrubbed env; HTTP DNS pinning with private-range blocking and no proxy; path
confinement; deterministic tool registry; canonical report renderer. Exact call
sites and tests are in `docs/PRODUCTION_PLAN.md` §2.

## Remaining gaps

OS-level isolation (container/VM with restricted egress), clustering beyond
process-local claims, a real browser engine, a live submission path, a
performance benchmark and a maintained fuzz corpus are all deferred. H-01…H-14
and B1–B14 have landed and are awaiting the verification gate; benchmark results
must be recorded by an operator. See `REMAINING_GAPS.md` for the honest list,
`PRODUCTION_PLAN.md` §4 for the gate and §5 for readiness criteria.
