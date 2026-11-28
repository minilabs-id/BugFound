# 03 — Architecture Gap Analysis (baseline → Agent-Driven Hybrid V3)

> Prepared 2026-11-26. Baseline evidence: `01_CURRENT_STATE_AUDIT.md`.
> Research basis: `02_AGENT_ARCHITECTURE_RESEARCH.md`. No source code changed.

## 1. The three approaches

### 1.1 Workflow-driven system
The system owns the sequence. A planner enumerates tasks up front; each task is
a bounded runner invocation with a fixed role and tool set; completion is
measured by task state and budget. The LLM is a step executor, not a strategist.

- **Strengths**: predictable, cheap, auditable, easy to harden, trivial to
  reason about for compliance. Fits deterministic scope/ROE enforcement.
- **Weaknesses**: cannot exploit early observations; re-runs busy work;
  "coverage" can be achieved without information gain; quality ceiling is the
  quality of the pre-authored playbooks.
- **Source support**: Anthropic's workflow pattern with programmatic gates [S07];
  WSTG explicitly warns against treating the guide as a checklist [S22].

### 1.2 General autonomous agent
The LLM owns both strategy and execution: it decides the next action, the
tool, the arguments and when to stop, with minimal external control.

- **Strengths**: maximal flexibility; can follow unexpected evidence.
- **Weaknesses**: scope/ROE become prompt text; no deterministic enforcement;
  prompt injection can pivot to unintended targets; hard to audit, reproduce
  or budget; compounding errors; approval fatigue or bypass.
- **Source support**: ReAct [S01] shows the loop pattern; OpenAI guardrails/HITL
  [S10][S11] and OWASP LLM01/ASI02 [S37][S39] document exactly the failure modes
  that appear when the loop is unconstrained.

### 1.3 Agent-driven hybrid (target)
The **agent chooses the next investigation step** from an explicit, persistent
investigation state; a **domain engine** supplies technique knowledge and
mappings; a **deterministic security harness** authorizes every action and owns
budgets/approvals/stopping; an **evidence verifier** decides what is proven.

- **Strengths**: adaptive while auditable; knowledge is contextual, not a
  rigid order; the model cannot widen scope, raise permission, skip approval
  or forge a verdict.
- **Costs**: more components, more state to version, harder testing; needs
  explicit plan/replan artifacts and a real intent gate.
- **Source support**: S01/S03/S06/S07 for plan + replan; S10/S11/S20/S21/S37/
  S39 for the harness; S22–S36 for domain/evidence; S16/S17 for persistence.

## 2. Where BugFound actually is

**Verdict: workflow-driven, with limited single-step delegation — not
agent-driven.** Evidence:

| Dimension | Code evidence | Verdict |
| --- | --- | --- |
| Who picks the next task | `wstg_playbooks()` static 9 items `engagement/lib.rs:3414-3453`, enumerated `:1466-1472` | System |
| How rounds work | `search_round_tasks :2122-2138`; round ≥2 returns **every** task | System (blind replay) |
| Role selection | `role_for_playbook` static map `roles.rs:42-48` | System |
| Target prioritization | `prioritize_targets domain.rs:92-128` only called by CLI `plan` | Orphaned, not in loop |
| Hypothesis feedback | `feedback_hypotheses :2207-2267` → `feedback_prompt :2292-2312` text only; created count ignored `:1821` | Prompt-only |
| Agent freedom within a step | One LLM call → one tool call → harness gate; `role_handoff` one-level, depth 1, ≤9 children | Bounded |
| Stopping | Config `max_rounds`, budget/stall guard, abort; no "goal satisfied" state | Harness-only |
| Verdict authority | Replay oracles `:3856-3946`; model advisory | Harness (correct) |

The one genuinely adaptive mechanism is the kernel's stall guard
(`core/lib.rs:2050-2087`, `stall_limit: 6`), which stops repetitive playbooks —
but it reacts to absence of progress; it does not choose a better next step.

## 3. Gap matrix

Each row: baseline → V3 target → gap class (**S** structural seam missing,
**D** data missing, **E** enforcement hole, **T** test/eval missing, **U** UX/surface).

| # | Capability | Baseline | V3 target | Class |
| --- | --- | --- | --- | --- |
| G1 | Next-step selection | Static task queue | `NextStep` chosen by agent from investigation state; one tool call per step | S |
| G2 | Plan / replan artifacts | No plan object; task state only | Persisted `Plan` + `Replan` decision after each observation | S/D |
| G3 | Information value | No scoring; `prioritize_targets` orphaned | `expected_information_gain`, cost, risk, novelty fields drive ordering | D |
| G4 | Coverage-driven revisit | Round ≥2 replays all tasks | Revisit only tasks whose coverage/hypothesis delta justifies it | S/T |
| G5 | Discovery feedback | Prompt text only | State transition mutates asset graph and plan; rejection written to memory | S/D |
| G6 | Investigation state | Split across tasks/hypotheses/coverage/assets | Single versioned `InvestigationState` owned by agent, snapshotted per step | D |
| G7 | Hypothesis lifecycle | Status only; mirrors tasks | `draft→planned→running→tested→{confirmed,refuted,blocked,open_gap}` with confidence + oracle before testing | D/E |
| G8 | Domain knowledge | 9 hard-coded WSTG playbooks | Versioned technique catalog (WSTG/ASVS/API/CWE), deferred MCP exposure, dynamic priority | S |
| G9 | Scope/ROE authority | Typed scope works; `roe_hash` empty, `roe_json` untyped, `brief_version` ack ignored, CLI bypass | Machine-readable ROE object + ordered deny-wins rules; every path honors it | E |
| G10 | Approval semantics | Durable single-use expiry; "always" not project-scoped; no idempotency key | Server-side approval state, authenticated reviewer, replay-safe atomic transition, idempotency keys, dry-run preview | E |
| G11 | Sandbox / egress | Workspace confinement, DNS pin, blocked ranges; no OS isolation | Dual filesystem + network isolation, egress allowlist proxy, least privilege | E |
| G12 | Verification coverage | Canary echo + differential; other classes always `open_proof_gap` | Multi-oracle engine including OOB consumer; confidence classes; CVSS v4 vector + Report Confidence | S/D |
| G13 | Finding lifecycle | Model advisory, verifier promotes; status fields exist | `observed→reproducible→proven|inconclusive|rejected`; only verifier sets `confirmed`; TLP label inherited | E/D |
| G14 | Memory / compaction | `CompactionV2` summarizes conversation; subagents return full text | `investigation.json` + `progress.md` + 1–2k-token digests; tool-result clearing; tuned compaction | S/D |
| G15 | Resume semantics | Leases + guarded transitions + inbox; no agent-facing checkpoint | Authenticated, version-checked `RunState` resume; step-level replay from event log | D |
| G16 | Audit / replay | Hash-chained events, `trace_events`, redaction | Append-only `(run_id, step_id, call_id)` log of plan + policy decision + args + redacted output + verdict + approver | D/T |
| G17 | Stopping conditions | `max_rounds`, budget, stall, abort (verifier still runs) | Goal-satisfied vs exhausted distinction; tripwire on out-of-scope/malformed approval; graceful finalize | S |
| G18 | Evaluation | `score.py` scaffolding; reproducibility not_measured; stale e2e | Metrics for next-step quality, replanning, coverage, FP/FN, efficiency, injection resistance, resume, consistency | T |
| G19 | Operator console | Tauri Phase 0: one command, disabled controls | Sessions, timeline, approvals, findings, report, budget controls wired to Rust commands | U |
| G20 | Multi-agent | `role_handoff` one level; two roles used | Only if justified: subagents return condensed evidence; planner stays single-path by default | S (optional) |

## 4. Gap clusters (what blocks what)

1. **G1–G5 (decision loop)** are one structural cluster: without a plan/replan
   artifact and a state mutation path, "agent-driven" cannot exist. Must be
   designed together, not shipped one at a time.
2. **G6–G8 (state & knowledge)** provide the inputs the decision loop needs.
   `InvestigationState` and the technique catalog must precede replanning.
3. **G9–G11 (harness)** are a correctness/safety precondition for *any*
   increased autonomy. They must not be weakened to make G1–G5 easier.
4. **G12–G13 (verifier)** determine whether adaptive actions can be trusted;
   OOB consumer and confidence classes are prerequisites for accepting
   non-reflection findings.
5. **G14–G17 (continuity/control)** make long adaptive runs safe to stop/resume.
6. **G18–G19 (evaluation/console)** make the change measurable and operable.

## 5. What can be preserved (incremental viability)

A full rewrite is **not** justified. The following are sound and should be
retained: runner step loop and leases; policy scope matcher; approval atomicity;
tool registry with risk labels and canary evidence; store schema (extend, don't
replace); ROE classifier; canonical report renderer; event hash chain; eval
scorer arithmetic. The change is mostly **adding a decision layer and
re-wiring the orchestrator**, plus closing specific enforcement holes — not
replacing the kernel.

The highest-leverage seam is `run_engagement`'s task loop
(`engagement/lib.rs:1502-1962`): replace "iterate playbook tasks" with "ask the
planner for the next step given `InvestigationState`, then execute it through
the existing harness". Everything downstream (runner, policy, store, verifier)
already has the needed primitives.

## 6. Non-negotiables while closing the gap

- LLM output is untrusted input to the harness; never the authority for scope,
  permission, approval or verification status [S37][S39].
- Deny wins over allow/ask; "always allow" is project-scoped and never overrides
  a configured deny [S21].
- No submission path, local report only.
- Every consequential action carries an idempotency key and replay protection
  [S10].
- Every catalog mapping is version-pinned [S26][S29][S35].
- Do not claim a capability V3-ready until it is on the production execution
  path and covered by a test (acceptance criterion 8 of the master prompt).

## 7. Open questions

1. Should technique catalog exposure be in-process Rust catalog + tool search,
   or a separate MCP server? (Trade-off: deployment complexity vs. reuse.)
2. Should the planner be a separate LLM role or the same model with a different
   prompt/context projection? (Cost vs. context isolation.)
3. How to score expected information gain without overfitting to known
   vulnerabilities? Needs an eval fixture set.
4. Which oracle classes become first-class in V3 after canary/differential?
5. Is OS-level sandboxing in scope for V3 or staged after the decision loop?
6. Should `role_handoff` remain, be replaced by planner subagents, or be
   deleted? (Currently one-level and lightly used.)
