# 04 — BugFound V3: Agent-Driven Target Architecture (blueprint)

> Status: **design only — not implemented**. Prepared 2026-11-26.
> Inputs: `01_CURRENT_STATE_AUDIT.md`, `02_AGENT_ARCHITECTURE_RESEARCH.md`,
> `03_ARCHITECTURE_GAP_ANALYSIS.md`. Source-code mapping and phases are in
> `05_MIGRATION_AND_IMPLEMENTATION_PLAN.md`; measurement in
> `06_AGENT_EVALUATION_PLAN.md`. No source code was changed for this document.

## 0. One-sentence definition

**The agent decides *what to investigate next*; the domain engine supplies
*how*; tools supply *capability*; investigation state supplies *continuity*;
the security harness supplies *authorization*; the evidence verifier decides
*what is proven*.**

## 1. Component architecture and dependency direction

```
                         ┌──────────────────────────┐
   operator ────────────►│  Operator Console (Tauri) │◄──────── reviewer
                         │  timeline / approvals /  │
                         │  findings / budgets      │
                         └────────────┬─────────────┘
                                      │ commands + events (read-only projection)
                                      ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                         SECURITY HARNESS (authority)                    │
│  ROE/authorization · ordered rules (deny>ask>allow) · budgets · approvals│
│  intent gate (PEP/PDP) · sandbox FS+egress · stop conditions · audit log │
└──────▲───────────────────────┬───────────────────────┬───────────────────┘
       │ NextStep (untrusted)  │ authorized action    │ verdict / state
       │                       ▼                       │
┌──────┴───────────┐   ┌──────────────────┐   ┌────────┴───────────────┐
│ AGENT / PLANNER  │   │ TOOL EXECUTION   │   │ EVIDENCE VERIFIER      │
│ observe→plan→act │──►│ registry / schema│   │ oracles · provenance · │
│ →evaluate→replan │   │ timeout / retry  │   │ CVSS+CWE · confidence  │
└──────▲───────────┘   └────────┬─────────┘   └────────┬───────────────┘
       │ context projection     │ artifacts            │ verdict written back
       ▼                        ▼                      ▼
┌──────────────────────────────────────────────────────────────────────────┐
│              PERSISTENT INVESTIGATION MEMORY (single source)            │
│  InvestigationState · AssetGraph · HypothesisLedger · CoverageLedger    │
│  Plan/Replan · Observations · Decisions · EvidenceRefs · Reflection     │
└──────────────────────────────────────────────────────────────────────────┘
       ▲
       │ technique lookup (deferred, versioned)
┌──────┴───────────────────┐
│ BUG BOUNTY DOMAIN ENGINE │  WSTG/ASVS/API Top10/CWE · ROE semantics ·
│ (knowledge catalog)      │  vulnerability classes · technique metadata
└──────────────────────────┘
```

**Dependency direction rules:**
- Planner → harness (request), never harness → planner (authority).
- Domain engine is read-only knowledge; it never grants permission.
- Tool execution is only reachable through the harness intent gate.
- Verifier writes verdicts to memory; only the verifier may set `confirmed`.
- Console reads projections; it never writes the store directly.
- Kernel stays domain-free (ADR-001): no finding/bounty/WSTG vocabulary in
  `bugfound-core`. New domain types live in domain/engagement crates.

## 2. Runtime lifecycle and agent loop

### 2.1 Lifecycle

| Phase | Owner | Exit condition |
| --- | --- | --- |
| `initialize` | Harness | ROE object parsed/acked; workspace created; investigation state seeded; checkpoint written |
| `plan` | Planner | `Plan` with at least one actionable step, or explicit `inconclusive` |
| `authorize` | Harness | rule decision recorded (`allow`/`ask`/`deny`) before any tool dispatch |
| `act` | Tool layer | one tool call returns bytes (even on failure) within timeout |
| `observe` | Harness | redacted observation appended; evidence refs hashed |
| `evaluate` | Planner + verifier | hypothesis status updated; verdict recorded |
| `replan` | Planner | next step chosen or termination requested |
| `finalize` | Verifier + report | report built from verified state; operator review flag set |

### 2.2 The loop (ReAct-shaped, plan-and-execute discipline)

```
while harness.allows_continue():
    plan   = planner.next_step(investigation_view(ctx_budget))   # untrusted
    intent = harness.intent_gate(plan)        # validate schema, scope, budget, risk
    if intent.requires_approval:
        approval = harness.request_approval(intent, diff_preview=True)
        if not approval.granted: memory.reflection("denied", plan); continue
    observation = tools.execute(intent)       # sandboxed, idempotency key, timeout
    evidence    = harness.capture(observation)  # raw bytes, canary, digest, TLP
    verdict     = verifier.evaluate(intent, evidence)
    memory.apply(plan, observation, verdict)  # atomic step transaction
    planner.replan(memory.delta_since(plan.id))
    if harness.stop_condition(memory): break
report = verifier.build_report(memory)        # local only, no submission
```

Key properties inherited from research: one tool call per step preserves ground
truth [S01][S07]; explicit plan/replan artifacts provide transparency [S07];
tool-result clearing + 1–2k-token digests keep context small [S16]; the harness,
not the model, owns iteration/time/token/cost ceilings [S07][S39].

### 2.3 Stopping conditions (all harness-owned)

1. Goal satisfied: all in-scope hypotheses terminal
   (`proven|refuted|blocked|not_applicable|accepted_open_gap`) and coverage
   reconciled.
2. No positive-information action remains (planner returns `no_action` twice).
3. Budget ceiling reached (steps, tools, network, RPM, tokens, cost).
4. Stall: no coverage/hypothesis/evidence transition for N steps (existing
   stall guard, keep).
5. Tripwire: out-of-scope intent, malformed approval arguments, tool misuse —
   halt with explicit reason, never silently continue.
6. Operator abort/pause — durable control row; abort stops new actions but
   still finalizes the current evidence and writes an `aborted` report.
7. Context compaction threshold — not a stop, but a checkpoint before
   continuation.

## 3. Execution flow: engagement → report (end to end)

```
[ROE object + scope + objective]
        │
        ▼
 Harness seeds InvestigationState (assets, open questions, allowed classes,
 budgets, TLP) and writes checkpoint #0
        │
        ▼
 Planner asks Domain Engine: candidate techniques for current state
 (deferred catalog lookup; returns technique ids + preconditions, not a fixed order)
        │
        ▼
 Planner emits NextStep {hypothesis_id, technique_id, target, rationale,
                          expected_evidence, estimated_cost}
        │
        ▼
 Intent Gate: schema valid? target in scope? ROE allows class? budget left?
 permission? → deny / ask / allow (deny wins)
        │
        ├── ask ──► Approval card with dry-run/diff → operator decision
        ▼
 Sandboxed tool execution (egress allowlist, idempotency key, timeout/retry)
        │
        ▼
 Evidence capture: raw bytes + canary + digest + source + timestamp + TLP
        │
        ▼
 Verifier: replay oracle / differential / paired control / confidence
        │
        ▼
 Memory transaction: observation + verdict + hypothesis transition +
 coverage row + reflection + audit event appended atomically
        │
        ▼
 Planner replans from the state delta; loop or terminate
        │
        ▼
 Verifier builds report: scope, limitations, findings (vector+confidence),
 coverage, timeline, cleaned artifacts, TLP header — draft, operator review
```

## 4. Data model and investigation state

### 4.1 `InvestigationState` (versioned, one row per engagement)

```
InvestigationState {
  id, engagement_id, revision,            // optimistic concurrency
  objective, roe_ref, scope_ref, tlp_label,
  phase,                                   // metadata only, not execution order
  assets: AssetGraph,
  hypotheses: HypothesisLedger,
  coverage: CoverageLedger,
  plan: Plan,                              // current actionable steps
  open_questions: [Question],
  reflections: [Reflection],              // verifier/operator feedback
  stop_reason: Option<StopReason>,
  checkpoint_ref, updated_at
}
```

Stored as a durable row plus an append-only `investigation_events` log. The
agent's view is a **projection** of this state under the current context budget;
the full state is never dumped into the prompt.

### 4.2 Asset graph

Nodes: host, IP, port, service, URL/path, parameter, identity/role, artifact.
Edges: `resolves_to`, `hosts`, `exposes`, `linked_by`, `same_origin`,
`authority_for`. Each node carries `source`, `scope_status` (in/out/unknown),
`discovered_at`, `confidence`, `evidence_ref`. The graph makes "what is left to
investigate" computable instead of relying on prompt text.

### 4.3 Hypothesis ledger and lifecycle

```
draft → planned → running → tested → confirmed | refuted | blocked |
                                     not_applicable | open_proof_gap
```

Each hypothesis carries: `claim`, `source_observation`, `technique_id`,
`oracle_required`, `priority`, `expected_information_gain`, `cost_estimate`,
`confidence`, `counterevidence`, `owner_step`, `terminal_reason`.

Only the verifier may move a hypothesis to `confirmed`; the planner may propose
and may mark `refuted`/`blocked` with a named control. An `open_proof_gap` must
name the missing proof and blocks finalization unless explicitly accepted by
the operator (existing V1 rule — keep).

### 4.4 Coverage ledger

Keep the V1 requirement-keyed rows, but add `information_value` and
`last_action_id` so the orchestrator can decide *what to revisit* rather than
replaying all tasks. `attempted-and-denied` remains valid coverage.

### 4.5 Priority / information value

A deterministic scoring function (not the model's self-report):

```
priority(h) = w1*expected_information_gain
            + w2*severity_potential
            + w3*asset_reachability
            - w4*estimated_cost
            - w5*repetition_penalty
```

Weights are config, versioned with the plan. The planner may override with a
written rationale, which the harness logs; the harness never lets an override
bypass scope, ROE or budget.

## 5. Planning, prioritization, replanning

- **Plan artifact**: ordered steps with dependencies; steps may form a DAG for
  independent passive recon (scheduler in harness, not in LLM).
- **Replan decision** after every observation: `continue`, `skip`, `replace`,
  `insert`, `stop`, each with rationale and the state delta that triggered it.
- **Dynamic catalog priority**: technique records carry preconditions and
  benefits/limitations [S22][S24]; the planner scores them against current
  state. WSTG phases are metadata for filtering, not a sequence.
- **Anti-repetition**: a durable action signature (`tool + normalized args +
  target + technique`) deduplicates and applies a repetition penalty; this
  replaces V1's blind round replay.
- **Stop**: harness-owned, per §2.3.

## 6. Tool discovery, selection, invocation, result handling

| Concern | Design |
| --- | --- |
| Discovery | Tool registry (existing) + deferred catalog: at most ~20 definitions in context; technique/tool search returns schemas just in time [S08][S13]. |
| Selection | Planner proposes a technique id; harness maps to allowed tools for the current role/ROE. Model never invents a capability. |
| Invocation | One call per step; strict JSON Schema; arguments you already know are injected by the harness, not requested from the model. |
| Authorization | Pre-approval tool guardrails validate target, method, rate and budget before dispatch [S11]. |
| Execution | Sandbox (FS + egress allowlist), timeout, bounded retry, cooperative-then-forced cancellation, idempotency key [S10][S20][S39]. |
| Result | Raw bytes captured even on failure; filtered/redacted view returned to the model; full bytes stay in the evidence store; cleaned artifacts only in the report [S19][S25]. |
| Error | Typed failure with `retryable` flag; repeated failure becomes a reflection and a hypothesis state change, not a silent retry loop. |

## 7. Policy decision pipeline and approval flow

```
planner output (untrusted)
   │
   ├─ 1. schema validation (strict) ────────────► reject + reflection
   ├─ 2. ROE/scope check (blocking guardrail) ──► deny, no token/tool side effect
   ├─ 3. ordered rules: deny > ask > allow (last match wins) [S21]
   ├─ 4. budget + rate + duplicate guard ───────► deny/defer
   ├─ 5. risk classification → needs approval?
   │       yes: approval request with diff/dry-run, authenticated reviewer,
   │       server-owned pending id, atomic owner-checked resolution,
   │       project-scoped "always" that never overrides deny
   └─ 6. execute with idempotency key; audit every decision
```

Non-negotiables: the LLM cannot write scope/ROE/permission/budget tables;
approval never guarantees exactly-once execution; every consequential action
carries a stable idempotency key; out-of-scope tripwire halts the run.

## 8. Memory, context projection, compaction, persistence, resume

- **Persistent memory**: `investigation.json`-equivalent durable state plus
  `progress.md`-equivalent operator-facing summary; artifacts referenced by
  hash, not embedded in prompts.
- **Context projection**: smallest high-signal set — current plan, top-k
  hypotheses, relevant asset subgraph, last N redacted observations, tool
  schemas. Just-in-time identifiers (paths, ids, queries) for the rest [S16].
- **Compaction**: summarize near-limit context preserving decisions,
  unresolved questions and oracle choices; **clear tool results first**;
  subagents return 1–2k-token digests; keep the five most-recently-touched
  artifacts.
- **Checkpoint**: every step is a transaction — observation, evidence refs,
  verdict, state revision, event log. Resume is authenticated and version-
  checked; a stale checkpoint fails closed rather than replaying side effects.
- **Replay**: event log keyed `(run_id, step_id, call_id)` allows deterministic
  reconstruction of decisions (not of live network responses).

## 9. Evidence provenance, verification, finding lifecycle

```
raw tool bytes ─► canary + digest + source + timestamp + scope fingerprint
                  + TLP label  ⇒ EvidenceBundle (immutable)
EvidenceBundle ─► oracle (canary echo | differential | paired control |
                          state delta | timing | OOB | browser deferred)
                  ⇒ Verdict {proven|inconclusive|refuted, confidence, counterevidence}
Verdict ─► Finding {id, scope_ref, CVSS version+vector+score, CWE/OWASP v-pinned,
                    repro steps, masked artifacts, limitations, TLP, retest status}
Only verifier sets status=confirmed. Model labels are advisory.
```

Finding lifecycle mirrors hypothesis terminal states; `open_proof_gap` names
the missing proof and blocks finalization until operator acceptance. Report is
local-only, marked `draft — operator review required`; no submission path.

## 10. Error handling, timeout, retry, cancellation, recovery

| Failure | Behavior |
| --- | --- |
| Tool timeout | Bound per tool; cooperative cancel then forced kill; capture partial bytes; typed failure with `retryable`. |
| Provider error | Existing recovery table; auth errors never fall back; model-not-found falls back; bounded retries with backoff. |
| Malformed tool args | Strict schema reject; one bounded repair attempt; otherwise reflection + replan. |
| Approval expiry | Fail closed; step skipped with reason; no deferred execution. |
| Crash mid-step | Lease recovery + `settle_on_boot`; incomplete step marked `interrupted`; resume from last committed revision. |
| Duplicate/ambiguous execution | Idempotency key + signature dedupe; reconcile before retry, never blind re-execution. |
| Out-of-scope intent | Tripwire: halt, audit event, operator notice. |

## 11. Observability, tracing, audit log, replay

Append-only `harness_events` keyed `(run_id, step_id, call_id)`:
`plan_generated`, `policy_decision`, `approval_requested/resolved`,
`tool_invoked`, `tool_result_redacted`, `verdict`, `state_transition`,
`compaction`, `stop_reason`. Each event carries revision, actor (`model`,
`harness`, `operator`), and a hash link. Redaction is applied **before** the
event is written, not at display time. Export to the eval harness as replay
JSONL; `score.py` consumes the same schema. Operator console reads a projection.

## 12. Model/provider abstraction

Keep `bugfound-llm` as the boundary: OpenAI-compatible chat + streaming, model
discovery, tool schemas, typed errors. Add:
- a `Planner` role with its own context projection (may be the same provider
  with a different system prompt — decision deferred, see Open Question 2);
- a `Verifier` advisory role (existing verification-role pattern);
- catalog access through a tool-search interface, not a second provider;
- version marker for agent definition + catalog versions stored with each plan,
  so replay knows which instructions were active [S10].

## 13. Security boundary and threat model

| Trust boundary | Control |
| --- | --- |
| Operator → harness | Authenticated approvals; ROE object is operator-owned, versioned. |
| Model → harness | All planner output untrusted; strict schema + intent gate. |
| Harness → tools | Least privilege per tool; egress allowlist; FS sandbox; rate/budget ceilings. |
| External target → agent | Indirect prompt injection treated as untrusted content; segregate and label; deterministic output validation [S37]. |
| Domain engine → agent | Catalog is data, never executable authority; validate schemas; pin versions. |
| Verifier → report | Only verifier sets `confirmed`; no self-grading; cleaned artifacts only. |
| Console → store | Read-only projection; no direct DB access from webview. |
| Evidence → report | Immutable bundles, TLP inherited, local artifact links. |

**Out of scope / explicitly forbidden**: auto-submission; privilege escalation;
model-editable scope/ROE; unverified severity; unbounded fan-out; remote
origins in the desktop shell.

## 14. End-to-end illustrative investigation (not a claim of current behavior)

1. Objective: "determine whether `/api/v1/orders` exposes another tenant's data".
2. Harness seeds state: target in scope, ROE forbids intrusive tests, TLP:AMBER,
   20-step budget.
3. Planner consults catalog → technique `AUTHZ-IDOR-DIFFERENTIAL`; emits step
   with two identities from the asset graph.
4. Gate: in scope, read-only, within budget → allow (no approval).
5. Tool executes two GETs; harness captures raw bytes + canary + digests.
6. Verifier: differential with negative control → `proven`, confidence high;
   writes finding with CVSS v4 vector, CWE, masked responses, TLP:AMBER.
7. State: hypothesis `confirmed`; coverage row for target/param; reflection
   "control held" appended.
8. Planner replans: next highest-value hypothesis is rate-limit bypass; emits
   new step. Loop continues until all hypotheses terminal or budget reached.
9. Finalize: canonical local report, draft, operator review; no submission.

## 15. Trade-offs and risks

- **More state = more versioning risk.** Mitigate with revision numbers and
  append-only logs; avoid a second source of truth.
- **Planner quality is the ceiling.** Needs eval fixtures that measure
  next-step choice, not just report sections.
- **Latency/cost increase** vs. V1 fixed workflow. Mitigate with DAG scheduling
  of independent passive steps and deferred tool loading.
- **Sandboxing may break lab tools.** Stage OS isolation after the decision
  loop, with an explicit lab opt-in path preserved.
- **Catalog drift.** Pin all versions in plans and findings.
- **Partial migration risk.** Until replanning is production-connected, V1's
  static workflow remains the fallback — do not delete it early.

## 16. Acceptance gates for this blueprint (design-level)

- [ ] Agent, domain engine, harness, memory and verifier have disjoint owners.
- [ ] No path from model output to scope/permission/verdict authority.
- [ ] Every step is a replayable transaction with an idempotency key.
- [ ] Stop conditions are harness-owned and distinguish goal-satisfied from exhausted.
- [ ] WSTG/ASVS/CWE mappings are version-pinned and contextual.
- [ ] This blueprint maps to actual crates in `05_MIGRATION_AND_IMPLEMENTATION_PLAN.md`.
- [ ] Evaluation in `06_AGENT_EVALUATION_PLAN.md` can detect adaptive quality.
