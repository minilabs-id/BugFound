# 12 — Architecture Comparison (synthesis of 01–11)

> **About these notes.** These are point-in-time analyses of third-party reference
> projects, kept for design input. They describe the reference projects at the
> snapshots examined and are not claims about the current BugFound code; verify
> current behavior in `crates/`.

Status: research synthesis. No code changes.

## 1. The five architectures in one table

| System | Core unit | Durable state | Orchestration | Recovery | What BugFound should learn |
| --- | --- | --- | --- | --- | --- |
| OpenCode | Session + durable Step | Event store + inbox + claim | Runner/coordinator, cooldown doorbell | stale settlement, bounded resume | one LLM call per step; steer/queue/control; wild-card permission gates |
| PentAGI | Flow → Task → Subtask → ToolCall | Msgchain snapshots + rich SQL | LLM planner/refiner, ordered subtasks | running→created reset | ordered plan + barrier completion + bounded layered recovery |
| Temporal | Workflow + Activity | Authoritative event history | task queues, signals/queries | history replay + fence | event log authority, outbox, idempotent activities |
| LangGraph | Graph node + reducer | checkpoints/versions | conditional edges, typed retry/timeout | interrupt/resume | task graph vocabulary, policy objects |
| Goose | Operation (Applied/Yielded/NotApplicable) | reload session per step | extension/tool composition | finalize hooks + cancellation tokens | cancellation protocol, idempotent approval records |
| Rig | Effect + Decider gate | append-only log | 7-stage fixed-point pipeline | reconcile as effects | single effect path, gate/decider unifying policy + human |
| Strix | Orchestrator → child jobs | artifact-bound evidence | mandatory discover→validate→report | closure states | ternary finding closure + counterevidence |
| CAI | Reasoner/Retester/Reporter | typed memory | cyclic triage swarm | guardrails (default off!) | FP elimination role, non-executive reasoner |

## 2. Where BugFound already aligns

- Durable SQLite sessions + event hash chain + trace events → Temporal/OpenCode shape.
- One Runner step = one LLM call, reloaded history → OpenCode invariant.
- Scope/ROE fail-closed, rate limit, shell allowlist, DNS pin → stronger than MCP/Strix defaults.
- SHA-256 tool captures, atomic approvals, stop flags, guarded transitions → solid primitives.
- Canonical report + redaction + replay scorer → present in the current design.

## 3. Where BugFound diverges in important ways

| Dimension | References | BugFound today | Verdict |
| --- | --- | --- | --- |
| Kernel/domain separation | universal core + domain adapters | core/tools contain bounty logic | **must refactor** |
| Multi-agent | specialist roles + delegation | no real multi-agent | **gap** |
| Memory | working/episodic/semantic/procedural | working + episodic events only | **gap** |
| Program intelligence | typed assets, versions, VRT, safe harbor | one URL + heuristic scope | **gap** |
| Verification | counterevidence, paired controls, ternary closure | single canary+2xx oracle | **critical gap** |
| Evaluation | resettable golden labs, baseline, N≥3 | scaffolding, zero results | **gap** |
| Provider | capability negotiation, multi-provider | one OpenAI-shaped client | **gap** |
| Sandbox | container capability controls | isolated PC accepted | **documented risk acceptance** |

## 4. Critical contradiction to resolve first

Research 11 found that `HttpRequestTool` mints a canary from request bytes + nanoseconds but did not inject it into the outgoing request or the captured response in that snapshot; the verifier requires `response.contains(canary)`. The tests described there hand-splice the canary into synthetic bytes. Research 11 also records a later fix; verify current behavior in `crates/`.

This is P0: the verifier must be made satisfiable by real tool captures before any architecture work matters.

## 5. Proposed target shape

```
Universal Agent Kernel
  event bus / inbox / execution coordinator / step runner / tool registry / permission gate / memory tiers / provider router
        ↑ depends only on kernel types
Bug Bounty Domain Engine
  program intelligence / ROE / playbooks / recon adapters / hypotheses / verifier / evidence / report / opportunity ranking
        ↑ separate crate(s), no domain types in kernel
```

Keep SQLite; add outbox/fence/plan revision patterns rather than replacing the store.
