# ADR-V3-001 — Agent-driven hybrid as the V3 operating model

- Status: **Proposed** (design gate; requires explicit approval before implementation)
- Date: 2026-11-26
- Related: `docs/architecture/03_ARCHITECTURE_GAP_ANALYSIS.md`, S01/S03/S06/S07/S22

## Context
BugFound currently executes a static queue of nine WSTG playbooks
(`engagement/lib.rs:3414-3453`, enumerated `:1466-1472`) with a static role map
(`roles.rs:42-48`). Rounds ≥2 replay every task (`:2122-2138`). Discovery feeds
the next step only as prompt text (`:2207-2312`). The system is workflow-driven:
the LLM executes steps, it does not choose them. Yet a purely autonomous agent
would put scope, ROE and verification at the mercy of prompt text — unacceptable
for authorised security testing.

## Options
1. **Workflow-driven** — keep static playbooks, improve prompt quality.
2. **General autonomous agent** — LLM owns strategy and execution.
3. **Agent-driven hybrid (chosen)** — agent chooses the next step; deterministic
   harness authorises; domain engine supplies knowledge; verifier decides proof.

## Decision
Adopt option 3. The agent emits a `NextStep` artifact; the harness owns
authorisation, budgets, approvals and stopping; WSTG becomes a knowledge catalog.
The V1 workflow remains as a fallback until the new loop passes its gate.

## Reasons
- ReAct/plan-and-execute research shows interleaved reasoning + environmental
  ground truth improves adaptive task performance [S01][S03][S06].
- Anthropic's guidance: agents trade cost for flexibility; use the simplest
  solution that works, and keep explicit planning steps visible [S07].
- WSTG itself says to treat the guide as techniques, not a checklist, and to
  continuously re-prioritise [S22].
- Only the hybrid keeps the deterministic security boundary intact while
  allowing evidence-driven strategy.

## Trade-offs
- More components and state versioning than option 1.
- Higher latency/cost than a fixed workflow; mitigated with DAG scheduling of
  independent passive steps and deferred tool loading.
- Less freedom than option 2 by design — that is the point.

## Consequences / risks
- Planner quality becomes the ceiling; needs lab-based evaluation (doc 06).
- Premature removal of the V1 loop would regress capability — forbidden until
  P2 acceptance passes.
- Any model-written scope/permission/verdict is a violation of this ADR.

## Status / gate
Proposed. Effective only after design approval; first implementation in
`05_...md` Phase P2.
