# ADR-V3-002 — One versioned InvestigationState as the continuity boundary

- Status: **Proposed** (design gate)
- Date: 2026-11-26
- Related: ADR-V3-001, `01_CURRENT_STATE_AUDIT.md` §4, S16/S17/S10

## Context
Investigation state is currently split across `tasks`, `hypotheses`, `coverage`,
`assets` and prompt text. `feedback_hypotheses` creates asset hypotheses but the
only consumer is prompt injection; the created count is ignored
(`engagement/lib.rs:2207-2312`, `:1821`). `prioritize_targets` is orphaned
(`domain.rs:92-128`). There is no single object the agent can plan from,
checkpoint, compact or resume. Compaction summarises conversation text, not
investigation state.

## Options
1. Keep using task/hypothesis/coverage tables plus prompt text.
2. Create a separate planning service with its own database.
3. Add one versioned `InvestigationState` aggregate in the engagement layer,
   backed by existing SQLite plus an append-only event log.

## Decision
Option 3. `InvestigationState` holds assets graph, hypothesis ledger, coverage
ledger, current `Plan`, open questions, reflections and stop reason. Every step
is a revision; `investigation_events` is append-only and hash-linked. The
agent's context is a **projection** under a token budget, never the full state.

## Reasons
- Long-running agent research shows progress files + explicit feature ledgers
  outperform conversation-only memory and avoid premature "done" [S17].
- Context engineering: smallest high-signal token set, just-in-time identifiers,
  tool-result clearing [S16].
- Serializable `RunState` with version markers is the documented resume pattern
  [S10].
- SQLite/WAL and guarded transactions already exist; a second database would
  create a new consistency boundary for no benefit.

## Trade-offs
- Extra aggregate layer over existing tables; must avoid a second source of
  truth (mitigated by making the state row authoritative and backfilling).
- Migration needed for existing engagements (additive columns + lazy backfill).
- State size must be bounded by projection rules or context costs grow.

## Consequences / risks
- If any component writes old tables directly, state diverges — enforce via
  code review and tests.
- Stale checkpoints must fail closed rather than replay side effects.
- Only the verifier writes `confirmed` into the hypothesis ledger.

## Status / gate
Proposed; implemented in Phase P0. Gate: a recorded V1 engagement round-trips
into one state with no information loss.
