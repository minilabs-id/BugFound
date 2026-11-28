# ADR-V3-006 — Incremental migration; keep the kernel, retire only proven-defective paths

- Status: **Proposed** (design gate)
- Date: 2026-11-26
- Related: ADR-001, ADR-009, `01_CURRENT_STATE_AUDIT.md`, `05_...md`

## Context
The V3 target differs substantially from V1, but the audit shows the runner
loop, lease recovery, inbox/stop/steer, policy matcher, approval atomicity, tool
registry, store schema, ROE classifier, canonical report and event hash chain
are sound and heavily tested. A rewrite would discard proven safety properties
and risk regressions in a security tool. Conversely, keeping every legacy path
forever carries dead code (e.g. `MemoryRecallTool` TEST-only, ignored
`brief_version` acks, stale e2e script).

## Options
1. Full rewrite of core + engagement with a new clean architecture.
2. Freeze V1 forever and add a parallel agent layer.
3. Incremental phases: add decision layer, rewire orchestrator, extend harness,
   retire legacy paths only after parity gates.

## Decision
Option 3. `bugfound-core` stays domain-free (ADR-001). New domain types live in
engagement. V1 static workflow remains until the adaptive loop passes its gate.
Legacy egui desktop is removed only at ADR-009 Phase 3. Dead features are either
wired or explicitly removed with a documented reason.

## Reasons
- Existing tests (52 runner integration + 74 engagement + 63 store + 98 tools)
  are evidence of correctness that a rewrite would throw away.
- ADR-001 already enforces the kernel/domain boundary in CI.
- Research warns that premature rewrites and one-shotting are failure modes for
  long-running agents [S17].

## Trade-offs
- Temporary coexistence of old and new paths increases maintenance and
  dependency duplication (already visible with egui + Tauri).
- Migration code (backfill, version markers) must be maintained until the old
  format is retired.

## Consequences / risks
- Dual writes could diverge — make the new state authoritative early (P0).
- Scope creep: no new crates without a real boundary; no P3 parallel sessions.
- Each phase must record go/no-go evidence before the next begins.

## Status / gate
Proposed. Effective for all V3 implementation; violations require a written
deviation.
