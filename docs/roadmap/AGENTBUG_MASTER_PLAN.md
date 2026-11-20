# AgentBug Master Plan (post-research, 2026-11-20)

Basis: `docs/research/01..16`. This plan replaces the greenfield master prompt with a plan for the **existing** AgentBug repository. Research/ADR checkpoint is complete; implementation has not started.

## 0. Current baseline

- Rust workspace `agentbug-*` at `D:\Github\Agent Bug Bounty`, 215 tests, fmt/clippy/build green.
- 17 reference clones in `research/`, pinned commits recorded in research docs.
- Strong existing primitives: Runner step loop, SQLite event chain, scope/ROE gate, atomic approvals, budgets, stop flags, SHA-256 captures, canonical report, desktop UI, eval scaffolding.
- Critical defect found: canary verifier unsatisfiable in production (no real finding can be promoted).
- Architecture defect: kernel/domain boundary not real.

## 1. Principles

1. Patterns from references, never copied code (license audit §10).
2. Keep working primitives; refactor boundaries, not behavior.
3. Universal Kernel must not depend on Bug Bounty Domain.
4. Every phase has evidence-based exit criteria.
5. No benchmark claims without operator-recorded artifacts.
6. Isolated PC is the sandbox boundary; policy engine is runtime boundary.

## 2. Phases

### R0 — Research & ADR (COMPLETE)
Deliverables: `docs/research/01..16`, commit hashes, license audit, component matrix.
Exit: all 16 docs present, no code changed. ✅

### R1 — P0 corrections + ADR approval (NEXT, 3–5 days)
Tasks:
- R1.1 make canary verifier satisfiable from real tool captures; add local HTTP integration test that promotes a real finding.
- R1.2 document defect in README/docs until fixed, then mark fixed.
- R1.3 ADR-001 Kernel/Domain split; ADR-002 SQLite vs Postgres; ADR-007 sandbox risk acceptance; ADR-008 verification oracle.
- R1.4 no module moves yet except as needed for R1.1.

Exit: a real local finding reaches `validated`; ADRs approved; tests green.

### R2 — Kernel purity refactor (5–8 days)
- Move bounty-specific logic from `agentbug-core`/`agentbug-tools` into bounty crate(s).
- Introduce generic `GoalLock`/`DomainPolicy` traits.
- Keep public behavior and all tests unchanged.

Exit: `agentbug-core` has no `finding|asset|bounty|WSTG` domain types; dependency graph documented.

### R3 — Core maturity (7–10 days)
- Typed `LlmErrorKind`, provider usage in response, capability descriptors.
- Gate/decider unification; sliding-window repeat detection; schema arg repair; terminal tool.
- Durable inbox control, coalescing doorbell, boot stale settlement, outbox/fence.
- Unified ToolSpec + JSON Schema validation.

Exit: multi-step task with provider failure + cancel + resume passes integration tests.

### R4 — Multi-agent & memory (10–14 days)
- Role profiles with tool allowlists; General + ProgramIntel + Recon + Research + Testing + Verification + Report.
- Synchronous child-session handoff with typed result and lineage.
- Working/episodic/semantic memory over SQLite with provenance + scope-gated retrieval.

Exit: one goal delegated to ≥2 roles; recalled memory provenance visible in replay.

### R5 — Domain depth (10–14 days)
- Program intelligence: typed assets, scope versions, VRT/safe-harbor/status, source-linked rules.
- Verification: ternary closure, counterevidence, paired controls, multi-oracle.
- Strict CWE/CVSS with rationale and confidence.
- Platform-specific report templates; no auto-submit.

Exit: lab finding with counterevidence + paired control + strict CVSS vector validated.

### R6 — Proof & optimization (ongoing)
- Golden dataset with target/endpoint binding, negatives, reset, tiers A–D.
- N≥3 repeat driver, baseline lane, metrics, tier-stratified reporting.
- Performance: latency, token/cost, false-positive rate; optimize from measurements.

Exit: only measured claims; baseline vs harness comparison recorded.

## 3. Stop conditions

- P0 not fixed → no architectural expansion.
- ADR-001 not approved → no crate split.
- No golden artifacts → no effectiveness claims.
- Any scope/ROE regression → stop and fix.

## 4. Deliverable ownership

Research docs already written by parallel agents; synthesis docs 12–16 by parent session; this master plan is the single source of truth. Future code work must update this file with phase status and evidence links.
