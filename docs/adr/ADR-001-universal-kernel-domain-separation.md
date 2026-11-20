# ADR-001: Universal Kernel vs Bug Bounty Domain Separation

- Status: Accepted (R1). Code changes scheduled for R2.
- Date: 2026-11-20
- Basis: `docs/research/01..16`, `docs/roadmap/AGENTBUG_MASTER_PLAN.md`

## Context

AgentBug is intended as a reusable, LLM-agnostic Universal Agent Kernel with a
separate Bug Bounty Domain Engine layered on top (`README.md:3-5`,
`docs/architecture.md:5-10`, research `12_architecture_comparison.md:45-54`).
Today there is no seam: `agentbug-core` depends concretely on `agentbug-llm`,
`agentbug-tools`, `agentbug-policy`, `agentbug-store` and contains bounty-only
logic (`persist_bounty_tool_result`, WSTG `prioritize_targets`, scope-bound
`goal_digest`, finding/asset stall guards, domain-injected system prompt).
"Universal kernel" is currently a label, not an architecture.

## Problem

Domain concepts leak into the kernel, so the kernel cannot be reused without
bounty semantics and every domain change ripples through core/tools. CI cannot
enforce a boundary that does not exist.

## Alternatives considered

1. Big-bang rewrite into `agentbug-kernel` + `agentbug-domain` crates —
   rejected: violates "refactor boundaries, not behavior" and risks 215 green
   tests.
2. Feature-flag `domain` module inside core — rejected: leaves dependency
   inversion and CI enforcement unsolved.
3. **Incremental seam via injected traits + domain Observer/Planner, then
   physical crate split — accepted.**
4. Do nothing and rename core "kernel" — rejected by master plan principle 3.

## Recommendation

Declare the target boundary now: **kernel** = session/step/runner/LLM/tool
registry/permission abstractions; **domain** = ROE/scope/WSTG/findings/evidence/
report/verifier. The kernel must not depend on the domain; the domain depends
on kernel abstractions. New workspace crates are a subsequent phase (R2).

## Technical justification

- `docs/research/14_rust_adaptation_strategy.md:12-18` lists the exact functions
  to move: `persist_bounty_tool_result`, `prioritize_targets`, scope digest
  (generalize via `GoalLock`), domain system-prompt injection.
- `docs/research/11_current_gap_analysis.md:182-191` prescribes a four-step seam
  and a CI dependency check: core must not import domain types or mention
  `finding|scope|cvss|cwe|WSTG`.
- `docs/research/12_architecture_comparison.md:30` verdict: "must refactor."

## Trade-offs

- Pro: reusable/testable kernel; domain changes stop rippling; CI-enforceable.
- Con: Observer/Planner indirection in a currently simple runner; R2 regression
  risk across 215 tests; temporary duplication during migration.

## Implementation consequences (R2, not R1)

- Replace `persist_bounty_tool_result` (core `lib.rs:377-549`, wrapper `:709-717`,
  call sites `:574,1561,1673,1958`) with a generic `ToolResultSink` supplied by
  `agentbug-engagement`.
- Move `prioritize_targets` (`:165-201`) to domain Planner; caller
  `agentbug-cli/src/main.rs:979`.
- Generalize `goal_digest` (`:70-76`) to a `GoalLock` trait; domain owns scope
  digest.
- Move domain prompt injection (`:718-722,1248-1249,1298-1307`) to a domain
  adapter; kernel keeps only a generic optional `system_prompt` field.
- Move stall/progress guards (`:1020-1048,1763-1771`) and
  `extract_policy_target` (`:2123-2193`) to domain.
- Move domain tools, WSTG/CWE knowledge, report renderer
  (`tools/src/lib.rs:2044-2087,2115-2131,2870-2988,3010-3178`) and scope policy
  (`policy/src/lib.rs:38-54,168-223,341-363`) to domain crates; split domain
  tables in `store/src/lib.rs:270-380`.
- Invert dependency directions in `core/Cargo.toml:19-22` and
  `tools/Cargo.toml:18`; add CI dependency check.

## What would invalidate this decision

- A requirement that the kernel natively understand findings/ROE.
- Evidence that indirection costs more than reuse benefit (all deployments
  bounty-only) — then downgrade "universal" to branding.
- Failure of the R2 exit criterion: core still mentions domain types or the
  dependency graph points kernel -> domain.
