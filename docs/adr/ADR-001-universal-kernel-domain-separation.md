# ADR-001: Universal Kernel vs Bug Bounty Domain Separation

- Decision: 2026-11-20 (incremental kernel/domain seam; physical crate split is a later stage).
- Date: 2026-11-20
- Basis: `docs/research/01..16`, `docs/roadmap/BUGFOUND_MASTER_PLAN.md`

## Context

BugFound is intended as a reusable, LLM-agnostic Universal Agent Kernel with a
separate Bug Bounty Domain Engine layered on top (`README.md:3-5`,
`docs/architecture.md:5-10`, research `12_architecture_comparison.md:45-54`).
At the time of the decision there was no seam: `bugfound-core` depended
concretely on `bugfound-llm`, `bugfound-tools`, `bugfound-policy`,
`bugfound-store` and contained bounty-only logic (`persist_bounty_tool_result`,
WSTG `prioritize_targets`, scope-bound `goal_digest`, finding/asset stall guards,
domain-injected system prompt). "Universal kernel" was a label, not an
architecture.

## Problem

Domain concepts leak into the kernel, so the kernel cannot be reused without
bounty semantics and every domain change ripples through core/tools. CI cannot
enforce a boundary that does not exist.

## Alternatives considered

1. Big-bang rewrite into `bugfound-kernel` + `bugfound-domain` crates —
   rejected: violates "refactor boundaries, not behavior".
2. Feature-flag `domain` module inside core — rejected: leaves dependency
   inversion and CI enforcement unsolved.
3. Incremental seam via injected traits + domain Observer/Planner, then a
   physical crate split — selected.
4. Do nothing and rename core "kernel" — rejected by master plan principle 3.

## Decision

Declare the target boundary: **kernel** = session/step/runner/LLM/tool
registry/permission abstractions; **domain** = ROE/scope/WSTG/findings/evidence/
report/verifier. The kernel must not depend on the domain; the domain depends
on kernel abstractions. New workspace crates are a subsequent stage.

## Technical justification

- `docs/research/14_rust_adaptation_strategy.md:12-18` lists the exact functions
  to move: `persist_bounty_tool_result`, `prioritize_targets`, scope digest
  (generalize via `GoalLock`), domain system-prompt injection.
- `docs/research/11_current_gap_analysis.md:182-191` prescribes a four-step seam
  and a CI dependency check: core must not import domain types or mention
  `finding|scope|cvss|cwe|WSTG`.
- `docs/research/12_architecture_comparison.md:30` records a "must refactor"
  finding.

## Trade-offs

- Pro: reusable/testable kernel; domain changes stop rippling; CI-enforceable.
- Con: Observer/Planner indirection in a simple runner; regression risk across
  the migration; temporary duplication during the move.

## Consequences — current code mechanism

- `bugfound-kernel-traits` defines `GoalLock`, `PromptContributor`,
  `ToolResultSink`, `ProgressObserver`, the `Domain` bundle trait and a
  `KernelDomain` default adapter.
- `Runner` holds `Arc<dyn Domain>` with a `with_domain(...)` builder;
  `Runner::new` keeps its five-argument signature. Kernel call sites go through
  the ports.
- `bugfound-engagement::domain::BountyDomain` supplies scope-bound digest,
  scope prompt, tool-result persistence and progress counting.
- `prioritize_targets` lives in `bugfound-engagement`; CLI imports it there.
- `persist_tool_result` and `domain_progress_count` live in `bugfound-store`,
  which owns the domain tables; the kernel calls them through the default
  adapter.
- CI enforces the boundary: `bugfound-core/src` must not contain domain
  vocabulary and `cargo tree -p bugfound-core` must not contain domain crates.
- Verify the workspace checks with the commands in `docs/PRODUCTION_PLAN.md` §2.

### Boundary changes this decision calls for

- Replace `persist_bounty_tool_result` (core `lib.rs:377-549`, wrapper `:709-717`,
  call sites `:574,1561,1673,1958`) with a generic `ToolResultSink` supplied by
  `bugfound-engagement`.
- Move `prioritize_targets` (`:165-201`) to domain Planner; caller
  `bugfound-cli/src/main.rs:979`.
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
  `tools/Cargo.toml:18`; add a CI dependency check.

### Deliberate deviations (recorded, not hidden)

- `extract_policy_target` and its aliases stay in core: they are neutral JSON
  key/shell token helpers with five hot kernel call sites and no domain types.
- Domain tool implementations and WSTG/CWE knowledge stay in `bugfound-tools`
  this stage; moving them would require promoting private helpers or creating a
  tools -> engagement cycle.
- The store still owns domain tables and the one SQLite connection; the
  table-level split would change DDL and config serde compatibility with no
  kernel-purity gain.
- Scope policy types (`ScopeConfig`, `parse_scope_brief`) stay in
  `bugfound-policy` for now; the widest fan-out (CLI/desktop/engagement) is a
  later stage.

## What would invalidate this decision

- A requirement that the kernel natively understand findings/ROE.
- Evidence that indirection costs more than its reuse benefit (all deployments
  bounty-only) — then downgrade "universal" to branding.
- A failed boundary check: core still mentions domain types or the dependency
  graph points kernel -> domain.
