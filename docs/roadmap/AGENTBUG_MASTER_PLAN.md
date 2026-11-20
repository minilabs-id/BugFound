# AgentBug Master Plan (post-research, 2026-11-20)

Basis: `docs/research/01..16`. This plan replaces the greenfield master prompt with a plan for the **existing** AgentBug repository. Research/ADR checkpoint is complete; implementation has not started.

## 0. Current baseline

- Rust workspace `agentbug-*` at `D:\Github\Agent Bug Bounty`, 217 tests, fmt/clippy/build green.
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

### R1 — P0 corrections + ADR approval (COMPLETE, 2026-11-20)
Tasks:
- R1.1 ✅ canary verifier satisfiable: mint-once + `X-AgentBug-Canary` injection into the real request, scrub from LLM-visible output, single token through all captures. Tests `real_http_capture_promotes_finding` and `non_reflecting_capture_is_rejected` drive a real local TCP server.
- R1.2 ✅ README/HARDENING_PLAN/PRODUCTION_PLAN/architecture/REMAINING_GAPS/research-11 updated; verifier is explicitly a reflection-class oracle.
- R1.3 ✅ ADR-001, ADR-002, ADR-007, ADR-008 accepted in `docs/adr/`.
- R1.4 ✅ no module moves; no new crates.

Exit evidence: `cargo test -p agentbug-tools -p agentbug-engagement` green (19 engagement + 52 tools tests); a real local finding reaches `validated`. Next: R2 (kernel purity) after fresh evaluation/research per the user's staged-execution rule.

### R2 — Kernel purity refactor (COMPLETE, 2026-11-20)
- ✅ Added `agentbug-kernel-traits` (`GoalLock`, `PromptContributor`,
  `ToolResultSink`, `ProgressObserver`, `Domain`, `KernelDomain`).
- ✅ `Runner` holds `Arc<dyn Domain>` via `with_domain(...)`; `new` unchanged.
- ✅ `BountyDomain` in `agentbug-engagement` owns scope digest, prompt,
  persistence and progress; `prioritize_targets` moved there.
- ✅ `persist_tool_result` / `domain_progress_count` moved to `agentbug-store`.
- ✅ CI boundary check added (`.github/workflows/ci.yml`).

Exit evidence: `git grep` for domain vocabulary in `core/src` is clean;
`cargo tree -p agentbug-core` has no domain crate; 217 tests green; clippy
`-D warnings` green. Deferred to Stage 2: domain tools/knowledge/report renderer,
store table split, scope policy move (recorded in ADR-001). Next: R3 after fresh
evaluation/research.

### R3a — Core maturity, provider & descriptor seams (COMPLETE, 2026-11-20)
- ✅ Typed `LlmErrorKind` / `LlmError` / `Recovery` in `agentbug-llm/src/error.rs`;
  status/body mapping and legacy-message compatibility.
- ✅ Usage carried in `ChatResponseWithUsage` via `chat_full`; the shared
  `Arc<Mutex<Option<TokenUsage>>>` side channel is gone. Core logs additive
  `kind=` on `llm.chat_failed` and keeps identical error text/category.
- ✅ Unified `ToolSpec`: canonical tools-side descriptor re-exported by
  `agentbug-llm`, deprecated `LlmToolSpec` alias, lossy conversions deleted.
- ✅ Doc-vs-code drift corrected in README/architecture/PRODUCTION_PLAN/threat-model.

Exit evidence: 222 tests green, fmt/clippy `-D warnings` green.

### R3b-1 — Durable inbox + boot settlement (COMPLETE, 2026-11-20)
- ✅ `session_inbox` table + idempotent enqueue, priority promotion
  (control > steer > queue), atomic deliver with visible message, cancel/resteer.
- ✅ `Runner::drain_inbox` drains durable rows first, keeps the in-memory
  `Inbox` as a compatibility source (existing control-cancel test untouched).
- ✅ `settle_on_boot` called from CLI/desktop construction: interrupts stale
  running sessions, settles unanswered tool calls and parked deferred calls,
  bounded by `resume_attempts` (max 10, no auto-resume).
- ✅ 8 new tests; 230 tests green, fmt/clippy clean.

### R3c — Remaining core maturity (DEFERRED, each needs its own review)
1. ✅ (adapter-only) `ModelCapabilities` / `ModelDescriptor` with conservative
   defaults, `LlmConfig.fallback_models`, typed `ModelNotFound` mapped to
   `Recovery::Fallback`, and an outer candidate loop in `LlmClient::chat_full`.
   Five local `TcpListener` fixture tests cover fallback, no-fallback-on-auth,
   verbatim exhaustion errors and generic-404 handling. Core is untouched; the
   config file does not yet expose `fallback_models`.
2. ✅ (partial) `tool_calls` table, host-risk consistency and explicit
   `session.finish` terminal tool. Intercepted in deferred, approval-resume and
   main-loop paths; still checks goal lock and stop before committing; exempt
   from policy/budget/approval. Remaining: table-backed sliding-window repeat
   echo and one-shot arg repair (repair deferred: needs typed tool errors and
   schema validation).
3. `Scope` doorbell coalescing / re-drain — no production consumer yet.
4. ✅ (partial) Tool `risk` is frozen as host-owned registry metadata. JSON
   Schema validation remains deferred: `jsonschema` is not in the offline cargo
   cache; adding it needs an explicit dependency/network decision.

Do not start R4 until R3c is completed or explicitly re-scoped.

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
