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
2. ✅ `tool_calls` table, host-risk consistency, explicit `session.finish`
   terminal tool, and table-backed sliding-window repeat echo. Echo is limited
   to host-owned `safe`/`read` tools with a prior successful result; dangerous
   tools keep the hard block. Existing flag detector is retained; the table is
   the echo source. One-shot arg repair remains deferred (needs typed tool
   errors and schema validation).
3. `Scope` doorbell coalescing / re-drain — no production consumer yet.
4. ✅ (partial) Tool `risk` is frozen as host-owned registry metadata. JSON
   Schema validation remains deferred: `jsonschema` is not in the offline cargo
   cache; adding it needs an explicit dependency/network decision.

R3c is now complete except the explicitly deferred JSON Schema item. R4 may proceed.

### R4a — Multi-agent & memory foundation (COMPLETE, 2026-11-20)
- ✅ `memory_items` and `session_results` tables with provenance fields,
  scope-gated retrieval, hash verification and typed child results.
- ✅ `agentbug-engagement::roles` with 7 domain-owned role profiles and
  `build_role_tools` (role filtering is a second layer over ROE filtering and
  preserves host-owned risk).
- ✅ `BountyDomain` carries an opaque `RoleId` and composes the role addendum
  into its prompt through the existing `PromptContributor` port.

### R4b — Synchronous handoff & episodic memory (COMPLETE, 2026-11-20)
- ✅ `agentbug-engagement::handoff` with `HandoffTool`, `RoleResultTool` and
  `MemoryRecallTool`. Depth ≤ 1, fixed delegable role set, wall-clock bound,
  typed `session_results`, scoped run_goal children using `build_role_tools`.
- ✅ `BountyDomain::on_tool_result` writes redacted episodic memory with
  provenance (`source_event_hash` from the event hash chain) and a shared
  scope key; recall is scope-gated and framed as untrusted data.
- ✅ Integration test proves one goal delegated to `recon` and `verification`,
  with episodic memory and event-chain integrity for each session.

Deferred: semantic tier (off by default, no embeddings), nested/cooperative
cancellation, parent tool-call id on child results, `Report`/`General` roles.

Exit evidence: 248 tests green; clippy `-D warnings` clean; ADR-001 boundary
clean.

### R5a — Strict taxonomy & rationale (COMPLETE, 2026-11-20)
- ✅ Strict CVSS v3.1 parser: canonical prefix, key order, metric count,
  duplicates and allowed values are validated; v4 and numeric strings are
  rejected instead of silently scored. `cvss_base` signature unchanged.
- ✅ Deterministic CWE rule table with root-cause-first ordering, word-boundary
  matching, and rule/basis/rationale emitted into the report. IDOR/BOLA still
  maps to CWE-639; unclassified findings are explicitly marked for review.
- ✅ Report renderer emits `CWE rationale` and a `CVSS note` when a vector is
  unscorable; `docs/report-format.md` updated. Model severity never becomes a
  score by itself.

### R5b — Remaining domain depth (DEFERRED)
- Ternary closure (`confirmed | ruled_out | open_proof_gap`), counterevidence,
  paired controls, multi-oracle dispatch and `Finding` schema extension —
  touches the finding DDL and verifier; separate review needed.
- ✅ Platform-specific report appendix: `Platform` + `platform_from_program_url`,
  Appendix C field checklist (HackerOne/Bugcrowd/Generic), self-authored, no
  auto-submit, eval headings unchanged.
- Program intelligence (typed assets/scope provenance) — deferred: scope
  enforcement is a stop-condition boundary and platform semantics are not
  pinned offline.
- Verifier ternary closure (`confirmed | ruled_out | open_proof_gap`),
  counterevidence and paired controls — deferred: needs a `Finding` DDL
  migration and a second independent control exchange; the current
  `tool_captures` table permits only one authoritative capture per finding.

Exit (when complete): lab finding with counterevidence + paired control +
strict CVSS vector validated.

### R6a — Wiring record scaffolding (COMPLETE, 2026-11-20)
- ✅ Offline loopback lab server (`eval/lab/local_reflect_server.py`) with a
  reflected endpoint and a non-reflective negative control.
- ✅ `eval/lab/golden.local.json` with target/endpoint/oracle/reset/tier and an
  explicit `wiring-fixture-only` status.
- ✅ `eval/repeat_lab.py` N>=3 driver producing hashed, timed manifests and
  per-run replays with a stable `run_id` per run; baseline recorded as
  `not-run.json` unless an operator supplies a command.
- ✅ `export_trace.py` maps verifier `candidate` -> `finding_id` and preserves
  additive provenance keys.

No effectiveness number is recorded. All artifacts state
`harness wiring record; not a benchmark result`.

### R7 — Next roadmap (defined 2026-11-20)

#### R7a-1 — Verifier closure storage foundation (COMPLETE)
- ✅ `finding_captures` multi-role table (`paired_benign` / `paired_payload`)
  additive to the unchanged primary `tool_captures` row.
- ✅ `RoleCapture` + `attach_role_capture` / `get_role_capture`; `Finding`
  gains `verdict` and `gap_reason` with DDL/migration/row-mapping updates.
- ✅ `set_finding_verdict` never stamps `validated_at`; ruled-out/uncertain
  findings cannot enter `verified_findings`.

#### R7a-2 — Production capture attachment (COMPLETE)
Fixed the gap where no production path attached an HTTP tool capture to a
finding: `persist_tool_result` now keeps every tool-generated capture at
session scope (`session_captures`) and consumes it once when a `save_finding`
result has no capture of its own. LLM-supplied request/response remain advisory.
Regression test `http_capture_flows_to_a_later_finding_without_llm_bytes`
proves the tool bytes, not LLM text, reach `tool_captures`.

#### R7a-3 — Paired control & authoritative closure (COMPLETE)
- ✅ `ValidatePoCTool` runs a tool-minted benign control alongside the payload;
  both captures carry distinct HTTP-tool canaries and are stored as role-tagged
  `finding_captures` (never from LLM input).
- ✅ `verify_findings` rules a candidate out only on a benign-success /
  payload-blocked contrast with matching tool markers; anything else becomes
  `open_proof_gap`. Verdicts never stamp `validated_at`, so ruled-out and
  uncertain findings cannot enter `verified_findings`.
- ✅ Negative-control tests: benign failure and missing pair stay
  `open_proof_gap`; full pair yields `ruled_out`.

Other oracle classes remain `open_proof_gap` (no implementation exists).

#### R7b — Program intelligence provenance (COMPLETE)
- ✅ Additive advisory `brief_rule_provenance` table with source URL, section
  pointer, verbatim quote + SHA-256, document hash, extractor and observed time.
- ✅ `parse_scope_brief_traced` in policy; legacy parser delegates to it, so
  scope decisions are structurally identical. Engagement captures deterministic
  provenance at brief time and persists it best-effort after `save_brief`.
- ✅ Provenance never feeds `PolicyEngine`, `build_tools`, or ROE enforcement.
- Deferred: typed assets, eligibility flags, freshness/TTL gating, platform
  VRT/safe-harbor semantics (sources stale/unpinned/license-restricted).

#### R7c — Tool argument validation (PARTIAL)
- ✅ Added `jsonschema` dependency (operator-approved) with external `$ref`
  resolution disabled; `validate_tool_args` checks tool args at the guard chain.
- ✅ `SchemaValidationMode` `Off` (default) / `Warn` (audit event) / `Enforce`
  (block before any guard state or budget is consumed). Tests cover all paths.
- ✅ `Scope`-aware coalesced doorbell: `WakeScope::{Steer, Input}` with widening,
  consumed by `Runner` at each step boundary; `Runner::enqueue_prompt` admits a
  durable inbox item and rings it. Docs updated (no longer claimed unwired).
- ✅ Arg repair resolved safely: an in-step second LLM call was implemented,
  then reviewed and reverted. It re-ran a side-effecting tool with arguments
  that never passed schema/policy/scope/budget/approval gates, permanently
  poisoned a durable one-shot flag on transient failure, consumed scripted
  responses in mocks, and made the transcript describe args that never ran.
  The shipped behavior instead emits an additive `tool.args_repair_hint`
  event naming required fields; the model sees the existing `ok=false` tool
  result and self-corrects on the next step, preserving one LLM call per step
  and every gate. Test `args_error_hints_next_step_without_extra_model_call`
  proves correction without an extra model call.

#### R8 — Later
- Measured results from real local engagements N>=3 + baseline lane.

### R6b — Measured results (NOT STARTED)
- Golden dataset tiers A-D with reset recipes and negative controls from real
  local lab engagements, N>=3, baseline lane, time-to-first-valid, tier-stratified
  recall/precision and FPR with real negative controls.

Exit: only measured claims; baseline vs harness comparison recorded.

## 3. Stop conditions

- P0 not fixed → no architectural expansion.
- ADR-001 not approved → no crate split.
- No golden artifacts → no effectiveness claims.
- Any scope/ROE regression → stop and fix.

## 4. Deliverable ownership

Research docs already written by parallel agents; synthesis docs 12–16 by parent session; this master plan is the single source of truth. Future code work must update this file with phase status and evidence links.


### R8a — Live monitor engine (COMPLETE, 2026-11-20)
- ✅ `agentbug-core::monitor`: bounded ring buffers (tool/result/verdict/error/
  latency), per-key pause/resume, snapshot API, `evaluate()` health report, and
  a hash-chained JSONL journal under `eval/work/monitor/`.
- ✅ CLI `engage` starts/stops the monitor automatically, tracks the engagement
  id, and observes action/result/error events. Journal lines always carry
  `no_benchmark_claim: true`.
- ✅ Live evaluation against `security.cake.com`: engagement completed with
  9/9 playbooks, 0 verified findings, coverage 0, report sha256
  `2699c0d42d3004cda37f611b07f4d9f3a62de0f546f32a92fe34a606652ba370`;
  `score.py --strict` reported 0 problems and no effectiveness claim.
- Fixed during live testing: ROE line classification (reward/report policy no
  longer aborts, vuln-class exclusions are enforced), provider-safe tool names,
  empty LLM-scope fallback, and explicit-asset scope precedence over broad
  out-of-scope wildcards.

### R8b — Measured results (NOT STARTED)
Await operator-recorded local engagements (N>=3) and a declared baseline lane.
No effectiveness number may be asserted until those artifacts exist.


### R9 — Honest coverage and completion (IN PROGRESS)
- ✅ Requirement-keyed coverage ledger: `coverage` rows now carry
  `requirement_id`, `status` (covered|blocked|skipped|not-applicable),
  `rationale` and `evidence_ref`; `CoverageDecision` input struct.
- ✅ A tool call refused by the policy gate is recorded as `blocked` coverage,
  so a ROE-restricted engagement is no longer indistinguishable from one that
  tested nothing.
- ✅ Playbook completion requires evidence: a task whose runner returns `Ok`
  but produced no coverage and no artifacts is marked `needs-review`, not
  `done`; an `engagement.outcome` trace records `incomplete` when tasks or
  coverage are missing.
- ✅ Report Coverage section now prints a Result column with reason.
- ✅ Hypothesis lifecycle (COMPLETE): structured fields, production status
  transitions (`running → tested/blocked → confirmed-candidate → validated/
  ruled_out/open_proof_gap`), passive→active feedback that creates in-scope
  asset hypotheses from discoveries and feeds them into later task goals, and
  `open_hypotheses > 0` blocking `completed` outcome. Coverage mirroring no
  longer launders `blocked` into `covered`.
- ✅ Deterministic role pipeline (COMPLETE): `role_for_playbook` maps WSTG
  playbooks to Recon/Research/Testing; each task's Runner uses a role-scoped
  ToolRegistry over the ROE-filtered base (no privilege widening) and a
  role-specific agent config.
- ✅ Mandatory verification before confirmation: every candidate finding spawns
  a bounded Verification-role session that must write a complete `role_result`
  verdict; only then is the hypothesis marked `confirmed-candidate`. The
  verdict is advisory — only `verify_findings` may promote to `validated`.
- ✅ Per-class oracles + falsification fields (COMPLETE): Finding carries
  counterevidence/confidence/rationale/severity-change-conditions/oracle_type;
  `SaveFindingTool` enforces them when `ToolOptions.require_falsification` is
  on (engagement always on, generic tests off). `verify_findings` keeps
  `canary_echo` byte-identical and routes every other class to
  `open_proof_gap` with a named missing proof — never confirming from absence.
  Differential remains rule-out-only (no identity pair exists).
- ✅ Authorization snapshot foundation (COMPLETE, conservative slice):
  `authorization_snapshots` (version + content/scope hashes + observed_at),
  `authorization_acks` (hash-scoped, out-of-band, idempotent) and
  `authorization_open_rules` (nothing silently dropped) are stored before the
  ROE abort. The abort remains the ONLY behavior — an acknowledgement is
  recorded but does not yet bypass it, so no LLM/tool path can self-authorize.
- Deferred from step 5: ack-driven bypass, version-change revalidation on
  resume, and CLI/desktop authorize entry points.


### R14 — Evidence binding in report (COMPLETE)
- ✅ `ReportFinding` carries 8 evidence-binding fields, populated ONLY from
  authoritative `tool_captures` / `finding_captures` / store timestamps — never
  from model-authored finding fields.
- ✅ Raw evidence bytes written to a deterministic, cwd-confined artifact file
  (`evidence/<id>-<hash>.bin`); report references it with hash equality.
- ✅ Canary scrubbed from redacted views; `inline_view` prevents captured bodies
  from creating fake headings. Renderer lines are additive and guarded.
- Deferred: step 7 budgets/fan-out and ack-driven bypass (ROE decision).


### R15/R16 — Bounded fan-out + operator authorization (COMPLETE)
- ✅ Handoff depth counter (`handoff_depth=N`, max 1) and children cap (9);
  role-scoped non-terminal tool caps; graceful step-limit announcement event
  `runner.limit_approaching` without an extra LLM call.
- ✅ Ack-driven ROE bypass: proceeds only when EVERY unmapped line has a
  hash-scoped operator ack; same abort text/shape otherwise; `denied_finding_classes`
  unchanged; outcome forced `incomplete` and trace `authorization.ack_applied`.
- ✅ Offline CLI `agentbug authorize --url --content-hash --rule|--version
  --operator [--note]` writes hash-scoped acks only; no LLM/tool path can create one.
- Deferred: budget-offset inheritance parent→child, revalidation-on-resume,
  platform adapters, safe-harbor typing, auto-submit.

All results remain construction evidence. No benchmark claim is asserted.


### Live evaluation — CAKE.com 2026-11-21 (construction evidence)
- Fixed from live run: missing hypotheses ALTER migrations, nested tokio runtime
  in monitor stop, tool-layer scope specificity (exact in-scope asset beats
  wildcard out-of-scope), and engagement-scoped report timeline.
- Run e43c21f9: 9 tasks planned, 2/9 evidenced, 0 findings, coverage 0,
  outcome `incomplete`, report sha256 9d80aad765bd7e8367153c3c70be58eed5d77f96542c6811d123c18fdf07a235.
- Root causes still open: LLM extraction target key `name` rejected by the
  intentionally narrow policy target list (security gate), path-bearing scope
  patterns (`*.api.clockify.me/api/`) don't match host keys, and 6/9 playbooks
  failed on upstream LLM POST errors. No benchmark claim is asserted.
- All fixes must keep existing tests green; speculative loosening of the narrow
  policy target key list was reverted.
