# BugFound Master Plan (post-research, 2026-11-20; updated 2026-11-23)

Basis: `docs/research/01..16`. This plan replaces the greenfield master prompt with a plan for the **existing** BugFound repository. ADRs were recorded in R0/R1; subsequent phases append implementation notes chronologically.

**Reading note:** phase sections were appended chronologically, so their numeric order in this file is not their execution order (R7–R19 appear before R8 in the file). Figures written inside a phase describe that snapshot only. Use the commands in `docs/PRODUCTION_PLAN.md` §2 to inspect the current checkout.

## 0. Current baseline

- Rust workspace `bugfound-*` at `D:\Github\BugFound`.
- 17 reference clones in `research/`, pinned commits recorded in research docs.
- Existing primitives: Runner step loop, SQLite event chain, scope/ROE gate, atomic approvals, budgets, stop flags, SHA-256 captures, canonical report, desktop UI, eval scaffolding.
- Defect recorded in R1: the canary verifier could not be satisfied by a real capture because the canary was not transmitted into the request.
- Architecture defect recorded: the kernel/domain boundary was nominal.

## 1. Principles

1. Patterns from references, never copied code (license audit §10).
2. Keep working primitives; refactor boundaries, not behavior.
3. Universal Kernel must not depend on Bug Bounty Domain.
4. Each phase records evidence-based exit criteria.
5. No effectiveness claims without operator-recorded artifacts.
6. Isolated PC is the sandbox boundary; policy engine is runtime boundary.

## 2. Phases

### Phase R0 — Research and ADR (2026-11-20)
Produced `docs/research/01..16`, pinned commit hashes, a license audit and a component matrix. No code changed.

### Phase R1 — P0 corrections and ADR decisions (2026-11-20)
- R1.1 Canary verifier satisfiability: mint-once plus `X-BugFound-Canary` injection into the real request, token scrubbed from LLM-visible output, single token through all captures. Tests `real_http_capture_promotes_finding` and `non_reflecting_capture_is_rejected` drive a real local TCP server.
- R1.2 README/HARDENING_PLAN/PRODUCTION_PLAN/architecture/REMAINING_GAPS/research-11 updated; verifier described as a reflection-class oracle.
- R1.3 ADR-001, ADR-002, ADR-007, ADR-008 recorded in `docs/adr/`.
- R1.4 No module moves; no new crates.
Verify with the commands in `docs/PRODUCTION_PLAN.md` §2. Next: R2 after a fresh evaluation/research pass.

### Phase R2 — Kernel/domain seam (2026-11-20)
- Added `bugfound-kernel-traits` (`GoalLock`, `PromptContributor`, `ToolResultSink`, `ProgressObserver`, `Domain`, `KernelDomain`).
- `Runner` holds `Arc<dyn Domain>` via `with_domain(...)`; `new` unchanged.
- `BountyDomain` in `bugfound-engagement` owns scope digest, prompt, persistence and progress; `prioritize_targets` moved there.
- `persist_tool_result` / `domain_progress_count` moved to `bugfound-store`.
- CI boundary check added (`.github/workflows/ci.yml`).
Verify with the commands in `docs/PRODUCTION_PLAN.md` §2, including the ADR-001 boundary check. Deferred to a later stage: domain tools/knowledge/report renderer, store table split, scope policy move (recorded in ADR-001).

### Phase R3a — Error, usage and tool descriptor seams (2026-11-20)
- Typed `LlmErrorKind` / `LlmError` / `Recovery` in `bugfound-llm/src/error.rs`; status/body mapping and legacy-message compatibility.
- Usage carried in `ChatResponseWithUsage` via `chat_full`; the shared `Arc<Mutex<Option<TokenUsage>>>` side channel removed. Core logs additive `kind=` on `llm.chat_failed` and keeps identical error text/category.
- Unified `ToolSpec`: canonical tools-side descriptor re-exported by `bugfound-llm`, deprecated `LlmToolSpec` alias, lossy conversions deleted.
- Doc-vs-code drift corrected in README/architecture/PRODUCTION_PLAN/threat-model.
Verify with the commands in `docs/PRODUCTION_PLAN.md` §2.

### Phase R3b-1 — Durable inbox and boot settlement (2026-11-20)
- `session_inbox` table + idempotent enqueue, priority promotion (control > steer > queue), atomic deliver with visible message, cancel/resteer.
- `Runner::drain_inbox` drains durable rows first, keeps the in-memory `Inbox` as a compatibility source (existing control-cancel test untouched).
- `settle_on_boot` called from CLI/desktop construction: interrupts stale running sessions, settles unanswered tool calls and parked deferred calls, bounded by `resume_attempts` (max 10, no auto-resume).
Verify with the commands in `docs/PRODUCTION_PLAN.md` §2.

### Phase R3c — Remaining core items (each reviewed separately)
1. (adapter-only) `ModelCapabilities` / `ModelDescriptor` with conservative defaults, `LlmConfig.fallback_models`, typed `ModelNotFound` mapped to `Recovery::Fallback`, and an outer candidate loop in `LlmClient::chat_full`. Local `TcpListener` fixtures cover fallback, no-fallback-on-auth, verbatim exhaustion errors and generic-404 handling. Core is untouched; the config file does not expose `fallback_models`.
2. `tool_calls` table, host-risk consistency, explicit `session.finish` terminal tool, and table-backed sliding-window repeat echo. Echo is limited to host-owned `safe`/`read` tools with a prior successful result; dangerous tools keep the hard block. The existing flag detector is retained; the table is the echo source. One-shot arg repair deferred here (needed typed tool errors and schema validation).
3. `Scope` doorbell coalescing / re-drain — no production consumer at this point.
4. Tool `risk` frozen as host-owned registry metadata. JSON Schema validation deferred here: `jsonschema` was not in the offline cargo cache, so adding it needed an explicit dependency/network decision (revisited in R7c).
JSON Schema validation and one-shot arg repair were outside this phase; see R7c.

### Phase R4a — Multi-agent and memory foundation (2026-11-20)
- `memory_items` and `session_results` tables with provenance fields, scope-gated retrieval, hash verification and typed child results.
- `bugfound-engagement::roles` with 7 domain-owned role profiles and `build_role_tools` (role filtering is a second layer over ROE filtering and preserves host-owned risk).
- `BountyDomain` carries an opaque `RoleId` and composes the role addendum into its prompt through the existing `PromptContributor` port.
Verify with the commands in `docs/PRODUCTION_PLAN.md` §2.

### Phase R4b — Synchronous handoff and episodic memory (2026-11-20)
- `bugfound-engagement::handoff` with `HandoffTool`, `RoleResultTool` and `MemoryRecallTool`. Depth ≤ 1, fixed delegable role set, wall-clock bound, typed `session_results`, scoped run_goal children using `build_role_tools`.
- `BountyDomain::on_tool_result` writes redacted episodic memory with provenance (`source_event_hash` from the event hash chain) and a shared scope key; recall is scope-gated and framed as untrusted data.
- Integration test delegates one goal to `recon` and `verification`, with episodic memory and event-chain integrity for each session.
Deferred: semantic tier (off by default, no embeddings), nested/cooperative cancellation, parent tool-call id on child results, `Report`/`General` roles.
Verify with the commands in `docs/PRODUCTION_PLAN.md` §2.

### Phase R5a — Strict taxonomy and rationale (2026-11-20)
- Strict CVSS v3.1 parser: canonical prefix, key order, metric count, duplicates and allowed values are validated; v4 and numeric strings are rejected instead of silently scored. `cvss_base` signature unchanged.
- Deterministic CWE rule table with root-cause-first ordering, word-boundary matching, and rule/basis/rationale emitted into the report. IDOR/BOLA maps to CWE-639; unclassified findings are explicitly marked for review.
- Report renderer emits `CWE rationale` and a `CVSS note` when a vector is unscorable; `docs/report-format.md` updated. Model severity never becomes a score by itself.
Verify with the commands in `docs/PRODUCTION_PLAN.md` §2.

### Phase R5b — Remaining domain depth
- Ternary closure (`confirmed | ruled_out | open_proof_gap`), counterevidence, paired controls, multi-oracle dispatch and `Finding` schema extension — touches finding DDL and the verifier.
- Platform-specific report appendix: `Platform` + `platform_from_program_url`, Appendix C field checklist (HackerOne/Bugcrowd/Generic), self-authored, no auto-submit, eval headings unchanged.
- Program intelligence (typed assets/scope provenance) — deferred: scope enforcement is a stop-condition boundary and platform semantics are not pinned offline.
- Verifier ternary closure, counterevidence and paired controls — deferred: needs a `Finding` DDL migration and a second independent control exchange; the `tool_captures` table permits only one tool capture per finding.
Exit check when implemented: lab finding with counterevidence, paired control and strict CVSS vector.

### Phase R6a — Wiring record scaffolding (2026-11-20)
- Offline loopback lab server (`eval/lab/local_reflect_server.py`) with a reflected endpoint and a non-reflective negative control.
- `eval/lab/golden.local.json` with target/endpoint/oracle/reset/tier and a `wiring-fixture-only` status.
- `eval/repeat_lab.py` N>=3 driver producing hashed, timed manifests and per-run replays with a stable `run_id` per run; baseline recorded as `not-run.json` unless an operator supplies a command.
- `export_trace.py` maps verifier `candidate` -> `finding_id` and preserves additive provenance keys.
Artifacts are labeled as wiring records; no effectiveness figure is derived from them.

### Phase R7 — Next roadmap (2026-11-20)

#### R7a-1 — Verifier closure storage foundation
- `finding_captures` multi-role table (`paired_benign` / `paired_payload`) additive to the unchanged primary `tool_captures` row.
- `RoleCapture` + `attach_role_capture` / `get_role_capture`; `Finding` gains `verdict` and `gap_reason` with DDL/migration/row-mapping updates.
- `set_finding_verdict` never stamps `validated_at`; ruled-out/uncertain findings cannot enter `verified_findings`.

#### R7a-2 — Production capture attachment
Addressed the gap where no production path attached an HTTP tool capture to a finding: `persist_tool_result` now keeps every tool-generated capture at session scope (`session_captures`) and consumes it once when a `save_finding` result has no capture of its own. LLM-supplied request/response remain advisory. Regression test `http_capture_flows_to_a_later_finding_without_llm_bytes` confirms tool bytes, not LLM text, reach `tool_captures`.

#### R7a-3 — Paired control and verifier closure
- `ValidatePoCTool` runs a tool-minted benign control alongside the payload; both captures carry distinct HTTP-tool canaries and are stored as role-tagged `finding_captures` (never from LLM input).
- `verify_findings` rules a candidate out only on a benign-success / payload-blocked contrast with matching tool markers; anything else becomes `open_proof_gap`. Verdicts never stamp `validated_at`, so ruled-out and uncertain findings cannot enter `verified_findings`.
- Negative-control tests: benign failure and missing pair stay `open_proof_gap`; full pair yields `ruled_out`.
Other oracle classes remain `open_proof_gap` (no implementation exists).

#### R7b — Program intelligence provenance
- Additive advisory `brief_rule_provenance` table with source URL, section pointer, verbatim quote + SHA-256, document hash, extractor and observed time.
- `parse_scope_brief_traced` in policy; legacy parser delegates to it, so scope decisions are structurally identical. Engagement captures deterministic provenance at brief time and persists it best-effort after `save_brief`.
- Provenance never feeds `PolicyEngine`, `build_tools`, or ROE enforcement.
- Deferred: typed assets, eligibility flags, freshness/TTL gating, platform VRT/safe-harbor semantics (sources stale/unpinned/license-restricted).

#### R7c — Tool argument validation
- Added `jsonschema` dependency (operator-approved) with external `$ref` resolution disabled; `validate_tool_args` checks tool args at the guard chain.
- `SchemaValidationMode` `Off` (default) / `Warn` (audit event) / `Enforce` (block before any guard state or budget is consumed). Tests cover all paths.
- `Scope`-aware coalesced doorbell: `WakeScope::{Steer, Input}` with widening, consumed by `Runner` at each step boundary; `Runner::enqueue_prompt` admits a durable inbox item and rings it.
- Arg repair resolved safely: an in-step second LLM call was implemented, then reviewed and reverted. It re-ran a side-effecting tool with arguments that never passed schema/policy/scope/budget/approval gates, poisoned a durable one-shot flag on transient failure, consumed scripted responses in mocks, and made the transcript describe args that never ran. The shipped behavior instead emits an additive `tool.args_repair_hint` event naming required fields; the model sees the existing `ok=false` tool result and self-corrects on the next step, preserving one LLM call per step and every gate. Test `args_error_hints_next_step_without_extra_model_call` confirms correction without an extra model call.

#### R8 — Later
- Measured results from real local engagements N>=3 + baseline lane.

### Phase R6b — Measured results
- Golden dataset tiers A-D with reset recipes and negative controls from real local lab engagements, N>=3, baseline lane, time-to-first-valid, tier-stratified recall/precision and FPR with real negative controls.
Exit check: report only operator-measured figures; record the baseline vs harness comparison.

## 3. Stop conditions

- P0 unresolved → no architectural expansion.
- No ADR-001 decision → no crate split.
- No golden artifacts → no effectiveness claims.
- Any scope/ROE regression → stop and fix.

## 4. Deliverable ownership

Research docs were written by parallel agents; synthesis docs 12–16 by the parent session. Future code work should update this file with phase notes and evidence links.


### Phase R8a — Live monitor engine (2026-11-20)
- `bugfound-core::monitor`: bounded ring buffers (tool/result/verdict/error/latency), per-key pause/resume, snapshot API, `evaluate()` health report, and a hash-chained JSONL journal under `eval/work/monitor/`.
- CLI `engage` starts/stops the monitor automatically, tracks the engagement id, and observes action/result/error events. Journal lines carry `no_benchmark_claim: true`.
- A live run against `security.cake.com` produced a report (sha256 `2699c0d42d3004cda37f611b07f4d9f3a62de0f546f32a92fe34a606652ba370`); `eval/score.py --strict` was run against it.
- Fixes from that run: ROE line classification (reward/report policy no longer aborts, vuln-class exclusions enforced), provider-safe tool names, empty LLM-scope fallback, explicit-asset scope precedence over broad out-of-scope wildcards.

### Phase R8b — Measured results
Await operator-recorded local engagements (N>=3) and a declared baseline lane; effectiveness figures require those artifacts.

### Phase R9 — Coverage and completion semantics (2026-11-23 scope-fidelity follow-up)
- Requirement-keyed coverage ledger: `coverage` rows carry `requirement_id`, `status` (covered|blocked|skipped|not-applicable), `rationale` and `evidence_ref`; `CoverageDecision` input struct.
- A tool call refused by the policy gate is recorded as `blocked` coverage, so a ROE-restricted engagement is distinguishable from one that tested nothing.
- A task whose runner returns `Ok` but produced no coverage and no artifacts is marked `needs-review`, not `done`; an `engagement.outcome` trace records `incomplete` when tasks or coverage are missing.
- Report Coverage section prints a Result column with reason.
- Hypothesis lifecycle: structured fields, production status transitions (`running → tested/blocked → confirmed-candidate → validated/ruled_out/open_proof_gap`), passive→active feedback that creates in-scope asset hypotheses from discoveries and feeds them into later task goals, and `open_hypotheses > 0` blocking `completed` outcome. Coverage mirroring does not convert `blocked` into `covered`.
- Deterministic role pipeline: `role_for_playbook` maps WSTG playbooks to Recon/Research/Testing; each task's Runner uses a role-scoped ToolRegistry over the ROE-filtered base (no privilege widening) and a role-specific agent config.
- Mandatory verification before confirmation: every candidate finding spawns a bounded Verification-role session that must write a complete `role_result` verdict; only then is the hypothesis marked `confirmed-candidate`. The verdict is advisory — only `verify_findings` may promote to `validated`.
- Per-class oracles and falsification fields: Finding carries counterevidence/confidence/rationale/severity-change-conditions/oracle_type; `SaveFindingTool` enforces them when `ToolOptions.require_falsification` is on (engagement always on, generic tests off). `verify_candidate` keeps `canary_echo` byte-identical and routes every other class to `open_proof_gap` with a named missing proof — never confirming from absence. `differential` has a confirm path when a tool-minted `paired_benign` / `paired_payload` role-capture pair exists (`differential_candidate`), plus a rule-out path from `paired_control_verdict`. `bugfound-tools::oracle_proof_gap` is aligned with the verifier.
- Authorization snapshot foundation (conservative slice): `authorization_snapshots` (version + content/scope hashes + observed_at), `authorization_acks` (hash-scoped, out-of-band, idempotent) and `authorization_open_rules` stored before the ROE abort. The abort remains the only behavior — an acknowledgement is recorded but does not bypass it, so no LLM/tool path can self-authorize.
- Deferred from step 5: ack-driven bypass, version-change revalidation on resume, and CLI/desktop authorize entry points.

### Phase R14 — Evidence binding in report
- `ReportFinding` carries 8 evidence-binding fields, populated only from stored `tool_captures` / `finding_captures` / store timestamps — never from model-authored finding fields.
- Raw evidence bytes written to a deterministic, cwd-confined artifact file (`evidence/<id>-<hash>.bin`); report references it with hash equality.
- Canary scrubbed from redacted views; `inline_view` prevents captured bodies from creating fake headings. Renderer lines are additive and guarded.
- Deferred: step 7 budgets/fan-out and ack-driven bypass (ROE decision).

### Phase R15/R16 — Bounded fan-out and operator authorization
- Handoff depth counter (`handoff_depth=N`, max 1) and children cap (9); role-scoped non-terminal tool caps; step-limit announcement event `runner.limit_approaching` without an extra LLM call.
- Ack-driven ROE bypass: proceeds only when every unmapped line has a hash-scoped operator ack; same abort text/shape otherwise; `denied_finding_classes` unchanged; outcome forced `incomplete` and trace `authorization.ack_applied`.
- Offline CLI `bugfound authorize --url --content-hash --rule|--version --operator [--note]` writes hash-scoped acks only; no LLM/tool path can create one.
- Deferred: budget-offset inheritance parent→child, revalidation-on-resume, platform adapters, safe-harbor typing, auto-submit.
These are construction records; verify the mechanism with the commands in `docs/PRODUCTION_PLAN.md` §2.

### Live evaluation — CAKE.com (2026-11-21)
- Fixed from the live run: missing hypotheses ALTER migrations, nested tokio runtime in monitor stop, tool-layer scope specificity (exact in-scope asset beats wildcard out-of-scope), and engagement-scoped report timeline.
- Run e43c21f9 produced a report (sha256 `9d80aad765bd7e8367153c3c70be58eed5d77f96542c6811d123c18fdf07a235`); outcome `incomplete`.
- Root causes recorded: LLM extraction target key `name` rejected by the intentionally narrow policy target list (security gate), path-bearing scope patterns (`*.api.clockify.me/api/`) don't match host keys, and playbooks failed on upstream LLM POST errors.
- Changes must not break the checks in `docs/PRODUCTION_PLAN.md` §2; speculative loosening of the narrow policy target key list was reverted.

### Phase R17 — Burp/ZAP tool mechanisms (local slice)
- Deep research from authoritative sources under `/research/` (git-ignored): PortSwigger `burp-extender-api` (42 interfaces, proprietary API contracts — concepts only, no code copied) and OWASP ZAP (Apache 2.0, sparse clone of `ascan`, `network`, `httppanel`). Written up in `docs/research/18_burp_tool_mechanisms.md`.
- BugFound already had the defensive half of these tools — `HttpRequestTool` canary + method gate, `HttpFuzzTool` caps (200/200), fail-closed tool withholding, byte-level evidence from tool captures. The gap was the local analysis layer.
- Added three local, no-egress, no-gate tools: `decode` (Decoder), `enumerate_insertion_points` (Burp Scanner/Intruder + ZAP `VariantFactory` equivalent, with byte offsets for url/form/cookie/header/path), and `http_diff` (Comparer + `analyzeResponseVariations` equivalent).
- Live rerun a9c02821 produced a report (sha256 `ab727e33696769d8a9d246f6010cc361897e78d9faf7b4e929303246a6e666c5`); outcome `incomplete`.
- Fixes from that run: path-scoped exclusions apply only to the named path, specificity compares host-label counts, report timeline is session-scoped.
- Still deferred: OOB Collaborator, live intercepting proxy, Sequencer, cookie jar/redirect control, full gated active-scan orchestrator.
Verify the mechanism with the commands in `docs/PRODUCTION_PLAN.md` §2.

### Phase R18 — Remaining engine capabilities
- `bugfound-tools`: cookie jar + per-hop scope-validated redirects on `http_request` (fail-closed on every `Location`); `sequencer` (entropy, bit balance, chi-square, verdict); `collaborator` (loopback-only OOB simulation, capped 32 interactions — explicitly cannot be a real external oracle); `active_scan` (gated Intruder-style runner, caps 20/200, reuse of all scope/method/rate/canary gates).
- `bugfound-store` + `bugfound-core` + `handoff`: budget-offset inheritance from parent to child sessions; child caps clamped to parent remaining, never widened; zero-consumption handoff rejected when parent is exhausted.
- `bugfound-engagement` + CLI: opt-in `--revalidate-brief` on resume — hash match clears, hash mismatch pauses, blocks further resume, emits no report and never marks aborted; `active_scan` registered only when all four gates (`allow_fuzzing`, `allow_intrusive`, `allow_network_write`, `allow_state_change`) are true, with audit event on withholding.
- New `bugfound-proxy` crate: bounded deterministic HTTP intercepting proxy, operator `y` ack required by default in gated mode, scope fail-closed, JSONL history flushed per request. Plain HTTP only; no TLS MITM.
- `bugfound-core` keeps exactly one `chat_full`.
- Deliberately not implemented: auto-submit / report transmission (forbidden by design invariant and requires a new ADR), external Collaborator server / DNS listener, TLS MITM certificate generation, platform adapters, typed safe-harbor model.
Verify with the commands in `docs/PRODUCTION_PLAN.md` §2 (includes the ADR-001 boundary check).

### Phase R19 — External OOB, TLS MITM, safe harbor, platform adapters
- New `bugfound-collaborator` binary: HTTP + UDP DNS + loopback-only admin listeners, token minting, capped interactions, JSONL history; `collaborator` tool talks to a real external endpoint via `ToolOptions.oob_endpoint` while retaining the loopback simulation fallback. DNS requires a delegated zone and UDP 53 (or port-forward); HTTP payloads are plain HTTP.
- `bugfound-proxy`: HTTPS/CONNECT interception with locally generated CA and cached per-host leaf certs; CONNECT passes the same fail-closed scope gate and operator ack; `--no-mitm` refuses tunnels with reason `mitm_disabled`. History records `scheme` and decision per request.
- Typed safe-harbor: `safe_harbor_receipts` table + idempotent hash-scoped CRUD + offline `bugfound receipt add|list`. Advisory only — never a ROE bypass and never changes outcome/final_state.
- Read-only platform adapters (`generic|hackerone|bugcrowd|intigriti`) with `--platform` and `--api-key-env`; missing token is a hard error, API contract caveats documented in code. No submission path exists.
- `bugfound-core` keeps exactly one `chat_full`.
- Still forbidden by design (requires a new ADR): auto-submit / report transmission.
Verify with the commands in `docs/PRODUCTION_PLAN.md` §2.

### Phase R20 — Scope fidelity and verifier parity (2026-11-23)
- Relative subdomain prefixes in briefs (`providers.`) are anchored to apex hosts derived from the deterministic brief before scope intersection; LLM scope is re-anchored after extraction.
- Path-scoped out-of-scope rules (`host/help/*`) are enforced on the named path in both `bugfound-policy` and `bugfound-tools`; a bare host is still allowed.
- `bugfound-tools::oracle_proof_gap` matches the verifier: `canary_echo` and `differential` are confirmable, all other classes remain named proof gaps. `validate_finding` is a contract pre-flight, not evidence validation.
- Docs drift corrected: no hardcoded test counts, no `AGENTS.md` reference, CLI surface documented, IPv6 blocked ranges documented, R9 differential wording aligned with code.
Verify with the commands in `docs/PRODUCTION_PLAN.md` §2 (evidence matrix rows 21–23 name the regression tests).
