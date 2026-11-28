# 05 — BugFound V3 Migration & Implementation Plan

> Status: design only — not implemented. Prepared 2026-11-26.
> Companion ADRs: `adr/`. Blueprint: `04_AGENT_DRIVEN_TARGET_ARCHITECTURE.md`.
> **No source code was changed for this document.** Phases are ordered by
> architectural need (security before autonomy), not by implementation ease.

## 1. Mapping target components to the actual repository

Legend: **KEEP** = retain as-is · **EXTEND** = add fields/paths · **MOVE/SPLIT** =
change ownership · **NEW** = create · **RETIRE** = remove after replacement.

| Target component | Existing code | Action | Notes / boundary |
| --- | --- | --- | --- |
| Universal agent runtime (loop, lifecycle, recovery) | `bugfound-core/src/lib.rs` runner; `step.rs`, `execution.rs`, `inbox.rs`, `event.rs`, `monitor.rs`, `compaction.rs` | EXTEND | Keep one-call-per-step, lease recovery, inbox/stop/steer, stall guard, `CompactionV2`. Add `NextStep`/`Replan` types **in a domain crate**, not in `bugfound-core` (ADR-001). |
| Model/provider abstraction | `bugfound-llm/src/lib.rs` | EXTEND | Add planner/verifier role contexts; keep typed errors, discovery, streaming, tool schemas; catalog via tool search, not a second provider. |
| Bug bounty domain engine | `bugfound-engagement` WSTG helpers `wstg_playbooks() :3414-3453`, `roles.rs`, `domain.rs` | MOVE/SPLIT + NEW | Turn WSTG data into a versioned technique catalog with metadata; keep ROE classifier. Catalog must be read-only knowledge. |
| Dynamic investigation controller | Spread across `tasks`, `hypotheses`, `coverage`, `assets` in `bugfound-store`; `engagement/lib.rs:2207-2312` | NEW (thin) + EXTEND | New `InvestigationState` aggregate in `bugfound-engagement`/store; extend tables with priority/value/confidence; replace prompt-only feedback. |
| Security policy harness | `bugfound-policy/src/lib.rs`; approvals in `core`/`store`; authorization in `engagement/lib.rs:1130-1314` + `store` ack APIs | EXTEND + FIX | Machine-readable ROE object; intent gate; ordered rules with deny precedence; idempotency keys; project-scoped "always"; close `roe_hash`/`brief_version`/CLI bypass holes. |
| Tool execution layer | `bugfound-tools/src/lib.rs` registry | EXTEND | Add intent-gate handoff, per-tool least-privilege profiles, idempotency key plumbing, richer failure taxonomy. Keep canary/capture/redaction. |
| Persistent memory | `bugfound-store` schema `:335-560`; `CompactionV2`; inbox | EXTEND | Append-only `investigation_events`; `progress`/`reflection` records; authenticated version-checked resume; tool-result clearing. |
| Evidence verification engine | `engagement/lib.rs:3819-4138` verifier; `bugfound-collaborator` binary | EXTEND + WIRE | Add state-delta/timing/OOB consumers and confidence classes; store CVSS v4 vector + Report Confidence; TLP label; only verifier sets `confirmed`. |
| Reporting | `bugfound-tools::render_canonical_report`, `engagement::build_canonical_report :4219` | KEEP + EXTEND | Add confidence/TLP/limitations fields; keep local-only, no submission. Fix CLI `report` divergence (uses store export). |
| Surfaces | `bugfound-cli`, legacy `bugfound-desktop`, new `bugfound-app` + `frontend` | EXTEND / RETIRE | Wire Tauri commands for sessions/chat/approvals/findings/report; retire egui at its parity gate (ADR-009 Phase 3). Keep CLI first-class. |
| Evaluation | `eval/score.py`, `export_trace.py`, fixtures | EXTEND | Lab fixtures + agent-quality metrics + adversarial suite; fix stale e2e names. |

## 2. Dependency-direction changes

- `bugfound-core` **must not** depend on `bugfound-engagement` or any domain
  crate (ADR-001 CI check). New plan/hypothesis types live in `engagement`.
- `bugfound-engagement` may depend on `core`, `llm`, `policy`, `tools`, `store` —
  as today. The new `InvestigationState` aggregate belongs here.
- Harness rules stay in `bugfound-policy`; the intent gate calls policy, never
  the reverse. The planner calls the harness through commands, not by writing
  store tables.
- `bugfound-desktop-core` is the only store reader for the Tauri shell; no
  webview DB access (ADR-009).

## 3. Data migration / compatibility risks

| Change | Risk | Mitigation |
| --- | --- | --- |
| New `investigation_state` + `investigation_events` tables | Existing engagements have no state row | Lazy backfill from `tasks`/`hypotheses`/`coverage` on first read; keep old tables readable |
| New fields on `hypotheses`/`coverage` (priority, value, confidence) | Old rows missing fields | SQL `DEFAULT` + `#[serde(default)]`; no destructive ALTER |
| Typed ROE object vs `roe_json` reporting rules | Existing snapshots store rules, not policy | New `roe_policy_json` column; keep old column for report provenance |
| `roe_hash` previously empty | Hash-scoped acks created under old hash | Introduce `roe_policy_hash` with version 1; grandfather old acks explicitly, fail closed otherwise |
| Approval idempotency key | Old pending approvals lack key | Derive deterministic key from `(session, tool, normalized_args)` for legacy rows |
| `brief_version` acks ignored | Operator believes an ack is active | On migration, surface ignored acks in `status`/console and require re-ack |
| Catalog versions in findings | Old findings have no version | Mark `catalog_version: "legacy"`; never present as V3 evidence |

## 4. Phased roadmap

Priorities are architectural. Each phase has its own go/no-go gate.

### Phase P0 — Investigation state & audit substrate — **DONE (2026-11-26)**
- **Goal**: single versioned state + replayable step log.
- **Changes (implemented)**: `investigation_state` + `investigation_events`
  tables (schema v3) in `bugfound-store/src/lib.rs` with revision guard, hash
  chain, backfill from legacy tables; domain shape `InvestigationState`, `Plan`,
  `PlanStep`, `Reflection` and `load/save/audit` helpers in
  `bugfound-engagement/src/investigation.rs`. No behavior change to V1.
- **Risks**: dual source of truth if old tables keep being written independently
  (state row is authoritative from P2 onward).
- **Tests (green)**: `investigation_tests::backfill_and_revision_guard`,
  `investigation_tests::audit_event_chain_detects_tampering`,
  `investigation::tests::state_round_trip_preserves_revision_and_plan`.
- **Acceptance**: legacy engagement backfills into one state; stale revisions
  are rejected; event tampering is detected.
- **Gate passed**: store + engagement targeted tests green; full workspace suite
  still green.

### Phase P1 — Harness hardening (before any added autonomy) — **core done, gate partial**
- **Goal**: close enforcement holes; intent gate exists and denies first.
- **Changes**: typed `RoePolicy` + `roe_policy_hash`; fill `roe_hash`; intent gate
  (schema → ROE → ordered rules → budget → risk); idempotency keys; authenticated
  approval resolution with replay protection; project-scoped "always"; honor
  operator ROE mode on `--platform`/`--brief-only`; make `brief_version` acks
  effective or remove them. **Deep-audit additions**: enable strict schema
  validation (currently `Off` in CLI/desktop), stop `build_tools` from
  re-copying tool-supplied risk over frozen operator risk
  (`engagement/lib.rs:4558-4560`), consolidate the two `redact` implementations,
  and set a SQLite `busy_timeout`.
- **Prerequisites**: P0 event ids (for audit).
- **Affected**: `bugfound-policy`, `engagement/lib.rs:1130-1314`, `core` approval
  path, `store` ack APIs, `cli/main.rs:1476-1514`.
- **Risks**: stricter gating may break existing labs — keep explicit opt-in,
  never silently widen scope.
- **Tests**: `intent_gate_denies_out_of_scope`, `approval_replay_rejected`,
  `always_never_overrides_deny`, `platform_path_honors_roe_mode`.
- **Implemented (2026-11-26)**:
  - `roe_hash` now binds the typed `RoePolicy` (hash helper + test
    `roe_policy_hash_binds_the_typed_policy`).
  - `IntentGate` preflight in `bugfound-policy/src/intent.rs`, called from
    `PolicyEngine::evaluate`: unclassified risk denies, deny wins over allow,
    target deny wins. 3 tests.
  - `bugfound_store::idempotency_key` (stable canonical signature) + test.
  - `build_tools` uses `register_with_host_risk`, preserving frozen host risk.
  - Schema validation default changed `Off → Warn` (Enforce stays opt-in).
  - SQLite `PRAGMA busy_timeout=5000`.
  - CLI `--platform` / `--brief-only` now use ROE-aware variants
    (`engage_with_platform_and_roe`, `engage_brief_only_with_platform_and_roe`).
- **Deviations (explicit, not silently dropped)**: approval identity/replay keys
  are not yet threaded through the runner (needs the P2 orchestrator seam);
  `brief_version` acks remain audit-only; the two `redact()` implementations are
  not yet consolidated (cross-crate refactor with high regression risk).
- **Acceptance**: existing policy/approval/engagement/cli tests green plus new
  denial/hash/idempotency tests. The full §7 adversarial-suite gate belongs to
  P6 and is **not yet satisfied**.
- **Gate**: targeted tests green; full workspace suite and clippy re-run before P2.

### Phase P2 — Decision loop (agent becomes strategist) — **seam done, planner is reference implementation**
- **Goal**: agent emits `NextStep`; plan/replan persisted; replace round replay.
- **Changes**: `Plan`/`Replan`/`NextStep` types in engagement; planner context
  projection from `InvestigationState`; `run_engagement` task loop replaced with
  "ask planner → gate → execute → observe → replan"; priority function from
  coverage/hypothesis/asset deltas; durable action-signature dedupe; wire
  `prioritize_targets` or delete it; discover feedback mutates state, not just
  prompt.
- **Prerequisites**: P0 + P1.
- **Affected**: `engagement/lib.rs:1502-1962`, `:2122-2312`, `domain.rs:92-128`.
- **Risks**: planner may choose useless actions; mitigate with eval M1/M2 and
  fallback to V1 task order behind a config flag during rollout.
- **Tests**: `adaptive_reorder` (missing today, `HARDENING_PLAN.md:148-162`),
  `replan_on_coverage_delta`, `repeat_action_penalized`, `no_action_stops`.
- **Implemented (2026-11-26)**:
  - `Planner` trait + `NextStep` + deterministic `HeuristicPlanner` in
    `investigation.rs`; `adaptive_planning` config-only knob in
    `EngagementLoopOptions` (off by default until the P2 gate passes).
  - `select_round_tasks` is the task-selection seam used by `run_engagement`
    when the flag is on: refreshes `InvestigationState`, ranks open hypotheses,
    applies coverage-delta and repetition penalties, persists `Plan` + audit
    events, and returns bounded `Task`s for the *unchanged* runner/policy/
    verifier path. Round-end state sync + `state_transition` audit added.
  - `prioritize_targets` is now on the production decision path (target bonus).
  - 6 tests: `adaptive_reorder_skips_terminal_hypotheses`,
    `replan_on_coverage_delta_changes_priority`, `repeated_action_is_penalised`,
    `no_actionable_steps_stops_the_loop`, `select_round_tasks_persists_plan_and_dedupe`,
    `state_round_trip_...`.
- **Deviation (explicit)**: the planner is a deterministic reference, **not yet
  LLM-backed**. The agent-decides seam exists and is testable, but calling this
  "agent-driven strategy" would overstate it until the LLM planner lands.
  V1 static queue remains the default behind the flag.
- **Acceptance (partial)**: adaptive reorder, replan-on-delta, dedupe and stop
  are proven by unit tests; fixture-level M1/M2 measurement is P6.
- **Gate**: targeted tests green; full suite/clippy/deny re-run before P3.

### Phase P3 — Domain catalog & technique-driven planning — **catalog done, LLM planner pending**
- **Goal**: WSTG/ASVS/API/CWE as versioned knowledge, not fixed sequence.
- **Changes**: technique catalog records (id, preconditions, safe bounds,
  expected artifact, benefits/limitations, mappings); deferred loading/tool
  search; planner scores techniques against state; phase names become metadata.
- **Prerequisites**: P2.
- **Affected**: `engagement/src/domain.rs`, playbook helpers `:3414-3453`,
  `bugfound-tools` tool registry (schema exposure).
- **Risks**: catalog drift; pin versions in every plan and finding.
- **Tests**: catalog version pinning, deferred tool search under token budget,
  technique precondition gating.
- **Implemented (2026-11-26)**:
  - `bugfound-engagement/src/catalog.rs`: versioned `Catalog` with 9 technique
    records carrying preconditions, safe bounds, expected artifact,
    benefits/limitations and version-pinned WSTG/ASVS/API/CWE mappings.
  - Deferred lookup: `search(query, max_results)` returns compact `TechniqueView`s;
    `get(id)` returns the full record only for selected ids.
  - `HeuristicPlanner` now ranks **catalog techniques**, not static playbook
    rows; `Plan`/`NextStep` carry `catalog_version`. Precondition gating excludes
    techniques needing assets or state-change authorization.
  - 4 new catalog tests + `planner_uses_catalog_not_static_playbooks`.
- **Deviation (explicit)**: the planner is still deterministic. The catalog is
  the right substrate for an LLM-backed planner, but that swap has not happened
  yet — calling V3 "agent-driven" remains premature. Finding-level catalog
  pinning is deferred to P4 (verifier) because it needs the finding schema.
- **Acceptance (partial)**: capability survives removal of a static playbook row
  (unit-proven); fixture-order gate is P6.
- **Gate**: 85 engagement tests green; full suite/clippy/deny re-run before P4.

### Phase P4 — Verifier extension & finding authority — **authority layer done, live OOB pending**
- **Goal**: more oracle classes, confidence, no self-grading.
- **Changes**: state-delta, timing and OOB consumers; collaborator wired into
  verifier; CVSS v4 vector + Report Confidence; TLP labels inherited from ROE;
  `observed→reproducible→proven|inconclusive|rejected`; only verifier may set
  `confirmed`; rejection reflections written to memory. **Deep-audit addition**:
  report must print the authoritative `evidence.sha256`, not the
  model-derived `finding.evidence_hash` (`tools/lib.rs:5771,5847`).
- **Prerequisites**: P0, P1 (evidence ids).
- **Affected**: `engagement/lib.rs:3819-4138`, `bugfound-collaborator` client,
  `bugfound-tools` report renderer.
- **Risks**: new oracles can produce false positives — paired controls required.
- **Tests**: each oracle with positive/negative control; `model_claim_never_confirms`.
- **Implemented (2026-11-27)**:
  - `bugfound-engagement/src/verification.rs`: `Verdict` state machine
    (`observed→reproducible→proven|inconclusive|rejected`), `Confidence` with
    CVSS Report Confidence semantics, `OobOracle` trait + `EvidenceOob`
    (interaction keys from stored evidence), `Verifier::decide` as the only path
    to `Proven`, and `from_model_claim` that always yields `Observed`.
  - Store: `finding_provenance` table (catalog version, TLP label, verdict,
    confidence, oracle) + `finding_evidence_digest` (authoritative tool-bytes
    SHA-256). `verify_findings` pins catalog/TLP and writes provenance.
  - Report renderer now prefers `authoritative_evidence_hash` over the
    model-supplied value (`canonical_report_prefers_authoritative_evidence_hash`).
  - 5 verifier tests incl. `model_claim_never_confirms` and OOB positive/negative.
- **Deviation (superseded)**: OOB consumption was initially evidence-key only.
  `HttpOobOracle` now reads the loopback collaborator admin API
  (`GET /interactions?token=…`) and `verify_findings_with_oob` promotes an
  `oob_hit` candidate only on a matching interaction. Token correlation uses
  the finding id. `state_delta`/`timing`/`browser_deferred` remain
  `inconclusive` by design until real controls exist.
- **Acceptance (partial)**: model text cannot promote; provenance pinned.
  Fixture false-positive measurement is P6.
- **Gate**: targeted tests + full suite/clippy/deny re-run; FP rate still unmeasured.

### Phase P5 — Memory, compaction, resume hardening — **substrate done, lab acceptance pending**
- **Goal**: long adaptive runs survive restarts with no duplicated side effects.
- **Changes**: `investigation.json`-equivalent checkpoint; `progress.md`-equivalent
  operator summary; tool-result clearing; 1–2k-token subagent digests; version-
  checked authenticated resume; replay from event log. **Deep-audit addition**:
  add a cost gate — cost was recorded but never enforced. The suspected
  cumulative token double-count (`core/lib.rs:2158-2160`) was audited and
  **refuted**: per-request deltas are summed correctly (`docs/AUDIT_2026-11-27.md`
  §4), so nothing was fixed there; see the P5 "Implemented" note below.
- **Prerequisites**: P0 + P4.
- **Affected**: `core/src/compaction.rs`, `store`, `engagement` checkpoint writer.
- **Risks**: stale checkpoint replay causing duplicate HTTP requests.
- **Tests**: resume-to-identical-verdict, duplicate side-effect count = 0.
- **Implemented (2026-11-27)**:
  - Store: immutable `investigation_checkpoints` table with revision, digest,
    `agent_version`; `save_checkpoint` / `latest_checkpoint` /
    `checkpoint_agent_version`.
  - `investigation::checkpoint` + `resume_checkpoint`: digest, revision and
    agent-version checks all fail closed. Called at round end by
    `run_engagement` when adaptive planning is enabled, so it is on the
    production path (not a dead helper).
  - `project_context`: bounded context projection (plan steps, open hypotheses,
    counts) that excludes raw tool output; `digest_observation` caps a
    subagent/tool summary at ~tokens×4 chars with a truncation marker.
  - Cost gate: `AgentConfig.max_cost_usd` (0 = unlimited) + deterministic
    `cost_within_budget`; runner stops before the next billable call. Audited
    the claimed token double-count: `token_usage()` sums per-request deltas and
    the runner adds the current prompt estimate — no double count found in the
    production path; recorded as verified, not "fixed by assumption".
  - Tests: version/revision mismatch fails closed, bounded projection without
    tool noise, digest cap, cost gate including NaN fail-closed.
- **Deviation (explicit)**: no `progress.md`/`investigation.json` file export and
  no ≥3-run interrupted-lab measurement yet (needs P6 fixtures). Replay from
  event log is partial (durable events exist; deterministic replay of live
  responses is out of scope).
- **Acceptance (partial)**: version-checked resume and bounded context unit-
  proven; M9 still unmeasured.
- **Gate**: targeted tests + full suite/clippy/deny re-run before P6.

### Phase P6 — Operator console & evaluation integration — **IPC + harness done, lab acceptance pending**
- **Goal**: operators can supervise adaptive runs; quality measurable.
- **Changes**: Tauri commands for sessions/timeline/approvals/findings/report/
  budgets; event-driven updates (Channel for streaming); report viewer;
  export to eval harness; adversarial suite in CI/nightly; fix stale e2e script.
- **Prerequisites**: P1–P5 expose the needed commands/data.
- **Affected**: `bugfound-desktop-core`, `bugfound-app`, `frontend/`, `eval/`,
  `.github/workflows/`.
- **Risks**: console scope creep — keep P3 parallel sessions out of V3.
- **Tests**: IPC contract tests, frontend typecheck/test, smoke of full flow.
- **Implemented (2026-11-27)**:
  - `bugfound-desktop-core`: commands `sessions_list`, `session_history`,
    `approvals_list`, `findings_list`, `investigation_view`, `audit_events`,
    `report_read` with redacted DTOs; wired into the Tauri `invoke_handler`.
    Frontend IPC wrappers + a Findings rail that renders verifier verdict,
    confidence and TLP label from the new command.
  - `eval/agent_eval.py`: honest evaluator for M1–M12; computes M2 proxy,
    M4, M6, M11, M12 from exported events/state and leaves the rest
    `not_measured`. `--self-test` added to CI.
  - Stale `eval/e2e_test.ps1` binary/env names fixed (`bugfound`,
    `BUGFOUND_API_KEY`).
- **Deviation (explicit, superseded by the console increment below)**: the
  original P6 scope had no control commands. `engagement_start` and interactive
  approval cards remain open; the chat/steer/stop/approval runtime and streaming
  Channel were added afterwards.
- **Acceptance (partial)**: IPC contract + evaluator self-test green; M1/M3/
  M5/M7–M10 remain unmeasured by design.
- **Gate**: no effectiveness claim published; doc 06 §8 metadata rule still applies.

### Post-P6 console increment (2026-11-27)

- `bugfound-desktop-core/src/runtime.rs`: `RuntimeHandle` owns a long-lived
  Tokio runtime thread and dispatches `Chat`, `ChatSend`, `Steer`, `Stop` and
  `Approval` through the proven core APIs (`run_goal_stream`, `chat_turn`,
  `steer`, `request_stop`, `resume_session`). `RuntimeEvent`s (started/delta/
  approval-required/finished/error/status) are serialized and bridged into an
  ordered Tauri `Channel`.
- `bugfound-app`: 6 additional commands (`runtime_status`, `runtime_chat`,
  `runtime_chat_send`, `runtime_steer`, `runtime_stop`, `runtime_decide`) — 14
  total. Frontend composer now sends messages and offers Steer/Stop with a live
  event feed.
- Follow-up in the same increment: `engagement_start` now dispatches
  `engage_with_options_and_loop` and maps `EngagementEvent`s into the ordered
  Channel; `pending_approvals` lists decisions across sessions and the frontend
  renders Approve/Deny cards wired to `runtime_decide`. Total: 16 IPC commands.
- Deviation: the GUI flow is compile/unit-tested, not smoke-tested end-to-end
  against a live provider.

## Post-P6 increment — LLM planner (2026-11-27)

- `bugfound-engagement/src/planner.rs`: `AsyncPlanner` trait + `LlmPlanner`.
  The model sees only a bounded `ContextProjection` and capped catalog views
  (deferred loading), returns strict JSON proposals, and **every proposal is
  re-ranked and filtered through `HeuristicPlanner`** before becoming a
  `NextStep`. Unknown technique ids, inapplicable techniques and out-of-scope
  targets are dropped; non-JSON output yields no steps (fail closed).
- `EngagementLoopOptions.llm_planning` (config-only, default `false`) switches
  `run_engagement` to the LLM path; `agent.llm_planning` in `bugfound.toml`
  enables it and also turns on adaptive planning. Audit events record actor
  `llm_planner` so model-originated plans are distinguishable.
- Tests: `llm_planner_only_selects_safe_catalog_steps`,
  `malformed_model_output_fails_closed`.
- **Still honest**: enabling this flag does not by itself make V3 "agent-driven
  complete" — M1/M2 fixture measurement (P6) and the full operator command set
  remain open. The model proposes; the harness still decides.

### Phase P7 — OS-level sandbox (staged, optional in V3)
- **Goal**: dual filesystem + network isolation for lab runs.
- **Changes**: container/bubblewrap/seatbelt profile; egress allowlist proxy;
  scoped credentials outside the sandbox.
- **Prerequisites**: P1–P6 stable; lab opt-in preserved.
- **Risks**: breaks external recon adapters; must remain opt-in with a clear
  warning, never a silent default that disables capabilities.
- **Tests**: egress denial, FS escape denial, subprocess coverage.
- **Acceptance**: 84%-class reduction in routine prompts is a target, not a claim.
- **Gate**: lab tools still work under an explicit profile.

## 5. What must NOT be done

- No full rewrite of `bugfound-core`; its loop, leases and inbox are sound.
- No model-editable scope/ROE/permission/budget/verdict.
- No deletion of the V1 static workflow until P2 has passed its gate.
- No weakening of deny precedence or approval checks to enable P2.
- No effectiveness claim from a synthetic example; no public-target testing.
- No new crate unless it owns a real boundary (ADR-001/009 precedent).

## 6. Cross-phase acceptance checklist

- [ ] Every phase's tests are in `cargo test --workspace` or the eval harness.
- [ ] ADR-001 boundary check stays green.
- [ ] `cargo deny check` stays green; new advisories triaged with dates.
- [ ] Data migrations are additive and reversible.
- [ ] Each phase's go/no-go gate is recorded with evidence before the next starts.
- [ ] Deviations from the blueprint are written down with a technical reason.
