# 01 — BugFound Current State Audit (forensic, source of truth = code)

> Prepared 2026-11-26 for the V3 blueprint. **No source code was changed for
> this document.** Documentation is treated as a claim, not evidence; every
> finding below is traced to a file, symbol, test or execution path. Where a
> capability cannot be proven from code it is labelled **unproven**, not mature.

> **Historical snapshot.** This describes the tree at 2026-11-26. Claims
> refuted by `docs/AUDIT_2026-11-27.md` §4 or superseded by the 2026-11-28
> repairs are marked inline; see §9 for consolidated corrections. Do not read
> the pre-V3 rows below as current behavior.

## 0. Repository state at audit time

- Branch: `dev`
- HEAD: `e344cc022ec0cb732f95cddbb7add33c865bc509` — `chore: rename agentbug to bugfound`
- Working tree: 115 changed/untracked entries. It already contained a large
  uncommitted agentbug→bugfound rename plus the **Phase 0 Tauri shell work**
  recorded in `docs/roadmap/DESKTOP_UI_OVERHAUL.md`. Both were preserved; this
  audit changed only documentation.
- Baseline for "pre-existing" comparisons: the staged tree and `HEAD` lockfile.

## 1. Component inventory

Status legend: **P** production-used · **PARTIAL** reachable but incomplete ·
**TEST** only tests/callers · **STUB** scaffold · **ABSENT** no implementation.

| Component | Location / entry point | Responsibility actually implemented | Status |
| --- | --- | --- | --- |
| `bugfound-kernel-traits` | `crates/bugfound-kernel-traits/src/lib.rs` | Ports: `Domain`, `GoalLock`, `PromptContributor`, `ToolResultSink`, `ProgressObserver`. | P |
| `bugfound-core` runner | `crates/bugfound-core/src/lib.rs` — `open_conversation`, `chat_turn`, `run_goal_stream`, `resume_session`, `steer`, `request_stop`, `settle_on_boot`, `recover_stale_sessions`, `enqueue_prompt` | One LLM call per step → gated tool → atomic persistence; leases, guarded transitions, budget checks, compaction, inbox, event bus, monitor/stall guard. | P |
| `bugfound-core` execution/inbox/monitor | `src/execution.rs`, `src/inbox.rs`, `src/monitor.rs`, `src/event.rs`, `src/step.rs`, `src/compaction.rs` | Lease/wake coalescing, control>steer>queue priority, bounded ring monitor, hash-chained events, `CompactionV2`. | P |
| `bugfound-llm` | `crates/bugfound-llm/src/lib.rs` | OpenAI-compatible chat + streaming, tool schemas, model discovery, retry/backoff, typed error classification & recovery table. | P |
| `bugfound-tools` | `crates/bugfound-tools/src/lib.rs` registry | fs/shell/http/dns/finding/artifact/fuzz/diff/sequencer/OOB/active-scan; risk labels, workspace confinement, DNS pinning, canary minting, capture hashing, redaction. | P (some classes partial) |
| `bugfound-policy` | `crates/bugfound-policy/src/lib.rs` | `ask`/`full_auto`, allow/ask/deny, scope parse + wildcard/path/CIDR match, deny precedence, budget aliases. | P |
| `bugfound-store` | `crates/bugfound-store/src/lib.rs` schema at `:335-560` | SQLite/WAL; sessions, messages, approvals, events, budgets, usage, findings, captures, coverage, hypotheses, assets, artifacts, tasks, clues, authorization snapshots/acks, reports, trace events. | P |
| `bugfound-engagement` | `crates/bugfound-engagement/src/lib.rs:222-` → `engage_async:949` → `run_engagement:1089-2112` | Brief fetch/parse, ROE classification, 9 fixed WSTG playbooks, role-scoped runs, deterministic verification, canonical report. | P, workflow-driven |
| `bugfound-engagement` roles/handoff | `roles.rs`, `handoff.rs` | Two used roles (General/Testing + verification role); one-level `role_handoff` (depth 1, ≤9 children, clamped budgets). `ProgramIntel`/`Report` roles unused; `MemoryRecallTool` TEST-only. | PARTIAL |
| `bugfound-engagement` verifier | `lib.rs:3819-4138`, `:3856-3946` | **Pre-V3 snapshot:** canary-echo and differential oracles alone could promote; `state_delta`, `timing`, `oob_hit`, `browser_deferred` were always `open_proof_gap`. P4 added `Verifier::decide`, verifier-owned provenance and an OOB consumer; see §9. | PARTIAL (historical) |
| `bugfound-cli` | `crates/bugfound-cli/src/main.rs` | 25 subcommands; `engage` `:1392-1605` is the main production path; control/receipt/read-only inspectors. `report` uses store export, not the canonical engagement renderer. | P |
| `bugfound-desktop` (egui) | `crates/bugfound-desktop/src/{main,worker}.rs` | Legacy chat + engagement UI, one Tokio worker. Known defects: `engage_url` never assigned → engagement button dead; no history reload; input blocked while `busy`. Scheduled for deletion at ADR-009 Phase 3. | P (legacy, defective) |
| `bugfound-app` + `bugfound-desktop-core` + `frontend/` | `crates/bugfound-app/src/lib.rs:5-18`, `projection.rs:12-53` | **Pre-V3 snapshot:** Tauri 2 shell with **one** command `app_ready`; redacted snapshot; degraded in-memory fallback; no sessions/chat/approval/engagement commands yet. P6 added 16 IPC commands and an ordered event Channel; see §9. | STUB (Phase 0 — historical) |
| `bugfound-proxy` | `crates/bugfound-proxy/src/main.rs:28-58` | Standalone scope-gated HTTP/CONNECT intercept proxy with local CA and request cap. No call sites from the engagement engine. | P standalone |
| `bugfound-collaborator` | `crates/bugfound-collaborator/src/main.rs:40-74` | Standalone OOB HTTP/DNS oracle. Only reachable via operator config `oob.endpoint`; **not consumed by the verifier**. | P standalone |
| `eval/` | `eval/score.py`, `export_trace.py`, fixtures | Self-declared scaffolding; fail-closed verification and metrics present, but `reproducibility: not_measured`; `e2e_test.ps1` references stale `agentbug.exe`/`AGENTBUG_API_KEY` and is effectively brief-only/offline. | PARTIAL / scaffolding |

## 2. Reconstructed execution flow (from code)

### 2.1 Engagement path (CLI / desktop → report)

```
engage(...)  [engagement/src/lib.rs:222] → engage_with_options:242 →
engage_with_options_and_roe:264 → engage_with_options_and_loop:287 →
engage_async:949
   ├─ create workspace + Store + ReplayLog + ControlCenter row (:971-984)
   └─ run_engagement:1089
        ├─ 1. brief: fetch_engagement_brief:2518 / generic fetch:2557
        │       (no redirects, private-host reject, 1 MiB cap) or platform
        │       adapter platform.rs:112; local brief bypasses fetch
        ├─ 2. scope: parse_scope_brief_traced, expand_relative_scope_patterns
        │       :2957, normalize_scope_pattern :2975; deterministic empty ⇒ abort
        │       :1145; AuthorizationSnapshot with hash; roe_hash EMPTY :1169
        ├─ 3. ROE: parse_roe :3040 + classify_brief roe_classifier.rs:277;
        │       unmapped lines abort :1204-1314 unless hash-scoped ack;
        │       PermissiveAudited auto-acks :1244 and forces `incomplete`
        ├─ 4. profile: extract_profile_with_llm :2779 (BUGFOUND_API_KEY /
        │       OPENAI_API_KEY :1330), intersect LLM scope with deterministic
        │       hosts :1369-1382, save_brief :1416, BriefIngested :1458
        ├─ 5. plan: wstg_playbooks() :3414-3453 → **9 hard-coded tasks** +
        │       1 hypothesis each :1466-1479; brief_only returns :1481
        ├─ 6. rounds (max_rounds, config 1..=10):
        │       search_round_tasks :2122 — round 1 pending only;
        │       **round ≥2 returns EVERY task** :2132-2137
        │       per task: wait_while_paused :1563 (500 ms DB poll),
        │       optional brief revalidation :1570, build_tools :1645,
        │       role_for_playbook :1738 (static), HandoffTool :1725,
        │       Runner::new().with_domain(BountyDomain) :1741,
        │       feedback_prompt :1755 (hypotheses only as text),
        │       runner.run_goal :1794, coverage mirror :1795,
        │       sync_hypotheses_from_coverage :2180, task done/needs-review
        │       by evidence+coverage :1824, optional verification-role
        │       second opinion :1877-1932
        ├─ 7. verify :1964: verify_findings :3856 → replay oracles :3913-4070;
        │       final hypothesis transitions :1971, outcome :2014 (aborted /
        │       incomplete / completed), canonical report :2042,
        │       save_report :2047, Finished :2091
        └─ control: pause/resume/abort/status :566-685; abort still runs
              verifier + report; status_at counts ALL findings :681
```

### 2.2 Per-step runner loop (`bugfound-core`)

`Runner` holds an OpenAI-compatible session, a `GoalLock`, a `PolicyConfig`,
budgets in `session_budgets`, a `ToolResultSink`, an `EventBus` and a
`CompactionV2`. A step: build tool specs from the role/domain; one LLM call
(`chat_turn` / `run_goal_stream` for streaming deltas); parse a single tool
call; run it through `bugfound-policy`'s decision; if `ask` and risky, park the
session with an approval row (`waiting_approval`) and deferred calls; on
resolution, guarded `status='pending'` + expiry update executes or rejects;
persist message, tool result, budget counters, evidence and event **atomically**
before the next step. `steer` admits a message at a step boundary via the
durable inbox (control > steer > FIFO). `request_stop` sets a cancel flag;
`ExecutionCoordinator` can interrupt across sessions. `settle_on_boot` +
`recover_stale_sessions` reclaim stale leases after restart. The monitor emits
`no-progress / progress / refuted / confirmed-candidate / blocked / terminal`;
a stall guard (`stall_limit: 6` from `engagement/src/lib.rs:3339`) stops
repetitive playbooks.

**Verified by:** `crates/bugfound-core/tests/runner_integration.rs` (52 tests
including `ask_mode_pauses_for_approval_and_resumes_on_approve`,
`steer_enqueues_an_item_for_a_conversation_session`, `stall_guard_*`,
`budget_survives_resume_with_a_new_runner`, `interrupted_...`).

### 2.3 LLM / tool / policy pipeline

- **LLM**: `bugfound-llm` builds JSON-Schema tool specs, retries with backoff,
  classifies errors (auth errors never fall back), supports model discovery and
  streaming assembly of deltas + tool calls. Evidence: `bugfound-llm` unit tests
  `stream_full_emits_deltas_and_assembles_tools_and_usage`,
  `auth_error_never_falls_back`, `model_not_found_falls_back_to_second_model`.
- **Tools**: registration is deterministic; each tool carries a risk label and
  schema. High-risk network/write tools are gated. HTTP mints a canary into the
  real request, stores raw bytes, disables proxy by default, pins DNS, blocks
  private ranges, re-checks scope on manual redirects. Evidence:
  `bugfound-tools` tests `http_capture_records_request_response_and_canary`,
  `http_blocks_private_and_encoded_addresses`, `validate_finding_redacts_canary_everywhere`.
- **Policy**: in-scope match AND no out-of-scope match; relative prefixes anchored
  to program apex; path-scoped exclusions apply to that host/path only; deny
  wins over allow. Evidence: `bugfound-policy` tests `scope_denies_out_of_scope_and_allows_in_scope`,
  `path_scoped_exclusion_blocks_only_the_excluded_path`, `ask_mode_safe_allows_risky_asks`.

### 2.4 Runtime details confirmed by the deep audit

- `Runner::run_loop` is the real production step loop at
  `bugfound-core/src/lib.rs:2029-2491`: budget seed → stall guard → inbox drain →
  stop checks → lease/record step → history reload + `CompactionV2` → token
  preflight → LLM call → usage/cost → tool batch → terminal text.
- `open_conversation` (`:1387-1390`) and `step.rs` helpers are **test-only**;
  `step.rs:1-2` explicitly says the Runner keeps its own inline implementation.
  `steer`/`queue_message` have only test callers; `ExecutionCoordinator` and
  `EventBus` are process-local.
- `settle_on_boot` (`:49-82`) marks interrupted, settles unanswered calls and
  **never auto-resumes**; resume attempts are capped at 10 and the reset helper
  is only test-called.
- `PolicyEngine::evaluate` (`bugfound-policy/src/lib.rs:473-571`) gates denied/
  allowed tools → destructive deny → target lists → scope → mode. Core adds
  goal-lock, injection, target-change reapproval, auto-approve rules, duplicate
  cooldown and budget gates (`core/lib.rs:933-1036`).
- Production tool registry: `try_default_registry_with_options`
  (`tools/lib.rs:4389-4509`); risk labels are frozen from operator config via
  `register_with_host_risk`, but `build_tools` re-registers with `register()`
  (`engagement/lib.rs:4558-4560`), re-copying tool-supplied risk.
- **Evidence caveat**: captured response bytes are redacted/truncated before
  hashing (`tools/lib.rs:1735,1762-1763`), while `finding.evidence_hash` is
  computed from model-supplied text (`store/lib.rs:1309,1357-1367`); the
  authoritative digest lives in `evidence.sha256`. The report currently prints
  the former.
- `schema_validation` exists (`tools/lib.rs:3986-4009`) but was **Off** in both
  CLI and desktop at audit time (P1 changed the default to `Warn`; `Enforce`
  stays opt-in). Redaction is implemented twice (`tools/lib.rs:9182`,
  `store/lib.rs:3237`) — drift risk, still open (see §9).
  **REFUTED (2026-11-27):** provider token usage is *not* double-counted.
  `record_token_usage` stores one row per call with per-request deltas and
  `token_usage()` SUMs those deltas correctly (`core/lib.rs`); the runner adds
  the current prompt estimate, not a second cumulative total. The real cost-gate
  gap was different: `0` means unlimited and no config surface exposed
  `max_cost_usd`, so the gate was practically unreachable — it is now wired via
  `AgentConfig.max_cost_usd` with `cost_within_budget` (P5). `busy_timeout` was
  absent **at audit time (pre-V3)**; P1 added `PRAGMA busy_timeout=5000`.

## 3. What is genuinely working vs claimed

### 3.1 Working, production-connected

- Durable sessions/messages/approvals/budgets/events with guarded transitions
  and lease-based recovery (`bugfound-store`, `bugfound-core`).
- Policy + scope enforcement and deterministic approval flow; risk-labelled
  tools with workspace confinement and blocked private ranges.
- Canary-in-request + raw byte capture + SHA-256 digest; findings verifier rejects
  self-graded/model-supplied evidence (`self_graded_finding_is_rejected`,
  `finding_without_tool_capture_is_never_validated`).
- Authorization snapshot/ack machinery with hash scoping and TTL
  (`safe_harbor_receipt_is_idempotent_hash_scoped_and_expires`).
- Canonical Markdown report with Executive Summary/Scope/Methodology/Findings/
  Coverage/Timeline/Appendices (`canonical_report_contains_all_sections_and_f001`).
- ROE classification with abort-on-unparsed strict default and hash-scoped acks
  (`strict_mode_aborts_unparsed_line_and_records_pending_open_rule`).

### 3.2 Partial / reachable but incomplete

- **Adaptive planning is absent.** `wstg_playbooks()` is a static 9-item queue
  (`:3414-3453`), executed in enumeration order (`:1466-1472`), with a static
  role map (`roles.rs:42-48`). `max_rounds` is a config cap, not an evidence
  decision. Round ≥2 blindly returns all tasks (`:2132-2137`) — the docs'
  claim that only `needs-review/failed` are revisited (`docs/engagement.md:194-196`)
  is contradicted by code and by the test that asserts the current behavior
  (`engagement_integration.rs:740-756`).
- Discovery feedback is **prompt-only**: `feedback_hypotheses` (`:2207-2267`)
  creates at most 8 `asset:<target>` hypotheses, but the only consumer is
  `feedback_prompt` (`:2292-2312`) injected as untrusted goal text. The created
  count is ignored at the call site (`:1821`). There is no plan mutation.
- `prioritize_targets` (`engagement/domain.rs:92-128`) is used only by the CLI
  `plan` command and its unit test — never by orchestration.
- **Pre-V3 snapshot:** verification covered canary echo and differential only;
  `state_delta`, `timing`, `oob_hit`, `browser_deferred` were hard
  `open_proof_gap` (`:3839-3944`) despite the collaborator binary existing.
  P4 added `Verifier::decide`, `HttpOobOracle` against the loopback collaborator
  admin API and verifier-owned finding provenance; the other three oracle
  classes remain inconclusive by design (see §9).
- **Pre-V3 snapshot:** `bugfound-app`/Tauri was Phase 0 scaffolding: one
  `app_ready` command; the frontend had disabled "New session"/"Settings" and
  a placeholder composer. The console now exposes 16 IPC commands (chat/steer/
  stop/approvals/engagement plus read projections) with an ordered event
  Channel; live-provider smoke is still open (see §9).
- `eval/` cannot measure agent quality; reproducibility is `not_measured`, and
  the e2e script uses a stale binary name and env var. The stale names were
  fixed in P6; reproducibility is computable from ≥2 replay runs (see §9).

### 3.3 Design/documentation only, or absent

- `docs/HARDENING_PLAN.md:148-162` names `adaptive_reorder` and
  `durable_duplicate_guard` acceptance tests; **neither symbol exists in
  `crates/`**.
- "Autonomous adaptive planner" and "hypothesis-driven playbooks"
  (`docs/engagement.md:16-22`) are not backed by code.
- `authorize --version` writes a `brief_version` ack (`cli/main.rs:1369`) that
  the gate never reads (`ack_subject_kinds :1081-1086`) — dead feature.
- **Pre-V3 snapshot:** `roe_hash` was always empty in `AuthorizationSnapshot`
  (`:1169`) and `roe_json` stored reporting rules, not a typed `RoePolicy`
  (`:1421`). P1 bound `roe_hash` to the typed policy; `brief_version` acks remain
  audit-only (still open; see §9).
- **Pre-V3 snapshot:** CLI `--platform` / `--brief-only` paths dropped the
  operator ROE mode (`cli/main.rs:1476-1514`), unlike generic/local paths. P1
  routed both through ROE-aware variants (see §9).
- No submission path (confirmed: `platform.rs` is read-only and the goal text
  explicitly forbids it `:1783`) — this is a deliberate, correct boundary.

## 4. Data model (what persists)

- **Kernel/store**: `sessions`, `messages`, `approvals`, `events`,
  `session_budgets`, `token_usage`, `finding_captures`, `tool_captures`,
  `tool_calls`, `coverage`, `hypotheses`, `findings`, `memory_items`, flags.
- **Engagement overlay**: `engagements`, `brief_snapshots`,
  `brief_rule_provenance`, `authorization_snapshots`, `authorization_acks`,
  `authorization_open_rules`, `safe_harbor_receipts`, `tasks`, `clues`,
  `evidence`, `reports`, `trace_events`, `engagement_controls`,
  `authorization_revalidation`. Schema: `bugfound-store/src/lib.rs:335-560`.
- **Gap**: there is no single *investigation state* object owned by the agent —
  state is spread across `tasks`, `hypotheses`, `coverage`, `assets` and prompt
  text, with no priority/value/confidence fields that drive ordering.

## 5. Baseline classification

| Capability | Verdict |
| --- | --- |
| Durable session + resume + approvals + budgets | **Working** |
| Deterministic scope / ROE / policy enforcement | **Working** (strict fail-closed) |
| Evidence capture, hashing, redaction, verifier for 2 oracle classes | **Working, narrow** |
| Canonical local report, no submission | **Working** |
| Static WSTG engagement execution | **Working** |
| Agent-chosen next step, plan mutation, replanning | **Absent** |
| Hypothesis scoring / information-value prioritization | **Absent** |
| Persistent investigation state owned by agent | **Absent** |
| Multi-oracle verification / OOB consumer in verifier | **Partial** (OOB consumer wired in P4; other oracles inconclusive) |
| Adaptive evaluation metrics | **Scaffolding only** (≥2-run reproducibility now computable) |
| Full Tauri operator console | **Stub at audit time → 16 IPC commands in P6** (no live-provider smoke) |

## 6. Top architectural risks / bottlenecks for V3

1. Fixed playbook queue + static role map make the system workflow-driven; no
   seam exists for an agent decision that mutates the plan.
2. Round ≥2 replays every task; coverage/hypothesis deltas do not drive what to
   revisit, so token spend grows without information gain.
3. Hypothesis objects exist but carry no prioritization/value/confidence that
   the orchestrator reads; `prioritize_targets` is orphaned.
4. Discovery results reach the agent only as prompt text, not as state transitions.
5. At audit time the verifier covered 2 of 5 declared oracle classes and the
   OOB collaborator was not wired; P4 wired OOB with authenticated admin API
   access and structured interaction records keyed by finding id.
   `state_delta`/`timing`/`browser_deferred` remain inconclusive by design (§9).
6. Authorization model holes at audit time: empty `roe_hash`, untyped
   `roe_json`, ignored `brief_version` acks, CLI paths that bypassed the operator
   ROE mode. P1 fixed the hash, typed policy and CLI paths; `brief_version` acks
   remain audit-only (see §9).
7. State is split across kernel and engagement tables with no unified
   investigation snapshot for planning/compaction/resume.
8. Stop conditions are coarse (budget/stall/abort); no "goal satisfied" distinct
   from "exhausted", and abort still runs verification+report.
9. At audit time the Tauri surface had no commands for sessions/chat/approvals/
   findings; P6 added 16 IPC commands and a Channel-based console. Stop and
   steer are now handled synchronously; end-to-end live-provider smoke remains
   open (see §9).
10. Evaluation cannot distinguish agent-quality improvements from report-format
    compliance; no live-lab, adaptive-reorder, or multi-run consistency test.

## 7. Post-audit implementation note (V3 Phase P0)

After design approval, Phase P0 added the state/audit substrate without changing
agent behavior: `investigation_state` + `investigation_events` tables (schema
version 3, hash chain, optimistic revision guard) in `bugfound-store`, and the
domain shape `InvestigationState`/`Plan`/`Reflection` plus `load/save/audit`
helpers in `bugfound-engagement/src/investigation.rs`. Tests: 2 store tests
(backfill + revision conflict, chain tamper detection) and 1 domain round-trip
test, all green. This is infrastructure only — no orchestrator path uses it yet.

## 8. Unknowns / limits of this audit

- No live LLM or live platform engagement was executed; conclusions about LLM
  behavior come from unit tests and code paths only.
- PDF-only standards (NIST SP 800-115/218) were not readable; no claim from
  their full text is made here.
- Line numbers for `bugfound-core` runtime symbols are cited by symbol name and
  test, not always by exact line, because the working tree is mid-rename and
  line positions are unstable; the symbols and test names are stable evidence.

## 9. Corrections applied after this audit (2026-11-27/28)

This is a 2026-11-26 forensic snapshot. The claims below were refuted or
superseded by `docs/AUDIT_2026-11-27.md` §4, `docs/REPAIR_PLAN_2026-11-28.md`
and the repairs now present in `crates/`. Inline markers above point here; the
audit register remains the record of what was originally found.

- **Token double-count — REFUTED.** There is no second summation of cumulative
  provider usage. `record_token_usage` writes one row per call with per-request
  deltas and `token_usage()` sums those deltas correctly; the runner adds the
  current prompt estimate only. Do not "fix" a double count that does not exist.
- **Cost gate — real gap, now wired.** `0 = unlimited` is intentional; the
  actual defect was that no config surface exposed `max_cost_usd`, making the
  gate unreachable. `AgentConfig.max_cost_usd` + `cost_within_budget` now enforce
  a ceiling before the next billable call.
- **`busy_timeout` — historical (pre-V3).** Absent at audit time; P1 added
  `PRAGMA busy_timeout=5000`.
- **Tauri / operator console — historical.** The "one `app_ready` command, no
  operator console" rows describe Phase 0. P6 added 16 IPC commands (read
  projections plus `runtime_chat`, `runtime_chat_send`, `runtime_steer`,
  `runtime_stop`, `runtime_decide`, `pending_approvals`, `engagement_start`)
  with an ordered event Channel; stop/steer are handled synchronously in
  `RuntimeHandle`. No end-to-end smoke against a live provider has been run.
- **ROE — historical holes.** `roe_hash` is now bound to a typed `RoePolicy`
  and `--platform` / `--brief-only` use ROE-aware variants. `brief_version`
  acks remain audit-only.
- **Verifier / OOB — historical.** P4 introduced `Verifier::decide`,
  verifier-owned finding provenance, authoritative report hashes, and
  `HttpOobOracle` reading the loopback collaborator admin API with bearer auth
  and structured JSON interaction records keyed by the finding id (no separately
  minted per-finding token in code). `state_delta`, `timing` and
  `browser_deferred` remain inconclusive by design until paired controls exist.
- **Schema.** The store is now at schema v4 (atomic v4 migration); P0's v3
  `investigation_state`/`investigation_events` described in §7 is superseded.
- **Still open — do not claim fixed:** A18 goal-lock scope (no reproducer yet),
  D17 full retention of append-only tables, OS-level sandbox, parallel
  sessions, `brief_version` acks, redaction consolidation, live-provider GUI
  smoke, and any effectiveness claim for public targets.
