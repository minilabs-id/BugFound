# AgentBug — Production Readiness & Evidence

**Status:** hardening execution in progress (baseline audit 2026-11-19).
**Source of truth for work items:** [`HARDENING_PLAN.md`](HARDENING_PLAN.md) (H-01…H-14).
This document records the *evidence* for claims — a single feature → call site →
test matrix — and the verification gate. It intentionally does **not** restate a
"all done / N tests passed" verdict: those numbers were true of an earlier snapshot
and are not a substitute for running the current checks.

No benchmark result is claimed anywhere in this repository. `eval/` is scaffolding;
an operator must run a real engagement and record artifacts under `eval/results/`.

---

## 1. Relationship to the hardening plan

The baseline audit (findings A1–A9, B1–B5 in `HARDENING_PLAN.md`, and F-01…F-18 in
the earlier audit) identified gaps between documented claims and production call
sites. The hardening plan is the execution queue; this document is the live map
from advertised feature to the code that actually implements it and the test that
guards it. A claim without a call site in the matrix below is not a claim.

| Workstream | Scope | Plan items | State |
| --- | --- | --- | --- |
| WS1 | `agentbug-core/**` | H-03, H-08, H-09 | Owned by core workstream; verify at integration |
| WS2 | `agentbug-engagement/**` | H-01, H-02, H-04, H-06, H-10, H-11 | Owned by engagement workstream; verify at integration |
| WS3 | `agentbug-tools/**`, `agentbug-store/**` | H-04/H-05 evidence, H-06 renderer, H-12 | Owned by tools/store workstream; verify at integration |
| WS4 | `eval/**`, `docs/**`, `README.md`, `.gitignore`, `LICENSE`, `.github/**`, `rust-toolchain.toml` | **H-07, H-13, H-14** | Delivered here: scorer + Windows drivers + golden manifest + license/toolchain pin + truthful docs. No results asserted. |

The principles applied by WS4: truth over features (a claim must have a call
site), no self-grading verifier, evidence as bytes + SHA-256, evaluation that can
fail a claim, operator-controlled autonomy, and a single canonical report renderer.

---

## 2. Evidence matrix — feature → call site → test

Call sites were verified against the source at the hardening baseline. Because the
Rust workstreams are applying H-01…H-12 concurrently, the integrator must re-run
the verification gate (§4) and update any moved symbols before calling the build
production-ready. "Test" names below are the tests that exercise the relevant
module; they are not a count of passing tests.

| # | Advertised feature | Production call site (symbol; line numbers drift) | Test / evidence |
| --- | --- | --- | --- |
| 1 | Durable sessions, crash recovery | `agentbug-store::create_session`, `claim_session`, `transition_state_owned`; `agentbug-core::recover_stale_sessions` | `crates/agentbug-core/tests/runner_integration.rs`; store claim/transition unit tests |
| 2 | Approval flow (`ask` / `full_auto`) | `agentbug-store::resolve_approval`; CLI `Commands::Resume/Approve/Deny` | store single-resolve / scope-change tests; runner integration tests |
| 3 | Durable budgets (steps / tools / network / RPM) | `agentbug-store::ensure_budget`, `budget_usage`, `session_budgets` table | `runner_integration.rs::budget_survives_resume_with_a_new_runner` |
| 4 | Scope & policy enforcement | `agentbug-policy::parse_scope_brief`; `ExternalCommandTool` / `HttpRequestTool` policy checks; `Mode::Ask` / `FullAuto` | `engagement_integration.rs::heuristic_extracts_scope_from_local_html`, `heuristic_without_scope_stays_empty_for_fail_closed` |
| 5 | Tool runtime (registry, confinement, caps) | `agentbug-tools::try_default_registry_with_options`, `FsReadTool`, `FsWriteTool`, `HttpRequestTool`, `DnsLookupTool` | tools unit tests (registry, confinement, truncation) |
| 6 | Shell hardening (allowlist + env scrub) | `agentbug-tools::ExternalCommandTool` | tools unit tests for command allowlist and secret env scrubbing |
| 7 | HTTP egress control (DNS pin, no redirects, private-range block) | `agentbug-tools::HttpRequestTool` (`dns_overrides`, `no_proxy`) | tools unit tests for reserved IP matrix |
| 8 | Redaction at every egress boundary | `agentbug-store::redact`, used by `report()` and CLI output paths | store redaction unit tests (JSON, header, multi-bearer, PII) |
| 9 | Evidence bytes + SHA-256 | `agentbug-store::add_finding_with_evidence`; `agentbug-engagement` `Sha256::digest` at report write | store evidence unit tests; `eval/score.py` evidence-hash check |
| 10 | Deterministic PoC verifier | `agentbug-tools::validate_poc` tool | `validate_poc_tool_has_expected_spec` |
| 11 | Tamper-evident event chain | `agentbug-store::verify_event_chain`; CLI `Commands::VerifyLog` | store chain-integrity unit tests |
| 12 | Canonical Markdown report | `agentbug-tools::render_canonical_report` (`ReportInput`); `agentbug-engagement::build_canonical_report` | `eval/score.py --strict` (Executive Summary, Scope & ROE, Methodology, Findings, Coverage, Timeline, Appendices) |
| 13 | Autonomous engagement (brief → plan → report, local only) | `agentbug-engagement::engage`, `engage_brief_only`, `EngagementStatus`; CLI `Commands::Engage`, `Commands::Engagement` | `engagement_integration.rs`; `eval/e2e_test.ps1` |
| 14 | ROE as executable policy (fail-closed) | `agentbug-engagement::roe_overrides`, `fetch_brief` + in-scope guard | `engagement_integration.rs::roe_rules_are_translated_into_tool_enforcement`, `cvss_matches_first_v31_reference_vectors` |
| 15 | Coverage ledger + hypotheses + planner | `agentbug-store::record_coverage`, `add_hypothesis`; `agentbug-core::prioritize_targets`; `wstg_playbooks` | `engagement_integration.rs::planner_has_supported_playbook_count`; CLI `status`, `hypothesis`, `plan` |
| 16 | Context compaction | `agentbug-core::CompactionV2::compact_messages` via `Runner::build_llm_messages` | `agentbug-core::compaction_summarizes_old_turns_and_keeps_recent_tail` |
| 17 | Token / cost accounting | `agentbug-store::token_usage`; CLI `Commands::Tokens` | store usage unit tests; `score.py` reads `usage` events from replay |
| 18 | Trace / replay events | `agentbug-store::append_trace`, `trace_events` table | `eval/run_benchmark.ps1` exports `trace_events` → `replay.jsonl`; `score.py` consumes it |
| 19 | Desktop mission control | `agentbug-desktop` `main.rs` + `worker.rs` (Engagement tab, pause/resume/abort, report export) | `cargo test --workspace` covers shared crates; manual desktop smoke |
| 20 | Evaluation harness (no results) | `eval/score.py`, `eval/run_benchmark.ps1`, `eval/e2e_test.ps1`, `eval/golden.example.json` | `python -m py_compile eval/score.py`; PowerShell syntax check; `eval/e2e_test.ps1` (wiring only) |

**Explicitly not advertised** (H-03 acceptance): `SubagentJobs`, `SkillLoader` and
`UsageTracker` were removed from `agentbug-core` during hardening. The remaining
core modules (`inbox`, `execution`, `event`, `step`, `compaction`, `error`) are
re-exported but have no production call site from `agentbug-engagement`; there is
no steer queue, wake coalescing, skill loader or subagent job in the shipping flow.
They are therefore not presented as features here or in `README.md` /
`docs/architecture.md`. If a workstream wires one, add a matrix row with the new
call site and test before advertising it.

---

## 3. Baseline audit findings — tracking, not a verdict

The earlier F-IDs are tracked to plan items; final closure is recorded by the
integrator after §4. This table replaces the old "all done" status table.

| Finding | Area | Plan item | Evidence in matrix |
| --- | --- | --- | --- |
| F-01 | Shell risk label / scope / allowlist | H-01, H-12 | #4, #6 |
| F-02 | Proxy / SSRF pinning | H-02, H-12 | #7 |
| F-03 | Durable budgets | H-01 | #3 |
| F-04 | Atomic approval + claim | H-01, H-10 | #1, #2 |
| F-05 | Redaction | H-01 | #8 |
| F-06 | IP ranges | H-12 | #7 |
| F-07 | Guarded transitions | H-03 | #1 |
| F-08 | Deferred batch | H-03 | #1, #13 |
| F-09 | Env allowlist | H-12 | #6 |
| F-10 | Path pre-validation | H-12 | #5 |
| F-11 | Malformed LLM responses | H-09 | #16 |
| F-12 | Config / panic safety | H-11 | #4 |
| F-13 | Report fields | H-06 | #12 |
| F-14 | Allowlist substring | H-02 | #4 |
| F-15 | Registry accuracy (`echo`) | H-12 | #5 |
| F-16 | Schema / index | H-10 | #1 |
| F-17 | Tool-output framing | H-02 | #4, #14 |
| F-18 | Test coverage | all | §4 |

---

## 4. Verification gate (run; do not assume)

Run from the repository root / affected package. Record the actual output; do not
copy numbers from an older snapshot.

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo build --release --workspace
python -m py_compile eval/score.py
python eval/score.py --dir eval/results --manifest eval/golden.example.json \
    --replay eval/results/<id>/replay.jsonl --strict
```

Windows-only wiring (no WSL):

```powershell
pwsh eval/run_benchmark.ps1          # dry run
pwsh eval/e2e_test.ps1               # local brief -> engage --brief-only -> report exists
```

On Windows, `tsc` is the source of truth when `bun check` disagrees; reproduce with
`bun run typecheck:tsc` from the affected package (see `AGENTS.md`).

---

## 5. Production readiness criteria

AgentBug may be called production-ready only when:

- H-01…H-14 are complete with accompanying tests (see `HARDENING_PLAN.md` §7).
- The four Rust checks in §4 are green on CI Linux + Windows; toolchain pinned to
  `1.90.0` in `rust-toolchain.toml` and CI.
- Every row in the evidence matrix resolves to a current call site and a test.
- A production report passes `eval/score.py --strict`.
- Real benchmark results (with replay + manifest) are recorded by an operator;
  this repository ships only the harness and an example manifest.

Until then the honest label is **hardened prototype**: single-node, requires OS
isolation, shell gated behind allowlist, no auto-submit, no live-program benchmark
results.
