# BugFound — evidence map and verification

This document maps advertised behavior to a call site and a test. A row is
useful only while its symbol and test still exist; re-check them before relying
on this document. It records no verdict about maturity. The commands in §2 are
the way to inspect the current checkout.

## 1. Documents used as work logs

| Document | Contents |
| --- | --- |
| `HARDENING_PLAN.md` | H-01…H-14 work items from an earlier audit. |
| `B1_B14_FIX_PLAN.md` | B1–B14 work items from a later gap pass. |
| `REMAINING_GAPS.md` | Items recorded as outside the current prototype scope. |
| `roadmap/BUGFOUND_MASTER_PLAN.md` | Chronological phase log. Phase numbers are not a maturity scale. |

## 2. Verification commands

Run from the repository root and record the output of the run:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo build --release --workspace
cargo deny check
python -m py_compile eval/score.py eval/export_trace.py
python eval/score.py --dir eval/results/example-synthetic \
  --manifest eval/results/example-synthetic/manifest.json \
  --replay eval/results/example-synthetic/replay.jsonl --strict
```

Windows wiring:

```powershell
pwsh eval/run_benchmark.ps1          # dry run
pwsh eval/e2e_test.ps1               # local brief -> engage -> report sections + score.py --strict
```

CI runs the Rust checks on Linux and Windows, installs `cargo-deny`, and checks
the ADR-001 boundary. The toolchain is pinned to `1.90.0`.

## 3. Feature → call site → test

Line numbers drift; symbol names are the stable reference. Test names identify
coverage, not a count of passing tests.

| # | Behavior | Call site | Test / evidence |
| --- | --- | --- | --- |
| 1 | Durable sessions, crash recovery | `bugfound-store::create_session`, `claim_session`, `transition_state_owned`; `bugfound-core::recover_stale_sessions` | `runner_integration.rs`; store claim/transition unit tests |
| 2 | Approval flow | `bugfound-store::resolve_approval`; CLI `Resume/Approve/Deny` | store single-resolve and expiry tests; runner integration tests |
| 3 | Durable budgets | `bugfound-store::ensure_budget`, `budget_usage`, `token_usage`; `bugfound-core::budget_gate` | `budget_survives_resume_with_a_new_runner` |
| 4 | Scope and policy | `bugfound-policy::parse_scope_brief`, `ScopeConfig::check_target`; `bugfound-tools::scope_target_allowed` | `heuristic_extracts_scope_from_local_html`, `path_scoped_exclusion_blocks_only_the_excluded_path` |
| 5 | Tool registry and caps | `bugfound-tools::try_default_registry_with_options`, `FsReadTool`, `FsWriteTool`, `HttpRequestTool`, `DnsLookupTool` | tools registry, confinement and truncation tests |
| 6 | Shell restriction | `bugfound-tools::ShellExecTool` / `ExternalCommandTool` | `shell_allowlist_is_only_echo_and_whoami`, `shell_exec_scrubs_secret_environment` |
| 7 | HTTP egress | `bugfound-tools::HttpRequestTool` (`dns_overrides`, `no_proxy`, `is_blocked_ip`) | reserved-IP matrix; redirect scope tests |
| 8 | Redaction | `bugfound-store::redact` in report and CLI paths | store redaction unit tests |
| 9 | Evidence bytes and hash | `bugfound-store::attach_capture`, `get_capture`, `verify_evidence` | store evidence tests; `eval/score.py` hash check |
| 10 | Finding verifier | `bugfound-engagement::verify_findings`, `verify_candidate`, `canary_candidate`, `differential_candidate` | `real_http_capture_promotes_finding`, `non_reflecting_capture_is_rejected`, paired-control tests |
| 11 | Event hash chain | `bugfound-store::verify_event_chain`; CLI `VerifyLog` | store chain-integrity tests |
| 12 | Markdown report | `bugfound-tools::render_canonical_report`; `bugfound-engagement::build_canonical_report` | `eval/score.py --strict` section check |
| 13 | Engagement flow | `bugfound-engagement::engage`, `engage_brief_only`, `EngagementStatus` | `engagement_integration.rs`; `eval/e2e_test.ps1` |
| 14 | ROE as policy input | `bugfound-engagement::roe_classify`, `roe_overrides`, `fetch_brief` | `roe_rules_are_translated_into_tool_enforcement`, CVSS vector tests |
| 15 | Coverage and hypotheses | `bugfound-store::record_coverage`, `add_hypothesis`; `bugfound-engagement::prioritize_targets` | `planner_has_supported_playbook_count`; CLI `status`, `hypothesis`, `plan` |
| 16 | Context compaction | `bugfound-core::CompactionV2::compact_messages` | `compaction_summarizes_old_turns_and_keeps_recent_tail` |
| 17 | Token accounting | `bugfound-store::token_usage`; CLI `Tokens` | store usage tests; `score.py` reads `usage` replay events |
| 18 | Trace and replay | `bugfound-store::append_trace`, `trace_events`; `eval/export_trace.py` | `score.py` consumes `run_start`/`action`/`finding`/`usage`/`verifier` |
| 19 | Desktop interface | `bugfound-desktop::main`, `worker` | shared-crate tests; manual desktop check |
| 20 | Evaluation harness | `eval/score.py`, `eval/export_trace.py`, `eval/run_benchmark.ps1`, `eval/e2e_test.ps1` | `python -m py_compile`; PowerShell syntax check; `e2e_test.ps1` |
| 21 | Relative scope prefixes | `bugfound-engagement::expand_relative_scope_patterns`, `expand_relative_scope_pattern` | `relative_subdomain_prefixes_expand_against_the_program_apex` |
| 22 | Path-scoped exclusions | `bugfound-policy::ScopeConfig::path_scoped_rule_matches`; `bugfound-tools::scope_entry_matches_path` | `path_scoped_exclusion_blocks_only_the_excluded_path` in policy and tools |
| 23 | Oracle parity | `bugfound-tools::oracle_proof_gap` | `oracle_proof_gap_matches_verifier_capability` |
| 24 | Streaming chat | `bugfound-llm::Llm::chat_stream_full`, `LlmClient::consume_chat_sse` | `stream_full_emits_deltas_and_assembles_tools_and_usage` |
| 25 | Conversation session | `bugfound-core::Runner::open_conversation`, `chat_turn`, `run_goal_stream` | `conversation_turns_reuse_one_session_with_growing_history` |
| 26 | Live steering | `bugfound-core::Runner::steer`, `queue_message` | `steer_enqueues_an_item_for_a_conversation_session`; existing `enqueue_prompt_admits_durable_item_and_rings_doorbell` |
| 27 | Unified desktop driver | `bugfound-engagement::engage_drive`, `bugfound-desktop::worker::ChatWorker` | shared-crate tests; manual desktop check |

## 4. What the matrix does not cover

`subagent`, `skill` and `usage` modules are absent from `bugfound-core`. The
retained `inbox`, `execution` and `event` modules have runner call sites;
several helper functions in them are exercised only by unit tests. Some event
bus methods and `step.rs` are additive without a production consumer. This is
recorded in `architecture.md` and is not presented as a feature.
