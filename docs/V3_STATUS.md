# BugFound V3 — Status & Handoff (2026-11-27)

> One-page, honest status of the V3 work. Source of truth is `crates/` and
> `eval/`; design intent is in `docs/architecture/01`–`06`. This file does not
> claim V3 is complete.

## 1. What V3 is

**Agent-Driven Hybrid Bug Bounty Agent.** The agent chooses the next
investigation step; the domain engine supplies versioned technique knowledge;
tools provide capability; persistent investigation state provides continuity;
a deterministic security harness owns authorization; the evidence verifier
decides what is actually proven.

Non-negotiables — **design intent, not a claim that they were originally
enforced**: scope/ROE fail-closed, deny precedence, durable budgets and
approvals, tool-captured bytes + canary as the only proof, local report only
(no submission), ADR-001 kernel/domain separation. Enforcement gaps were closed
by the 2026-11-27 audit / 2026-11-28 repair work; items still deferred are
listed in §6.

## 2. Implementation status

| Phase | Delivered | Honest caveat |
| --- | --- | --- |
| P0 | `investigation_state` + hash-linked `investigation_events`, optimistic revisions, backfill | — |
| P1 | `roe_hash` bound to typed policy, `IntentGate` fail-closed preflight, idempotency keys, host-risk preservation, schema `Warn` default, `busy_timeout`, ROE-aware CLI paths | approval identity threading, `brief_version` ack, redaction consolidation still open |
| P2 | `Planner` seam + `NextStep`/`Plan`, `select_round_tasks`, coverage/repetition ranking, `prioritize_targets` wired | deterministic reference planner initially |
| P3 | Versioned 9-technique catalog with preconditions/safe bounds/pinned mappings, deferred `search`/`get`, catalog-aware ranking | LLM planner landed as a later increment, not in P3 itself |
| P4 | Verifier state machine, CVSS-style confidence, `OobOracle` trait + `HttpOobOracle` (loopback admin API), verifier-owned finding provenance, authoritative report hash | `state_delta`/`timing`/`browser_deferred` stay inconclusive; OOB correlation uses a harness-minted per-finding token |
| P5 | Immutable version-checked checkpoints, bounded context projection, observation digests, cost gate | M9 interrupted-run consistency unmeasured by a lab |
| P6 | 16 Tauri IPC commands: read projections + `runtime_chat`, `runtime_chat_send`, `runtime_steer`, `runtime_stop`, `runtime_decide`, `pending_approvals`, `engagement_start` with ordered event Channel; frontend composer, Engage button, approval cards with Approve/Deny, live event feed; honest evaluator, fixed stale e2e script | GUI flow compile/unit-tested, not end-to-end smoke-tested with a live provider |
| Increment | `LlmPlanner` behind `AsyncPlanner`; model proposes, harness re-ranks/filters | config flag `agent.llm_planning` default `false` |
| Increment | Offline + live fixture lab + adversarial lab | numbers are local-fixture verification only |

Full Rust checks, frontend build, and eval self-tests are green (see §4).
**Caveat:** these are offline checks on local authorised fixtures. Live-provider
GUI smoke and live OOB are not merge gates, and the M1/M3/M7/M8 numbers below
are fixture-local verification — not public-target effectiveness. Metrics
marked `not_measured` were never fabricated.

## 3. Measured evidence (local authorised fixture only)

| Metric | Value | Source |
| --- | --- | --- |
| M1 useful next step | 1.0 | 3/3 plans selected a fixture-relevant technique (`eval/agent_lab.py --live`). **Caveat:** local fixture only; planner selection, not agent-quality proof on public targets. |
| M2 replan coherence (proxy) | 1.0 | 3 `plan_generated` + 3 `state_transition` events |
| M3 hypothesis quality | 1.0 | 3/3 hidden facts got a `proven` verifier verdict. **Caveat:** fixture-local and measured before the verifier-authority repairs; re-measure after C1/C5/C6. |
| M4 coverage | 3 | requirement-keyed rows |
| M5 reproducibility | 1.0 | identical verdict sets across 3 runs |
| M7 scope compliance | 1.0 | 3 adversarial cases, zero out-of-scope tool calls. **Caveat:** fixture-local; path/wildcard scope repairs (B1/B2/E27) need re-test. |
| M8 injection resistance | 1.0 | no forged verdict / no injected scope change. **Caveat:** fixture-local; approval-guard repairs (A2/A3/A19) need re-test. |
| M11 stop quality | not_measured | no `stop_reason` events are emitted yet |
| M12 audit completeness | ok | hash-linked events |

**Not measured by design:** M6 aggregate tokens/cost, M9/M10 interrupted and
multi-run consistency beyond verdict sets. No effectiveness claim is made for
public targets.

### Production bug found by the lab and fixed

Findings are stored under the runner's session id, but `verify_findings`
looked them up by engagement id — so no finding could be promoted in a real
engagement. Fixed with `Store::list_findings_for_engagement` (session-goal
marker + legacy fallback); regression test
`findings_for_engagement_use_runner_session_marker`.

## 4. Verification commands

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo deny check
pnpm --dir frontend test
pnpm --dir frontend build
python eval/score.py --self-test
python eval/agent_eval.py --self-test
python eval/agent_lab.py --runs 3 --adaptive
python eval/agent_lab.py --runs 3 --adaptive --live
python eval/adversarial_lab.py
```

CI: `.github/workflows/ci.yml` (Rust checks, ADR-001 boundary) and
`.github/workflows/desktop-ui.yml` (frontend, Tauri shell, both labs).

## 5. Key file map

| Concern | Location |
| --- | --- |
| Kernel / runner / policy harness | `crates/bugfound-core/src/lib.rs`, `crates/bugfound-policy/src/lib.rs` |
| Investigation state, planner seam, checkpoints | `crates/bugfound-engagement/src/investigation.rs` |
| Versioned technique catalog | `crates/bugfound-engagement/src/catalog.rs` |
| LLM planner | `crates/bugfound-engagement/src/planner.rs` |
| Verifier authority | `crates/bugfound-engagement/src/verification.rs` |
| Persistence & provenance | `crates/bugfound-store/src/lib.rs` |
| Tauri shell & IPC | `crates/bugfound-app/src/lib.rs`, `crates/bugfound-desktop-core/src/{commands,dto,projection}.rs`, `frontend/` |
| Evaluation & fixtures | `eval/agent_eval.py`, `eval/agent_lab.py`, `eval/adversarial_lab.py`, `eval/fixtures/agent/` |
| Design docs | `docs/architecture/01_CURRENT_STATE_AUDIT.md` … `06_AGENT_EVALUATION_PLAN.md`, `docs/architecture/adr/ADR-V3-*` |
| Desktop UI overhaul (Tauri decision) | `docs/adr/ADR-009-tauri-react-desktop-ui.md`, `docs/roadmap/DESKTOP_UI_OVERHAUL.md` |

## 6. Open items / recommended next order

1. **Operator console verification** — run an end-to-end GUI smoke against a
   local provider. Stop/steer are fixed: `RuntimeHandle` handles them
   synchronously instead of queueing behind a blocking worker; the chat/steer/
   stop/approval/engagement IPC, streaming Channel and approval cards are in
   place. The live smoke is still not a merge gate.
2. **Adversarial depth** — more attack classes (tool poisoning, replay,
   approval escalation) before treating M7/M8 as anything but fixture-local.
3. **Live OOB depth** — the loopback collaborator admin API is wired into
   `HttpOobOracle` with bearer admin auth; `collaborator start` mints an
   `oob_proof.token` that the harness stores on the finding, and the oracle
   matches the interaction record's exact `token` field. What remains is
   paired-control coverage and broader oracle classes.
4. **Additional oracles** — `state_delta`, `timing`, `browser_deferred` with
   paired controls. Tokenless legacy OOB findings fail closed: OOB alone can
   no longer promote them.
5. **OS sandbox** — filesystem + egress isolation as an explicit lab opt-in;
   not implemented.
6. **Parallel sessions** — deliberately out of V3 scope; not implemented.
7. **A18 goal-lock scope** — fixed: `GoalLock::digest_with_context` binds a
   canonical scope JSON, locks are `v2:`-prefixed, and legacy v1 locks require
   an explicit `Runner::relock_session(id, "approve")` ruling instead of being
   silently accepted. Reproducers are in `runner_integration.rs`.
8. **D17 retention scheduling** — config-driven retention is now wired:
   `storage.retention_days` (0 = disabled, max 36500) triggers a chain-guarded
   audit/trace prune at desktop startup, and `bugfound prune --dry-run` previews
   the same operation for the CLI. A recurring background scheduler (cron/TTL
   worker) is still not implemented; pruning happens at process start or on
   explicit CLI invocation.

**Schema note:** the store has migrated to schema v5 (atomic v4 migration plus
the v5 OOB-token column and `session_oob_tokens` table). Earlier layers added
the coverage unique index, event-chain anchor, canonical timestamps, migration
ledger, capture digest, and `AuthorizationAck.restriction_json`. The D17 prune
API and config/startup wiring are layered on top; a recurring retention
scheduler and deterministic replay of live responses remain open.

## 7. Decisions worth remembering

- Model output is untrusted input to the harness everywhere (intent gate,
  planner filtering, verifier authority, report evidence hash).
- The static V1 workflow remains the default; `agent.llm_planning` is opt-in
  until fixture gates are reviewed for the deployment.
- No rewrite of the kernel: all changes were additive seams over existing
  tested code (ADR-V3-006).
