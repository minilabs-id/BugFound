# 17 — Ideal Bug-Bounty Agent Workflow (research synthesis, 2026-11-20)

Status: research only. This document is the reference for future construction. No code was changed for it.

Sources: `01` OpenCode, `02` PentAGI, `03` harness patterns, `04` Strix/CAI, `06` OWASP WSTG, `08` platform docs, `09` PortSwigger, `10` license audit, `docs/report-format.md`, `docs/engagement.md`, ADR-001/007/008, and live run artifacts under `eval/work/cake-loop1`.

---

## 1. What "perfect" means

An engagement is **done** only if all of these hold:

1. Authorization receipt accepted; no unresolved scope conflict or ambiguous constraint.
2. Coverage ledger reconciles: every in-scope asset has ≥1 coverage row; every uncovered requirement has a `blocked` / `not-applicable` rationale. Attempted-and-denied counts as coverage.
3. Every hypothesis is terminal (`validated | ruled_out | blocked | not-applicable`) or explicitly carried as `open_proof_gap` and accepted by the operator.
4. Each verified finding has authoritative tool bytes, the correct class-specific oracle, a paired control where applicable, a redacted repro, and calibrated severity.
5. Evidence digests re-verify; zero orphan hypotheses / findings / bundles.
6. Report matches the template, is derived from trace events, passes `score.py --strict`, and is stamped `draft — operator review required`.
7. Operator review recorded. No auto-submit.

**Zero findings is valid only with non-zero coverage plus an explanation of what was ruled out.** Otherwise the correct verdict is `incomplete — needs operator resolution`, not `completed`.

---

## 2. The nine phases

| # | Phase | Exit criterion |
|---|---|---|
| 1 | Brief ingestion & authorization | Typed scope / ROE / eligibility models; every line mapped or listed as an open question; `AuthorizationReceipt.json`; no target touched |
| 2 | Asset & scope modeling | Every in-scope pattern resolves to a probe-able asset or is flagged; zero unresolved `ScopeConflict`; `AssetInventory.json` |
| 3 | Attack-surface mapping (passive → active) | `SurfaceMap.json` with ≥1 access point per primary asset (or evidence of attempts); every access point creates a coverage row |
| 4 | Threat model & hypotheses | Every access point has ≥1 falsifiable hypothesis with a declared oracle before testing; `ThreatModel.json`, `Hypotheses.jsonl` |
| 5 | Prioritized testing | Each hypothesis ends `confirmed-candidate / refuted-with-named-control / open-proof-gap / blocked / not-applicable`; paired captures + negative controls |
| 6 | Verification with controls | Per-class oracle applied; independent falsification pass; status exactly `validated / ruled_out / open_proof_gap`; severity calibrated after |
| 7 | Evidence packaging | Immutable bundles (bytes, canary, digest, source, timestamp, scope fingerprint, paired control), redacted views, repro command, artifact index |
| 8 | Report writing | All template sections, evidence bound to bytes, coverage with Result column, `score.py --strict`, report SHA-256 |
| 9 | Operator review | Per-finding decision; final `operator-confirmed` or accepted `no-findings-with-coverage-X`; no submission by the agent |

---

## 3. The loop (one logical step)

`observe → decide → act → verify → record`, then reload from the store.

- **Exactly one LLM call per step** for the decision. Extra bounded sub-calls only for compaction, structured falsification, or narrow arg repair.
- Tool call executes behind the policy gate; raw bytes captured with tool-minted canary; cooperative-then-forced cancellation; bounded recovery.
- Immediately evaluate the local oracle and emit `progress | no-progress | refuted | confirmed-candidate | blocked | terminal`.
- Persist tool lifecycle, capture, coverage row, hypothesis transition, trace event and usage **atomically** before the next call.

Hypothesis lifecycle: `draft → planned → running → tested → {confirmed-candidate | refuted | open-proof-gap | blocked | not-applicable} → validated | ruled_out → filed | withdrawn`. Retire only with a named control; reopen on new evidence.

Stop decision: continue while new coverage tuples or hypothesis transitions occur; switch when a hypothesis is refuted/blocked or a higher-priority one becomes testable; stop a playbook when all its hypotheses are terminal; stop the engagement only when coverage reconciles and the completeness check passes. Stall = no coverage/hypothesis progress for N steps, producing an explicit reason, not a silent `completed`.

---

## 4. Verification per class

| Class | Oracle |
|---|---|
| Reflected input / XSS-like | Stored bytes + tool canary + 2xx + self-graded echo rejection |
| IDOR / BOLA / BFLA | Differential, two identities / owners, negative control |
| Mass assignment | Schema/field comparison + side-effect check |
| Business logic | State-invariant snapshot before/after + reset recipe |
| Blind SSRF / resource | Timing baseline or controlled listener |
| Anything | Paired benign-success + payload-blocked ⇒ `ruled_out` |

Authority ladder: deterministic verifier over tool bytes > independent falsification opinion (advisory) > operator acceptance. Never the model's own `validate_poc` verdict, never self-grading, never auto-submit.

`open_proof_gap` must name the missing proof and block finalization until accepted by the operator.

---

## 5. Report and evidence

A reader with only the report plus referenced artifacts must be able to reproduce and independently verify each finding.

Per finding: ID, title, severity derived from CVSS, full vector, CWE + name + root-cause rationale, OWASP crosswalk, bound asset/endpoint/parameter, status, steps, PoC derived from captured bytes, impact, remediation + re-test, evidence block (SHA-256 over `request||response||canary`, artifact path, capture source, canary, timestamp, redacted request/response), counterevidence / confidence / severity-change conditions.

Coverage table rows: `target, method, path, parameter, requirement ID, status ∈ covered|blocked|skipped|not-applicable, rationale, evidence ref`.

Platform drafts stay self-authored field checklists (HackerOne: asset, weakness, eligibility, severity cap, repro, evidence manifest, disclosure; Bugcrowd: title, target, VRT class, prior art, evidence, attestation left to operator). No copied restricted prose, no submission.

---

## 6. Diagnosis: why the live run produced 9/9 playbooks but 0 findings and coverage 0

| ID | Gap | Evidence |
|---|---|---|
| D1 | Scope self-contradiction (`app.clockify.me` in-scope vs `*.clockify.me` out-of-scope) never resolved; deny wins | `eval/work/cake-loop1/report-*.md:13-41,280-462` |
| D2 | A single ambiguous ROE prose line aborted the whole engagement (now classified, but still abort-only) | `engagement/src/lib.rs:730-744`, `cake-full-run.log` |
| D3 | Hypotheses are the same sentence as tasks and never transition; `set_hypothesis_status` only called in a test | `engagement/src/lib.rs:896-909`, `store/src/lib.rs:1985-1990,2022` |
| D4 | Fresh Runner per task; no passive→active feedback; roles defined but production uses `General` | `engagement/src/lib.rs:932-1113,1023-1030`, `roles.rs` |
| D5 | Task `done` = runner returned `Ok`, not evidence produced; stall guard calls `finish(completed)` after denied calls | `engagement/src/lib.rs:1060-1067`, `core/src/lib.rs:1861-1883` |
| D6 | Coverage recorded only on successful network calls; attempted-and-denied invisible; no requirement key | `core/src/lib.rs:2104-2106`, `store/src/lib.rs:1930-1966` |
| D7 | Ask mode + network-risk gating parks every probe in unattended runs; deferred calls reported as failures | `cli/main.rs:488-496`, `engagement/src/lib.rs:2760-2772`, `cake-loop1.log:21-23` |
| D8 | Verifier is single-oracle and only promotes; 0 candidates ⇒ nothing to verify | `engagement/src/lib.rs:2377-2489` |
| D9 | Report written and marked ready even with empty findings/coverage; fixed methodology prose not derived from events | `engagement/src/lib.rs:2542-2668,1136-1185` |
| D10 | Tool failure (`role.handoff` rejected by provider) presented as no findings; runtime nesting panic | `report-*.md:190-271`, `cake-loop1.log:53-57` |
| D11 | Scorer checks headings only, so empty-but-valid report passes | `eval/score.py:46-54,155-207` |

A correct verdict for that run would have been: `incomplete — scope conflict unresolved; coverage 0; 9 hypotheses untested due to scope deny + approval parking`.

---

## 7. Anti-patterns to avoid

1. Trusting model severity/risk labels — calibrate after verification; model value is advisory only.
2. Self-grading or LLM-as-verification-gate — deterministic byte oracle is authoritative.
3. Unbounded fan-out — hard budgets, depth limit, graceful termination, repeat detection.
4. Auto-submit — forbidden; requires a new ADR.
5. LLM as permission judge or runtime-disabled guardrails — compiled policy gates.
6. Candidate → report without closure — `open_proof_gap` must block finalization.
7. Local dedup mistaken for platform novelty — prior art is advisory.
8. Verifying after the fact only — verification must be in the loop.
9. Trusting one brief snapshot forever — version, TTL, revalidate, fail-closed pause on change.
10. Relabelling disproved findings as informational — withdraw with reason; downgrade constrained ones only.
11. Removing goal lock / untrusted framing — keep deterministic authorization boundary.

---

## 8. Build order (proposed, not started)

1. Fix the definition of `done` and coverage: requirement-keyed ledger, attempted-and-denied counts, completeness check blocks finalization. This directly removes D5/D6/D9/D11.
2. Structured hypotheses with terminal states and replanning; passive→active feedback (D3/D4).
3. Role-scoped deterministic pipeline (research → recon → testing → verification → report), with mandatory verification before confirmation (D4/D8).
4. Per-class oracles beyond canary echo; falsification fields at the save boundary; named-control bar (D8).
5. Authorization snapshot typed/versioned with operator acknowledgement path, while keeping fail-closed defaults (D2).
6. Report evidence binding: redacted request/response, canary, artifact path, scope fingerprint (§5).
7. Bounded budgets/fan-out and graceful termination (anti-pattern 3).
8. Re-run the live loop after each step; treat results as construction evidence, never as benchmark claims.

The non-negotiable substrate to keep: tool-captured bytes + canary as only proof, deterministic ROE fail-closed, local-report-only, durable budgets/leases, and ADR-001 kernel/domain separation.
