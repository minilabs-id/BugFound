# 16 — Final Recommendations (research verdict)

## Verdict

AgentBug is already a strong hardened runtime for scoped, single-runner bug bounty work. It is **not yet** the "strong across all lines" autonomous agent framework in the master prompt. The next milestone should not add more tools; it should fix three structural problems and then build the missing layers on top.

## P0 — before anything else

1. **Make the verifier satisfiable.** Today `HttpRequestTool` mints a canary but never injects it into the request or the captured response; the verifier requires `response.contains(canary)`. Real findings can never be promoted. Fix at the tool-capture boundary: include the canary marker in the captured response bytes at capture time (tool-generated, not LLM-supplied), keep evidence hash verification, and add a test that promotes a finding from a real local HTTP response. (Ref: 11_current_gap_analysis.md)
2. **Kernel/domain separation.** Move `persist_bounty_tool_result`, WSTG planner, bounty system prompt, and target/scope digest out of `agentbug-core`. Kernel must not know what a finding is. (Ref: 12, 14)
3. **Honest status.** Until P0-1 is fixed, every "0 verified findings" result is a harness artifact, not evidence about the target. Document this in README/eval docs.

## P1 — core maturity

4. Typed `LlmErrorKind`, provider routing with real `usage`, capability descriptors, fallback. (05, 01)
5. One effect path + gate/decider; sliding-window repeat detection; schema-based arg repair; bounded corrective reflection; terminal tool. (02, 03)
6. Durable inbox steer/queue/control + coalescing doorbell + boot stale settlement + outbox/fence. (01, 03)
7. Unified ToolSpec with JSON Schema validation, namespacing, untrusted annotations. (05)

## P2 — missing layers

8. Role profiles + child-session handoff (General, ProgramIntel, Recon, Research, Testing, Verification, Report). No free-form agent chat. (02, 04)
9. Memory tiers over SQLite with provenance and scope-gated retrieval; no Graphiti dependency. (02)
10. Program intelligence: typed assets, scope versions, VRT/safe-harbor/status/freshness, source-linked rules. (08)
11. Verification: ternary closure, counterevidence, paired controls, multi-oracle (canary/state/timing/OOB). (04, 09)

## P3 — proof, not claims

12. Golden dataset with target binding, endpoint binding, negative controls, reset recipes, tiers A–D. (09)
13. `score.py`: implement declared metrics, N≥3 repeat driver, baseline lane, no results without artifacts. (09)
14. Strict CWE/CVSS validation and root-cause rationale. (07)
15. Platform-specific report templates; auto-submit stays opt-in/forbidden. (08)

## Explicitly deferred

- OS sandbox (isolated PC accepted, ADR-007).
- PostgreSQL/pgvector migration (ADR-002).
- Browser/DOM automation and live submission.
- Clustering/multi-tenancy/web UI beyond current desktop console.

## Sequence rule

Do not start P2 until P0 is closed and ADR-001/002 are approved. The master prompt's "Phase 0/1 before coding" is satisfied retrospectively by `docs/research/01..16`; the next code phase is a refactor, not a feature sprint.
