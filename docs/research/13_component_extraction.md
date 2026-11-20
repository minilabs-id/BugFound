# 13 — Component Extraction & Decision Matrix

Classification: **Adopt pattern** (reimplement in Rust), **Adapt** (keep idea, change shape), **Rebuild** (new AgentBug implementation), **Reject** (do not include). No source code is copied.

| Capability | Primary reference | Decision | Rationale / AgentBug target |
| --- | --- | --- | --- |
| Agent step loop | OpenCode, Rig | Adopt pattern | already present; add typed LlmErrorKind + explicit terminal tool |
| Session/inbox/admission | OpenCode | Adapt | add explicit steer/queue/control delivery and coalescing doorbell |
| Execution ownership/recovery | OpenCode, Temporal | Adapt | durable event log + outbox/fence; keep SQLite |
| Context compaction | OpenCode, PentAGI | Adapt | CompactionV2 exists; add background precompute + chain snapshots per role |
| Tool registry & schemas | OpenCode, MCP | Adapt | unify ToolSpec, add JSON Schema validation, namespacing, untrusted annotations |
| Permission engine | OpenCode, PentAGI | Adopt pattern | last-match-wins wildcards; role-scoped registries; policy gate independent of prompt |
| Multi-agent orchestration | PentAGI, LangGraph, Strix | Rebuild | role-scoped profiles + child sessions, synchronous bounded handoff |
| Plan/refine loop | PentAGI | Adapt | ordered plan rows + revision/UPSERT, deterministic-first, LLM proposes deltas |
| Reflection/recovery | PentAGI, Goose | Adapt | sliding-window repeat detection, schema repair, corrective message, mentor at budget thresholds |
| Memory tiers | PentAGI | Rebuild over SQLite | working/episodic/semantic/procedural; provenance + scope-filter on retrieval |
| Provider abstraction | MCP + LlmClient | Rebuild | capability negotiation, routing, fallback, real usage tokens |
| Program intelligence | H1/Bugcrowd docs | Rebuild | typed assets, scope versions, VRT, safe harbor, status/freshness |
| Scope enforcement | AgentBug + MCP | Keep/harden | deterministic, deny-by-default, source-linked rules |
| Verification | Strix, CAI, PortSwigger | Rebuild | ternary closure + counterevidence + multi-oracle + paired controls |
| CVSS/CWE | FIRST/CWE | Adapt | strict vector validation, root-cause CWE with rationale, confidence |
| Reporting | OWASP/H1/Bugcrowd | Adapt | platform-specific templates, evidence contract, no auto-submit |
| Sandbox | PentAGI | Reject (OS) | isolated PC is accepted risk; keep runtime policy as boundary |
| Submission | platform docs | Defer | local report only unless explicitly authorized |

## ADRs to create in Phase R1

- ADR-001 Universal Kernel vs Bounty Domain boundary.
- ADR-002 SQLite vs PostgreSQL/pgvector.
- ADR-003 Multi-agent model (profiles + child sessions, not free chat).
- ADR-004 Memory tiers and retrieval without external Graphiti.
- ADR-005 Tool schema unification and MCP-style discovery.
- ADR-006 Permission/gate/decider design.
- ADR-007 Sandbox risk acceptance (dedicated isolated host).
- ADR-008 Verification oracle model and canary satisfiability.
- ADR-009 Evaluation golden dataset and no-result claims.
