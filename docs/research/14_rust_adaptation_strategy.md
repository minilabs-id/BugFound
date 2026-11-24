# 14 — Rust Adaptation Strategy

> **About these notes.** These are point-in-time analyses of third-party reference
> projects, kept for design input. They describe the reference projects at the
> snapshots examined and are not claims about the current BugFound code; verify
> current behavior in `crates/`.

## Principles

1. Extract ideas, do not copy source. Respect license audit (`10_license_audit.md`).
2. Keep existing working primitives (Runner, store, policy, budgets, approvals).
3. Prefer small trait seams over new crates; avoid excessive fragmentation.
4. Every new mechanism must have a test and a call site.

## Adaptation map

### Kernel purity
Move bounty-specific functions out of `bugfound-core`:
- `persist_bounty_tool_result` → bounty domain crate.
- WSTG `prioritize_targets` → bounty crate.
- bounty-specific goal/scope digest → domain-owned policy object, kernel uses generic `GoalLock` trait.
- bounty-specific system prompt injection → domain adapter.
Keep core depending only on llm/tools/policy/store abstractions.

### Step + recovery
- Keep one step = one LLM call from reloaded history.
- Add typed `LlmErrorKind` (retryable/rate_limited/blocked/fatal) mapped from provider errors.
- Add sliding-window repeat detection (return previous result) and bounded arg repair against tool schema.
- Add explicit terminal tool/signal that maps to session state instead of implicit completion.
- Add cancellation token with grace period and terminal `tool_calls` row for every started call.

### Inbox/execution
- Replace in-memory-only wake coalescing with durable `control` items; expose steer vs queued semantics.
- Add boot-time stale settlement with bounded resume counter.

### Tool runtime
- Unify the two `ToolSpec` types; add JSON Schema validation at the boundary.
- Add namespacing and capability metadata; treat model-provided risk annotations as untrusted.
- Add dynamic discovery seam inspired by MCP without adopting deprecated MCP primitives.

### Provider router
- Extend `Llm` with capability descriptors, streaming, structured output, model routing, fallback.
- Replace `Arc<Mutex<Option<TokenUsage>>>` side channel with usage returned in response.
- Budget/cost use API-reported tokens; estimator remains fallback only.

### Memory
- Three SQLite tiers: working (messages/events), episodic (trace/tool_result rows), semantic (optional embeddings + provenance).
- Retrieval is scope-gated; unverified items not promoted to confirmed knowledge.

### Verification
- P0: make canary satisfiable by real tool captures.
- Add ternary closure: `confirmed | ruled_out | open_proof_gap`.
- Add counterevidence and paired-control fields to finding/report schemas.
- Add multi-oracle support: canary echo, state delta, timing, OOB listener (local lab only).

### Multi-agent
- Role profiles with tool allowlists, model config, memory policy, output schema.
- Synchronous child-session handoff with typed result event and parent/child lineage.
- No free-form agent-to-agent chat; no unbounded parallel fan-out.

## Non-goals for this adaptation

- No new workspace crates until ADR-001 is approved.
- No PostgreSQL migration until ADR-002 is approved.
- No container/Job Object sandbox because isolated host is accepted (ADR-007).
- No auto-submission (deferred).
