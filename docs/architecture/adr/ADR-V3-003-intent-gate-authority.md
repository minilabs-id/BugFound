# ADR-V3-003 — Deterministic intent gate is the only execution authority

- Status: **Proposed** (design gate)
- Date: 2026-11-26
- Related: ADR-V3-001, S07/S10/S11/S20/S21/S37/S39, `03_...md` G9–G11

## Context
Today scope/policy enforcement is deterministic and mostly sound, but there are
holes: `roe_hash` is empty (`engagement/lib.rs:1169`), `roe_json` stores reporting
rules rather than typed policy (`:1421`), `brief_version` acks are written but
never read (`cli/main.rs:1369`, gate `:1081-1086`), and `--platform`/`--brief-only`
paths drop the operator ROE mode (`cli/main.rs:1476-1514`). As autonomy increases,
a model-written argument or a prompt-injected target must not reach a tool.

## Options
1. Trust the planner's structured output and validate only the JSON schema.
2. Add per-tool checks inside each tool implementation.
3. Introduce a central intent gate (policy enforcement point) every action must
   pass before dispatch.

## Decision
Option 3. Every planner output is untrusted. The gate runs in order:
strict schema → ROE/scope (blocking) → ordered allow/deny/ask rules with
**deny winning** → budget/rate/duplicate check → risk classification → approval
when required → execute with idempotency key and audit event. The model cannot
write scope, ROE, permissions, budgets, approvals or verification status.

## Reasons
- Guardrails research: blocking input guardrails prevent token use and side
  effects; tool guardrails run on every invocation; tripwires halt [S11].
- OpenCode rule semantics: last match wins, any deny denies, "always allow"
  never overrides a configured deny [S21].
- OWASP LLM01 / Agentic ASI02: treat planner output as untrusted, validate with
  deterministic code, use least privilege, approval, sandbox, immutable logs and
  an intent gate [S37][S39].
- Sandboxing must include both filesystem and network isolation [S20].

## Trade-offs
- One more hop per step; acceptable versus the safety property.
- Strictness may break legacy labs — changes must be opt-in/versioned, never
  silently widened.
- Approval UX must show dry-run/diff to avoid approval fatigue [S20].

## Consequences / risks
- If any tool bypasses the gate, the security boundary is void — enforce at
  the registry dispatch layer with tests.
- Approval is not exactly-once; idempotency keys and replay protection are
  mandatory [S10].
- Every denial must produce an auditable event for evaluation M7/M8.

## Status / gate
Proposed; implemented in Phase P1. Gate: adversarial suite has zero successful
scope/permission/approval bypasses.
