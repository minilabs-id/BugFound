# ADR-007: Sandbox Risk Acceptance (Dedicated Isolated Host)

- Decision: 2026-11-20. Documentation-only; no code changes.
- Date: 2026-11-20
- Basis: research `12`, `13`, `14`, `15`, `16`; master plan principle 6

## Context

BugFound separates runtime controls from OS containment (`README.md:170-184`;
`REMAINING_GAPS.md:20-21`). Runtime controls exist — policy allow/ask/deny and
scope enforcement, shell allowlist (`echo`/`whoami`), private-IP blocking, DNS
pinning, no redirects, egress redaction — and deployment docs require
container/VM, default-deny egress, non-root, `--cap-drop ALL`, `--read-only`
(`deployment.md:3-5,153-188,278`).

## Problem

Containment is an operator/deployment responsibility, not an in-product
guarantee. Decide whether to build an OS sandbox or formally accept the risk.

## Alternatives considered

1. Container/Docker capability sandbox in-product — rejected: research
   `13:23` "Reject (OS)"; research `15:26` rejects Docker SDK for core.
2. OS primitives (Job Objects/seccomp) in Rust — deferred: research `14:60`.
3. Full VM per engagement — already operator-run; not a product feature.
4. Accept the risk and document the boundary — selected.

## Decision

Accept the risk. The isolated host/VM is the **sandbox boundary**; the policy
engine is the **runtime boundary**. No code changes; strengthen operator
documentation and checklist.

## Technical justification

- research `12:37`: "Sandbox | container capability controls | isolated PC
  accepted | documented risk acceptance."
- research `16:36`: "OS sandbox (isolated PC accepted, ADR-007)" deferred.
- master plan principle 6: "Isolated PC is the sandbox boundary; policy engine
  is runtime boundary."
- research `11:314-332`: "keep the policy layer, add OS-level isolation at
  deployment."
- `config/bugfound.example.toml:30-31,59-68`: `auto_approve_all=false`, proxy off,
  `allow_network_write=false`, `allow_intrusive=false` remain active.

## Trade-offs

- Pro: no large security-engineering scope; runtime policy is deterministic and
  testable.
- Con: security depends on operator discipline; prompt injection remains a
  design-level threat; a compromised adapter or symlink TOCTOU (`F-10`) escapes
  containment; unsuitable for multi-tenant/untrusted hosts.

## Consequences — current mechanism and operator obligations

Documentation only. Operator obligations: dedicated isolated host/VM;
default-deny egress (`deployment.md:158-176`); non-root, cap-drop, read-only
container; `mode="ask"`; credentials via `env:VAR`; review approvals; no
scale-out (`REMAINING_GAPS.md:14`). Keep consistent: `README.md:170-184`,
`REMAINING_GAPS.md:14,20-22`, `deployment.md`, `threat-model.md:17-23`,
`architecture.md:107-114`, `config/bugfound.example.toml:59-68`. Verify the
workspace checks with the commands in `docs/PRODUCTION_PLAN.md` §2.

## What would invalidate this decision

- Multi-tenant hosting or shared/untrusted host.
- A capability executing arbitrary model-produced code or broadening the
  shell allowlist.
- Compliance requiring an enforced OS boundary.
- Evidence of an actual escape despite deployment guidance — reopen and
  revisit an A/B sandbox decision.
