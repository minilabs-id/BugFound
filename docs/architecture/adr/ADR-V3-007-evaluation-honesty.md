# ADR-V3-007 — No effectiveness claim without recorded, authorised lab runs

- Status: **Proposed** (design gate)
- Date: 2026-11-26
- Related: doc 06, `eval/score.py`, S07/S17/S39

## Context
`eval/score.py` self-declares scaffolding and reports `reproducibility:
not_measured`; the synthetic example exists to check arithmetic, not agent
quality. `eval/e2e_test.ps1` still invokes `agentbug.exe` / `AGENTBUG_API_KEY`
and effectively runs offline (no tool calls). Publishing a recall/precision
number from such artefacts would be misleading for a security tool.

## Options
1. Treat the scorer's synthetic output as a benchmark result.
2. Skip evaluation until the implementation is complete.
3. Build lab-only, fixture-based evaluation with explicit metadata and
   `not_measured` as a legitimate outcome.

## Decision
Option 3. Every published number must be tied to: fixture id + hash, config
hash, catalog versions, model id/parameters, run count, seed policy, date and
command. Reproducibility requires ≥2 runs; otherwise `not_measured`. Format
compliance (report sections) and agent quality (next-step choice, replanning,
scope compliance) are reported separately. Evaluation targets are local labs or
explicitly authorised fixtures only.

## Reasons
- Anthropic's long-running-agent guidance: only mark success after end-to-end
  testing [S17]; transparency of planning steps [S07].
- OWASP ASI02 calls for immutable logs and drift monitoring [S39].
- The existing scorer already implements fail-closed verification — extend it,
  do not replace it with a claim.

## Trade-offs
- Slower, more expensive evaluation; fast CI subset + nightly full suite.
- Some classes (timing/OOB) need dedicated lab infrastructure.
- Honest numbers may look worse than synthetic ones — acceptable.

## Consequences / risks
- Fixture truth must not be readable by the agent under test.
- Provider nondeterminism requires multiple runs and spread reporting.
- Any public-target testing without authorisation is forbidden.

## Status / gate
Proposed; Phase P6. Gate: doc 06 §9 acceptance criteria all met.
