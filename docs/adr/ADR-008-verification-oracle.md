# ADR-008: Verification Oracle Model and Canary Satisfiability

- Status: Accepted (R1). R1.1 fix implemented; multi-oracle/ternary closure
  deferred to R5.
- Date: 2026-11-20
- Basis: deep-dive P0 investigation; research `04`, `06`, `09`, `11`, `14`, `16`

## Context

The engagement layer advertises a "deterministic verifier" that only promotes
findings whose tool-captured bytes contain a canary. The B1 fix made the
verifier read **stored tool bytes** instead of LLM-supplied fields
(`core/src/lib.rs:539-548`; `engagement/src/lib.rs:2140-2156`). However the
canary was minted only into `HttpCapture.canary` and never transmitted, so
`response.contains(&canary)` (`engagement/src/lib.rs:2184-2186`) could never be
satisfied by a real response. Tests hand-spliced the canary into synthetic
bytes, so the suite was green while production promoted nothing — every report
had zero verified findings.

## Problem

Make the verifier authoritative AND satisfiable by a real tool capture, without
letting the LLM forge the canary or the evidence.

## Alternatives considered

1. **Inject the minted canary into the outgoing request; verify its reflection
   in stored response bytes — accepted (R1.1).** Fits reflected-input classes,
   keeps bytes tool-generated and LLM-invisible.
2. Append a tool-generated marker to captured response bytes — rejected:
   vacuous self-attestation, destroys the property being advertised
   (research `06:332-341`).
3. Replace substring check with a capture hash — rejected: proves only "bytes
   were stored," accepts every capture including failed probes. Hashes stay
   integrity checks only.
4. Let `validate_poc` be authoritative — forbidden: `tools/src/lib.rs:1279-1282`.

## Recommendation

Adopt option 1 for reflected classes as the R1.1 fix, within a broader oracle
model: (a) declare oracle semantics per finding class; (b) LLM fields strictly
advisory; (c) reserve independent ground truth (local canary server/OOB listener,
state delta, timing) for non-reflected classes in R5; (d) target ternary closure
`confirmed | ruled_out | open_proof_gap` with counterevidence and paired
controls.

## Technical justification

- Deep dive confirmed: `tools/src/lib.rs:940-960` mints from request+nanos;
  `:885-919` request repr and `:1056-1088` outbound request had no canary;
  `:1125-1160` capture stored it without injecting; `engagement:2184-2186`
  required reflection; tests hand-spliced at `engagement:2935-2965,2978-2985,
  3080-3083` and `tools:4952-4975`.
- research `11:121-128`: "inject a canary header or parameter into the outgoing
  request inside HttpRequestTool and verify its reflection… add an integration
  test that drives a real HTTP tool against a local server and asserts a
  finding is promoted without any hand-built ToolCapture."
- research `09:160,170`: oracle descriptor types
  `canary_echo | state_delta | timing | oob_hit | browser_deferred`.
- research `04:43-46`: ternary closure with named-control bar and mandatory
  counterevidence.

## Trade-offs

- Pro: restores the single most important advertised capability; preserves
  independence from model self-grading; unblocks report/eval claims.
- Con: injecting a header may perturb the target or be blocked by a WAF; the
  oracle is valid only for reflection classes and must not be presented as
  universal; multi-oracle/ternary work is later (R5).

## Implementation consequences

R1.1 (implemented):
- `tools/src/lib.rs:940-960,953-960` — mint canary **before** request build.
- `tools/src/lib.rs:1056-1088,885-919` — inject `X-AgentBug-Canary` into the real
  request and its authoritative representation; keep real bytes authoritative.
- `tools/src/lib.rs:1125-1160` — scrub the reflected token from the LLM-visible
  `out` (headers/body) while leaving it in `capture` and structured bytes.
- Thread the single minted token through all four `build_capture` call sites.
- `ValidatePoCTool` inherits injection by delegating to `HttpRequestTool::run`;
  stays advisory.
- Integration tests in `engagement`: `real_http_capture_promotes_finding`
  (real local TCP server reflects canary -> finding promoted to `validated`) and
  `non_reflecting_capture_is_rejected` (2xx without reflection stays candidate).

R5 (deferred): per-oracle dispatch, ternary closure, counterevidence and paired
controls in finding/report schema.

## What would invalidate this decision

- A real local-server test still cannot promote a finding after injection —
  the oracle/capture pipeline is wrong, not just the wiring.
- Canary injection materially changes target behaviour, so reflection is not a
  valid proxy for vulnerability.
- Product decision to accept LLM-judged verification as authoritative —
  would invert the "no LLM-supplied bytes" invariant and need a new ADR.
- Urgent need for blind/stateful/timing classes before multi-oracle exists —
  pull R5 work forward.
