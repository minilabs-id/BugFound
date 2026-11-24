# ADR-008: Verification Oracle Model and Canary Satisfiability

- Decision: 2026-11-20. `verify_candidate` confirms `canary_echo` from stored
  tool bytes and `differential` from a tool-minted paired-control capture; other
  oracle classes return `open_proof_gap`.
- Date: 2026-11-20
- Basis: deep-dive P0 investigation; research `04`, `06`, `09`, `11`, `14`, `16`

## Context

The engagement layer's verifier promotes findings from tool-captured bytes
containing a canary. An earlier fix made the verifier read **stored tool bytes**
instead of LLM-supplied fields (`core/src/lib.rs:539-548`;
`engagement/src/lib.rs:2140-2156`). At that point the canary was minted only
into `HttpCapture.canary` and never transmitted, so `response.contains(&canary)`
(`engagement/src/lib.rs:2184-2186`) could not be satisfied by a real response.
Tests hand-spliced the canary into synthetic bytes, so the byte check passed
without any real capture being able to satisfy it.

## Problem

Make the byte check both independent of model input and satisfiable by a real
tool capture, without letting the LLM forge the canary or the evidence.

## Alternatives considered

1. Inject the minted canary into the outgoing request; verify its reflection in
   stored response bytes — selected. Fits reflected-input classes, keeps bytes
   tool-generated and LLM-invisible.
2. Append a tool-generated marker to captured response bytes — rejected:
   self-attestation, destroys the property being described
   (research `06:332-341`).
3. Replace substring check with a capture hash — rejected: proves only that
   bytes were stored, accepts every capture including failed probes; hashes stay
   integrity checks only.
4. Let `validate_poc` decide — excluded: `tools/src/lib.rs:1279-1282`.

## Decision

Adopt option 1 for reflected classes, within a broader oracle model:
(a) declare oracle semantics per finding class; (b) LLM fields strictly
advisory; (c) reserve independent ground truth (local canary server/OOB
listener, state delta, timing) for non-reflected classes in a later stage;
(d) target ternary closure `confirmed | ruled_out | open_proof_gap` with
counterevidence and paired controls.

## Technical justification

- Deep dive: `tools/src/lib.rs:940-960` mints from request+nanos;
  `:885-919` request repr and `:1056-1088` outbound request had no canary;
  `:1125-1160` capture stored it without injecting; `engagement:2184-2186`
  required reflection; tests hand-spliced at `engagement:2935-2965,2978-2985,
  3080-3083` and `tools:4952-4975`.
- research `11:121-128`: "inject a canary header or parameter into the outgoing
  request inside HttpRequestTool and verify its reflection… add an integration
  test that drives a real HTTP tool against a local server."
- research `09:160,170`: oracle descriptor types
  `canary_echo | state_delta | timing | oob_hit | browser_deferred`.
- research `04:43-46`: ternary closure with named-control bar and mandatory
  counterevidence.

## Trade-offs

- Pro: preserves the byte-check path and independence from model self-grading;
  gives report/eval a defined confirm signal.
- Con: injecting a header may perturb the target or be blocked by a WAF; the
  oracle is valid only for reflection classes and must not be presented as
  universal; multi-oracle/ternary work is later.

## Consequences — current code mechanism

- `HttpRequestTool` mints the canary **before** request build
  (`tools/src/lib.rs:940-960,953-960`), injects `X-BugFound-Canary` into the real
  request and the captured request representation (`:1056-1088,885-919`), and
  scrubs the reflected token from the LLM-visible `out` (headers/body) while
  leaving it in `capture` and structured bytes (`:1125-1160`).
- The single minted token is threaded through all four `build_capture` call sites.
- `ValidatePoCTool` inherits injection by delegating to `HttpRequestTool::run`;
  it stays advisory.
- `verify_candidate` reads `store.get_capture` bytes. `canary_echo` is confirmed
  from a byte-identical canary; `differential` has a confirm path when a
  tool-minted `paired_benign` / `paired_payload` role-capture pair exists
  (`differential_candidate`), plus a rule-out path from `paired_control_verdict`.
  Every other class returns `open_proof_gap`. Model-supplied fields are advisory
  and recorded only in the detail string.
- `set_finding_verdict` never stamps `validated_at`; ruled-out and uncertain
  findings do not enter `verified_findings`.
- Tests `real_http_capture_promotes_finding` and
  `non_reflecting_capture_is_rejected` drive a real local TCP server: reflection
  promotes the finding through `verify_candidate`, while a 2xx response without
  reflection leaves it a candidate.
- Verify the workspace checks with the commands in `docs/PRODUCTION_PLAN.md` §2.

## Consequences — later stage

Per-oracle dispatch, counterevidence and paired controls beyond the
differential path, and the remaining oracle classes (`state_delta`, `timing`,
`oob_hit`, `browser_deferred`) — these currently return `open_proof_gap`.

## What would invalidate this decision

- A real local-server test still cannot promote a finding after injection —
  the oracle/capture pipeline is wrong, not just the wiring.
- Canary injection materially changes target behaviour, so reflection is not a
  valid proxy for vulnerability.
- A product decision to use LLM-judged verification as the deciding signal —
  would invert the "no LLM-supplied bytes" invariant and need a new ADR.
- Urgent need for blind/stateful/timing classes before multi-oracle exists —
  pull the later-stage work forward.
