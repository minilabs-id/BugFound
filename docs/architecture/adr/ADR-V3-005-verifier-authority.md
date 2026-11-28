# ADR-V3-005 — Only the evidence verifier may set `confirmed`

- Status: **Accepted; authority layer implemented in Phase P4** (live OOB and
  fixture FP measurement still pending)
- Date: 2026-11-26
- Related: ADR-V3-002, S02/S17/S25/S33/S35/S36, `03_...md` G12–G13

## Context
V1 already rejects self-graded findings and trusts tool-captured bytes over
model-supplied evidence — this is correct and must be preserved. But only canary
echo and differential oracles can promote; `state_delta`, `timing`, `oob_hit` and
`browser_deferred` are always `open_proof_gap` (`engagement/lib.rs:3839-3944`),
and the collaborator binary is not consumed by the verifier. Model confidence
is not a proof, and a bare numeric severity can hide inconclusive evidence.

## Options
1. Let the planner label severity/status and trust it.
2. Keep two oracles and mark everything else inconclusive forever.
3. Extend the verifier with multiple oracles, confidence classes and a strict
   authority rule: only the verifier writes `confirmed`.

## Decision
Option 3. Finding lifecycle: `observed → reproducible → proven | inconclusive |
rejected`. Each verdict requires named oracle, paired control where applicable,
repro steps, evidence digests, masked artifacts, limitations, TLP label and
`cvss_version + vector + score + Report Confidence`. Model labels are advisory.
Verifier rejections are written back as structured reflections to the
investigation ledger. `open_proof_gap` must name the missing proof and blocks
finalisation unless the operator accepts it.

## Reasons
- WSTG reporting requires masked data, how-to-exploit, limitations, cleaned
  tool output and documented rating [S25].
- CVSS v4 requires both score and vector; v3.1 Report Confidence defines
  `confirmed` vs `reasonable` vs `unknown` [S35][S36].
- Reflection memory converts rejection into better next steps [S02]; "only mark
  passing after testing" [S17]; finder must supply verification artifacts [S33].

## Trade-offs
- More verifier code and paired-control fixtures.
- New oracles can raise false positives — controls are mandatory.
- Some classes (timing/OOB) need dedicated lab fixtures.

## Consequences / risks
- If model text can change a finding status, the whole evidence model collapses —
  test `model_claim_never_confirms`.
- Reproducibility must be measured across ≥2 runs or reported `not_measured`.
- TLP label must be inherited from the ROE object; evidence without TLP is
  rejected.

## Status / gate
Proposed; Phase P4. Gate: false-positive rate measured on fixtures; zero
model-driven promotions.
