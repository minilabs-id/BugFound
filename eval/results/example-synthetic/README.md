# Synthetic example result (NOT a benchmark result)

This directory is a fixture generated offline. No agent engagement, network
request, or LLM call produced it. It shows the artifact layout and the JSON
shape of `eval/score.py`. No measured effectiveness data is stored in
`eval/results/`; the example directory contains invented data used to check
arithmetic.

To produce a real result, run `eval/run_benchmark.ps1 -Execute` against a local
licensed testbed (or record an operator-run engagement yourself) and keep the
new directory under `eval/results/`. See `eval/results/README.md`.

Files:

- `report.md` — a hand-written canonical report containing one invented finding.
- `manifest.json` — invented ground truth for that finding.
- `replay.jsonl` — invented `run_start`/`action`/`tested`/`finding`/`verifier`/
  `usage`/`report` events.
- `score.json` — UTF-8 (no BOM) output of `python eval/score.py report.md
  --manifest manifest.json --replay replay.jsonl --json --strict` over the
  synthetic fixture, regenerated from the current scorer. Its
  `false_positive_rate` is measured from the negative `tested` event only;
  `false_discovery_rate_proxy` (`1 - precision`) is reported separately and is
  never used by `--max-fpr`.

`eval/score.py --dir eval/results` deliberately skips directories named
`example-*` so this fixture is not included in operator-recorded scores.
