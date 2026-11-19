# Synthetic example result (NOT a benchmark result)

This directory is a **documentation fixture generated entirely offline**. No
agent engagement, no network request, and no LLM call produced it. It exists to
show the artifact layout and the JSON shape of `eval/score.py`; the numbers in
`score.json` are an arithmetic check on invented data and must never be quoted
as a benchmark result.

To produce a real result, run `eval/run_benchmark.ps1 -Execute` against a local
licensed testbed (or record an operator-run engagement yourself) and keep the
new directory under `eval/results/`. See `eval/results/README.md`.

Files:

- `report.md` — a hand-written canonical report containing one invented finding.
- `manifest.json` — invented ground truth for that finding.
- `replay.jsonl` — invented `run_start`/`action`/`tested`/`finding`/`verifier`/
  `usage`/`report` events.
- `score.json` — output of `python eval/score.py report.md --manifest manifest.json \
  --replay replay.jsonl --json --strict` over the synthetic fixture.

`eval/score.py --dir eval/results` deliberately skips directories named
`example-*` so this fixture cannot contaminate operator-recorded scores.
