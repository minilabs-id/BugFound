# Operator-recorded evaluation results

Files in this directory are intended to be recorded by an operator from an
engagement against a local, licensed testbed; the harness does not generate them
in CI. `eval/score.py` is a scorer that needs a report, manifest and replay to
compute metrics. No measured effectiveness data is stored in `eval/results/`;
the example directory contains invented data used to check arithmetic.

`eval/results/` is intentionally **tracked** (see `.gitignore`, which ignores
only `eval/work/`). Keep the report, manifest, replay and score together so a
reviewer can recompute the metrics.

## Layout of one recorded result

```
eval/results/<target-id>/
├── report.md       # canonical engagement report
├── manifest.json   # ground truth (never shown to the agent)
├── engagement-replay.jsonl  # verbatim copy of workspace/replay-<id>.jsonl
├── trace.jsonl     # raw trace_events export (audit)
├── replay.jsonl    # engagement replay joined with trace_events — feed to score.py --replay
├── score.json      # recorded scorer output (report checks + metrics)
└── run.log         # stdout/stderr of the engagement
```

`eval/run_benchmark.ps1 -Execute` produces this layout. It exports SQLite
`trace_events` with `eval/export_trace.py`, joins the engagement's
`workspace/replay-<id>.jsonl`, and invokes `python eval/score.py --manifest
<manifest.json> --replay <replay.jsonl> --json`. A run without a replay log is
not a valid result.

## Recompute a score

```powershell
python eval/score.py eval/results/<target-id>/report.md `
  --manifest eval/results/<target-id>/manifest.json `
  --replay eval/results/<target-id>/replay.jsonl --json --strict
```

Metrics are computed only from inputs that exist: recall/precision/FPR need a
manifest; reproducibility needs at least two runs in the replay;
tokens-per-finding needs `usage` events with real API token counts. Missing
inputs are reported as `null` / `n/a` and are never guessed.

## Example fixture

`example-synthetic/` is a hand-written, fully offline documentation fixture
(no engagement, no network, no LLM). It shows the artifact layout and the JSON
shape of the scorer, and it is skipped by `eval/score.py --dir eval/results`
because directories named `example-*` are not scored. Its numbers are invented
and are used only to check scorer arithmetic. See its own README for details.

## What is still deferred

No baseline comparison, performance benchmark, live-platform submission,
fuzz corpus, real browser, or clustering is shipped. See
[`docs/REMAINING_GAPS.md`](../docs/REMAINING_GAPS.md).
