# BugFound evaluation harness

This directory holds a report scorer (`score.py`) and a trace exporter
(`export_trace.py`) for operator-run engagements, plus an invented synthetic
fixture used to check arithmetic. See `../docs/evaluation.md` for the plan,
metrics, baseline and replay requirements. No measured effectiveness data is
stored in `eval/results/`; the example directory contains invented data used to
check arithmetic.

## Offline wiring record (not a benchmark)

`python eval/repeat_lab.py --repeat 3` starts a loopback-only lab fixture
(`eval/lab/local_reflect_server.py`), probes its reflected and non-reflected
endpoints three times, and writes a hashed, timed `run-manifest.json` plus one
replay per run under the gitignored `eval/work/lab/`. Use `--record` to copy the
wiring record into `eval/results/local-reflect-lab/`; a baseline lane is
recorded as `not-run.json` unless an operator supplies `--baseline-cmd`.

These artifacts show the harness can capture and hash repeat observations. They
are wiring records, not effectiveness measurements; no recall, precision, FPR,
latency or baseline figure should be quoted from them. `export_trace.py`
also maps the verifier's `candidate` key to `finding_id` and preserves additive
provenance keys for future metrics.

## Layout

```
eval/
├── README.md              # this file
├── targets.example.yml    # local testbeds + expected vuln classes (copy to targets.yml)
├── golden.example.json    # small ground-truth manifest example (not a result)
├── run_benchmark.ps1      # Windows driver — DRY RUN BY DEFAULT (no WSL)
├── run_benchmark.sh       # POSIX driver kept for convenience
├── e2e_test.ps1           # local HTML brief -> engage --brief-only -> report + strict score check
├── score.py               # stdlib-only report + metrics scorer
├── export_trace.py        # stdlib SQLite trace_events -> replay JSONL exporter
├── work/                  # scratch dirs (gitignored)
└── results/               # operator-recorded reports + replays (tracked, not gitignored)
    └── example-synthetic/ # invented data used to check arithmetic (not scored)
```

## Quick start (Windows)

```powershell
# 1. copy and edit the target inventory for your local testbeds
Copy-Item eval/targets.example.yml eval/targets.yml

# 2. preview what would run (no network calls, no files written)
pwsh eval/run_benchmark.ps1

# 3. actually run (isolated host, local targets only)
pwsh eval/run_benchmark.ps1 -Execute

# 4. export a trace DB by hand (the driver already does this for each target)
python eval/export_trace.py eval/results/<id>/engagement.db `
    eval/results/<id>/trace.jsonl --merge <workdir>/replay-<engagement-id>.jsonl

# 5. score the generated reports with ground truth + replay
python eval/score.py --dir eval/results/<id> `
    --manifest eval/results/<id>/manifest.json `
    --replay eval/results/<id>/replay.jsonl --json --strict

# 6. wiring smoke test (loopback only): report sections + score.py --strict
pwsh eval/e2e_test.ps1
```

`run_benchmark.ps1` is **safe by default**: without `-Execute` it only prints the
commands it would run. It refuses URLs that are not loopback/private unless
`-AllowRemote` is passed (isolated lab only).

## Configuration

`targets.yml` uses a small YAML subset (a `targets:` list of mappings with `id`,
`url`, `cwd`, `expected_vulns`). Keep every `url` on loopback or an isolated private
network. `expected_vulns` is a comma-separated list written to each target's
`manifest.json` as ground truth; it is never shown to the agent.

## Output

For each target, `-Execute` writes under `eval/results/<id>/`:

- `report.md` — a copy of the engagement report.
- `run.log` — stdout/stderr of the run.
- `manifest.json` — expected vulnerabilities for that target.
- `engagement.db` — isolated SQLite store for the run.
- `engagement-replay.jsonl` — verbatim copy of `workspace/replay-<id>.jsonl`.
- `trace.jsonl` — raw `trace_events` export (audit copy).
- `replay.jsonl` — the engagement replay joined with the trace export; this is
  the file fed to `score.py --replay`. Trace events win for kinds both sources
  carry, so findings and tokens are not double-counted. A run without a replay
  log is not a valid result.
- `score.json` — the recorded `score.py` output for operator review.

Scratch working directories live in `eval/work/` and are gitignored. `eval/results/`
is **tracked** so an operator can commit recorded results; see
`eval/results/README.md`. The `example-*` fixture is skipped by `--dir` scans.

## `score.py`

Standard library only. Run it on Markdown reports with or without ground truth:

```sh
python eval/score.py --dir eval/results/<id>
python eval/score.py --dir eval/results/<id> --manifest eval/results/<id>/manifest.json \
    --replay eval/results/<id>/replay.jsonl --json --strict
```

`score.py` accepts both the engagement replay's `event` key and the trace DB's
`kind` key. Recognised kinds are `run_start`, `action`, `finding`, `tested`,
`verifier`, `usage` and `report`. FPR prefers explicit `tested` hypotheses, then
deterministic `verifier` verdicts, then failed `action` events that carry a
hypothesis identifier; its basis is reported in `false_positive_basis`.

Checks and metrics:

| Output | Source | Meaning |
| --- | --- | --- |
| required sections / finding fields | report Markdown | Executive Summary, Scope & ROE (`Scope` accepted), Methodology, Findings, Coverage, Timeline, Appendices; CVSS v3.1, CWE, steps, PoC, impact, remediation, evidence hash |
| `recall` | manifest + reports/replay | `|G ∩ R| / |G|` over ground-truth keys |
| `precision` | manifest + reports/replay | true positives / reported findings |
| `false_positive_rate` | replay `tested` / `verifier` / failed `action` events, else reported findings | `FP / (FP + TN)`; `false_positive_basis` states which basis was used |
| `reproducibility` | replay grouped by `run_id` (`run_start` marks a run) | fraction of findings present in every run + fraction of runs with the modal report hash (needs ≥2 runs) |
| `tokens_per_finding` | replay `usage` events | API prompt + completion tokens / valid findings (no `len/4` estimates) |

`--json` emits a single object with `reports`, `summary`, `metrics`, `notes`, and a
`claim` field.
`--strict` fails on missing sections/fields and on optional `--min-recall`,
`--min-precision`, `--max-fpr` thresholds when those are supplied. Metrics whose
input is absent are reported as `null` / `n/a` and are not guessed.

Replay JSONL event kinds: `run_start`, `action`, `finding`, `tested`, `verifier`,
`usage`, `report`. Unknown kinds are ignored with a warning.

Deferred product scope (real browser, clustering, live submission, performance
benchmark, fuzz corpus) is listed in `docs/REMAINING_GAPS.md`.
