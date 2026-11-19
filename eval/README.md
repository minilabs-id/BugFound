# AgentBug evaluation harness

Internal benchmarking **scaffolding** for the autonomous engagement flow. See
`../docs/evaluation.md` for the full plan, metrics, baseline and replay
requirements. **No benchmark result is asserted here** — an operator must run real
engagements, keep the artifacts, and record the outcome.

## Layout

```
eval/
├── README.md              # this file
├── targets.example.yml    # local testbeds + expected vuln classes (copy to targets.yml)
├── golden.example.json    # small ground-truth manifest example (not a result)
├── run_benchmark.ps1      # Windows driver — DRY RUN BY DEFAULT (no WSL)
├── run_benchmark.sh       # POSIX driver kept for convenience
├── e2e_test.ps1           # local HTML brief -> engage --brief-only -> report check
├── score.py               # stdlib-only report + metrics scorer
├── work/                  # scratch dirs (gitignored)
└── results/               # operator-run reports + replay logs (tracked, not gitignored)
```

## Quick start (Windows)

```powershell
# 1. copy and edit the target inventory for your local testbeds
Copy-Item eval/targets.example.yml eval/targets.yml

# 2. preview what would run (no network calls, no files written)
pwsh eval/run_benchmark.ps1

# 3. actually run (isolated host, local targets only)
pwsh eval/run_benchmark.ps1 -Execute

# 4. score the generated reports with ground truth + replay
python eval/score.py --dir eval/results `
    --manifest eval/golden.example.json `
    --replay eval/results/<id>/replay.jsonl --json --strict

# 5. wiring smoke test (loopback only)
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
- `replay.jsonl` — trace events exported from `trace_events`, mapped to the event
  kinds consumed by `score.py`. A run without a replay log is not a valid result.

Scratch working directories live in `eval/work/` and are gitignored. `eval/results/`
is **not** ignored so an operator can commit recorded results.

## `score.py`

Standard library only. Run it on Markdown reports with or without ground truth:

```sh
python eval/score.py --dir eval/results
python eval/score.py --dir eval/results --manifest eval/golden.example.json \
    --replay eval/results/<id>/replay.jsonl --json --strict
```

Checks and metrics:

| Output | Source | Meaning |
| --- | --- | --- |
| required sections / finding fields | report Markdown | Executive Summary, Scope & ROE (`Scope` accepted), Methodology, Findings, Coverage, Timeline, Appendices; CVSS v3.1, CWE, steps, PoC, impact, remediation, evidence hash |
| `recall` | manifest + reports/replay | `|G ∩ R| / |G|` over ground-truth keys |
| `precision` | manifest + reports/replay | true positives / reported findings |
| `false_positive_rate` | replay `tested` events, else reported findings | `FP / (FP + TN)`; `false_positive_basis` states which basis was used |
| `reproducibility` | replay grouped by `run_id` | fraction of findings present in every run + fraction of runs with the modal report hash (needs ≥2 runs) |
| `tokens_per_finding` | replay `usage` events | API prompt + completion tokens / valid findings (no `len/4` estimates) |

`--json` emits a single object with `reports`, `summary`, `metrics`, `notes`, and a
`claim` field that is always `scaffolding only — no benchmark results asserted`.
`--strict` fails on missing sections/fields and on optional `--min-recall`,
`--min-precision`, `--max-fpr` thresholds when those are supplied. Metrics whose
input is absent are reported as `null` / `n/a` and never guessed.

Replay JSONL event kinds: `run_start`, `finding`, `tested`, `usage`, `report`.
Unknown kinds are ignored with a warning.
