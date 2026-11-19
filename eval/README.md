# AgentBug evaluation harness

Internal benchmarking scaffolding for the autonomous engagement flow. See
`../docs/evaluation.md` for the full plan, metrics, baseline, and replay requirements.

## Layout

```
eval/
├── README.md              # this file
├── targets.example.yml    # local testbeds + expected vuln classes (copy to targets.yml)
├── run_benchmark.sh       # benchmark driver — DRY RUN BY DEFAULT
├── score.py               # stdlib-only Markdown report scorer
└── results/               # generated reports + replay logs (gitignored)
```

## Quick start

```sh
# 1. copy and edit the target inventory for your local testbeds
cp eval/targets.example.yml eval/targets.yml

# 2. preview what would run (no network calls, no files written)
bash eval/run_benchmark.sh

# 3. actually run (isolated host, local targets only)
bash eval/run_benchmark.sh --execute

# 4. score the generated Markdown reports
python3 eval/score.py --dir eval/results
```

`run_benchmark.sh` is **safe by default**: without `--execute` it only prints the
commands it would run. It also refuses URLs that are not loopback/private unless
`--allow-remote` is passed.

## Configuration

`targets.yml` uses a small YAML subset (a `targets:` list of mappings with `id`, `url`,
`cwd`, and `expected_vulns`). Keep every `url` on loopback or an isolated private
network. `expected_vulns` is a comma-separated list used by the scorer/human reviewer
as ground truth; it is never shown to the agent.

## Output

For each target, the driver writes:

- `eval/results/<id>/report.md` — the engagement report (canonical format).
- `eval/results/<id>/run.log` — stdout/stderr of the run.
- `eval/results/<id>/replay/` — Cochise replay log (produced by the agent; required).

After a run, `score.py` prints severity counts, CVSS/CWE presence, and any missing
required sections or finding fields. Use `--json` for machine-readable output and
`--strict` to fail on incompleteness.
