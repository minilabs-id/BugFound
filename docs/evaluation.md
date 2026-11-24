# BugFound Internal Benchmark Plan

This document describes the benchmark harness and the procedure for running it.
Benchmark targets are local testbeds. `eval/results/` currently contains one
synthetic example (`example-synthetic`); see `eval/results/README.md`. No recorded
recall, precision, FPR, or timing measurement is present in this repository.

Verify current behavior with the commands in `docs/PRODUCTION_PLAN.md` §2.

## 1. Purpose

Measure whether the engagement flow finds vulnerabilities in local testbeds, how it
compares to a plain agent given the same tasks, and what the guardrails cost in tokens
and time.

## 2. Testbeds

| Testbed | What it covers | Deployment |
| --- | --- | --- |
| **OWASP Juice Shop** | Modern web app: XSS, SQLi, IDOR, broken auth, SSRF-like flows; rich front-end | Docker, `http://127.0.0.1:3000` |
| **DVWA** | Classic web vulns with adjustable difficulty: SQLi, XSS, CSRF, file inclusion, command injection | Docker/LAMP, `http://127.0.0.1:4280` |
| **Vulhub** | Curated CVE environments (framework/server misconfigurations, RCE) | `docker-compose up` per vuln, loopback ports |
| **HTB-like VMs** | Full-machine, multi-service puzzles requiring recon and privilege escalation | Isolated internal network (`10.x/16`), no egress |
| **XBOW-style tasks** | Single-service containers with a natural-language vulnerability description and hidden ground truth; graded by a deterministic verifier | One container per task |

Each task records a **ground-truth manifest**: expected vulnerability classes, CWE,
affected endpoint/parameter, and a deterministic oracle (for example a canary file, a
marker row in a DB, or a verifier script). Ground truth is withheld from the agent.

## 3. Procedure

1. Start the target testbed in the isolated network; confirm reachability.
2. Create a task config in `eval/targets.example.yml` (URL, expected classes).
3. Run `pwsh eval/run_benchmark.ps1 -Execute` (Windows; dry-run is the default) or
   `bash eval/run_benchmark.sh --execute` (POSIX).
4. Each run executes `bugfound engage --url <url> --cwd <workdir>` and writes a report
   under `eval/results/<target>/report.md`.
5. The driver copies `workspace/replay-<id>.jsonl` into the result directory, exports
   SQLite `trace_events` with `eval/export_trace.py`, joins the two into
   `eval/results/<target>/replay.jsonl`, and records `score.json`.
6. Recompute with
   `python eval/score.py --dir eval/results/<target> --manifest eval/results/<target>/manifest.json --replay eval/results/<target>/replay.jsonl --json --strict`.
7. Check each reported finding against the ground-truth oracle and record verdicts.
   `score.py --strict` requires a replay log.

## 4. Metrics

For a task set with ground truth `G` and reported findings `R`:

| Metric | Definition |
| --- | --- |
| **Recall** | `|G ∩ R| / |G|` — fraction of known vulns found. Report overall and per class. |
| **Precision** | `|G ∩ R| / |R|` — fraction of reports that are true positives. |
| **False-positive rate (FPR)** | `FP / (FP + TN)` over tested hypotheses; also report raw FP count. A "finding" that fails the deterministic verifier is an FP. |
| **Time-to-first-valid-finding** | Wall-clock from run start to the first finding that passes the verifier; report median and p90. |
| **Reproducibility** | Fraction of findings reproduced across N≥3 identical runs from the same replay log; and fraction of runs producing an identical report hash. |
| **Branch coverage** | Fraction of distinct code paths / in-scope branches exercised (coverage ledger entries vs. known attack surface). |
| **Token / time per finding** | LLM tokens and wall-clock seconds divided by valid findings; compare to baseline. |

Also record: budget exhaustion rate, approval count, pause/abort incidents, and
ROE-stop events.

## 5. Baseline comparison

Each evaluation includes a **plain-agent lane** following the methodology of
**arXiv:2607.13085**: the same LLM and task set, but a bare agent loop without the
scope engine, planning/coverage ledger, deterministic verifier, or structured evidence
pipeline. Report all metrics for both lanes on identical tasks and budget so the
guardrail cost can be separated from raw discovery ability. No baseline run is recorded
in `eval/results/`.

## 6. Replay logs

`score.py` consumes a Cochise-style replay JSONL (`workspace/replay-<id>.jsonl`, copied
and joined by the driver) containing:

- `run_start` with `run_id` (run boundary), plus program URL, brief snapshot context,
  and ROE-stop decisions;
- `action` events for ordered tool calls with redacted arguments and results;
- `finding` and `verifier` events with stored request/response bytes, canary, and
  evidence hashes — the verifier reads tool-captured bytes rather than LLM-supplied
  fields;
- `usage` events with API token counts;
- `report` with the final report hash and lifecycle context (pause/abort).

`eval/score.py` also accepts the older `event`-keyed engagement log and maps its
`started` / `finding` / `report_ready` spellings to these kinds.

Replay logs are used to reproduce a finding, audit why a false positive was produced,
and diff BugFound against the baseline. `score.py --strict` requires one.

## 7. Acceptance thresholds (proposed)

| Metric | Target |
| --- | --- |
| Recall on Juice Shop + DVWA ground truth | ≥ 0.70 |
| Precision after deterministic verification | ≥ 0.90 |
| FPR on tested hypotheses | ≤ 0.10 |
| Reproducibility (N=3) | ≥ 0.95 |
| Deterministic verifier agreement with ground truth | 1.00 |

Thresholds are provisional; recalibrate after the first full run and record the change.

## 8. Safety

- Targets are local/private. `run_benchmark.sh` refuses non-loopback/private URLs unless
  explicitly overridden. Do not point it at a live program.
- Keep egress restricted and the host isolated. Intrusive tools stay gated.
- Secrets are redacted in reports, logs, and replay files; API keys come from the environment.

## 9. Artifacts

- `eval/targets.example.yml` — target/testbed inventory.
- `eval/run_benchmark.ps1` / `eval/run_benchmark.sh` — drivers, dry-run by default.
- `eval/export_trace.py` — stdlib SQLite `trace_events` → replay JSONL exporter.
- `eval/score.py` — stdlib-only Markdown report scorer and metrics calculator.
- `eval/e2e_test.ps1` — local wiring test: report sections + `score.py --strict`.
- `eval/results/` — operator-recorded reports, manifests, replays and scores; see
  `eval/results/README.md`. The `example-synthetic` fixture is documentation only and
  is skipped by `--dir` scans.
