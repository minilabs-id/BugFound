# AgentBug (hardened prototype)

AgentBug is a universal, LLM-agnostic agent core written in Rust, inspired by the
OpenCode execution model. It is aimed at assisted bug-bounty work: scoped tool
execution, durable sessions, evidence capture, and redacted reports.

**Brand asset:** `assets/agentbug-logo.svg` (source) and `assets/agentbug-logo.png`
are used as the desktop window icon and in-app logo.

Every feature below maps to a production call site and a test in the
[feature → call site → test evidence matrix](docs/PRODUCTION_PLAN.md#2-evidence-matrix--feature--call-site--test).
A claim without a call site is not a claim. No benchmark result is asserted — see
[Evaluation](#evaluation-scaffolding-no-results).

## Features

- **Session runtime**: durable SQLite (WAL) sessions, messages, approvals, events,
  findings, assets and artifacts; guarded state transitions (`transition_state_owned`);
  lease/claim based crash recovery (`recover_stale_sessions`).
- **Policy & scope**: `ask` / `full_auto` modes, allow/ask/deny decisions,
  engagement `in_scope` / `out_of_scope` enforcement from `parse_scope_brief`,
  tool allow/deny lists, destructive-action default deny.
- **Approval flow**: risky tool calls park the session in `waiting_approval`;
  `resume --approve|--deny` executes or rejects them and continues the run.
  Approvals resolve once under a `status='pending'` guard and expire after 15 minutes.
- **Budgets**: max steps, max tool calls, max network calls and requests/minute
  are enforced from a durable `session_budgets` table (survives `resume` and
  restarts); exceeding a budget emits a `budget.exceeded` event and returns a
  rejection to the model instead of silently running the tool.
- **Tool runtime**: deterministic registry (`try_default_registry_with_options`)
  with `fs_read`, `fs_write`, `shell_exec`, `http_request`, `dns_lookup`,
  `save_finding`, `record_asset`, `save_artifact`, `echo` plus common aliases.
  Workspace confinement, 512 KB read cap, 8 KB output truncation, shell command
  **allowlist** (no chaining, secret-scrubbed env), HTTP DNS pinning with proxy
  disabled, and private/reserved address blocking for IPv4/IPv6.
- **LLM layer**: OpenAI-compatible `/v1/chat/completions` with tool calling,
  `base_url` normalization, `GET /v1/models` discovery, retries with backoff,
  and fail-fast API-key resolution (`env:VAR` supported).
- **Reporting**: `store.export_report()` and the canonical renderer produce a
  Markdown report with Executive Summary, Scope & ROE, Methodology, Findings
  (CVSS v3.1 / CWE / PoC / impact / remediation / evidence SHA-256), Coverage,
  Timeline and Appendices. JSON/header/bearer secrets are redacted at every
  report and CLI output boundary.
- **Concurrency safety**: approvals resolve once and expire, session claims use
  atomic conditional updates, and runner transitions are guarded by owner/lease.
- **Operator workflow**: proxy mode (opt-in, for Burp/ZAP) with in-code scope
  gate, lab mode for trusted local targets, auto-approve rules, per-target
  cooldown after 429/403, coverage ledger + hypothesis-driven planning,
  deduped findings with request/response evidence + CVSS/CWE + PoC validation,
  goal lock and prompt-injection flags, token/cost accounting from API usage,
  tamper-evident event hash chain, PII redaction, and snapshot resume. External
  recon adapters are auto-detected, opt-in and gated; a pipeline tool chains
  their outputs.

## Autonomous engagement flow

AgentBug can run a full engagement from a single program URL. It fetches the public
program page, extracts scope and Rules of Engagement (ROE), queues tasks, explores
in-scope assets, validates findings with a deterministic verifier, and drafts a
standard report — all **locally**.

```sh
agentbug engage --url <program-url> --cwd ./engagement
# read-only: ingest the brief and build the plan, execute no tools
agentbug engage --url <program-url> --cwd ./engagement --brief-only
```

The same flow is available in the desktop **Engagement** tab (paste the program URL,
pick `ask` or `full_auto`, and start). Engagement events, clues, tasks, evidence, and
the report are persisted in the local SQLite store; `trace_events` can be exported
as a replay JSONL by the evaluation harness.

Non-negotiable guardrails:

- **Local report only, no auto-submit.** The report is written under `--cwd` for
  operator review. AgentBug never submits findings to a platform, email, or third
  party; there is no submission path.
- **ROE fail-closed.** If the program page cannot be fetched or scope/ROE cannot be
  established, the engagement refuses to act. Any target not explicitly in scope is
  refused, and ROE rules are translated into tool-level enforcement.
- **Pause / abort at any time.** `agentbug engagement --id <id> --pause` stops at the
  next safe boundary and is resumable with `... --resume`; `... --abort` is terminal.
  Ctrl+C also aborts a running `engage`.
- **Autonomy is still policy-bounded.** Budgets, scope, allowlists, tool risk labels,
  and approvals remain active in `full_auto`; guardrails are not disabled.

See `docs/engagement.md` (user guide), `docs/report-format.md` (canonical report
template, CVSS/CWE), `docs/evaluation.md` and `eval/` (benchmarks), and
`docs/threat-model.md` (guardrails).

## Desktop (Windows)

A native Windows desktop build is available. It uses the same core, store and
tool runtime as the CLI; no browser or WebView2 is required.

```bat
start-desktop.bat
```

The window reads and writes `agentbug.toml` in its working directory. Tabs:
**Engagement** (program URL, trace events, tasks, clues, findings, pause/resume/abort,
report export), Sessions (messages/events/findings/assets/artifacts/coverage/report),
New Run, Approvals (approve/deny with TTL shown), Config (all settings + scope), Tools
(adapter availability) and Logs. Runs and approvals execute on a background
worker thread, so the UI stays responsive.

The CLI remains available for scripting and automation:

```sh
agentbug init --force                       # write agentbug.toml
agentbug engage --url <program-url> --cwd ./engagement  # autonomous engagement
agentbug engagement --id <id> --status      # inspect engagement
agentbug engagement --id <id> --pause       # pause / resume / abort controls
agentbug engagement --id <id> --resume
agentbug engagement --id <id> --abort
agentbug run --goal "enumerate in-scope hosts" --cwd ./engagement
agentbug sessions
agentbug approve --session <id>             # or: agentbug deny --session <id>
agentbug findings --session <id>
agentbug assets --session <id>
agentbug artifacts --session <id>
agentbug report --session <id> --output report.md
agentbug logs --session <id>
agentbug status --session <id>          # state, budget, coverage, hypotheses
agentbug approvals --session <id>       # pending approvals + expiry
agentbug doctor                         # validate config/env
agentbug scope-import --file brief.txt --program "Acme"
agentbug hypothesis --session <id> --add "IDOR on /api/users"
agentbug plan --session <id>              # uncovered in-scope targets
agentbug tools                            # external adapter availability
agentbug tokens --session <id>            # token usage + cost from API usage
agentbug verify-log --session <id>        # event hash chain integrity
```

Configuration example: `config/agentbug.example.toml`. Set `scope.in_scope` for
every real engagement; network tools deny targets outside scope.

## Build & test

```sh
cd agentbug
cargo test --workspace
cargo build --release
```

The Rust toolchain is pinned to `1.90.0` in `rust-toolchain.toml`, matching CI.
Run the canonical checks from the repository root (`bun run check`) and the
focused typecheck from a package directory (`bun typecheck`) per `AGENTS.md`.

## Evaluation scaffolding (no results)

`eval/` contains a stdlib-only scorer, a Windows benchmark driver, a golden
manifest example and a local end-to-end smoke test. It is **scaffolding**: no
recall, precision, FPR or reproducibility figure is claimed here. An operator must
run a real engagement against local testbeds, keep reports and replay logs under
`eval/results/`, and record the outcome.

```powershell
pwsh eval/run_benchmark.ps1          # dry run by default
pwsh eval/run_benchmark.ps1 -Execute # isolated lab only
pwsh eval/e2e_test.ps1               # local brief -> engage --brief-only -> report
python eval/score.py --dir eval/results --manifest eval/golden.example.json --replay eval/results/<id>/replay.jsonl
```

See `eval/README.md` for inputs, metrics and safe usage.

## Operational notes

This is a hardened agent runtime, not an OS sandbox. For live engagements, run
it on a dedicated isolated host/VM (or container) with a restricted egress path,
keep `mode = "ask"`
unless the engagement explicitly authorizes autonomy, review approval prompts,
and keep credentials out of the workspace (the API key is read from the
environment). The shell allowlist is defense in depth; it is not a substitute
for OS-level isolation. Context compaction is implemented via `CompactionV2`
(the conversation is summarized as it approaches the configured model token
limit); `subagent`, `skill` and `usage` modules were removed during hardening,
and the retained `inbox`/`execution` modules are core-only with no engagement call
site. Steer and wake-coalescing are not implemented and not advertised. External
recon adapters are available but clustering is still open (see
`docs/PRODUCTION_PLAN.md`).

Licensed under the MIT License — see [`LICENSE`](LICENSE).
