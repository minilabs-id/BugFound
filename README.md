# AgentBug (hardened MVP)

AgentBug is a universal, LLM-agnostic agent core written in Rust, inspired by the
OpenCode execution model. It is aimed at assisted bug-bounty work: scoped tool
execution, durable sessions, evidence capture, and redacted reports.

**Brand asset:** `assets/agentbug-logo.svg` (source) and `assets/agentbug-logo.png`
are used as the desktop window icon and in-app logo.

## Features

- **Session runtime**: durable SQLite (WAL) sessions, messages, approvals, events,
  findings, assets and artifacts; guarded state transitions; lease/claim based
  crash recovery (`recover_stale_sessions`).
- **Policy & scope**: `ask` / `full_auto` modes, allow/ask/deny decisions,
  engagement `in_scope` / `out_of_scope` enforcement, tool allow/deny lists,
  destructive-action default deny.
- **Approval flow**: risky tool calls park the session in `waiting_approval`;
  `resume --approve|--deny` executes or rejects them and continues the run.
- **Budgets**: max steps, max tool calls, max network calls and requests/minute
  are enforced from a durable per-session table (survives `resume` and restarts);
  exceeding a budget emits a `budget.exceeded` event and returns a rejection to
  the model instead of silently running the tool.
- **Tool runtime**: deterministic registry with `fs_read`, `fs_write`,
  `shell_exec`, `http_request`, `dns_lookup`, `save_finding`, `record_asset`,
  `save_artifact`, `echo` plus common aliases. Workspace confinement, 512 KB
  read cap, 8 KB output truncation, shell command **allowlist** (no chaining,
  secret-scrubbed env), HTTP DNS pinning with proxy disabled, and
  private/reserved address blocking for IPv4/IPv6.
- **LLM layer**: OpenAI-compatible `/v1/chat/completions` with tool calling,
  `base_url` normalization, `GET /v1/models` discovery, retries with backoff,
  and fail-fast API-key resolution (`env:VAR` supported).
- **Reporting**: `store.export_report()` produces a Markdown report with
  findings, assets, artifacts and a timeline; JSON/header/bearer secrets are
  redacted at every report and CLI output boundary.
- **Concurrency safety**: approvals resolve once (`status='pending'` guard) and
  expire after 15 minutes, session claims use atomic conditional updates, and
  runner transitions are guarded by owner/lease.
- **Operator workflow**: proxy mode (opt-in, for Burp/ZAP) with in-code scope
  gate, lab mode for trusted local targets, auto-approve rules, per-target
  cooldown after 429/403, coverage ledger + hypothesis-driven planning,
  deduped findings with request/response evidence + CVSS/CWE + PoC validation,
  goal lock and prompt-injection flags, token/cost accounting, tamper-evident
  event hash chain, PII redaction, and snapshot resume. External recon adapters
  are auto-detected, opt-in and gated; a pipeline tool chains their outputs.

## Autonomous engagement flow

AgentBug can run a full engagement from a single program URL. It fetches the public
program page, extracts scope and Rules of Engagement (ROE), queues tasks, explores
in-scope assets, validates findings with a deterministic verifier, and drafts a
standard report — all **locally**.

```sh
agentbug engage --url <program-url> --cwd ./engagement
```

The same flow is available in the desktop **Engagement** tab (paste the program URL,
pick `ask` or `full_auto`, and start). Engagement events, clues, tasks, evidence, and
the report are persisted in the local SQLite store and can be replayed from the trace
log.

Non-negotiable guardrails:

- **Local report only, no auto-submit.** The report is written under `--cwd` for
  operator review. AgentBug never submits findings to a platform, email, or third
  party; there is no submission path.
- **ROE fail-closed.** If the program page cannot be fetched or scope/ROE cannot be
  established, the engagement refuses to act. Any target not explicitly in scope is
  refused, and scope is re-evaluated before every network action (including after
  resume).
- **Pause / abort at any time.** `agentbug engage pause --engagement <id>` stops at the
  next safe boundary and is resumable with `... resume --engagement <id>`;
  `... abort --engagement <id>` is terminal. Both stop new tool calls immediately.
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
agentbug engage pause --engagement <id>     # pause / resume / abort controls
agentbug engage resume --engagement <id>
agentbug engage abort --engagement <id>
agentbug engagement --id <id> --status      # inspect/control an engagement
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
agentbug tokens --session <id>            # estimated tokens + cost
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

## Operational notes

This is a hardened agent runtime, not an OS sandbox. For live engagements, run
it on a dedicated isolated host/VM (or container) with a restricted egress path,
keep `mode = "ask"`
unless the engagement explicitly authorizes autonomy, review approval prompts,
and keep credentials out of the workspace (the API key is read from the
environment). The shell allowlist is defense in depth; it is not a substitute
for OS-level isolation. Context compaction is implemented (older turns are
summarized once prompts exceed 32 KB). External recon adapters and clustering
are still open (see `docs/PRODUCTION_PLAN.md`).
