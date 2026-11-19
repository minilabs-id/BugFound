# MiniBug (hardened MVP)

MiniBug is a universal, LLM-agnostic agent core written in Rust, inspired by the
OpenCode execution model. It is aimed at assisted bug-bounty work: scoped tool
execution, durable sessions, evidence capture, and redacted reports.

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

## CLI

```sh
minibug init --force                       # write minibug.toml
minibug run --goal "enumerate in-scope hosts" --cwd ./engagement
minibug sessions
minibug approve --session <id>             # or: minibug deny --session <id>
minibug findings --session <id>
minibug assets --session <id>
minibug artifacts --session <id>
minibug report --session <id> --output report.md
minibug logs --session <id>
minibug status --session <id>          # state, budget, coverage, hypotheses
minibug approvals --session <id>       # pending approvals + expiry
minibug doctor                         # validate config/env
minibug scope-import --file brief.txt --program "Acme"
minibug hypothesis --session <id> --add "IDOR on /api/users"
minibug plan --session <id>              # uncovered in-scope targets
minibug tools                            # external adapter availability
minibug tokens --session <id>            # estimated tokens + cost
minibug verify-log --session <id>        # event hash chain integrity
```

Configuration example: `config/minibug.example.toml`. Set `scope.in_scope` for
every real engagement; network tools deny targets outside scope.

## Build & test

```sh
cd minibug
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
