# BugFound Autonomous Engagement — User Guide

This guide covers the autonomous engagement flow: point BugFound at a public
bug-bounty program URL, fetch the brief, derive scope and Rules of Engagement
(ROE), queue tasks, explore in-scope assets, and write a local Markdown report.

The report is written under `--cwd`. There is no submission code path in
`crates/` — no CLI flag or desktop button sends a report to a platform, email,
or third party. Scope and ROE are checked before network actions; the mechanisms
are described in §2.

Verify current behavior with the commands in `docs/PRODUCTION_PLAN.md` §2.

## 1. What an engagement does

An engagement is a local workflow driven by a program URL. It has five stages:

1. **Fetch** the program page and snapshot the raw HTML (`brief_snapshots`).
2. **Extract** scope (`in_scope` / `out_of_scope`) and ROE into the brief snapshot.
3. **Plan** a task queue (`tasks`) from the brief plus hypothesis-driven playbooks.
4. **Execute** policy-bounded tool calls, recording `clues`, `evidence`, and `findings`.
5. **Report** into a local Markdown file following `docs/report-format.md`.

Actions are appended to `trace_events` and the session event hash chain so a run
can be inspected after the fact.

## 2. Safety mechanisms in code

| Area | What the code does |
| --- | --- |
| Local report | `render_canonical_report` writes Markdown under `--cwd`. No submission adapter exists in `crates/` (see `PRODUCTION_PLAN.md` §3). |
| Pause / abort | `pause` and `abort` write a durable stop flag. The runner checks it at the next step boundary and before spawning a tool; it is not an in-tool interrupt. `abort` is terminal: `resume` refuses an aborted engagement. |
| ROE extraction | `roe_classify` returns unmapped brief lines. In `strict` mode the engagement stops until an operator records a hash-scoped acknowledgement; routing does not proceed with unmapped lines. |
| Scope | `expand_relative_scope_patterns` expands relative prefixes (for example `providers.`) against the program apex before scope intersection. Path-scoped out-of-scope rules are matched on the named path by `ScopeConfig::path_scoped_rule_matches` and `bugfound-tools::scope_entry_matches_path`. |
| Approvals | `resolve_approval` updates only rows with `status='pending'`. |
| Findings | `verify_findings` reads tool-captured bytes to assign a verdict. `validate_finding` is a local contract pre-flight with no store lookup; it does not persist a finding or set a verdict. |
| Autonomy | `full_auto` keeps budgets, scope, allowlists, tool risk labels, approvals, and egress controls active. |

## 3. Prerequisites

- An isolated host/VM or container with restricted egress (see `docs/deployment.md`).
  BugFound is a Rust agent runtime, not an OS sandbox.
- A compiled binary (`cargo build --release`) or the desktop build (`start-desktop.bat`).
- An OpenAI-compatible endpoint. The API key is read from an environment variable.

## 4. Get a program URL

The URL is the public program/brief page BugFound reads to learn scope and ROE. Common sources:

- Public bug-bounty program pages (HackerOne, Bugcrowd, Intigriti, YesWeHack, etc.).
- A customer-provided scope brief or `security.txt` (`https://example.com/.well-known/security.txt`).
- An internal engagement portal page your team is authorized to read.

Use the canonical public URL. If the page requires a login, see [Limitations](#10-limitations).
Scope can also be pre-seeded from a local brief:

```sh
bugfound scope-import --file brief.txt --program "Acme"
```

## 5. Configure the API key

`config/bugfound.example.toml` uses `env:VAR` indirection. Set the variable in the
shell that launches BugFound:

```sh
# POSIX / macOS / Linux
export OPENAI_API_KEY="sk-..."
# Windows PowerShell
$env:OPENAI_API_KEY = "sk-..."
```

And in `bugfound.toml`:

```toml
[llm]
base_url = "https://api.openai.com"   # may include or omit /v1
api_key = "env:OPENAI_API_KEY"
default_model = ""                    # empty → auto-discover via GET /v1/models
```

`bugfound doctor` checks config and environment. Keep the key out of the
engagement workspace; it is redacted from reports, CLI output, events, and tool output.

## 6. Run an engagement

### CLI

```sh
bugfound engage --url https://hackerone.com/acme --cwd ./engagement
```

A new engagement row is created in state `idle`, then transitions through `running`
to `completed`, `paused`, or `aborted`. The engagement ID is printed at start; save it
for control commands.

### Read-only platform brief adapters

```sh
# Public page (default): same plain fetch
bugfound engage --url https://example.com/program --platform generic

# Token-gated brief ingestion (read-only)
bugfound engage --url https://hackerone.com/acme --platform hackerone --api-key-env H1_API_TOKEN
bugfound engage --url https://bugcrowd.com/acme --platform bugcrowd --api-key-env BC_API_TOKEN
bugfound engage --url https://intigriti.com/program/acme --platform intigriti --api-key-env INTIGRITI_TOKEN
```

`--api-key-env` takes the **name** of an environment variable, not the token. The CLI
does not read, log, or write the token to config; the engagement reads the environment
variable at fetch time. Do not put a token in `bugfound.toml`, a report, or the
workspace. For a non-`generic` platform with no `--api-key-env` (or an unset/empty
variable), the engagement returns an error without retrying unauthenticated. Only
`http`/`https` URLs are accepted; redirects and private hosts are refused, and
extracted brief text is capped at 256 KiB. Scope/ROE parsing is unchanged: an adapter
only supplies text to read. The adapter has no submission method.

Platform API endpoints, response shapes, and token header conventions vary by API
version and can be program-specific. The `Authorization` header name and per-platform
schemes are constants in `bugfound-engagement/src/platform.rs`; check them against the
program you are reading. An unexpected response is an error, not permission.

### Safe-harbor receipts (offline, advisory)

Safe-harbor receipts are offline audit records bound to one program URL and one exact
brief hash. They cannot be created by an LLM or tool flag, and they have no submission
path.

```sh
# Hash arguments must be 64 hex characters; decision is set to "acknowledged"
bugfound receipt add \
  --program-url https://hackerone.com/acme \
  --brief-content-hash <sha256-hex-of-extracted-brief-text> \
  --scope-version v1 \
  --terms-hash <sha256-hex-of-terms> \
  --operator alice \
  --expires-at 2027-01-01T00:00:00Z \
  --note "out-of-band confirmation" \
  --db .bugfound/bugfound.db

bugfound receipt list --program-url https://hackerone.com/acme --db .bugfound/bugfound.db
```

Re-running the same `add` is idempotent. A receipt appears as an additive line
`Safe-harbor receipt: <id> (operator ..., expires ...)` in
`bugfound engagement --id <id> --status` and in the local report when it is
acknowledged, unexpired, and matches the engagement's latest brief hash. It does not
change `final_state`, verification, or outcome.

### Universal ROE policy mode

This config field controls how the engagement handles brief lines that cannot be
mapped to a typed `RoePolicy` field. It is operator-only: there is no CLI flag, and it
is not derived from `--platform`, `agent.mode`, `auto_approve_all`, or any LLM/tool value.

```toml
[authorization]
# Default: unmappable lines stop the engagement until an operator records a
# hash-scoped acknowledgement with `bugfound authorize`.
roe_policy_mode = "strict"

# Opt-in alternative (config-only):
# roe_policy_mode = "permissive_audited"
```

- **`strict` (default).** `roe_classify` returns unmapped lines and the engagement
  stops until an operator acknowledges each one. Acknowledgements are scoped to the
  exact brief content hash and the exact rule, are written to the audit trail, and are
  idempotent. A changed brief hash requires new acknowledgements; an acknowledgement
  for an older hash does not carry over.
- **`permissive_audited`.** For brief sources that emit arbitrary prose. Each
  unmappable line is auto-acknowledged for that exact brief hash so the run continues.
  The auto-acknowledgements are idempotent and audited (operator identity, rule, and
  brief hash), and a warning is printed while the mode is active. The outcome is set to
  `incomplete`.

Neither mode changes the other gates: `denied_finding_classes`, scope intersection,
tool/method allowlists and budgets, verification, and reporting are unchanged. Changing
the mode does not alter a running or finished engagement; start a new engagement to
apply it.

### Bounded search rounds

The playbook queue is revisited until the operator-configured round budget is used,
then the local report is written. The cap is an `[agent]` config field, not a CLI flag,
and is not derived from `auto_approve_all`, the run `mode`, tool output, or any LLM value:

```toml
[agent]
# Default: one pass. Valid range: 1..=10.
max_rounds = 1
```

Round 1 runs each unfinished playbook. Later rounds revisit only playbooks that are
`needs-review` or `failed`, plus playbooks with an open hypothesis from earlier clues;
`done` and `completed` playbooks are skipped. Each later round adds an instruction to
vary the parameter class, method (where allowed), asset, or browser snapshot. Scope,
tool/method, ROE, verification, and evidence checks apply on every round, within the
same budgets as a single pass.

Each round emits a `search.round` trace row (`round`, `max_rounds`, `retried_tasks`)
and a `search_round` action event. A playbook still `needs-review` after the final
round stays that way and is reflected in the report (`Search rounds: N of M`, under
Methodology) and in the `incomplete` outcome. Read-only platform and brief-only runs
do not run a search loop.

### Desktop

Open `start-desktop.bat` and select the **Engagement** tab. Paste the program URL,
choose a run mode (`ask` for approval-gated steps, `full_auto` for policy-bounded
autonomy), and start. The tab shows trace events, tasks, clues, findings, live state,
pause/resume/abort controls, and report export. Runs execute on a background worker
thread.

## 7. Understand events

The Engagement tab and trace log show events such as:

| Event kind | Meaning |
| --- | --- |
| `run_start` | Run boundary; carries `run_id` for reproducibility. |
| `brief.ingested` / `brief.extracted` | Program page snapshot and scope/ROE extraction result. |
| `action` | A tool call with `tool`, `target`, `ok` and redacted detail. |
| `search.round` | One bounded search round: `round`, `max_rounds`, retried playbook ids. |
| `finding` | A deduplicated finding with `id`, `type`, `cwe` and verifier verdict. |
| `verifier` | Verdict over tool-captured bytes and canary (not LLM fields). `canary_echo` and `differential` are confirmable; other oracle classes get `open_proof_gap` from `oracle_proof_gap`. |
| `usage` | API `prompt_tokens` / `completion_tokens` for the run. |
| `report.ready` | Local report written; payload includes the SHA-256 hash. |
| `engagement.error` | ROE-stop decision or run error (message redacted). |

The primary record is the `trace_events` table (`kind`, `payload_json`, `created_at`,
`run_id`) plus the session event hash chain. Check chain integrity with
`bugfound verify-log --session <id>`. The engagement also appends a redacted
`replay-<engagement-id>.jsonl` under `--cwd`; the evaluation harness joins it with
`trace_events` into `eval/results/<id>/replay.jsonl` so metrics can be recomputed from
the replay. See `docs/evaluation.md`.

## 8. Pause, resume, abort

```sh
bugfound engagement --id <id> --status
bugfound engagement --id <id> --pause
bugfound engagement --id <id> --resume
bugfound engagement --id <id> --resume --revalidate-brief
bugfound engagement --id <id> --abort
```

Pass `--db <path>` when the engagement was launched with `engage --db <path>`;
control commands must use the same database. `--revalidate-brief` requires `--resume`.

- **Pause** writes durable control state and requests a stop on runner sessions. It
  takes effect at the next step boundary, not mid-tool. State is persisted.
- **Resume** clears the stop flag and sets state back to running. By default it does
  not re-fetch the brief; scope and policy are still checked before each network
  action by the tool/runtime gates. `--revalidate-brief` re-fetches the brief at the
  next safe boundary and compares its SHA-256 hash with the versioned authorization
  snapshot. An unchanged hash clears the check (`authorization.revalidated`). A
  changed hash records `authorization.revalidation_conflict`, pauses the engagement,
  and blocks further `resume` on that engagement; start a new engagement instead. No
  report is produced under a changed brief.
- **Abort** is terminal: no further tool calls, and `resume` refuses the engagement.
  Existing findings, evidence, and any partial report remain available for inspection.
- In the desktop Engagement tab the same actions are buttons next to the state display.
  The desktop resume button uses the no-refetch behavior; brief revalidation is CLI-only.

## 9. Inspect findings and export the report

```sh
bugfound engagements
bugfound findings  --session <id>
bugfound artifacts --session <id>
bugfound assets    --session <id>
bugfound status    --session <id>       # state, budget, coverage, hypotheses
```

Findings carry severity, CVSS v3.1 vector, CWE, reproduction steps, PoC, impact,
remediation, and an evidence hash. See `docs/report-format.md` for the schema.

Export the report locally:

```sh
bugfound report --session <id> --output report.md
```

Or use **Save report to file** in the desktop Engagement tab. The file is written under
your working directory / `--cwd`. Review findings and redaction before sharing it.

## 10. Limitations

- **Public pages, not login portals.** BugFound reads unauthenticated public program
  pages. It has no CAPTCHA solver, login flow, or authenticated dashboard reader. If
  scope is behind a login, import a scope brief manually and verify authorization yourself.
- **Gated tools stay gated.** Intrusive tools (`nuclei`, `nmap`, Playwright, etc.) are
  opt-in and default-disabled. They require `allowed_tools` configuration and remain
  subject to scope, budget, and approval policy.
- **Brief data needs review.** Public pages can contain stale or misleading scope
  data. In `strict` mode a run stops when `roe_classify` returns unmapped lines, and
  `verify_findings` replays tool-captured bytes to assign a verdict. `validate_finding`
  is a local contract pre-flight with no store lookup, not an acceptance gate; operator
  review is a separate step.
- **Not an authorization grant.** A program page is a statement of intent. Confirm you
  are allowed to test each in-scope asset. A plain `resume` does not re-read the brief;
  use `bugfound engagement --id <id> --resume --revalidate-brief` to compare its content
  hash. A changed hash blocks that engagement; start a new one after reviewing the new brief.
- **No OS sandbox / no clustering.** Run on an isolated host with restricted egress and
  prefer `ask` mode unless the engagement explicitly authorizes autonomy.
- **Replay fidelity.** A replay JSONL is used for evaluation and audit, but it is not
  proof that a finding is valid. It has no ground truth, so it cannot by itself
  establish recall or precision. See `docs/evaluation.md`. Scope boundaries are listed
  in `docs/REMAINING_GAPS.md`.

## 11. See also

- `docs/report-format.md` — report template, CVSS bands, CWE/OWASP mapping.
- `docs/threat-model.md` — guardrails for ROE, prompt injection, and credentials.
- `docs/evaluation.md` / `eval/` — benchmark harness and scoring scripts.

## External recon adapters

`browser` and `content_discovery` are CLI adapters gated by config. They become
available when the operator maps a command:

```toml
[external_tools]
enabled = true
auto_detect = false

[external_tools.commands]
playwright = "node /path/to/bugfound/eval/fixtures/browser/playwright-wrapper.js {action} {url} {selector}"
ffuf = "/usr/local/bin/ffuf"
katana = "/usr/local/bin/katana"
```

The Playwright adapter is tracked under `eval/fixtures/browser/`. Install it and its
Chromium binary:

```sh
npm install eval/fixtures/browser
npx --prefix eval/fixtures/browser playwright install chromium
```

`playwright-wrapper.js` accepts `navigate`, `click`, and `screenshot` and emits bounded
JSON (status, title, body excerpt). The engagement reads command mappings from config
and `BUGFOUND_EXTERNAL_TOOLS`; config entries take precedence. Adapter arguments are
scope-checked before the process spawns.

`register_command_adapters` supports `nmap`, `naabu`, `nuclei`, `playwright`, `ffuf`,
and `katana`. A mapped command is still subject to scope, method, and ROE gates. If the
binary is unavailable the tool returns a structured gated result.

### Browser backend

The preferred backend is Google's `chrome-devtools-mcp` CLI, which speaks Chrome
DevTools Protocol directly (no browser extension and no AutoGLM-style service). Install
it as a tracked dependency:

```sh
npm install eval/fixtures/chrome-mcp
```

Register the wrapper in config (the MCP backend is tried first):

```toml
[external_tools]
enabled = true
[external_tools.commands]
chrome_mcp = "node /path/to/bugfound/eval/fixtures/chrome-mcp/chrome-mcp-wrapper.js {action} {url} {selector}"
```

The wrapper supports `navigate` (returns a page snapshot), `screenshot`, and a
restricted CSS-selector `click`. Playwright remains an optional fallback. Google's
server prints a one-time data-collection disclaimer; pass `--no-usage-statistics` in
the wrapper to opt out.

## External OOB collaborator

The `collaborator` tool defaults to a loopback-only simulation. To use a real OOB
oracle, run `bugfound-collaborator` with a delegated domain and configure its loopback
admin endpoint:

```toml
[oob]
endpoint = "http://127.0.0.1:8082"
```

The engagement mints tokens via `POST /token` and fetches interactions via
`GET /interactions?token=...`. DNS interactions require UDP 53 reachable from the
target (delegate the zone or port-forward). Keep the admin listener on loopback. No
token or API key is written to config or logs.

## Local brief files (offline lab only)

For authorized local targets, `--brief-file` bypasses the public brief fetcher (which
rejects private hosts). The local text still goes through the same scope parser, ROE
classifier, and tool/runtime gates. This is for offline labs and construction evidence.
