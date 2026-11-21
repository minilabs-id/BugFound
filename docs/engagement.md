# AgentBug Autonomous Engagement — User Guide

This guide covers the autonomous engagement flow: point AgentBug at a public bug-bounty
program URL and let it fetch the brief, derive scope and Rules of Engagement (ROE),
queue tasks, explore in-scope assets, validate findings, and draft a standard report.

> **Read this first.** AgentBug produces a **local report only**. It never submits a
> finding to a platform, by email, or to any third party. There is no auto-submit
> path. Scope/ROE enforcement is **fail-closed**, and the run can be **paused** or
> **aborted** at any time. See the safety rules below.

---

## 1. What an engagement does

An engagement is a durable, local workflow driven by a program URL. It has five stages:

1. **Fetch** the program page and snapshot the raw HTML (`brief_snapshots`).
2. **Extract** scope (`in_scope` / `out_of_scope`) and ROE into a brief snapshot.
3. **Plan** a task queue (`tasks`) from the brief plus hypothesis-driven playbooks.
4. **Execute** policy-bounded tool calls, recording `clues`, `evidence`, and `findings`.
5. **Report** into a local Markdown file following `docs/report-format.md`.

Every action is appended to a durable trace (`trace_events`) and the session event
hash chain, so a run can be inspected and replayed after the fact.

## 2. Non-negotiable safety rules

| Rule | What it means in practice |
| --- | --- |
| **Local report only** | The report is written inside `--cwd`. Review and submit it yourself. AgentBug has no submission adapter by design (see `PRODUCTION_PLAN.md` §7). |
| **No auto-submit** | No CLI flag or desktop button submits to HackerOne/Bugcrowd/Intigriti/etc. If a future build adds one, it must be opt-in and gated. |
| **ROE fail-closed** | If the program page cannot be fetched, parsed, or its scope/ROE cannot be established, the engagement does not act on that target. A target that is not explicitly in scope is refused. Scope is re-evaluated before every network action, including after resume. |
| **Pause / abort** | `pause` stops at the next safe boundary and keeps resumable state; `abort` is terminal. Both write a durable stop flag that a runner observes within one step (and immediately before spawning a tool), not instantaneously mid-tool. |
| **Policy still applies in `full_auto`** | Budgets, scope, allowlists, tool risk labels, approvals, and egress controls stay active. Autonomy does not disable guardrails. |

## 3. Prerequisites

- An **isolated host/VM or container** with restricted egress (see `docs/deployment.md`).
  AgentBug is a hardened agent runtime, not an OS sandbox.
- A compiled binary (`cargo build --release`) or the desktop build (`start-desktop.bat`).
- An OpenAI-compatible endpoint (API key read from the environment, never stored in
  the workspace).

## 4. Get a program URL

The URL is the public program/brief page AgentBug reads to learn scope and ROE. Common sources:

- Public bug-bounty program pages (HackerOne, Bugcrowd, Intigriti, YesWeHack, etc.).
- A customer-provided scope brief or `security.txt` (`https://example.com/.well-known/security.txt`).
- An internal engagement portal page your team is authorized to read.

Use the canonical, public URL for the program. If the page requires a login, see
[Limitations](#10-limitations). You can also pre-seed scope from a local brief with the
existing `agentbug scope-import --file brief.txt --program "Acme"` command before running
the engagement.

## 5. Configure the API key

`config/agentbug.example.toml` uses `env:VAR` indirection. Set the variable in the shell
that launches AgentBug:

```sh
# POSIX / macOS / Linux
export OPENAI_API_KEY="sk-..."
# Windows PowerShell
$env:OPENAI_API_KEY = "sk-..."
```

And in `agentbug.toml`:

```toml
[llm]
base_url = "https://api.openai.com"   # may include or omit /v1
api_key = "env:OPENAI_API_KEY"
default_model = ""                    # empty → auto-discover via GET /v1/models
```

Verify with `agentbug doctor` (checks config/env). Keep the key out of the engagement
workspace; it is redacted from reports, CLI output, events, and tool output.

## 6. Run an engagement

### CLI

```sh
agentbug engage --url https://hackerone.com/acme --cwd ./engagement
```

A new engagement row is created in state `idle`, then transitions through `running`
to `completed`, `paused`, or `aborted`. The engagement ID is printed at start; save it
for control commands.

### Read-only platform brief adapters

```sh
# Public page (default): identical to the existing plain fetch
agentbug engage --url https://example.com/program --platform generic

# Token-gated brief ingestion (READ-ONLY; never submits anything)
agentbug engage --url https://hackerone.com/acme --platform hackerone --api-key-env H1_API_TOKEN
agentbug engage --url https://bugcrowd.com/acme --platform bugcrowd --api-key-env BC_API_TOKEN
agentbug engage --url https://intigriti.com/program/acme --platform intigriti --api-key-env INTIGRITI_TOKEN
```

`--api-key-env` takes the **name** of an environment variable, never the token
itself. The CLI does not read, log, or write the token to config; the
engagement reads the environment variable only at fetch time. Do not put a
token in `agentbug.toml`, a report, or the workspace. For any non-`generic`
platform with no `--api-key-env` (or an unset/empty variable), the engagement
fails closed with an error — it never silently retries unauthenticated. Only
`http`/`https` URLs are accepted, redirects and private hosts are refused, and
extracted brief text is capped at 256 KiB. All scope/ROE parsing and fail-closed
gating is unchanged: an adapter only supplies the text to read.

**API contract caveat:** platform API endpoints, response shapes, and token
header conventions vary by API version and can be program-specific. The
`Authorization` header name and per-platform schemes are isolated constants in
`agentbug-engagement/src/platform.rs`; verify them against the program you are
reading. An unexpected response is an error, not permission. There is no
submission, publish, or write method in the adapter.

### Safe-harbor receipts (offline, advisory)

Safe-harbor receipts are typed, offline audit records bound to one program URL
and one exact brief hash. They are **advisory only**: they cannot be created by
an LLM or tool flag, cannot bypass a ROE abort, and never submit anything.

```sh
# Record (hash arguments must be 64 hex characters; decision is always "acknowledged")
agentbug receipt add \
  --program-url https://hackerone.com/acme \
  --brief-content-hash <sha256-hex-of-extracted-brief-text> \
  --scope-version v1 \
  --terms-hash <sha256-hex-of-terms> \
  --operator alice \
  --expires-at 2027-01-01T00:00:00Z \
  --note "out-of-band confirmation" \
  --db .agentbug/agentbug.db

agentbug receipt list --program-url https://hackerone.com/acme --db .agentbug/agentbug.db
```

Re-running the same `add` is idempotent. A receipt only appears as an additive
line `Safe-harbor receipt: <id> (operator ..., expires ...)` in
`agentbug engagement --id <id> --status` and in the local report when it is
acknowledged, unexpired, and matches the engagement's latest brief hash. It has
no effect on `final_state`, verification, or outcome.

### Universal ROE policy mode

The **universal ROE policy mode** controls how AgentBug handles brief lines that
cannot be mapped to a typed `RoePolicy` field. It is an **operator-only config
setting**: there is no CLI flag for it, and it is never derived from `--platform`,
`agent.mode`, `auto_approve_all`, or any LLM/tool value.

```toml
[authorization]
# Default. Unmappable ROE lines stop the engagement until an operator records a
# hash-scoped acknowledgement with `agentbug authorize`.
roe_policy_mode = "strict"

# Opt-in alternative (config-only):
# roe_policy_mode = "permissive_audited"
```

- **`strict` (default).** Fail-closed: an unmappable ROE line aborts the
  engagement until an operator acknowledges it explicitly. Acknowledgements are
  scoped to the **exact brief content hash** and the exact rule, are written to
  the audit trail, and are **idempotent** (re-recording the same acknowledgement
  is a no-op). Because an ack is hash-scoped, **changing the brief requires new
  acknowledgements** for the new hash — an acknowledgement for an older hash
  never carries over.
- **`permissive_audited`.** Intended for brief sources that emit arbitrary,
  unmappable prose. Each unmappable line is auto-acknowledged for **that exact
  brief hash** so the run can continue. Those auto-acknowledgements are
  idempotent and fully audited (operator-visible identity, rule and brief hash),
  and AgentBug prints a loud operator warning whenever this mode is active. It
  is still **not** an authorization bypass: the engagement outcome is forced to
  `incomplete`, so a run in this mode can never be reported as fully clean.

Neither mode relaxes a real gate. `denied_finding_classes`, scope intersection,
tool/method allowlists and budgets, verification, and reporting are unchanged;
gated tools stay gated and denied vulnerability classes stay excluded. Read-only
platform and brief-only runs keep the strict defaults. Changing the mode does not
retroactively alter a running or finished engagement — start a new engagement to
apply it.

### Desktop

Open `start-desktop.bat` and select the **Engagement** tab. Paste the program URL,
choose a run mode (`ask` for approval-gated steps, `full_auto` for policy-bounded
autonomy), and start. The tab shows trace events, tasks, clues, findings, the live
state, pause/resume/abort controls, and report export. Runs execute on a background
worker thread so the UI stays responsive.

## 7. Understand events

The Engagement tab and the trace log show a stream of events. Typical kinds include:

| Event kind | Meaning |
| --- | --- |
| `run_start` | Run boundary; carries `run_id` for reproducibility. |
| `brief.ingested` / `brief.extracted` | Program page snapshot and scope/ROE extraction result. |
| `action` | A tool call with `tool`, `target`, `ok` and redacted detail. |
| `finding` | A deduplicated finding with `id`, `type`, `cwe` and verifier verdict. |
| `verifier` | Deterministic verdict over tool-captured bytes + canary (not LLM fields). |
| `usage` | Real API `prompt_tokens` / `completion_tokens` for the run. |
| `report.ready` | Local report written; payload includes the SHA-256 hash. |
| `engagement.error` | Fail-closed decision or run error (message redacted). |

The authoritative source is the `trace_events` table (`kind`, `payload_json`,
`created_at`, `run_id`) plus the tamper-evident session event hash chain. Verify chain
integrity with `agentbug verify-log --session <id>`. The engagement also appends a
redacted `replay-<engagement-id>.jsonl` file under `--cwd`; the evaluation harness
joins it with `trace_events` into `eval/results/<id>/replay.jsonl` so metrics can be
recomputed without trusting the report. See `docs/evaluation.md`.

## 8. Pause, resume, abort

```sh
agentbug engagement --id <id> --status
agentbug engagement --id <id> --pause
agentbug engagement --id <id> --resume
agentbug engagement --id <id> --resume --revalidate-brief
agentbug engagement --id <id> --abort
```

Pass `--db <path>` when the engagement was launched with `engage --db <path>`;
control commands must point at the same database. `--revalidate-brief` requires
`--resume`.

- **Pause** writes a durable control state and requests a stop on the runner
  sessions; it takes effect at the next step boundary, not instantaneously. All
  state is persisted. Use it to review findings or tighten scope.
- **Resume** clears the durable stop flag and sets state back to running. By
  default it does **not** re-fetch or re-read the program brief; scope and policy
  are still re-evaluated before each network action by the tool/runtime gates.
  Add `--revalidate-brief` to explicitly re-fetch the brief at the next safe
  boundary and compare its SHA-256 content hash against the versioned
  authorization snapshot. An unchanged hash clears the check (`authorization.revalidated`)
  and the run continues. A changed hash records `authorization.revalidation_conflict`,
  pauses the engagement, and permanently blocks that engagement: any later
  `resume` is refused, so start a new engagement instead. No report is produced
  under a changed brief. If you changed the ROE without revalidating, re-run from
  a fresh engagement (or re-import scope manually).
- **Abort** is terminal: no further tool calls and `resume` refuses an aborted
  engagement. Existing findings, evidence, and any partial report remain available
  for inspection.
- In the desktop Engagement tab the same actions are buttons next to the state display.
  The desktop resume button uses the default no-refetch behaviour; brief revalidation
  is a CLI-only opt-in.

## 9. Inspect findings and export the report

Inspect with the existing commands (`--session` is the underlying run session):

```sh
agentbug engagements
agentbug findings  --session <id>
agentbug artifacts --session <id>
agentbug assets    --session <id>
agentbug status    --session <id>       # state, budget, coverage, hypotheses
```

Findings carry severity, CVSS v3.1 vector, CWE, reproduction steps, PoC, impact,
remediation, and an evidence hash. See `docs/report-format.md` for the canonical schema.

Export the report locally:

```sh
agentbug report --session <id> --output report.md
```

Or use **Save report to file** in the desktop Engagement tab. The file is written under
your working directory / `--cwd`. **Review every finding and redaction before sharing
or submitting it.**

## 10. Limitations

- **Public pages, not login portals.** AgentBug reads unauthenticated public program
  pages. It cannot solve CAPTCHAs, log in, or read authenticated dashboards. If a
  program hides its scope behind a login, import a scope brief manually and verify
  authorization yourself.
- **Gated tools stay gated.** Intrusive tools (`nuclei`, `nmap`, Playwright, etc.) are
  opt-in and default-disabled. They require explicit `allowed_tools` configuration and
  remain subject to scope, budget, and approval policy.
- **Honeypots and decoy assets.** Public pages can contain stale, misleading, or
  intentionally planted scope/data. Treat extracted ROE as a claim to verify, not
  authority: scope is fail-closed, and a deterministic verifier replaying stored
  request/response bytes and a canary (not the LLM's own judgment) must confirm a
  finding before it is reported. `validate_poc` is a tool, not an authoritative
  gate; operator review remains the final acceptance step.
- **Not a substitute for authorization.** A program page is a statement of intent,
  not a legal grant. Confirm you are allowed to test each in-scope asset. A plain
  `resume` never re-reads the brief, so a changed brief is not detected automatically;
  explicitly opt in with `agentbug engagement --id <id> --resume --revalidate-brief`
  to verify its content hash. A changed hash pauses and permanently blocks that
  engagement (no further resume); start a new engagement after reviewing the new
  brief and ROE.
- **No OS sandbox / no clustering.** Run on an isolated host, keep egress restricted,
  and prefer `ask` mode unless the engagement explicitly authorizes autonomy.
- **Replay fidelity.** A replay JSONL (Cochise-style) is required for evaluation,
  but it is a debugging and audit aid, not proof that a finding is valid; see
  `docs/evaluation.md`. A replay without ground truth cannot establish recall or
  precision. Deferred scope (no real browser, no clustering, no live submission)
  is listed in `docs/REMAINING_GAPS.md`.

## 11. See also

- `docs/report-format.md` — canonical report template, CVSS bands, CWE/OWASP mapping.
- `docs/threat-model.md` — guardrails behind ROE, prompt-injection, and credential rules.
- `docs/evaluation.md` / `eval/` — internal benchmark plan and scoring harness.


## External recon adapters

`browser` and `content_discovery` are CLI adapters and are **gated by default**.
They become available only when the operator explicitly maps a command in the
config file:

```toml
[external_tools]
enabled = true
auto_detect = false

[external_tools.commands]
playwright = "node /path/to/agentbug/eval/fixtures/browser/playwright-wrapper.js {action} {url} {selector}"
ffuf = "/usr/local/bin/ffuf"
katana = "/usr/local/bin/katana"
```

The Playwright adapter is a tracked dependency under `eval/fixtures/browser/`.
Install it and its Chromium binary once:

```sh
npm install eval/fixtures/browser
npx --prefix eval/fixtures/browser playwright install chromium
```

`playwright-wrapper.js` accepts `navigate`, `click` and `screenshot` and emits
bounded JSON (status, title, body excerpt). The engagement reads these command
mappings from config as well as from `AGENTBUG_EXTERNAL_TOOLS`; config entries
win. All adapter arguments are still scope-checked before the process spawns.

`register_command_adapters` supports `nmap`, `naabu`, `nuclei`, `playwright`,
`ffuf` and `katana`. A mapped command is still subject to scope, method and
ROE gates; providing a binary is **not** an authorization bypass. If the
binary is unavailable the tool returns a structured gated result instead of
failing silently.

### Browser backend

The preferred browser backend is Google's `chrome-devtools-mcp` CLI. It speaks
Chrome DevTools Protocol directly — no browser extension and no AutoGLM-style
service. Install it as a tracked dependency:

```sh
npm install eval/fixtures/chrome-mcp
```

Register the wrapper in config (the MCP backend is tried first):

```toml
[external_tools]
enabled = true
[external_tools.commands]
chrome_mcp = "node /path/to/agentbug/eval/fixtures/chrome-mcp/chrome-mcp-wrapper.js {action} {url} {selector}"
```

The wrapper supports `navigate` (returns a page snapshot), `screenshot` and a
restricted CSS-selector `click`. Playwright remains available as an optional
fallback backend. Google's server prints a one-time data-collection disclaimer;
pass `--no-usage-statistics` in the wrapper if the operator opts out.

## External OOB collaborator

The `collaborator` tool defaults to a loopback-only simulation. To use a real
OOB oracle, run `agentbug-collaborator` with a delegated domain and configure
its loopback admin endpoint:

```toml
[oob]
endpoint = "http://127.0.0.1:8082"
```

The engagement then mints tokens via `POST /token` and fetches interactions
via `GET /interactions?token=...`. DNS interactions require UDP 53 reachable
from the target (delegate the zone or port-forward). The admin listener is
loopback-only and must never be exposed publicly. No token or API key is
written to config or logs.

## Local brief files (offline lab only)

For authorized local targets, `--brief-file` bypasses the public brief fetcher
(which intentionally rejects private hosts). The local text still goes through
the same scope parser, ROE classifier and fail-closed gates. This exists for
construction evidence and offline labs, not for production engagements.
