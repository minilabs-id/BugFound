# MiniBug Autonomous Engagement — User Guide

This guide covers the autonomous engagement flow: point MiniBug at a public bug-bounty
program URL and let it fetch the brief, derive scope and Rules of Engagement (ROE),
queue tasks, explore in-scope assets, validate findings, and draft a standard report.

> **Read this first.** MiniBug produces a **local report only**. It never submits a
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
| **Local report only** | The report is written inside `--cwd`. Review and submit it yourself. MiniBug has no submission adapter by design (see `PRODUCTION_PLAN.md` §7). |
| **No auto-submit** | No CLI flag or desktop button submits to HackerOne/Bugcrowd/Intigriti/etc. If a future build adds one, it must be opt-in and gated. |
| **ROE fail-closed** | If the program page cannot be fetched, parsed, or its scope/ROE cannot be established, the engagement does not act on that target. A target that is not explicitly in scope is refused. Scope is re-evaluated before every network action, including after resume. |
| **Pause / abort** | `pause` stops at the next safe boundary and keeps resumable state; `abort` is terminal. Both stop new tool calls immediately. |
| **Policy still applies in `full_auto`** | Budgets, scope, allowlists, tool risk labels, approvals, and egress controls stay active. Autonomy does not disable guardrails. |

## 3. Prerequisites

- An **isolated host/VM or container** with restricted egress (see `docs/deployment.md`).
  MiniBug is a hardened agent runtime, not an OS sandbox.
- A compiled binary (`cargo build --release`) or the desktop build (`start-desktop.bat`).
- An OpenAI-compatible endpoint (API key read from the environment, never stored in
  the workspace).

## 4. Get a program URL

The URL is the public program/brief page MiniBug reads to learn scope and ROE. Common sources:

- Public bug-bounty program pages (HackerOne, Bugcrowd, Intigriti, YesWeHack, etc.).
- A customer-provided scope brief or `security.txt` (`https://example.com/.well-known/security.txt`).
- An internal engagement portal page your team is authorized to read.

Use the canonical, public URL for the program. If the page requires a login, see
[Limitations](#10-limitations). You can also pre-seed scope from a local brief with the
existing `minibug scope-import --file brief.txt --program "Acme"` command before running
the engagement.

## 5. Configure the API key

`config/minibug.example.toml` uses `env:VAR` indirection. Set the variable in the shell
that launches MiniBug:

```sh
# POSIX / macOS / Linux
export OPENAI_API_KEY="sk-..."
# Windows PowerShell
$env:OPENAI_API_KEY = "sk-..."
```

And in `minibug.toml`:

```toml
[llm]
base_url = "https://api.openai.com"   # may include or omit /v1
api_key = "env:OPENAI_API_KEY"
default_model = ""                    # empty → auto-discover via GET /v1/models
```

Verify with `minibug doctor` (checks config/env). Keep the key out of the engagement
workspace; it is redacted from reports, CLI output, events, and tool output.

## 6. Run an engagement

### CLI

```sh
minibug engage --url https://hackerone.com/acme --cwd ./engagement
```

A new engagement row is created in state `idle`, then transitions through `running`
to `completed`, `paused`, or `aborted`. The engagement ID is printed at start; save it
for control commands.

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
| `engagement.start` | Run began; program URL recorded. |
| `brief.fetch` | Program page was fetched and snapshotted. |
| `brief.extract` / `roe.decision` | Scope/ROE extraction result and fail-closed decision. |
| `task.created` / `task.status` | A task was queued or changed status. |
| `tool.call` / `tool.result` | A policy-approved tool call and its (redacted) result. |
| `clue.recorded` / `evidence.saved` | An observation or evidence artifact was stored. |
| `finding.saved` | A deduplicated finding was written. |
| `engagement.paused` / `engagement.resumed` / `engagement.aborted` | Lifecycle controls. |
| `report.exported` | A local report was written. |

The authoritative source is the `trace_events` table (`kind`, `payload_json`,
`created_at`, `run_id`) plus the tamper-evident session event hash chain. Verify chain
integrity with `minibug verify-log --session <id>`.

## 8. Pause, resume, abort

```sh
minibug engage pause  --engagement <id>
minibug engage resume --engagement <id>
minibug engage abort  --engagement <id>
```

- **Pause** stops new tool calls at the next safe boundary and persists all state.
  Use it to review findings or tighten scope. `resume` re-evaluates policy and scope
  before doing anything else (a changed program brief is re-read).
- **Abort** is terminal: no further tool calls, no further resume. Existing findings,
  evidence, and the partial report remain available for inspection.
- In the desktop Engagement tab the same actions are buttons next to the state display.

## 9. Inspect findings and export the report

Inspect with the existing commands (`--session` is the underlying run session):

```sh
minibug engagements
minibug findings  --session <id>
minibug artifacts --session <id>
minibug assets    --session <id>
minibug status    --session <id>       # state, budget, coverage, hypotheses
```

Findings carry severity, CVSS v3.1 vector, CWE, reproduction steps, PoC, impact,
remediation, and an evidence hash. See `docs/report-format.md` for the canonical schema.

Export the report locally:

```sh
minibug report --session <id> --output report.md
```

Or use **Save report to file** in the desktop Engagement tab. The file is written under
your working directory / `--cwd`. **Review every finding and redaction before sharing
or submitting it.**

## 10. Limitations

- **Public pages, not login portals.** MiniBug reads unauthenticated public program
  pages. It cannot solve CAPTCHAs, log in, or read authenticated dashboards. If a
  program hides its scope behind a login, import a scope brief manually and verify
  authorization yourself.
- **Gated tools stay gated.** Intrusive tools (`nuclei`, `nmap`, Playwright, etc.) are
  opt-in and default-disabled. They require explicit `allowed_tools` configuration and
  remain subject to scope, budget, and approval policy.
- **Honeypots and decoy assets.** Public pages can contain stale, misleading, or
  intentionally planted scope/data. Treat extracted ROE as a claim to verify, not
  authority: scope is fail-closed, and a deterministic verifier (not the LLM's own
  judgment) must confirm a finding before it is reported.
- **Not a substitute for authorization.** A program page is a statement of intent,
  not a legal grant. Confirm you are allowed to test each in-scope asset.
- **No OS sandbox / no clustering.** Run on an isolated host, keep egress restricted,
  and prefer `ask` mode unless the engagement explicitly authorizes autonomy.
- **Replay fidelity.** Replay logs (Cochise) are required for evaluation, but a replay
  is a debugging aid, not proof that a finding is valid; see `docs/evaluation.md`.

## 11. See also

- `docs/report-format.md` — canonical report template, CVSS bands, CWE/OWASP mapping.
- `docs/threat-model.md` — guardrails behind ROE, prompt-injection, and credential rules.
- `docs/evaluation.md` / `eval/` — internal benchmark plan and scoring harness.
