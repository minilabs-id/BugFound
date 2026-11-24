# BugFound

BugFound is a Rust workspace for LLM-driven bug-bounty assistance. A runner
calls an OpenAI-compatible model, the model requests tools, a policy layer
checks those requests, and results are written to SQLite. Findings are checked
against tool-produced bytes and rendered into a Markdown report in the local
workspace.

This is a prototype. It has no submission path, no browser engine, no OS
sandbox, and no recorded benchmark results. For what the code actually does,
read the call sites listed in `docs/PRODUCTION_PLAN.md`. For what is absent,
read `docs/REMAINING_GAPS.md`. For how to check the current state, run the
commands in `docs/PRODUCTION_PLAN.md` §4; no test count is recorded here.

## Workspace

| Crate | Role |
| --- | --- |
| `bugfound-kernel-traits` | Ports used by the runner: `Domain`, `GoalLock`, `PromptContributor`, `ToolResultSink`, `ProgressObserver`. |
| `bugfound-core` | Runner step loop, budgets, approvals, inbox, execution coordinator, event bus, compaction, monitor. |
| `bugfound-llm` | OpenAI-compatible chat client, tool schemas, model discovery, typed errors. |
| `bugfound-tools` | Tool registry and implementations: filesystem, shell, HTTP, DNS, findings, artifacts, fuzzing, diffing, sequencer, OOB simulation, active scan. |
| `bugfound-policy` | `ask` / `full_auto` modes, allow/ask/deny decisions, scope parsing and target matching. |
| `bugfound-store` | SQLite (WAL) tables for sessions, messages, approvals, events, budgets, findings, captures, coverage, hypotheses, traces and reports. |
| `bugfound-engagement` | Brief ingestion, ROE classification, WSTG planning, role-scoped runs, finding verification, report building. |
| `bugfound-proxy` | Bounded HTTP/CONNECT intercepting proxy with a scope gate. |
| `bugfound-collaborator` | Self-hosted HTTP/DNS interaction listener for OOB checks. |
| `bugfound-cli` | Command-line interface. |
| `bugfound-desktop` | Windows desktop interface (egui/eframe). |

`research/` holds third-party source clones kept for reference; they are
git-ignored and are not part of the build.

## Behavior implemented in code

- **Runner**: one LLM call per step, then tool execution, then a persisted
  result. State transitions are owner/lease guarded; stale sessions can be
  recovered. `CompactionV2` summarizes older turns. `open_conversation`,
  `chat_turn` and `run_goal_stream` keep one session across messages and stream
  assistant deltas when the provider supports it; `steer` admits a message at
  the next step boundary of a running session.
- **Policy**: a target must match an in-scope rule and no out-of-scope rule.
  Relative prefixes in a brief (`providers.`) are anchored to the program apex.
  Path-scoped exclusions (`host/help/*`) apply to that path only.
- **Approvals**: a risky call parks the session with a pending approval row.
  A transaction records the approval, its deferred calls and the state change;
  resolution is guarded by `status='pending'` and an expiry timestamp.
- **Budgets**: step, tool, network, RPM and token counters live in
  `session_budgets` and `token_usage`; the runner checks them at step and tool
  boundaries.
- **HTTP egress**: the tool resolves the host, checks the address against
  blocked IPv4/IPv6 ranges, pins the connection, disables proxies by default,
  and re-checks scope on each manual redirect.
- **Evidence**: the HTTP tool mints a canary, puts it in the real request, and
  stores raw request/response bytes. The verifier reads those stored bytes;
  model-supplied evidence fields are advisory.
- **Falsification**: `save_finding` requires five non-empty fields when
  `require_falsification` is on. `validate_finding` is a local contract
  pre-flight with no store lookup; it is not evidence validation.
- **Report**: a canonical Markdown renderer writes Executive Summary, Scope &
  ROE, Methodology, Findings, Coverage, Timeline and Appendices into the
  workspace. Redaction is applied at report and CLI output boundaries.

## Interfaces

```sh
bugfound init --force
bugfound engage --url <url> --cwd ./engagement
bugfound engage --brief-file brief.txt --cwd ./engagement --brief-only
bugfound engage --url <url> --platform hackerone --api-key-env H1_TOKEN
bugfound engagement --id <id> --status|--pause|--resume|--abort
bugfound engagement --id <id> --resume --revalidate-brief
bugfound authorize --url <url> --content-hash <sha> --rule <line> --operator <name>
bugfound receipt add --program-url <url> --brief-content-hash <sha> --scope-version <v> --terms-hash <sha> --operator <name> --expires-at <iso>
bugfound receipt list --program-url <url>
bugfound run --goal "..." --cwd ./engagement
bugfound resume --session <id> --approve|--deny
bugfound sessions|logs|findings|assets|artifacts|report|status|approvals
bugfound hypothesis --session <id> --add "..."
bugfound plan|tokens|tools|doctor|verify-log --session <id>
bugfound scope-import --file brief.txt --program "Acme"
```

The desktop build uses the same crates. `start-desktop.bat` launches it on
Windows. Its surface is a conversation: type a program URL or a follow-up
message, read streamed assistant text and tool activity in the same timeline,
and answer approval prompts inline. One long-lived worker owns the Tokio
runtime, the conversation session and the engagement driver. Configuration is
read from `bugfound.toml`; see `config/bugfound.example.toml`.

## Verification

Run from the repository root:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo build --release --workspace
cargo deny check
python -m py_compile eval/score.py eval/export_trace.py
python eval/score.py --dir eval/results/example-synthetic \
  --manifest eval/results/example-synthetic/manifest.json \
  --replay eval/results/example-synthetic/replay.jsonl --strict
```

CI runs the Rust checks on Linux and Windows, installs `cargo-deny`, and
enforces the `bugfound-core` domain-boundary check from ADR-001. The toolchain
is pinned to `1.90.0` in `rust-toolchain.toml`.

## Evaluation

`eval/` contains a scorer, a trace exporter, lab fixtures and Windows driver
scripts. `eval/results/example-synthetic` is invented data used to check the
scorer's arithmetic. No effectiveness number is recorded in this repository.
See `eval/README.md` and `docs/evaluation.md`.

## Scope boundaries

The code does not include: a browser engine, distributed execution, a
submission path, a maintained fuzz corpus, a performance benchmark, or an OS
sandbox. The shell tool runs an explicit short allowlist. A live engagement
still needs an isolated host and operator review of the local report. See
`docs/REMAINING_GAPS.md` and `docs/threat-model.md`.

Licensed under the MIT License — see `LICENSE`.
