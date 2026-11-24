# BugFound architecture

This document maps the workspace crates and the flow between them. It
describes code paths, not maturity. Check the paths against the source and run
the verification commands in `PRODUCTION_PLAN.md` §4.

## Crates

- `bugfound-kernel-traits` defines the ports a domain plugs into: `Domain`,
  `GoalLock`, `PromptContributor`, `ToolResultSink`, `ProgressObserver`.
- `bugfound-core` owns `Runner`. A step loads history from the store, calls the
  LLM with tool schemas, evaluates each tool call against policy, executes or
  parks it, and writes the result back. The loop does not keep an in-memory
  tool stack.
- `bugfound-llm` wraps `/v1/chat/completions`, tool schemas, model discovery and
  typed errors. `chat_full` returns usage alongside the response.
- `bugfound-tools` provides the registry and the tools. Each tool has a spec
  (name, schema, risk label) and runs with bounded output.
- `bugfound-policy` holds mode, tool/target lists and `ScopeConfig`.
  `ScopeConfig::check_target` handles in-scope/out-of-scope matching, including
  relative prefixes and path-scoped exclusions.
- `bugfound-store` is the SQLite layer. Sessions, approvals, budgets, events,
  captures, findings, coverage, hypotheses and traces are rows in tables.
  `verify_event_chain` recomputes the event hash chain.
- `bugfound-engagement` builds a profile from a brief, classifies ROE lines,
  plans WSTG tasks, runs role-scoped sessions, verifies findings and builds the
  report.
- `bugfound-proxy` and `bugfound-collaborator` are separate binaries for
  interception and OOB interaction.

## Control flow

1. `engage` fetches or reads a brief. `parse_scope_brief_traced` and
   `roe_classify` produce a scope and a typed ROE policy. Unmapped ROE lines
   stop the run unless a hash-scoped operator acknowledgement exists.
2. Relative scope prefixes are expanded against apex hosts taken from the
   deterministic brief. The LLM-extracted scope is intersected with that
   deterministic set.
3. `wstg_playbooks` produces tasks and hypotheses. Each task gets a fresh
   `Runner` with a role-scoped tool registry.
4. Tool calls pass through policy, budget and approval gates. Captures are
   stored by the tool, not supplied by the model.
5. `verify_findings` replays stored bytes. `canary_echo` and `differential`
   have confirm paths in `verify_candidate`; other classes return
   `open_proof_gap` with a named missing proof.
6. The report renderer writes to the engagement workspace. No code path in
   `crates/` sends a report to a third party.

## Budget and durability

`session_budgets` holds step, tool, network and RPM counters with inheritance
offsets for child sessions. `token_usage` holds API-reported tokens; the runner
also uses a pre-call estimate when checking the token limit. Leases and guarded
transitions in `bugfound-store` control ownership of a session.

## Coordination modules

`inbox`, `execution`, `event`, `step`, `compaction` and `error` live in
`bugfound-core`. `inbox` and `execution` have runner call sites; `event` is
used by `Runner::log_event`. Some helpers in these modules are used only by
unit tests, and `step.rs` is additive. The ADR-001 boundary check in CI keeps
domain vocabulary out of `bugfound-core/src`.

## Chat-native surface

- `bugfound-llm::Llm::chat_stream_full` has a default implementation that calls
  `chat_full` and emits one delta, so existing `Llm` implementations are
  unchanged. `LlmClient` overrides it with SSE parsing, tool-call fragment
  assembly and provider usage from the final chunk.
- `bugfound-core::Runner` exposes `open_conversation`, `chat_turn`,
  `run_goal_stream`, `steer` and `queue_message`. A conversation is one durable
  session; each turn appends a `user` message and reloads the full history at
  the next step. `steer` writes a durable inbox item and rings the doorbell, so
  a message sent while the agent is running is admitted at the next step
  boundary, not mid-tool.
- `bugfound-engagement::engage_drive` is the runtime-agnostic async entry point.
  The desktop worker calls it from one long-lived Tokio runtime and forwards
  `EngagementEvent`s into the same chat timeline. The engagement layer still
  creates a fresh role-scoped `Runner` per task; that boundary carries the
  `engagement_id=<id>` marker used by control, coverage and reporting.

## Deployment shape

The runner is single-node. SQLite is local to the process. There is no
cross-node fencing, no OS sandbox and no browser engine. The shell tool runs
`echo` and `whoami` from an allowlist with a scrubbed environment; that is a
tool-level restriction, not process isolation. See `threat-model.md` and
`REMAINING_GAPS.md`.
