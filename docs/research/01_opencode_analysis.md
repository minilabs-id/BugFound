# OpenCode Source Analysis - Patterns for a Rust-Native Agent Kernel (AgentBug)

**Research basis:** ACTUAL source code, not documentation.
**Reference:** `research/opencode` at commit `d643c875879feef6198d28307a5592a46c6fd56d`
**Product under study:** OpenCode (`packages/core`, `packages/ai`, `packages/schema`), an Effect-TS ("effect-smol" / Effect v4) coding-agent harness.
**Target:** `crates/agentbug-*` Rust-native agent kernel.
**Method:** Read-only source inspection. Patterns are extracted and translated into recommendations; no code is copied.

---

## 0. Scope, file inventory, and how to read this document

All paths are absolute from the reference checkout root `D:\Github\Agent Bug Bounty\research\opencode`. Line numbers are 1-based and refer to the exact commit above.

Analyzed files (primary), with line counts:

| File | Lines | Role |
| --- | ---: | --- |
| `packages/core/src/session/runner/llm.ts` | 457 | Turn/drain orchestration, step policy, recovery |
| `packages/core/src/session/runner/step.ts` | 380 | Single LLM-call Step: streaming, tools, cancellation, outcomes |
| `packages/core/src/session/compaction.ts` | 1152 | Context budgeting, summarization, background precompute |
| `packages/core/src/session/projector.ts` | 1151 | Event to durable state projections (read model) |
| `packages/core/src/session/inbox.ts` | 578 | Durable prompt admission, delivery modes (steer/queue) |
| `packages/core/src/session/model-transport.ts` | 541 | WebSocket/HTTP transport binding |
| `packages/core/src/session/execution/restart.ts` | 532 | Orphaned-claim crash recovery |
| `packages/core/src/provider.ts` | 517 | Provider/credential/model catalog loading |
| `packages/core/src/tool.ts` | 514 | Tool registry, snapshots, Code Mode, hooks |
| `packages/core/src/session/message-updater.ts` | 487 | Streaming message/event projection |
| `packages/core/src/session/runner/publish-llm-event.ts` | 610 | LLM event to durable message events (observability) |
| `packages/core/src/session/model-request.ts` | 455 | Per-flow request assembly, plugin hooks, media budget |
| `packages/core/src/session/session.ts` | 394 | Public Session facade and operation set |
| `packages/core/src/session/history.ts` | 379 | Durable history reads, compaction boundaries, replay |
| `packages/core/src/permission.ts` | 369 | allow/deny/ask evaluation, pending asks, replies |
| `packages/core/src/session/store.ts` | 308 | Session/message SQL store, execution claims |
| `packages/core/src/session/runner/to-llm-message.ts` | 300 | Stored history to canonical LLM messages |
| `packages/core/src/tool/runtime.ts` | 278 | Schema conversion, validation, result serialization |
| `packages/core/src/session/execution.ts` | 231 | Process-local execution, lifecycle, cancellation |
| `packages/core/src/session/run-coordinator.ts` | 183 | Per-session doorbell/coalescing coordinator |
| `packages/core/src/session/prompt.ts` | 239 | Prompt preparation, attachments, skills |
| `packages/core/src/session/execution/subagent-report.ts` | 186 | Subagent completion reporting |
| `packages/core/src/session/runner/model.ts` | 130 | Model resolution per request kind |
| `packages/core/src/plugin/agent.ts` | 119 | Built-in agent definitions (build/general/explore/title) |
| `packages/core/src/agent.ts` | 102 | Agent registry/selection |
| `packages/core/src/session/runner/retry.ts` | 72 | Retry decision + scheduled wait |
| `packages/core/src/tool/plugin/subagent.ts` | 269 | Subagent delegation tool |
| `packages/schema/src/agent.ts`, `permission.ts`, `session.ts`, `tool.ts`, `session-id.ts` | - | Canonical schemas |
| `packages/ai/src/llm.ts`, `provider-error.ts`, `effect.ts` | - | Provider abstraction, streaming, error classification |

Each component below records: **source**, **main structures**, **execution path**, **dependencies**, **responsibilities**, **strengths**, **weaknesses**, and a concrete **adapt-to-AgentBug recommendation**.

---

## 1. Executive summary - the architecture in one page

OpenCode's agent kernel is built on five ideas that are directly transferable to a Rust kernel:

1. **One durable Step = one LLM call.** The runner never keeps a tool loop in memory. It streams one model response, executes tool calls as concurrent fibers, persists everything as durable events, then *reloads history from the database* for the next call. (`llm.ts:236-387`, `step.ts:77-333`; AGENTS.md: "Each step is one explicit llm.stream call that continues from reloaded history. Do not add an in-memory tool loop.")
2. **Event sourcing with projections.** Almost nothing mutates state directly. Operations publish typed events on a `Bus`; projectors fold them into SQLite read models, and the `commit` option makes "publish event + local projection" atomic (`bus.ts:102-115`, `projector.ts`). This gives crash recovery, replay, and a single-writer ordering.
3. **Explicit admission/delivery separation.** Prompt *admission* (a `session_inbox` row, `session.inbox.enqueued`) is separate from *delivery* (`session.inbox.delivered`, the visible message). Steers take priority at safe boundaries; queue items wait for idle (`inbox.ts`, `llm.ts:63-214`).
4. **Process-global, Session-ID-based execution coordination.** A `SessionRunCoordinator` serializes drains per Session with a "doorbell" that coalesces wakeups and closes the check/idle race; cancellation targets the process-local ownership chain (`run-coordinator.ts`, `execution.ts`).
5. **Capability scopes everywhere.** Agents, sessions, tools, models, permissions, and instructions are all resolved through location-scoped services; permissions are ordered wildcard rules merged from agent + session + saved approvals, evaluated last-match-wins (`permission.ts:102-119`, `context.ts:148-208`).

Strengths to emulate: precise crash semantics (write-ahead claims, stale-settlement on boot, bounded resume attempts), prompt-cache-aware context engineering, a typed error taxonomy with recovery hints, and a permission system that distinguishes "deny", "ask", and "correct with feedback".

Weaknesses to avoid or compensate: extreme complexity (compaction alone is about 1150 lines of heuristics), reliance on Effect fiber/Deferred machinery with no direct Rust equivalent, heavy in-process mutation behind service abstractions, and an event-sourced design whose read-your-writes guarantees depend on careful projection discipline.

---

## 2. Agent runtime / execution loop

### 2.1 The drain loop - turn orchestration

**Source:** `packages/core/src/session/runner/llm.ts:43-470` (layer), especially `drain` at `:63-225`, `advanceToStep` at `:81-214`, `runStep` at `:237-387`. Interface: `packages/core/src/session/runner/index.ts:12-46`.

**Main structures:**
- `DrainResult = Complete | Moved | Reloaded` (tagged enum) with optional `continuation: {step}` and `stepped` flags (`index.ts:21-28`). A drain is one *turn*; it may hand off to another Location (`Moved`) or reload plugins (`Reloaded`) while preserving the step counter.
- `Continuation {step}` - the only transient state carried across a handoff; everything else lives in durable history.
- `RunError` union: `AIError | SessionRunnerModel.Error | MessageDecodeError | AgentNotFoundError | StepFailedError | Instructions.InitializationBlocked | FileSystem.DirectoryNotFoundError` (`index.ts:12-19`).

**Execution path (`drain`, `llm.ts:63-225`):**
1. If not forced/continuing, check `SessionInbox.nextPromotable(db, sessionID, "input")`; if nothing pending return `Complete` (`:71-76`). A `steer` drain will not promote `queue` items (`:75`).
2. `plugins.awaitActivation`, then `settleStaleCompactions` and `settleStaleToolCalls` - crash cleanup publishes failures for orphaned running compactions and tool calls (`:77-79`, implementations `:389-442`).
3. `advanceToStep()` (`:81-214`) loops:
   - If Location closed -> `Reloaded` (`:85-92`).
   - Under a per-session inbox mutex (`SessionInbox.serialized`), pick the next promotable item; handle `compaction` (publish Started, resolve compaction model, run `compaction.compact`, publish Failed on error) and `move` (close transport, publish Moved) controls (`:94-176`).
   - If idle and nothing promotable, fire the plugin `experimental.idle` hook which may admit work; otherwise `Complete` (`:177-190`).
   - Otherwise `prepareContext` + `SessionInbox.promote` + `context.load`; a promoted user item resets `step = 1` and may trigger background title generation (`:191-210`).
4. Outer loop: `runStep(context, step, interruption)` then `step++` (`:216-224`).

`runStep` (`:237-387`) owns *logical Step policy* and loops on outcomes:
- `SessionCompaction.estimatePrompt` + auto `compact`; `completed` -> new assistant ID and retry (`:253-260`).
- Step limit: if `agent.info.steps` is reached, append `MAX_STEPS_PROMPT` and set `toolChoice: "none"` (`:261-283`).
- `context.request.primary(...)` builds the request; `steps.attempt(...)` runs it (`:269-326`).
- Outcome match (`:328-384`): `Completed` (precompute a background summary if going idle), `Retry` (wait + maybe fresh assistant ID), `OutputLimit` (three consecutive `length` finishes -> fail; else publish a `CONTINUE_AFTER_OUTPUT_LIMIT` synthetic), `Compacted` (disable overflow recovery), `RecoverFull` (disable continuation recovery).

**Dependencies:** Bus, LocationLifecycle, SessionStore, SessionContext, SessionModelTransport, SessionCompaction, Plugin/Hooks, Job, SessionTitle, Snapshot, PersistentPty, ToolOutput, LLMClient (`:450-470`).

**Responsibilities:** boundary selection (what input is admitted when), step numbering, crash settlement, compaction triggering, step-limit policy, output-limit continuation, retry scheduling, plugin hooks at boundaries.

**Strengths:**
- The "reload from history each step" discipline makes resumes and cross-process handoff correct by construction; only `{step}` is transient.
- Steer-vs-queue promotion policy is explicit and location-independent.
- Stale work (compaction/tool calls) is settled at the start of every drain, so a process death cannot leave permanently "running" rows.

**Weaknesses:**
- `runStep` mixes many concerns (compaction, retry, output-limit, step-limit) in one long function; reasoning about interactions is hard.
- Transient `let` flags (`recoverOverflow`, `recoverContinuation`, `retryAttempt`) accumulate loop state; a bug in one branch can silently disable recovery.
- Relies on Effect fibers/Deferred/FiberMap for coordination that must be re-engineered in Rust.

**Adapt to AgentBug:** AgentBug's `run_loop` (`crates/agentbug-core/src/lib.rs:1750-1929`) already follows "one call per step, reload history" - keep that. Add: (a) an explicit `DrainResult`-style state machine so a Session can be handed between workers without losing the step counter; (b) a distinct **admission** phase (append to inbox durably) and **delivery** phase (promote at a boundary) with `steer`/`queue` semantics, instead of the current single `drain_inbox()` at the top of the loop (`lib.rs:628-650,1775`); (c) a boot-time "settle stale" sweep that publishes a terminal tool result for any unfinished tool call (mirrors `settleStaleToolCalls`, `llm.ts:419-442`).

### 2.2 The Step - one model call, tool execution, cancellation, outcomes

**Source:** `packages/core/src/session/runner/step.ts:30-401`.

**Main structures:**
- `Outcome = Completed{needsContinuation} | Retry{error,decision,freshAssistant?} | RecoverFull | Compacted | OutputLimit{needsContinuation}` (`:30-41`).
- `Input` (`:43-64`): `isLocationClosed`, `interruption: () => "user"|"shutdown"|undefined`, `handoffPrepared`, `assistantMessageID`, `agent`, `model`, `prepared`, `retry` callback, `recoverContinuation`, `recoverOverflow`.
- Constants `TOOLS_INTERRUPTED`, `STEP_INTERRUPTED`, `RESULT_MISSING` (`:66-68`).
- `Cancel` via `makeCancel()` (`:372-401`): a Deferred gate with a listener count; `trigger()` returns whether a tool was actually awaiting it (cooperative vs forced stop).

**Execution path (`attempt`, `:77-333`):**
1. Fork a start-snapshot capture (`:80`), annotate a trace span with `gen_ai.*` attributes (`:83-91`), create `createLLMEventPublisher` (`:92-100`).
2. `providerStream = llm.stream(request, options)` consumed with `Stream.runForEach` (`:135-163`): publish every event; for each `tool-call` create a Cancel gate and fork `executeTool` (permission check, truncation, `publisher.toolExecution`), with `Tool.Error` caught and converted to a failed tool event (`:145-159`).
3. Finalization under `Effect.uninterruptibleMask` (`:166-332`): capture stream exit/failure/interruption; cooperative `stopTools` on user stop (ask each tool to cancel via gate, wait `COOPERATIVE_STOP = 5 seconds`, then interrupt all) (`:106-117`, `:180`); join tool fibers; `classifyToolExits` into `declines`/`failure`/`interrupted` (`:344-367`).
4. Recovery classification: context overflow -> `Compacted` (`:198-209`); unknown finish -> `InvalidProviderOutputError` (`:211-221`); transport "retry-full"/"rotate-and-retry-full" with no output -> `RecoverFull` (`:237-243`); retryable -> `Retry` (`:244-259`).
5. Emit final events: settled tool failures, assistant failure, `RESULT_MISSING` for calls with no result, `Step.Ended` with usage/snapshot/files (`:262-315`).
6. Return `Completed`/`OutputLimit`/`Retry`/fail cause (`:317-330`).

**Dependencies:** LLMClient, Bus, Snapshot, ToolOutput, Permission, PluginHooks, SessionUsage, SessionRunnerRetry; `publisher` (`publish-llm-event.ts`) is the single writer of durable message events.

**Strengths:**
- Cooperative cancellation: a user stop first *asks* tools to stop (5s grace) and only then hard-interrupts - critical for not corrupting file/shell tools.
- Provider stream and tool fibers are ordered independently without a shared writer queue; the span covers only provider time, so model latency is separable from tool latency.
- Missing tool results are explicitly detected (`RESULT_MISSING`) so a malformed provider stream cannot leave a call hanging.
- `handoffPrepared` logic leaves a step unsettled on daemon handover so the *next* server settles it (`:187-196`).

**Weaknesses:**
- The finalization block is about 170 lines of defensive branches; the number of "did output start / was interrupted / was declined" combinations is large and easy to get wrong.
- `classifyToolExits` treats user declines as typed failures but other tool failures as defects - a subtle distinction documented in comments (`:344-345`).
- Error taxonomy is provider-specific in places (e.g. "rotate-and-retry-full" is a proxy concept).

**Adapt to AgentBug:** In Rust, model this as a `StepOutcome` enum returned by a `run_step()` async fn, with a `CancellationToken` passed to tools and a two-phase stop: signal -> bounded `tokio::time::timeout` wait -> abort. Persist a distinct terminal record for every tool call (including `missing_result` and `interrupted`). Keep the cooperative-then-forced stop; AgentBug's current `check_stop` only checks at step boundaries (`lib.rs:816-828`), which lets a long-running tool ignore a stop until it ends.

### 2.3 Request assembly and hooks

**Source:** `packages/core/src/session/model-request.ts:70-480`. `Prepared{event,request,options,retry,executeTool}` (`:70-79`); `Interface` has `primary|compaction|generate|title` builders (`:258-263`).

**Execution path (`prepare`, `:273-461`):**
- Build a per-flow hook event; deep-copy tool definitions so hooks can rename/edit by object identity (`:283-317`).
- Fit the output limit to remaining window (`outputLimit`, `:95-104`; constants at `:50-65`: image 25 MiB trigger / 15 MiB target, 4 chars per token estimate with 15% error, 1% window headroom, 32k output fallback, 256k max).
- `ai.request(...)` with cache-affinity headers (`x-opencode-session-id`, prompt cache key, `X-Session-Id`) (`:322-358`).
- Strip/adjust media: `unsupportedParts` (model capability check, xAI MIME restrictions) and `boundImages` (drop oldest images over byte budget in stable cuts to preserve the prompt cache) (`:139-253`, `:340-349`).
- Plugin hooks `session.model.request`, `http.request`/`http.response` (wrapping every HTTP call), and WebSocket handshake/send/receive (`:360-433`).
- `executeTool` recovers declines that intentionally tunneled as defects (`catchCauseFilter`, `:445-459`).

**Strengths:** prompt-cache-preserving media bounding; every external interaction is hookable; explicit separation of "event for hooks" and "sanitized wire request".

**Weaknesses:** deep-copying tool schemas per request for hook isolation is expensive; the hook contract is large and untyped at the edge.

**Adapt to AgentBug:** Centralize request assembly in `agentbug-llm` as a pure `build_request(session, agent, history, tools, budget) -> LlmRequest` function; keep a single `RequestContext` with typed extension points instead of mutable hook events. Adopt the explicit per-request output token budget formula (`outputLimit`) - AgentBug currently uses a coarse `max_estimated_tokens` total-session cap (`lib.rs:1819-1836`) with no per-call fitting to the model window.

### 2.4 Retry and provider error classification

**Source:** `packages/core/src/session/runner/retry.ts:1-78`; `packages/ai/src/provider-error.ts:16-87,198-260+`.

- `SessionRunnerRetry.policy` delegates to `ModelRetry.policy`, then fires the `session.retry` plugin hook which may override the decision/delay (`:32-55`). `wait` publishes `RetryScheduled` then sleeps the remaining delay (`:57-78`). Retry eligibility is `AIError.isRetryable` plus "output started and stream interrupted" (`step.ts:244-254`).
- Provider failure classification (`provider-error.ts`): large regex sets for context-overflow phrases (`:16-74`), payload-too-large (`:60,76`), and code sets for quota/auth/content-policy/server errors (`:89-161`). `classifyProviderFailure` (`:218+`) uses status + codes + raw body with the principle: "deterministic failures need positive identification; anything unrecognized stays UnknownProvider, which the retry policy treats as retry-eligible" (`:212-217`). `isContextOverflowFailure` checks `InvalidRequest` with classification `"context-overflow"` (`:78-82`).

**Strengths:** one canonical error taxonomy drives compaction, retry, and user-facing messages; conservative classification avoids false negatives on transient failures.

**Weaknesses:** regex-heavy and provider-specific; a constant maintenance burden.

**Adapt to AgentBug:** AgentBug has `error::AgentError::classify` (`lib.rs:1856`) and a cooldown on 429/403 (`:1050-1105`). Formalize a Rust `LlmErrorKind { ContextOverflow, PayloadTooLarge, RateLimited, Auth, ContentPolicy, Server, Transport, Unknown }` enum in `agentbug-llm`, and bind behavior explicitly: ContextOverflow -> compaction, RateLimited/Server/Unknown -> retry with backoff, Auth/ContentPolicy -> terminal. Carry a typed `retryable` and `recovery_hint` so the runner never re-derives intent from strings.

---

## 3. Session architecture

### 3.1 Public Session facade

**Source:** `packages/core/src/session/session.ts:1-403`. `make()` builds once in the host Scope; `forSession(id)` returns handles bound to one Session (`:32-36,343-398`).

**Main structures:**
- `PromptRequest = SessionPrompt.Input & {id?, resume?}` (`:27-30`).
- `Handle` = bound operation set (`:401`): `get, message, view, rename, archive, unarchive, setMetadata, setPermissions, switchAgent, switchModel, inbox, prompt, synthetic, shell, skill, compact, wait, resume, interrupt, cancelInbox, steerInbox, queueInbox, revert{stage,clear,commit}`.
- `Session.Info` schema (`packages/schema/src/session.ts:32-63`): `id, parentID?, fork?, projectID, agent?, model?, cost, tokens, outcome?, time{created,updated,busy,idle,viewed,archived}, title?, location, subpath?, metadata?, permissions?, revert?`. Session IDs are `ses_` + descending identifier (`packages/schema/src/session-id.ts:5-11`).

**Execution path - `prompt` (`:149-188`):**
1. `admission.reconcile({id, sessionID, type:"user", delivery: input.delivery ?? "steer"})` - first admission wins for matching Session and type (idempotent retries).
2. If new: `SessionPrompt.prepare` (plugin hook, attachments, skills), commit any staged revert, then `admission.admit` (publishes `session.inbox.enqueued`). All under the Session's location services.
3. Unless `resume: false`, call `execution.wake(sessionID)` (admit-only behavior otherwise).
4. `onAccepted` callback checkpoint, then return the admitted item.

Other notable operations: `compact` admits a compaction control item and wakes (`:256-274`); `interrupt` delegates to `execution.interrupt` uninterruptibly (`:286-289`); `shell` forks the command in the host scope so completion is recorded even if the client disconnects (`:189-232`); `switchAgent/switchModel/rename/...` are pure event publications (`:65-112`).

**Strengths:** idempotent admission by (Session, type, id); the `resume:false` "admit-only" flag is an explicit seam used by background jobs; operations arethin event publishers rather than state mutators.

**Weaknesses:** the facade is large; `forSession` rebinds every operation by hand (`:343-398`); "view"/"rename" semantics rely on projector details not visible here.

**Adapt to AgentBug:** Keep a single `Session` service with a `for_session(id)` handle, but generate the bound handle via a trait/macro or a small struct with methods taking `&self` rather than listing 20 closures. Pin down idempotency rules now: AgentBug should use `(session_id, item_id, type)` as the idempotency key for prompt admission, and expose `resume:false` admit-only as an explicit API for background/subagent work.

### 3.2 Durable inbox - admission and delivery modes

**Source:** `packages/core/src/session/inbox.ts:1-578`. Interface/materialization at `:167-297`, projections at `:299+`.

**Main structures:**
- `Promotable = "input" | "steer"` (`:57`): "steer" promotes only steers (mid-work step boundary); "input" also allows one queued input at idle.
- `Delivery` from `@opencode/schema/session-inbox`: `"steer" | "queue"` (re-exported `:35-50`). Item types: `User | MediaUser | Synthetic | Compaction | Move`.
- `LifecycleConflict` (`:75-77`); `serialized(sessionID, effect)` uses a `KeyedMutex` per Session (`:69-73`).
- `Pending` deferred (in permission) vs here: a `session_inbox` row with `delivery`, `enqueued_seq`, payload (`:324-339`).

**Execution path:**
- `reconcile` (`:177-189`): first admission wins for matching Session and type; a compaction ID reuse conflicts.
- `admit` (`:191-224`): publish `InboxEnqueued`; projection inserts the row; reconcile again on success.
- `promote` / `nextPromotable` / `serialized` (used by `llm.ts:94-209`) consume items in durable order; `delivered` inserts the visible message and consumes the inbox row in one transaction (per AGENTS.md).
- `cancel`/`steer`/`queue` (`:252-282`) publish delivery mutations; a steer wakes execution (`session.ts:138-144`).

**Strengths:** a clean, auditable state machine for user input; "steer" (steer active intent) vs "queue" (next turn) vs "control" (compaction/move) is a powerful vocabulary; cancellation and re-steering are possible between admission and delivery.

**Weaknesses:** the promotion rules are spread across `inbox.ts`, `llm.ts`, and AGENTS.md; implementing them correctly requires understanding all three.

**Adapt to AgentBug:** Add `delivery` to AgentBug's inbox items (`crates/agentbug-core/src/inbox.rs`, currently 260 lines) with `steer`/`queue`/`control` kinds. At each Step boundary, promote all steers in order, then at most one queue item only when idle; allow cancel/steer mutation while pending. This is a concrete upgrade over the current "drain everything at the top of the loop" behavior (`lib.rs:628-650`).

### 3.3 Process-local execution and the run coordinator

**Sources:** `packages/core/src/session/execution.ts:1-241`, `packages/core/src/session/run-coordinator.ts:1-198`.

**Main structures:**
- `SessionExecution.Interface` (`execution.ts:20-43`): `active, isActive, resume, wake, interrupt, awaitIdle`. Routes a Session ID to its selected instance's runner.
- `Coordinator<Key,E,Reason>` (`run-coordinator.ts:7-29`): `active, draining, isActive, run, wake, interrupt, interruption, awaitIdle`. Serializes execution per key while allowing different keys to run concurrently.
- `Execution<E,Reason>` (`:39-46`): `done` Deferred (joiners), `owner?` fiber, `scope: Promotable`, `pendingWake?` (the "doorbell"), `stopping`, `interruptionReason?`.
- `terminal(exit, reason)` (`:50-54`): maps a drain exit to `succeeded | interrupted(shutdown/user) | failed(error)`.

**Execution path:**
- `wake(key, scope?)` (`run-coordinator.ts:135-144`): idle -> start a new execution fiber; active -> coalesce `pendingWake` keeping the widest scope (`input` subsumes `steer`).
- `loop` (`:73-84`): drain; if a wake arrived during the drain, re-drain (trampolined with `yieldNow`) instead of settling - this closes the gap between the last eligibility check and the idle transition.
- `start` (`:86-111`): forks an owner fiber, calls `started` hook, runs the loop, and calls `settled` hook on exit; `settle` (`:115-119`) starts a successor if a wake survived, else deletes the key and resolves joiners.
- `interrupt(key, reason)` (`:146-166`): no-op if idle/stopping; marks `stopping`, clears `pendingWake` (the interrupt claims recorded wakes), records the reason, and fire-and-forgets `Fiber.interrupt(owner)` so the endpoint acknowledges immediately.
- `SessionExecution.layer` (`execution.ts:57-208`): wires `started` to publish `Execution.Started` with a **write-ahead claim** commit (`:78-85,139-153`), `drain` to run `SessionRunner.drain` with instance services provided (`:105-137`), and `settled` to publish exactly one terminal event per busy period (`:155-177`).

**Strengths:**
- The doorbell pattern elegantly solves wake coalescing and the idle race without a central queue.
- Interruption semantics are explicit: idle no-op, immediate acknowledgement, asynchronous cleanup; `interrupt(resume:true)` only resumes steer/control work and leaves queued next-turn prompts parked (`:185-201`).
- Write-ahead claim: terminal releases it; shutdown interruption deliberately preserves it for restart recovery.

**Weaknesses:** `holder`-based late binding between the report coordinator and run coordinator is subtle (`:88-102`); `awaitIdle` re-checks after each Deferred to catch late doorbells (`:170-175`) - a Rust port must preserve that detail.

**Adapt to AgentBug:** AgentBug already has `ExecutionCoordinator` (`crates/agentbug-core/src/execution.rs`, 243 lines) with leases, cancel, and stop-ack. Upgrade it with: (a) a **coalescing doorbell** (`pending_wake: Option<Scope>`) so a wake arriving during a drain triggers another drain rather than being lost; (b) `await_idle` that re-checks after each join; (c) an explicit `draining` set distinct from `active` (settlement window); (d) keep the write-ahead claim semantics - AgentBug's `claim_session`/`release_claim` already mirror this well (`lib.rs:688-707,1215-1233`).

### 3.4 Persistence, history boundaries, and crash recovery

**Sources:** `session/store.ts:1-308`, `session/history.ts:1-379`, `session/execution/restart.ts:1-532`, `session/sql.ts`, `session/projector.ts` (1151 lines).

**Main structures / mechanisms:**
- `SessionStore.Interface` (`store.ts:55-100`): `get, list, messages, context, lastAssistantAfter, message, messagesWithRefs, listSuspended, claim, release, releaseOrphanedChildClaims, countResume`.
- The claim (`time_suspended`) and `resume_attempts` columns are the durable recovery markers (`:256-301`). Claiming pins `time_updated` so bookkeeping never reorders sessions (`:257-265`).
- `history.ts` `Boundary = "latest" | "local" | Model.Ref` (`:32`): selects which completed compaction bounds a read; native windows replay only on the producing model (`:34-53`). `messageEntries` (`:193-239`) walks from the latest eligible compaction, hydrates blobs, and filters superseded instruction updates; `withRecentText` (`:246-280`) regenerates a summary's kept tail from stored rows by `metadata.keepID`.
- `restart.ts`: `resumeSuspendedSessions()` resumes Sessions whose claim was never released (`:52-61`); at-least-once semantics are documented (`:69-71`); the claim is only ever cleared by a terminal event (`:56-59`); `maxAttempts = 10` per turn prevents crash loops (`:38-48,101-120`); a synthetic `CONTINUE_AFTER_SERVER_RESTART` message is published before resume (`:30-31,116-120`).

**Strengths:** recovery requires no cooperation from the dead process (crash/SIGKILL/eviction all leave the same durable signature); native compaction replay is model-scoped; summary "kept text" is reconstructed rather than duplicated.

**Weaknesses:** the event-sourced read model (`projector.ts`) is large; correctness depends on the projector being deterministic and idempotent. `resumeSuspendedSessions` assumes the previous owner is dead - guaranteed only by the managed-server protocol (`:72-79`).

**Adapt to AgentBug:** AgentBug has `recover_stale_sessions()` (`lib.rs:670-686`) using `mark_stale_running_interrupted`. Add a durable **resume-attempt counter** per session with a bound (OpenCode's 10) so repeated crashes cannot loop forever, and a synthetic "continue after restart" message. Keep an explicit `Boundary`-like parameter when reading history after compaction, so native/provider checkpoints are only replayed on the model that produced them.

### 3.5 Event bus and observability

**Sources:** `packages/core/src/bus.ts:1-160+`, `packages/core/src/session/runner/publish-llm-event.ts` (610 lines), `packages/core/src/event-logger.ts`, `packages/core/src/session/event.ts` (re-export).

**Mechanisms:**
- Events are typed definitions (`ephemeral` / `durable` / `versionedType`, `bus.ts:98-100`). Durable events are persisted with a per-aggregate sequence (`reserveSequence`, `:35-49`), decoded through a single legacy-upgrade path (`:80-96`).
- `PublishOptions.commit?(seq)` (`:102-109`): an operational projection committed atomically with the durable event; not replayed.
- `subscribe()` is a volatile live stream; reliability comes from combining it with an event `log` (`:132-145`).
- LLM events are translated into message-level events by `createLLMEventPublisher` (used in `step.ts:92-100`), which also records: `providerFailed`, `outputStarted`, `finish`, and per-call tool outcomes; snapshots and usage are attached at `Step.Ended` (`step.ts:289-315`). OpenTelemetry-style spans use `gen_ai.*` semantic attributes (`step.ts:83-91,224-235`).

**Strengths:** durable audit trail + low-latency live channel; standardized observability attributes; a single writer (publisher) for streamed message state.

**Weaknesses:** volatile subscribe means a reconnecting client must replay the log; projection idempotency is a distributed-correctness burden.

**Adapt to AgentBug:** AgentBug has `EventBus::global().publish_json` plus durable `store.add_event` (`lib.rs:611-623`) - the right shape. Add: monotonic per-session event sequence numbers, typed event names (instead of free-form strings), and OpenTelemetry `tracing` spans with `gen_ai.*` fields so model time, tool time, and cost are separately measurable.

---

## 4. Context management

### 4.1 Two-phase context selection/loading

**Source:** `packages/core/src/session/context.ts:1-273`. `Selection` (`:37-42`), `Loaded` (`:44-51`), `Interface` (`:59-78`).

**Execution path:**
- `select(sessionID)` (`:148-208`): rejects cross-Location sessions (`Effect.interrupt`, `:151-152`); selects the agent; **merges agent + session permissions** (`:157-158`); samples model availability/websearch/flags concurrently (`:159-166`); builds a `Tool.Snapshot` narrowed by those permissions and a model-dependent policy (`modelTools`, `:169-177`); loads instruction sources concurrently and combines them in a deliberate order (`:178-207`): code-mode catalog, MCP, references, skills, machines, discovery, built-ins, entries - "ordered from most to least shared across sessions so the baseline stays a reusable prompt-cache prefix" (`:193-195`).
- `load(selection)` (`:210-226`): resolves the model for kind `"primary"` and reads history with `SessionHistory.entriesForRunner`.
- `selectTitle` (`:111-146`): picks a small/low-reasoning model variant for title generation (`MINIMAL_REASONING_VARIANTS = none/minimal/low`, `:232-245`).

**Strengths:** the two-phase split keeps request preparation separate from selection; instruction ordering is explicitly optimized for prompt caching; permission narrowing applies to both discovery and the tool snapshot.

**Weaknesses:** `select` touches many services; a slow MCP/instruction source delays every step (mitigated only by unbounded concurrency).

**Adapt to AgentBug:** Introduce a `ContextBuilder` that produces an immutable `AgentContext {system_parts, history, tool_snapshot, resolved_model, permissions}` in two stages (`select` = cheap capability resolution; `load` = history + model). Preserve the "instructions ordered from most-shared to least-shared" rule - AgentBug's system prompt is currently assembled ad hoc in `run_goal` (`lib.rs:1298-1318`), with no cache-prefix discipline.

### 4.2 System prompt composition

**Sources:** `packages/core/src/session/system-prompt.ts:1-28`, `packages/core/src/session/runner/prompt/system.txt` (base prompt), `packages/core/src/session/model-request.ts:106-137`.

- `baseTranscript` builds `system` as `[SystemPart(agent.system ?? SessionSystemPrompt.make(toolNames)), SystemPart(Instructions.join(initial)) with metadata]` (`:116-126`).
- `SessionSystemPrompt.render` conditionally injects tool guidance: shell ("prefer dedicated tools", no noisy command chaining), write ("prefer edit for targeted changes"), edit (exact-string semantics) (`:9-27`). The base `system.txt` sets the harness frame (Markdown rendering, `<system-update>` blocks, prefer parallel tool calls).
- A specialized agent can supply its own `system` string, bypassing the default entirely (`agent.ts` schema `system?`, `agent.ts:28`).

**Strengths:** tool guidance is generated from the *actual* advertised tool set, so the model is not told about tools it cannot call; agents can fully override the prompt.

**Weaknesses:** string templating with a single `OPENCODE_TOOL_GUIDANCE` placeholder is brittle as guidance grows.

**Adapt to AgentBug:** Generate a structured system prompt from typed sections (identity, harness rules, tool-specific guidance derived from the *filtered* tool list, engagement scope) and hash/cache it per tool-set. AgentBug currently appends the engagement scope to a hardcoded string (`lib.rs:1298-1304`).

### 4.3 History to LLM messages

**Source:** `packages/core/src/session/runner/to-llm-message.ts:1-320`.

**Key mechanics:**
- Each stored message type maps to canonical messages (`toLLMMessage`, `:245-313`): user (skills + text + attachments), synthetic/skill/shell (as user text), system, assistant (`:146-225`), compaction (checkpoint or native window) (`:292-310`); `agent-switched`/`idle` produce nothing; `model-switched` can emit an "effort" marker.
- Assistant lowering (`:146-225`) is the subtle part: on a failed/aborted stream it truncates content after the last locally executed tool result so the retry does not end on an assistant reply; it drops unfinished tool calls but keeps input errors; reasoning is only replayed once the model moved on; model-scoped provider metadata (Gemini signatures, OpenAI encrypted reasoning) is replayed only to the same model, while hosted-tool results are replayable across models of the same provider (`:202-211`).
- Tool results are emitted as separate `Message.tool` entries; completed calls become `ToolResultPart`, errors become error results (`:114-140,218-224`).

**Strengths:** replay correctness across model switches and partial streams is handled in one place; native compaction windows decode through a schema.

**Weaknesses:** complex heuristics with many message-type branches; attachments and media must be consistent with the separate media-budget pass in `model-request.ts`.

**Adapt to AgentBug:** Isolate a pure `history_to_messages(history, target_model) -> Vec<ChatMessage>` function in `agentbug-llm` and test it heavily: (a) truncate after the last completed tool on a failed step, (b) drop calls that never ran, (c) mark which provider metadata is model-scoped. AgentBug's `build_llm_messages` (referenced `lib.rs:1798`) should gain these rules before adding multi-provider/subagent support.

### 4.4 Compaction, token budgeting, and background summarization

**Source:** `packages/core/src/session/compaction.ts:1-1152`. This is the most sophisticated context subsystem.

**Main structures:**
- `Settings {auto, buffer?, keep, background}` (`:41-49`); defaults `{auto:true, keep:15000, background:true}` (`:264-272`).
- `Estimate {measured, estimated}` (`:55-56`): measured = provider count at last response, estimated = text since.
- `Trigger = {reason:"auto"|"overflow", context, estimate?} | {reason:"manual", context, inputID}` (`:58-63`).
- `Outcome = skipped | completed | failed{error}` (`:64-69`).
- `Precomputed` (`:110-120`): a held background summary with `keepID`, `tailLimit`, `failures`, usage, fiber.
- Key constants (`:122-168`): `SHRINK_STEPS=[0.85,0.7,0.5,0.35]`, `RESERVE_MIN=16000`, `RESERVE_SHARE=0.15`, `UNKNOWN_WINDOW=200000`, `SUMMARY_OUTPUT_FLOOR=32000`, `TRANSCRIPT_LEVELS` (whole, outputs clipped, outputs removed, user-only, omitted), `TRANSCRIPT_CLIP=2000`, `PRECOMPUTE_LEAD=60000`, cache lifetime 5 min, `PRECOMPUTED_TAIL_SHARE=0.4`, `PRECOMPUTE_MAX_FAILURES=2`.
- `SUMMARY_TEMPLATE` / `SUMMARY_RULES` (`:170-209`): structured checkpoint sections (Objective, Requirements, Decisions, Work State, Next Move, Relevant Files, Important Context); `buildPrompt(update, legacy)` (`:211-242`).

**Execution path:**
- `compact(trigger)` (`:298-336`): skip if auto-off (except manual) or not due; select the compaction model (special "compaction" agent, else current) (`:274-296`); on overflow aim below `SHRINK_STEPS[0]` of rejected size (`:313-317`); use a held precomputed summary if valid, else native or textual summarization; publish Started/Delta/Failed/Completed.
- `precompute(...)` (`:348-402`): when within `PRECOMPUTE_LEAD` of the ceiling, summarize everything before the latest provider-processed response **in the background**, reusing the prompt cache; hold it until compaction is due, replacing it on drift/failure. Swapping early would rewrite the cached prefix (`:338-347`).
- `summarize(...)` (`:461-541`): sends the whole conversation + summary prompt (reuse cache), with a nudge if the template is not filled; sizes output with `fitOutput`; uses kept tail via `splitConversation`. Checkpoint format diagram at `:441-460`.
- `deliver(...)` (`:608-696`): retry/shrink loop - send unchanged if it fits `fit`, else shrink history as text; on "too long" aim at 85/70/50/35% of the rejected size; on "payload too large" resend as text; otherwise apply the retry policy.
- `flattenAndDropOldest(...)` (`:710-778`): renders exchanges at five detail levels and shortens oldest-first (newest is never omitted) until the text fits.
- `compactNatively(...)` (`:555-593`): provider-native compaction via `ai.canCompact`/`llm.compact`, storing an encrypted replacement window.

**Strengths:** background precompute makes compaction nearly free at the moment it is needed; all shrinking preserves the provider prompt-cache prefix where possible; explicit template validation and "newer history wins" update rules; separate native and textual paths.

**Weaknesses:** very high complexity and many magic numbers; depends on provider-specific overflow phrasing and cache TTL; the "kept tail by reference" reconstruction couples compaction and history tightly.

**Adapt to AgentBug:** Adopt the *shape* in stages: (1) a deterministic `ContextBudget {ceiling, reserve, keep, estimate}` with `float | measured` token accounting (AgentBug currently estimates tokens as `len/4` with a total-session cap, `lib.rs:144-146,1819-1836`); (2) a structured summary template and a `compaction` LLM flow; (3) store a summary message plus a `keepID` reference and rebuild the tail from the event log; (4) only then add background precompute. Do NOT copy the overflow regex soup - keep the typed `LlmErrorKind` from section 2.4.

---

## 5. Tool runtime

### 5.1 Registry, snapshots, discovery, and execution

**Source:** `packages/core/src/tool.ts:1-544`.

**Main structures:**
- `Tool.Info<Input,Output,CMInput,CMOutput>` (`packages/schema/src/tool.ts:114-130`): `name`, `input` schema, `description`, `execute(input, context) -> Effect<Result>`, `output?` schema, `options?{namespace, codemode}`; `freeform?`.
- `RegisteredTool = Tool.Info & {id}`; `Data {tools, definitions, namespaces, errors}` (`:37-61`). `definitions` are converted **once at registration** (`:57-58`).
- `Snapshot {definitions, codeModeCatalog?, execute({sessionID,agent,messageID,call,progress?,cancel?,definitions?}) -> NormalizedResult}` (`:101-115`). This snapshot is what the runner advertises and executes against for a Step.
- `Policy {hidden?, direct?}` and `SnapshotOptions {services?, tools?}` (`:63-75`).
- `RegistrationError` (`:32-35`).

**Execution path:**
- `commit`/`register` (`:451-470,491-533`): normalize the name (`[^A-Za-z0-9_-] -> _`), validate namespace, reject reserved name `execute`, validate the input schema and JSON-schema conversion; failures are recorded (not thrown) and logged (`:285-298`).
- `snapshot(permissions, options)` (`:305-403`): filter hidden/wholly-disabled tools; partition tools into direct vs Code Mode by policy and model capability; cache catalogs by registry revision + visible set (`:236-242,329-364`); sort definitions for stable prompt caches (`:367-371`).
- `execute` (`:169-220`): span annotation; run `execute()` from `runtime.ts`; fire `tool.execute.before` hook (which may rename the call), then `tool.execute.after` (which may rewrite results), then normalize images/content.
- Hook-driven rename resolution is by **object identity** of the definition, with a name fallback (`:382-399`).

**Strengths:** a snapshot is an immutable capability boundary per Step; plugin hooks can observe and rewrite tool calls/results without changing the registry; invalid registrations degrade gracefully.

**Weaknesses:** Code Mode (tools invoked as generated TypeScript programs) adds substantial complexity; definition caching has a five-entry LRU with identity invalidation (`:480`, `:312-315`).

**Adapt to AgentBug:** AgentBug's `ToolRegistry` (`agentbug-tools`) should expose `snapshot(permissions, model) -> ToolSnapshot` that returns both the JSON schemas sent to the LLM and a `dispatch(call, ctx)` closure bound to that snapshot, so a tool removed mid-run cannot be executed by an old request. Keep validation at registration and execution boundaries but make it a single typed `ToolSpec` with `input_schema: serde_json::Value` plus a Rust-side decoder.

### 5.2 Validation and result serialization boundary

**Source:** `packages/core/src/tool/runtime.ts:1-311`.

- `definition(tool)` (`:27-38`): converts input/output schemas to JSON Schema (`emptyInputJsonSchema`, `toJsonSchema`, Standard Schema vendors such as Zod/ArkType).
- `execute(tool,input,context)` (`:40-74`): decode input, call `tool.execute`, **re-map any foreign thrown error into `Tool.Error` at the untrusted boundary** (`:44-57`) so downstream `catchTag("Tool.Error")` cannot be bypassed; validate declared output; normalize content.
- Input issues are formatted into a model-friendly message that includes the bad JSON and "Update the arguments and call the tool again" (`:101-113`) - errors are returned to the model, not just logged.
- JSON Schema normalization (`:187-283`): flatten `allOf`, inline local `$ref`s, drop unused `$defs`, strip safe-integer bounds - specifically to keep provider-acceptable schemas and **stable prompt caches**.
- `normalizeContent` (`:285-289`): string -> text part; empty -> `stringify(output)`.

**Strengths:** an explicit trust boundary that converts arbitrary plugin failures into typed tool errors; model-actionable validation messages; provider-compatible schema normalization.

**Weaknesses:** supports a wide schema zoo (Effect Schema, Standard Schema, raw JSON Schema); the normalization code is intricate.

**Adapt to AgentBug:** Keep a strict boundary in `agentbug-tools`: `execute()` should return `Result<ToolOutput, ToolError>` for *all* failures (never panic/poison the step), with validation errors rendered into the tool result text so the model can self-correct. Normalize JSON Schema once at registration and freeze it (do not regenerate per request) to keep request bytes stable.

### 5.3 Permissions inside tool calls

Tool execution consults `Permission.Service` via `executeTool`: file paths, shell commands, and `subagent` are all permission actions. The `Permission.invocation(context)` helper (`permission.ts:39-44`) stamps the tool call's `messageID` and call `id` as the request source. A decline is tunneled as a **defect** so a tool cannot catch it and return model-visible output; it is recovered only at `SessionModelRequest.executeTool` (`model-request.ts:441-459`). A decline *with feedback* becomes a typed `CorrectedError` that the leaf turns into a tool failure so the model can continue (`permission.ts:69-75,300-312`).

**Adapt to AgentBug:** Mirror this: a hard denial must not be convertible into a tool result that the model can argue with; it should abort the step. A "corrected/try-again-with-feedback" reply should be delivered as a tool result. AgentBug's guarded calls already write `DENIED ...` into the tool message (`lib.rs:971-1006`) - consider separating hard-deny (terminal) from feedback (continuable) to avoid leaking authority to the model.

---

## 6. Agent specialization and delegation

### 6.1 Agent registry and built-in agents

**Sources:** `packages/core/src/agent.ts:1-115`, `packages/schema/src/agent.ts:22-54`, `packages/core/src/plugin/agent.ts:1-119`.

**`Agent.Info` schema** (`schema/agent.ts:23-35`): `id, name, model?, request, system?, description?, mode: "subagent"|"primary"|"all", hidden, color?, steps?, permissions`. Default permissions allow all except `.env` reads which ask (`:46-51`). Default agent ID is `build` (`agent.ts:13`).

**Agent service** (`agent.ts:40-115`): `get, resolve, select, list` over a `State`-backed map; `selectable = mode !== "subagent" && !hidden` (`:53-54`); `selectedDefault` prefers configured default, then `build`, then any selectable (`:55-64`); ordering puts the selected agent first (`:65-70`). Updates publish `Agent.Event.Updated`.

**Built-in agents** (`plugin/agent.ts:52-118`):
- `build` (default primary): "Executes tools based on configured permissions", can `question`.
- `general` (subagent): general-purpose parallel work; denies `question` and nested `subagent`.
- `explore` (subagent): read-only file search specialist with a full custom system prompt (`PROMPT_EXPLORE`, `:7-17`); deny-all then allow shell/grep/glob/webfetch/websearch/read (+ `.env` ask) and external_directory; deny subagent.
- `compaction`, `title`, `summary`: hidden primary agents with specialized system prompts and deny-all permissions.

**Strengths:** specialization is data (an `Info` record), not code; permissions and `steps` are per-agent; hidden/selectable modes separate UI presence from executability.

**Weaknesses:** the built-ins are defined in a plugin via mutation callbacks, so the effective definition is spread across schema defaults, the plugin, and user config.

**Adapt to AgentBug:** Define agents as declarative config (`AgentSpec {id, mode, system_prompt?, model?, tool_allow/deny, max_steps, permissions}`) in `agentbug-core` or config, with built-ins shipped as data files. AgentBug's `AgentConfig` (`lib.rs:306-375`) already carries `mode`, `system_prompt`, `max_steps`, and budgets; extend it with `tool_permissions` and `model` reference, and add `hidden`/`subagent` modes. Keep the default "deny `.env`" style baseline.

### 6.2 Subagent delegation tool and lifecycle

**Sources:** `packages/core/src/tool/plugin/subagent.ts:1-269`, `session/subagent-job.ts:1-61`, `session/subagent-completion.ts:1-82`, `session/subagent-depth.ts:1-21`, `session/execution/subagent-report.ts:186`.

**`subagent` tool Input** (`subagent.ts:30-44`): `agent`, `description`, `prompt`, optional `model` ("providerID/modelID#variant", only when explicitly requested), optional `sessionID` for follow-ups. Output is always `{sessionID, status:"running", output}` with a directive: "DO NOT sleep, poll, proactively check on its progress, or duplicate this subagent's work" (`:19-28`).

**Execution path (`:109-218`):**
1. Load parent; enforce `SubagentDepth.reached` using `experimental.subagent_depth` (default 1) (`:118-126`, `subagent-depth.ts:9-21`).
2. Resolve agent; reject primary agents as subagents (`:127-130`); assert `subagent` permission on the agent id (`:131-138`).
3. A follow-up must be a child of the current session (`:140-154`); model resolution precedence: explicit override > agent model > parent model (`:155-171`).
4. Create a child Session (`parentID`, agent, model) or reuse; prompt it with `resume: false` when not already running (the job's `resume` owns the start) (`:171-207`).
5. Start a `SubagentJob` (background Job whose run is `execution.resume(childID)`), then return `backgroundResult` (`:209-217`).

**Completion/reporting:** `SubagentCompletion.deliver` (`:56-82`) emits a `<subagent sessionID=... state=... description=...>` synthetic message into the **parent** session, with status completed/error/cancelled and a note about still-running background work. `subagent-job.ts:32-39` ensures only an explicit caller cancel releases the child's claim (shutdown leaves it resumable). The tool description is dynamically augmented with the list of available subagents via session context hooks (`:240-267`).

**Strengths:** subagents are just Sessions - they inherit the entire durable execution, permission, compaction, and event machinery; depth limiting and permission checks prevent delegation loops; the parent is notified asynchronously rather than blocking.

**Weaknesses:** everything is background - no synchronous handoff mode; depth default of 1 limits useful hierarchies; the `<subagent>` message format is a textual protocol.

**Adapt to AgentBug:** AgentBug has no subagents yet. Implement them as child sessions in `agentbug-store` with `parent_id`, reusing the existing `ExecutionCoordinator` and inbox. Port: (a) depth cap (config, default 1), (b) `agent.mode` gate (cannot spawn a primary as subagent), (c) a `subagent` permission action, (d) explicit model precedence override > agent > parent, (e) a completion synthetic message with a typed metadata envelope (not just text). Reuse `request_stop`/leases for cancellation.

---

## 7. Permission architecture

**Source:** `packages/core/src/permission.ts:1-417`; schema `packages/schema/src/permission.ts:1-67`; persistence `packages/core/src/permission/saved.ts`.

**Main structures:**
- `Rule {action, resource, effect: allow|deny|ask}`; `Ruleset = Rule[]` (schema `:56-66`).
- `Request {id, sessionID, action, resources[], save?, metadata?, source?, message?}` (schema `:26-40`); `Reply = once|always|reject` (`:42-43`).
- Errors: `DeclinedError`, `CorrectedError{feedback}`, `BlockedError{rules,permission,resources,reason}`, `NotFoundError` (`permission.ts:67-92`).
- `Unattended` context reference: rules that settle asks when nobody is present (`:59-65`).
- `pathActions = external_directory, read, edit`; macOS case-insensitive matching (`:94-100`).
- Pending asks: `Map<ID, {request, agent?, deferred}>` (`:142-159`).

**Evaluation (`evaluate`, `:102-115`):** flatten all rulesets, find the last rule whose action and resource match (wildcards via `Wildcard.match`), default `{effect:"ask"}`. `merge(...rulesets)` is simple concatenation (`:117-119`); `configured(sessionID, agentID)` merges **agent permissions first, then session permissions** (`:186-191`), so session rules win. `evaluateInput` (`:212-238`): configured denies win; otherwise evaluate configured + saved "always" approvals; fire the `permission.evaluate` plugin hook (which can change the effect); apply Unattended rules for asks. `ask` publishes `Permission.Event.Asked` (`:269-271`). `assert` (`:284-316`): deny -> `BlockedError`, allow -> return, ask -> await a Deferred until `reply`.

**Reply batching (`:334-395`):** a `reject` with feedback becomes `CorrectedError`; rejecting one request rejects all pending requests from the same message (parallel asks) so feedback applies to the whole batch (`:351-365`); `always` saves a rule and auto-approves other pending requests now allowed (`:369-392`). `close()` rejects all pending asks on shutdown (`:161-174`).

**Strengths:** ordered, composable, wildcard rules with a safe "ask" default; saved approvals persist as allow rules; batch semantics make multi-tool approval coherent; a hook can adjust decisions; unattended mode handles scheduled work.

**Weaknesses:** the "defect tunnel" for declines (`:300-312`) is a subtle control-flow trick that must be carefully reproduced; `evaluate` is O(n) linear scan per resource; `ignoresCase` is platform-specific.

**Adapt to AgentBug:** AgentBug has `agentbug-policy` (`PolicyEngine`, `Decision::{Allow,Deny,Ask}`, `Mode`, scopes/approvals) and already does careful approval parking (`lib.rs:885-969`). Port these specific patterns: (1) **last-match-wins wildcard rules** merged agent-then-session; (2) **batch rejection/feedback** across all tool calls in one assistant message; (3) **"always" saves a durable allow rule** (AgentBug has `Approval`/`list_approved_targets` but no generic rule save); (4) an explicit **unattended** policy for scheduled/background work; (5) keep the hard-decline-vs-feedback distinction (section 5.3).

### 7.1 Scope boundaries in practice

Agent permissions are the real tool boundary: `explore` is deny-all-plus-explicit-allows (read-only + web), `title`/`summary` are deny-all, `general` denies question and nested subagents. Permission actions observed in source include: `read`, `edit`, `write`, `shell`, `grep`, `glob`, `webfetch`, `websearch`, `external_directory`, `question`, `subagent`, `execute` (Code Mode), plus tool names. File actions are path-resource rules; shell is a tool action; Code Mode can be wholly disabled via a `deny *` on `execute` (`tool.ts:472-478`).

**Adapt to AgentBug:** Extend `agentbug-policy::ActionRequest` to carry `{tool, risk, target, session, agent}` and evaluate wildcard rules over `action:resource`, so the same engine governs tool access, file paths, shell, network targets, and delegation. This unifies AgentBug's current separate `policy.evaluate` + `budget_gate` + `auto_approve_tools` paths (`lib.rs:910-968`).

---

## 8. Provider abstraction, streaming, observability, config, extensibility

### 8.1 Provider/model abstraction and streaming

**Sources:** `packages/core/src/provider.ts:1-517`, `packages/core/src/model-resolver.ts:597`, `packages/core/src/model.ts:339`, `packages/ai/src/llm.ts:1-240+`, `packages/ai/src/effect.ts:1-44`, `packages/ai/src/route/client.ts` (LLMClient).

- `provider.ts` maintains a static `builtins` map of dozens of lazily-imported provider packages (`:30-140+`) plus dynamic packages via NPM and credential/integration wiring. Provider plugins populate and filter the model catalog asynchronously during layer startup (`context.ts:87`, `runner/model.ts:87`).
- `effect.ts`: `ai = {request, generate, stream, loop, collect, compact, canCompact, image, decision, embedding, ...}` - the same shape as a plain SDK but returning Effect/Stream (`:9-27`).
- `llm.ts`: `stream(input)` -> `Stream<LLMEvent, AIError>` over one model call (`:110-128`); `loop(input)` is an *optional* in-memory tool loop for simpler consumers (`:130-167`) - **not used by the Session runner**, which uses `stream`. `stepStream` (`:196-226`) folds provider frames into a `ResponseFold`, holds back `finish`, and attaches partial responses to errors (`withPartial`).
- Model resolution (`runner/model.ts:88-129`): explicit session model > agent model > resolver fallback; a plugin hook may substitute a same-provider model for kind-specific work (title/compaction); `Resolved {model, ref, capabilities, cost, limit, compaction?, transport?}` (`:57-79`).

**Strengths:** a single canonical request/event schema across all providers; provider features (native compaction, transport=websocket, variants, cache TTL) are first-class model metadata; streaming frames are folded consistently and partial output survives errors.

**Weaknesses:** very large provider surface; lazy imports and async catalog population add startup complexity.

**Adapt to AgentBug:** Define a Rust `Llm` trait (already exists: `agentbug-llm::Llm`, used at `lib.rs:579`) with `stream_chat(&Request) -> Stream<ChatEvent>` as the primitive, plus `resolve_model() -> ModelInfo{limits, cost, capabilities, compaction}`. Keep an OpenAI-compatible adapter first; add variants/capabilities to `ModelInfo` so compaction and transport decisions are data-driven. Avoid an in-memory `loop` in the kernel - AgentBug's single-call-per-step already matches OpenCode's production path.

### 8.2 Configuration, plugins, and hot reload

**Sources:** `packages/core/src/config.ts`, `packages/core/src/plugin/*`, `packages/core/src/config/watch.ts`, `packages/core/src/agent.ts`, `packages/core/src/state.ts`.

- Configuration is a typed schema with normalization and variable substitution; agents/tools/MCP/instructions/plugins are config sources. A `State.create<Data,Editor>` pattern backs mutable registries (agent `agent.ts:71-91`, tool `tool.ts:243-299`, compaction `compaction.ts:264-272`): editors mutate a draft; `notify` publishes a change event and invalidates caches.
- Plugins can register agents, tools, hooks, and model/provider packages. Hooks include `session.*` (prompt, context, model.request, http.request/response, retry, idle, ws.*), `tool.execute.before/after`, `permission.evaluate`, and agent/tool registration transforms. `plugins.awaitActivation` is called at boundaries so a mid-turn plugin reload is respected (`llm.ts:77,229,306`).
- MCP tools are flushed/reloaded at context selection (`context.ts:154`).

**Strengths:** nearly every extension point is hookable; config reload is first-class; registries have a uniform editor/notify contract.

**Weaknesses:** the hook surface is enormous and loosely typed; `awaitActivation` points must be remembered at every boundary.

**Adapt to AgentBug:** Keep the extension surface small initially: a `ToolRegistry` trait object and a `Policy` trait object, with typed extension hooks only where needed (before/after tool, classify-error). If hot reload is required, snapshot the config into an `Arc<Config>` per Step (like OpenCode's tool snapshot) rather than mutating shared state mid-Step.

### 8.3 Observability and recovery summary

- Tracing: `gen_ai.provider.name`, `gen_ai.request.model`, `gen_ai.agent.name`, `gen_ai.tool.name/call.id`, `gen_ai.response.finish_reasons`, `gen_ai.usage.*`, `opencode.llm.first_output_ms`, `opencode.usage.cost_usd`, `opencode.retry.attempt` (`step.ts:83-91,224-235`, `tool.ts:175-180`).
- Durable events: every meaningful transition has an event (`SessionEvent.*`, `Permission.Event.*`, `Agent.Event.*`), persisted with sequence numbers and optionally an atomic local projection (`bus.ts`).
- Recovery: stale compaction/tool settlement (`llm.ts:389-442`), write-ahead claims + bounded resume (`restart.ts`), native/textual compaction replay boundaries (`history.ts`).

**Adapt to AgentBug:** AgentBug already persists events and uses `tracing`; add per-session sequence numbers, gen_ai span attributes, and the boot-time stale-settlement pass. These are high-value, low-risk wins.

---

## 9. Cross-cutting assessment and prioritized adapt-to-AgentBug roadmap

### 9.1 What AgentBug already does that matches OpenCode (keep these)

- Single LLM call per step with history reloaded from the store (`lib.rs:1750-1798`).
- Durable event log plus an in-process event bus (`lib.rs:611-623`).
- Execution claims/leases, cross-process stop flag, stale-session recovery (`lib.rs:688-707,805-828,670-686`).
- A unified policy/guard chain with approval parking, budget gates, duplicate-call guard, target cooldowns, and injection detection (`lib.rs:885-969`).
- Compaction scaffolding (`crates/agentbug-core/src/compaction.rs`, 225 lines) and inbox/execution/step modules already split out.

### 9.2 Highest-value patterns to adopt (ordered)

| Priority | Pattern | Evidence | AgentBug action |
| --- | --- | --- | --- |
| P0 | Typed LLM error taxonomy with recovery hints | `provider-error.ts:198-260`, `step.ts:198-259` | `LlmErrorKind` enum in `agentbug-llm`; bind ContextOverflow to compaction, RateLimit/Server/Unknown to backoff, Auth/Policy to terminal. |
| P0 | Cooperative tool cancellation with bounded grace | `step.ts:106-117,372-401` | `CancellationToken` + `timeout(5s)` then abort; persist a terminal record for every tool call. |
| P0 | Admission vs delivery with steer/queue/control | `inbox.ts:52-57,176-282`, `llm.ts:71-76` | Add `delivery` to `inbox.rs`; promote steers first, one queue item only at idle; allow cancel/steer while pending. |
| P1 | Doorbell/coalescing execution coordinator | `run-coordinator.ts:73-144,170-175` | Add `pending_wake` to `ExecutionCoordinator`; re-drain on late wake; re-check in `await_idle`. |
| P1 | Boot-time stale-settlement + bounded resume | `llm.ts:389-442`, `restart.ts:38-48,101-120` | Sweep unfinished tool calls/compactions at boot; per-turn resume counter capped at 10. |
| P1 | History-to-messages replay rules | `to-llm-message.ts:146-225` | Truncate after last completed tool on failed steps; drop calls that never ran; scope provider metadata to the model. |
| P1 | Last-match-wins wildcard permissions with batch replies | `permission.ts:102-119,334-395` | Unify policy rules as `action:resource` wildcards; batch reject/feedback; save "always" rules. |
| P2 | Per-request output budget + cache-aware media handling | `model-request.ts:50-104,139-253` | Compute `max_tokens` from window minus measured/estimated input; stable image-drop cuts. |
| P2 | Structured compaction summary + kept-text reference | `compaction.ts:170-209,441-541` | Structured summary template; store `summary + keep_id`; rebuild tail from event log. |
| P2 | Declarative agent specialization + subagents as child sessions | `plugin/agent.ts:52-118`, `subagent.ts:109-218` | `AgentSpec` config data; child sessions with depth cap, permission gate, typed completion envelope. |
| P3 | Background summary precompute | `compaction.ts:338-402` | Only after the above; reuse the cached prefix and swap at the threshold. |
| P3 | Typed hook/extension points and hot reload | `tool.ts:169-234`, `model-request.ts:360-433` | Snapshot config per Step via `Arc`; minimal typed before/after hooks. |

### 9.3 Design cautions when translating Effect patterns to Rust

- Effect **fibers + Deferred + uninterruptibleMask** have no direct std equivalent. Use `tokio::task::JoinHandle`/`AbortHandle`, `tokio::sync::Oneshot`/`Notify`, and explicit state machines; do not try to replicate mask semantics implicitly - make terminal settlement an explicit async step that always runs.
- The "defect tunnel" for permission declines (`permission.ts:300-312`, `model-request.ts:441-459`) relies on Effect's error channel. In Rust, encode this as a dedicated enum variant that `?` cannot accidentally convert into a tool result.
- Event-sourced projections require idempotent, deterministic reducers. If AgentBug keeps direct `store.add_message` writes, document that it is a hybrid (durable log for audit + direct read-model writes) and ensure every write path emits the corresponding event.
- Do not copy the compaction heuristics verbatim; implement the *invariants* (reserve headroom, newest exchange never omitted, prompt-cache prefix stability, typed overflow classification).

### 9.4 One-paragraph takeaway

OpenCode's kernel is strongest where it is explicit about boundaries: Step = one model call from reloaded history; admission is not delivery; a per-session doorbell owns execution; permissions are ordered rules with a safe ask default; tool execution is a typed, validated boundary; and context compaction is a cache-aware, budgeted, crash-recoverable subsystem. AgentBug already has the skeleton (per-step loop, store, claims, policy, compaction module). The most valuable next moves are not more features but **more explicit state machines and typed boundaries** around cancellation, inbox delivery, error classification, and permission replies - then subagents and background summarization can be layered on the same durable primitives.

---

## 10. Source-signal appendix (quick reference map)

- Execution loop: `session/runner/index.ts` (interface) -> `llm.ts:63` (drain) -> `llm.ts:237` (runStep) -> `step.ts:77` (attempt) -> `session/model-request.ts:273` (request) -> `ai/llm.ts:118` (stream).
- Tool call path: `step.ts:118-159` (fork) -> `model-request.ts:445` (executeTool) -> `tool.ts:373-400` (snapshot.execute) -> `tool.ts:169-220` (hooks) -> `tool/runtime.ts:40-74` (validate) -> tool implementation -> `publisher.toolExecution` (`publish-llm-event.ts`).
- Permission path: tool -> `Permission.invocation` (`permission.ts:39-44`) -> `assert` (`:284`) -> `evaluateInput` (`:212`) -> hook -> ask/Deferred -> `reply` (`:334`).
- Context path: `context.ts:148` (select: agent/permissions/tools/instructions) -> `:210` (load: model + `history.ts:290`) -> `model-request.ts:106` (baseTranscript) -> `to-llm-message.ts:316` (toLLMMessages) -> media filters -> `ai.request`.
- Compaction path: `llm.ts:253` (estimate/compact) or `:129-151` (manual) -> `compaction.ts:298` (compact) -> `selectModel`/`deliver`/`summarize` -> `publish` -> history boundary in `history.ts:55-88,193-239`.
- Session lifecycle: `session.ts:149` (prompt/admit) -> `execution.ts:91-179` (wake/coordinator) -> `run-coordinator.ts` -> `llm.ts` drain -> terminal events -> `restart.ts` recovery on boot.
- Subagents: `tool/plugin/subagent.ts:109-218` -> child `sessions.create/prompt` -> `subagent-job.ts` -> `subagent-completion.ts:56-82` synthetic report to parent.

**End of report.**
