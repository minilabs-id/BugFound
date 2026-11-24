# Agent Harness Patterns - LangGraph, Temporal, Goose, Rig vs. the BugFound Universal Kernel

> **About these notes.** These are point-in-time analyses of third-party reference
> projects, kept for design input. They describe the reference projects at the
> snapshots examined and are not claims about the current BugFound code; verify
> current behavior in `crates/`.

**Research basis:** actual pinned source trees (not marketing docs), read-only inspection with line evidence. Patterns are extracted and translated into design recommendations; no code is copied.
**Target:** `crates/bugfound-*` - the Rust-native universal agent kernel described in `docs/architecture.md`.
**Companion documents:** `01_opencode_analysis.md` (process-local execution baseline), `04_security_agents.md`, `05_mcp_provider_abstraction.md`.

## Pinned commits (recorded as requested)

| Repo | Absolute checkout path | Commit hash | Commit subject (date) |
| --- | --- | --- | --- |
| LangGraph | `D:\Github\BugFound\research\langgraph` | `58a6e1cc5b7dfc3619fc6e7e7573b040d554649b` | `release(langgraph): 1.2.24 (#9752)` (2026-11-20) |
| Temporal | `D:\Github\BugFound\research\temporal` | `a8f8328b001bd3302e658cdd062e18a5e92cf50f` | `WHN impl 1: the overall framework (#12991)` (2026-11-19) |
| Goose | `D:\Github\BugFound\research\goose` | `42055e73fda21edd8f3056a5eef682d08589aef0` | `fix(google): send thinking levels to Gemini 4 and later, including xhigh (#13673)` (2026-11-20) |
| Rig | `D:\Github\BugFound\research\rig` | `da8d6a935bdbe3bc9b6a72a56859df0100d2e998` | `feat(rig-basics, rig-memory, rig-ecs, rig-core)!: minimal compaction on the kernel's turns, queue and retries (#3436)` (2026-11-19) |

All line numbers below are 1-based and refer to those exact trees. Paths are absolute from each checkout root; the tables give the relative path for readability.

> Note on Temporal: the clone is shallow, so the pinned tip carries the whole tree. Documentation links inside `docs/architecture/*.md` point at older upstream commit SHAs; those are upstream references, not this pin. Line evidence cited here is from the pinned tree.

---

## 0. Scope and file inventory

### 0.1 LangGraph (`libs/` monorepo)

| File | Lines | Role |
| --- | ---: | --- |
| `libs/langgraph/langgraph/graph/state.py` | 1696 | `StateGraph` builder, nodes/edges/conditional routing, `compile()` |
| `libs/langgraph/langgraph/pregel/main.py` | 4173 | `Pregel` runtime, invoke/stream/resume entrypoints |
| `libs/langgraph/langgraph/pregel/_loop.py` | 2106 | The Pregel loop: supersteps, checkpoints, interrupt/resume |
| `libs/langgraph/langgraph/pregel/_algo.py` | 1369 | BSP write application and next-task preparation |
| `libs/langgraph/langgraph/pregel/_checkpoint.py` | 476 | Checkpoint creation/restore from channels |
| `libs/langgraph/langgraph/pregel/_retry.py` | 778 | Retry scheduling for failed tasks |
| `libs/langgraph/langgraph/types.py` | 877 | `RetryPolicy`, `TimeoutPolicy`, `CachePolicy`, `Interrupt`, `Command`, `Send` |
| `libs/langgraph/langgraph/channels/{last_value,binop,named_barrier_value}.py` | 115/132/133 | State reducers, fan-in barriers |
| `libs/checkpoint/langgraph/checkpoint/base/__init__.py` | - | `Checkpoint`, `CheckpointTuple`, `BaseCheckpointSaver` |
| `libs/checkpoint-sqlite/langgraph/checkpoint/sqlite/__init__.py` | - | SQLite checkpoint saver (closest analogue to BugFound's store) |
| `libs/prebuilt/langgraph/prebuilt/interrupt.py` | 105 | Human-in-the-loop request/response schema |
| `libs/prebuilt/langgraph/prebuilt/{chat_agent_executor,tool_node}.py` | - | ReAct agent, tool execution node |

### 0.2 Temporal (Go server + SDK-facing API)

| File | Role |
| --- | --- |
| `docs/architecture/README.md` | Design premises: event sourcing, deterministic workflows, idempotent activities |
| `docs/architecture/history-service.md` | History shards, mutable state, history events, state transitions, consistency/outbox |
| `service/history/api/update_workflow_util.go` | The shared transactional state-transition path |
| `service/history/api/signalworkflow/api.go` | Signal handling through the shared path |
| `service/history/api/queryworkflow/api.go` | Read-only query handling and rejection conditions |
| `service/history/workflow/{context.go,mutable_state_impl.go,task_generator.go}` | Mutable state load/commit, event+task generation |
| `service/history/workflow/{workflow_task_state_machine.go,state_machine_definition.go}` | Workflow task state machines |
| `chasm/{component.go,tree.go,statemachine.go,library.go,transition_history.go}` | Component-tree state-machine framework (component-tree state-machine framework) |
| `chasm/AGENTS.md` | Rules for offline decoding of persisted component trees |
| `common/backoff/{retrypolicy.go,retry.go,jitter.go}` | Retry/backoff policy primitives |
| `service/{frontend,matching,worker}/` | API boundary, task queues, activity/workflow task dispatch |

### 0.3 Goose (Rust agent harness)

| File | Lines | Role |
| --- | ---: | --- |
| `crates/goose/src/agents/mod.rs` | 64 | Agent module surface: extensions, retry, sessions, state machine |
| `crates/goose/src/agents/state_machine/mod.rs` | 77 | Re-entrant ordered pipeline over persisted conversation state |
| `crates/goose/src/agents/state_machine/session.rs` | 387 | `MachineSession`/`SessionLoader`/`EffectHandler` impls, effect persistence |
| `crates/goose/src/agents/state_machine/{ops_toolcalling,ops_retry,ops_subagent}.rs` | 665/288/580 | Tool calling, retry decision, delegation ops |
| `crates/goose/src/agents/state_machine/{tool_confirmation,tool_approval}.rs` | 164/114 | Approval requests/responses as conversation messages |
| `crates/oi-kit-agent/src/machine.rs` | 338 | Reusable `StateMachine`, `Step`, cancellation protocol |
| `crates/oi-kit-agent/src/operation.rs` | 258 | `Operation`, `Inference`, `RunStatus`, effect results |
| `crates/oi-kit-agent/src/{steer.rs,subagent.rs,tool_approval.rs}` | 83/271/237 | Steering, delegation, approval traits |
| `crates/goose/src/agents/active_run.rs` | 212 | `ActiveRunRegistry`: per-session cancellation tokens |
| `crates/goose/src/agents/subagent_handler.rs` | 364 | Spawn/cancel/abort-on-drop subagent runs |
| `crates/goose/src/permission/permission_judge.rs` | 246 | LLM-based permission classification |
| `crates/goose/src/session/session_manager.rs` | - | Durable session/conversation store |

### 0.4 Rig (Rust LLM framework + new kernel)

The pinned commit is specifically about the *kernel* - the most directly relevant reference for BugFound.

| File | Lines | Role |
| --- | ---: | --- |
| `crates/rig-ecs/README.md` | 34 | Kernel charter: agents/turns/calls as Bevy entities, plugins for subagents/compaction/usage/effect log |
| `crates/rig-ecs/src/lib.rs` | 274 | `AgentPlugin`, schedules, startup/reconcile, persist phase |
| `crates/rig-ecs/src/stage.rs` | 1530 | 7-stage fixed-point pipeline, `Effect`, `Decision`, `Outcome`, gates |
| `crates/rig-ecs/src/effects.rs` | 117 | One effect dispatch path, monotonic `EffectId`, record buffer |
| `crates/rig-ecs/src/turn.rs` | 2103 | Turn loop: model requests, tool calls, retries, stops, outcomes |
| `crates/rig-ecs/src/retry.rs` | 99 | `RetryPolicy`/`Verdict` (retry, overflow, gave up, final) |
| `crates/rig-ecs/src/restore.rs` | 650 | Strict session read, torn-line handling, crash reconcile |
| `crates/rig-ecs/src/session_log.rs` | 413 | Append-only per-agent logs, saved components, fork semantics |
| `crates/rig-ecs/src/inbox.rs` | 761 | Messages as effects; `Steer`/`Queue`/`Inform` delivery modes |
| `crates/rig-ecs/src/spawn.rs`, `fork.rs` | 245/300 | One agent-spawn path, `Origin::ChildOf/Like`, opt-in `Subagents` marker |
| `crates/rig-core/src/effect/mod.rs` | 1083 | `EffectId`, `EffectKind`, `EffectRecord`, `Decider`, `Disposition` |
| `crates/rig-core/src/tool/contextual.rs` | - | Rust-native `Tool` trait with `Args`/`Output`/`Error` and `footprint` |
| `crates/rig-agent/src/agent/{engine,runner,memory}.rs` | - | Higher-level agent engine, hook/memory patterns |
| `crates/rig-memory/src/compaction.rs` | - | Compaction as a store-level plugin |

---

## 1. Executive synthesis - what is actually worth emulating

BugFound today is deliberately simple: one bounded Runner step loop, typed tools, typed policy, SQLite as source of truth, DB-backed approval and leases, process-local engagement control (`docs/architecture.md:3-46`). The four references are four different answers to "what happens when the harness must survive everything":

1. **LangGraph answers with a graph + checkpoint per superstep.** Best-in-class *declarative task graph* (nodes, edges, conditional routing, reducers) and *time travel*. Weakness: Python runtime, heavy channel/version machinery, graph structure is static at compile time.
2. **Temporal answers with an append-only event history + transactional mutable state.** Best-in-class *durable execution and recoverability* semantics: history replay, transactional outbox, fencing, deterministic workflow/idempotent activity contract. Weakness: enormous distributed-system surface; not embeddable as a small kernel.
3. **Goose answers with a re-entrant operation pipeline over persisted conversation.** Best-in-class *operation composition* (`Operation` as a trait; `NotApplicable`/`Applied`/`Yielded`), conversation-log-based approval with idempotent resolution, and cancellation tokens. Weakness: tight coupling to Goose's own Session/Conversation/Extension stack.
4. **Rig answers with an ECS kernel and a single effect dispatch path.** The closest architectural match to a "universal kernel": everything (message, tool call, model call, stage) is an entity; a fixed 7-stage pipeline runs to a fixed point; every effect has an id, a decision, a reviewer hook, a recorded outcome; crash restore settles half-done work as ordinary effects. Weakness: very new, Bevy-coupled, complex ordering rules.

**Recommended stance for BugFound:** adopt the *semantics* of all four but only the *shape* of Rig. Concretely: keep the durable step loop and SQLite; add (a) an explicit stage pipeline with policy gates modeled on Rig's `Stage`/`Decision`, (b) an effect-id + record log with replay/restore modeled on Rig/Temporal, (c) an `Operation` trait with `Yielded`/`NotApplicable` modeled on Goose for planner/verifier/report phases, and (d) a small declarative task-graph overlay modeled on LangGraph for WSTG playbook fan-out. Reject Temporal's server/replication stack and LangGraph's channel-version engine outright.

### Cross-reference matrix

| Concern | LangGraph | Temporal | Goose | Rig | BugFound today | Direction |
| --- | --- | --- | --- | --- | --- | --- |
| Task graph | explicit graph, conditional edges | workflow code (imperative) | ordered operation list | stage sets + successor entities | durable tasks in store, no graph runtime | add LangGraph-style overlay around existing tasks |
| Durable state | checkpoint per superstep | event history + mutable state | persisted conversation | append-only session log + saved components | SQLite sessions/messages/events | strengthen with effect records + replay |
| One-unit-of-work | superstep task | workflow task / activity | `Step` over ops | `Effect` (turn/call/message/stage) | one LLM call step | align step -> effect record |
| Human approval | `interrupt()` + `Command(resume=...)` | signals/updates | `ActionRequired` messages | `Decision` + `Decider::Person` in Gate | DB transaction `waiting_approval` | keep DB txn, add gate/decider vocabulary |
| Cancellation | asyncio cancel + `interrupt_after` | cancel workflow/activity, timers | `CancellationToken` in machine + registry | `Stop`/`StopTurn`/`Exiting` on turns | process-local pause/resume/abort | add per-session token + terminal reasons |
| Recovery | resume from checkpoint | history replay + rebuild | reload session each step | strict restore + reconcile pass | claim/lease restart recovery | add reconcile pass for half-done steps |
| Trait design | Python protocols | Go interfaces | Rust async traits | Rust traits + ECS components | Rust functions/modules | introduce small `KernelEffect`/`KernelOp` traits |
| Multi-agent | subgraphs, `Send` | child workflows | subagent handler + `Subagents` tool | `spawn`/`fork` plugins | subagent removed during hardening | reintroduce deliberately as opt-in plugin |

---

## 2. LangGraph - graph orchestration with checkpoints

### 2.1 Structure and core mechanisms

`StateGraph` is a builder; nodes communicate by reading/writing shared state and return partial state (`libs/langgraph/langgraph/graph/state.py:131-145`). Each state key can carry a reducer `(Value, Value) -> Value` - the concurrency-safe write semantics for parallel nodes (`:136-138`). Edges are added with `add_edge` (`:928`) and `add_conditional_edges` (`:982`); the graph is only executable after `compile()` (`:142-145`). `START`/`END` are sentinel nodes; entering/leaving is sugar over edges (`:1079-1090`).

Execution is Pregel/BSP: `_algo.py:235` `apply_writes(checkpoint, channels, tasks, get_next_version, trigger_to_nodes)` applies a superstep's writes deterministically - tasks are sorted by `writes_sort_key(task_path_str(t.path))` ("to ensure deterministic order for update application", `:255`). `_algo.py:350` `prepare_next_tasks` computes the next frontier from channel versions. The loop in `_loop.py` owns `checkpoint`, `checkpoint_id_saved`, `checkpoint_ns`, `checkpoint_config`, `checkpoint_pending_writes` (`:288-295`) and has explicit handling for resuming from an addressed checkpoint, superseded checkpoints, and pending writes that must be durable before the checkpoint (`:216-223`, `:242-257`) - an outbox-like ordering guarantee inside a checkpoint save.

Durability is pluggable: `BaseCheckpointSaver` (`libs/checkpoint/langgraph/checkpoint/base/__init__.py:199`) with `get_tuple`/`list`/`put`/`put_writes`; `Checkpoint` carries `channel_values`, `channel_versions`, `versions_seen` (`:93-124`) - the last one is the "which node has seen which version" frontier, and `CheckpointTuple` carries `parent_config` and `pending_writes` (`:140-147`). `SqliteSaver` is explicitly a lightweight single-process implementation with a threading lock, not a multi-thread scale-out solution (`libs/checkpoint-sqlite/.../sqlite/__init__.py:49-100`). This is an honest scope statement BugFound should mirror: SQLite-backed checkpoints are fine for a local kernel.

Human-in-the-loop is a first-class primitive: `interrupt(value)` raises a resumable signal; `Interrupt` carries `value`, a stable `id`, and an optional response schema (`types.py:594-656`). Resumption is via `Command` (`:843`), with strict-resume validation (`:895`). The old prebuilt schema `HumanInterrupt`/`HumanResponse` records the useful vocabulary: `allow_ignore`, `allow_respond`, `allow_edit`, `allow_accept` and response types `accept|ignore|response|edit` (`libs/prebuilt/langgraph/prebuilt/interrupt.py:11-26`, `:87-105`). Note the deprecation: HITL has moved to `langchain.agents.interrupt` - the *pattern* is stable, the *location* is not.

Operational policies are declarative and per-node: `RetryPolicy` with `initial_interval`, `backoff_factor`, `max_interval`, `max_attempts`, `jitter`, `retry_on` predicate (`types.py:428-447`); `TimeoutPolicy` with distinct `run_timeout` (hard cap) and `idle_timeout` (progress-based, refreshed by `refresh_on="auto"|"heartbeat"`) plus a candid note that cancellation is cooperative (`:462-490`). `CachePolicy` and `TracePolicy` (with input/output processors, explicitly "not intended to redact secrets", `:530-568`) complete the toolkit.

### 2.2 Strengths

- The cleanest *declarative* task-graph model of the four: nodes, edges, conditional routing, and typed reducers make fan-out/fan-in and dynamic branching obvious and testable.
- Checkpoint-plus-versions gives time travel and resumable execution with a small, well-defined persistence contract (`get_tuple`/`put`/`put_writes`).
- Retry/timeout/cache/trace are *policies on a node*, not ad-hoc code in a loop - exactly the right abstraction boundary for a kernel.
- Deterministic write ordering (`:255`) removes a whole class of "parallel nodes produced different state" bugs.

### 2.3 Weaknesses

- The channel/version/delta machinery is large (multiple 1500+ line files, plus dedicated delta-channel tests); disproportionate for a local single-process kernel.
- Graph topology is fixed at `compile()` time; dynamic task graphs (new WSTG test added mid-engagement) need subgraph/`Send` tricks.
- Cooperative asyncio cancellation does not map to Rust; the idle-timeout "heartbeat" idea must be rebuilt on `tokio_util::sync::CancellationToken` or similar.
- Python-only; nothing is directly reusable as code.

### 2.4 Adopt / adapt / reject for BugFound

- **Adopt (pattern):** conditional routing + typed reducers as the model for an explicit engagement task graph. BugFound already stores durable tasks/hypotheses; give each a `KernelNode` with a `reducer`-like merge rule for findings/coverage so parallel WSTG playbooks can write without lost updates.
- **Adapt:** `RetryPolicy`/`TimeoutPolicy` split into `run_timeout` vs `idle_timeout` with progress heartbeats. BugFound's current tool timeout is a single cap; a per-step idle timeout protects long scans without killing them.
- **Adapt:** HITL vocabulary (`allow_accept|ignore|respond|edit`) as the payload of BugFound's existing `waiting_approval` row; keep the DB transaction as authority, expose LangGraph-like `Interrupt { id, value, response_schema }` as the wire shape. This makes "approve with edited command" representable without new state machinery.
- **Adapt:** per-checkpoint `parent_config` + `pending_writes` as a model for BugFound's trace/event chain - persist "events before state commit" so a crash cannot leave a state with no corresponding durable fact.
- **Reject:** channel-version/delta-channel engine, `compile()`-time static graph as the *only* graph model, and Python runtime concepts.

---

## 3. Temporal - durable execution as event sourcing plus transactional state

### 3.1 Structure and core mechanisms

Temporal's design premises are stated explicitly: durable execution must survive transient server and user-process failures; the system functions via **event sourcing** - an append-only history per execution from which all state can be replayed (`docs/architecture/README.md:24-35`). The key contract: workflow code is deterministic with no side effects; activity code must be **idempotent or non-retryable** ("at least once or at most once", `:35`). This is the honest statement of Temporal's exactly-once story: exactly-once *effect* is achieved by deterministic replay + idempotent side effects, not by a distributed transaction across everything.

The History Service handles user requests (Start/Cancel/Query/Update/Signal/Reset) and worker requests (workflow/activity completion), and each request follows the same shape: determine new History Events, append them, then create Transfer/Timer tasks (`docs/architecture/history-service.md:1-33`). `Workflow Execution History` is a linear event sequence (branching on Reset/conflict resolution) and is sufficient alone to recover mutable state and tasks (`:113-119`). `Mutable State` is a persisted *projection* of that history - recomputing from history on every request would be slow, so it is cached and stored in one row (`:98-103`). This is the same "irreducible facts + derived read model" split BugFound's ADR-001 kernel/domain boundary asks for.

The shared state transition path is `GetAndUpdateWorkflowWithNew` - `UpdateWorkflowWithNew` (`service/history/api/update_workflow_util.go:14-34`, `:62-125`): acquire a workflow lease, run caller-supplied mutation (`action(workflowLease)`), add a workflow-task event if needed, then commit via `UpdateWorkflowExecutionAsActive`. Signals go through it (`signalworkflow/api.go:16`, `:35`, `:100`); queries are explicitly read-only and never close a transaction (`queryworkflow/api.go:78-79`, `:105`) and can be rejected with conditions when the workflow is not open/clean or is paused (`:112-125`). This is a clean *command vs query* separation worth copying.

Consistency guarantees are the gold part (`docs/architecture/history-service.md:318-322`): DB transactions for mutable state + history tasks; history events only "valid" if reflected in mutable state, and on failed persistence the state is reloaded; Matching consistency via transactional outbox. Shard ownership uses a monotonically increasing `RangeID` generation for fencing (`:77-86`). Recovery is "rebuild from history" - `workflow_rebuilder.go` and `mutable_state_rebuilder.go` are the concrete entrypoints.

`chasm/` is the emerging component-tree framework in the pinned tree: `component.go`, `tree.go`, `statemachine.go`, `library.go`/`registry.go`, `transition_history.go`, with libs for activity, callback, nexus operation, scheduler, workflow. Its AGENTS.md gives a transferable rule: offline readers decode persisted trees with a nil library and **must not read config or schedule tasks**, because those paths only exist in the live service (`chasm/AGENTS.md:8-18`); reading a persisted tree needs the whole record, not just nodes, because namespace/IDs/transition history live outside the tree (`:20-33`).

The pinned commit itself is about **WHN - Workflow Heartbeat Notification** (`service/history/workflow/workflow_heartbeat_notification.go:26-67`): events such as signals, cancel requests, timer fires and child completions are "buffered" while a Workflow Task is already started; eligible input types trigger an early heartbeat to the worker so it can react before the current task finishes, gated by a rollout percentage (`:15-24`, `:69-75`). This is the server-side analogue of BugFound's "steer at safe step boundaries" requirement, but it wakes the worker *during* a busy task rather than only at idle.

Retry/timeouts are policy objects with jitter (`common/backoff/retrypolicy.go`, `retry.go`, `jitter.go`); activity attempts compute retry intervals and record failures explicitly (`chasm/lib/activity/attempt.go:73-84`, `:121-147`).

### 3.2 Strengths

- The most rigorous recoverability model: append-only history as the source of truth, mutable state as a cache/projection, explicit rebuild path.
- Command/query separation, lease-based mutation with a single shared transition path - highly auditable.
- Transactional outbox and fencing generation numbers solve "task created but state not committed" and "stale owner writes" precisely.
- Honest exactly-once framing: determinism + idempotency contract, not a magic guarantee.

### 3.3 Weaknesses

- Massive operational surface (shards, membership, replication, multiple persistence backends, visibility, archival). Copying this into a local bug-bounty kernel would be catastrophic scope creep.
- Workflow code determinism requirement constrains what a model-driven agent can do; LLM outputs and tool side effects are inherently non-deterministic unless modeled as activities with idempotency keys.
- Two commits to persistence per transition (events, then state+tasks) with reload-on-failure; a small SQLite kernel can get away with one transaction.
- The pinned commit's docs reference older upstream SHAs; treat docs as conceptual, not line-exact.

### 3.4 Adopt / adapt / reject for BugFound

- **Adopt (pattern):** "durable facts are the authority; projections are derived and rebuildable." BugFound's `trace_events`/events should be the authority; session state, coverage, budgets and findings are projections that can be rebuilt by folding events. Today budgets and approvals are themselves durable rows - keep them for performance but add an explicit rebuild path and test it.
- **Adapt:** command/query split for engagement control. `engage`, `resolve_approval`, `pause/resume/abort` are commands; `status`, reports, trace export are queries. Route all commands through one `transition(engagement_id, action)` function that acquires the claim, mutates, and commits - Temporal's shared transition path scaled down.
- **Adapt:** transactional outbox for side effects. BugFound's tool execution already appends trace events; make "tool result durable + trace event durable" one SQLite transaction so a crash cannot yield an executed-but-unrecorded action. This is directly relevant to bug bounty: unrecorded actions break report reproducibility and ROE auditing.
- **Adapt:** fencing generation. BugFound already has owner + lease; make the lease/generation part of every state write predicate (it already uses guarded transitions) and document it as a fence, not just a timestamp.
- **Adapt:** the chasm offline-reader rule: any replay/eval/export code must be able to read persisted state without invoking tools, policy, or LLM. BugFound's `eval/export_trace.py` is exactly such an offline reader - keep it pure and config-free.
- **Adapt:** WHN-style early wakeup for high-priority control inputs (pause/abort/steer/approval) that arrive while a tool call is in flight - mark the event as a wakeup-eligible input in the event log and have the runner check for it at the next cancellation point, instead of only at idle. Use a rollout/feature flag as Temporal does (`:15-24`).- **Reject:** sharding, replication, membership, external persistence backends, and the full workflow/activity SDK split. Also reject requiring deterministic workflow code - instead require *idempotent tool calls with deterministic dedupe keys*, which BugFound already does.

---

## 4. Goose - operation pipeline, approvals, and cancellation

### 4.1 Structure and core mechanisms

Goose extracted a reusable state-machine protocol into `oi-kit-agent`. `StateMachine::step` walks an ordered `Vec<Step>` where a `Step` is either an `Operation` or an `Inference` (`oi-kit-agent/src/machine.rs:55-67`, `:169-194`). Each operation returns `OperationResult::{NotApplicable, Applied}`; `Applied` carries a `StepResult` with `status: RunStatus::{Continuing, Yielded, Cancelled}` (`operation.rs:174-190`, helpers `:192-217`). The machine returns on the first `Applied`, skips `NotApplicable`, and yields if nothing applied (`:210-226`). This is a *re-entrant* pipeline: callers persist incoming messages, build steps, and call `step`/`apply`/`run` (`state_machine/mod.rs:1-6`).

Durability comes from **reload each loop iteration**: `StateMachine::run` loads the session from `SessionLoader` every iteration, applies effects, and loops only while `Continuing` (`machine.rs:248-263`). `finalize` handles cancellation by asking the interrupted step to `finalize_cancellation`, emitting synthetic error tool responses for pending calls, and finalizing every other step (`:265-321`). `goose`'s `SessionManager` implements `MachineSession`, `SessionLoader`, `EffectHandler` (`agents/state_machine/session.rs:29-100`) and persists effects as conversation messages/compactions/tool-meta patches. There is no in-memory tool loop; each effect is applied to the durable session.

Tool approval is modeled as messages: `ToolConfirmationRequest` and `ActionRequiredData::ToolConfirmationResponse { id, permission }` live in the conversation (`tool_confirmation.rs:37-45`). `ApprovalState::from_messages` reconstructs answered/requested/responded ids (`:14-82`); `pending_tool_confirmations` filters by active turn (`:97-138`). `persist_tool_confirmation_decision` is explicitly idempotent: same decision is OK, a different decision is rejected, and an already-answered request is rejected (`:145-184`). `GooseToolApproval::check` returns `Allow`/`Deny{reason}`/`Ask{prompt}` via a tool-inspection/permission-inspector pipeline (`:29-101`), and `on_confirmation` can persist `AlwaysAllow`/`NeverAllow` as a permission rule (`:103-121`). This is a direct analogue to BugFound's `ask`/`full_auto` modes, but with approval *state stored in the event stream* rather than only in a status row.

`Operation` also carries `set_message_meta`/`message_meta` notes: "Notes record past actions only - anything an operation would have to compute again does not belong here", so a pipeline rebuilt from persisted conversation reaches the same conclusion (`operation.rs:96-106`). Retry attempts are counted on the kickoff message because a retry *replaces* the conversation up to that point (`ops_retry.rs:69-78`). This is a compact alternative to full event sourcing.

Cancellation is explicit: `StateMachine` holds a `CancellationToken`, checks it before each step, uses `tokio::select!` biased to cancellation, records the interrupted step index, and transitions to `Cancelled` (`machine.rs:69-73`, `:176-207`, `:218-220`). `ActiveRunRegistry` tracks live runs/prompt runs/delegated runs per session and exposes `cancel_agent_run(session_id)` (`agents/active_run.rs:26`, `:105-116`). Subagents are spawned as `AbortOnDropHandle`-wrapped tokio tasks with their own cancellation tokens (`subagent_handler.rs:99-121`, `:141-151`, `:173-177`). Steering is its own module (`oi-kit-agent/src/steer.rs`) - the harness treats new user input as a first-class operation, not an ad-hoc side channel.

### 4.2 Strengths

- Excellent trait-level composition: adding a capability = adding an `Operation` to the ordered pipeline; `NotApplicable` makes optional features cheap.
- Approval as durable conversation facts with idempotent resolution - matches BugFound's transactional approval, but with a richer decision vocabulary and an audit trail.
- Cancellation design is coherent end-to-end (machine token -> run registry -> subagent token -> synthetic tool responses on finalize).
- Reload-per-step and message metadata notes give deterministic rebuild without a full event-sourcing engine.

### 4.3 Weaknesses

- Deeply coupled to Goose's `Session`, `Conversation`, `ExtensionManager`, `Permission` and `ToolInspectionManager`; extracting the protocol requires defining all those boundaries.
- The "replace conversation on retry" model discards intermediate history; for bug bounty this would erase evidence unless the trace store keeps the evidence.
- LLM-based permission judging (`permission/permission_judge.rs:145,189`) adds nondeterminism and cost; acceptable as an advisor, dangerous as a gate.
- Many ops files (tool pair compaction, context relevance, thinking recovery, doctor, skills, recipe...) show the complexity tax of an everything-pipeline.

### 4.4 Adopt / adapt / reject for BugFound

- **Adopt (pattern):** an `Operation` trait for the phases that are not the LLM step itself - planner (WSTG playbook selection), verifier, finding writer, report renderer. Status `Continuing | Yielded | NotApplicable` maps cleanly to BugFound's step/finalize/park states and gives a testable composition point without changing the Runner loop.
- **Adopt (pattern):** message-metadata notes with the "past actions only" rule. BugFound's `trace_events` can carry per-operation notes so an eval replay reaches the same decisions without re-running policy.
- **Adapt:** approval request/response as a typed record with idempotency: `request_id`, `decision in {accept, respond, edit, ignore}`, and reject a conflicting second decision. BugFound already resolves approvals once under `status='pending'`; add the decision payload and `Decider` identity so reports can show *who* approved *what*.
- **Adapt:** per-session cancellation token in `bugfound-engagement`, checked at each durable step boundary, with a finalize path that emits synthetic "interrupted" tool results - so an aborted engagement leaves a coherent, replayable history rather than a dangling pending call. Keep abort terminal as today.
- **Adapt:** `ActiveRunRegistry`-style explicit tracking of live prompt/subagent runs keyed by session/engagement id, used for graceful shutdown and to reject duplicate concurrent runs.
- **Reject:** "replace conversation on retry" (BugFound must keep evidence), LLM-as-permission-judge as a gate (use it only as an advisor feeding the typed policy), and the sprawling op set.

---

## 5. Rig - the closest thing to a universal kernel

### 5.1 Structure and core mechanisms

Rig's pinned commit introduces a genuine kernel design. `rig-ecs`'s charter: "It holds only what every agent needs, whatever its interface. Subagents, compaction, usage and the effect log are plugins on its public API" (`crates/rig-ecs/README.md:3-6`). Agents, turns and calls are Bevy entities; stages are effect entities; a plugin steps in with an ordinary system in a stage (`:8-17`). Crucially for BugFound: "The kernel depends on no view and no file system: the app fills in what it needs, such as the store and the Models" (`crates/rig-ecs/src/lib.rs:10-12`). That is exactly the dependency direction a universal kernel needs.

`AgentPlugin` wires the schedules: `SaveConversations`/`SaveFrame` before `Update`, `Persist` after `Last`; `StartupSystems::FirstAgent` then `Reconcile` (`:135-168`, `:182-265`). `Persist` is a dedicated final schedule where log records are written, including the exit frame (`:149-168`) - a strong durability ordering rule.

The heart is the 7-stage fixed-point pipeline (`crates/rig-ecs/src/stage.rs:87-163`): `AgentPass` runs `Arrive -> Review -> Commit -> Admit -> Prepare -> Gate -> Start`, and `AgentLoop` in `Update` repeats it "until nothing moved" (`:1-7`, `:99-106`). Stage responsibilities: Arrive reads finished tasks/retry verdicts; Review edits outcomes and turn proposals; Commit settles and writes effect records; Admit builds requests; Prepare composes/edits/adapts/fits (compaction is a *Fit* phase plugin, `:165-193`); Gate is where plugins hold or decide what may start, including footprint/conflict marking (`:207-238`); Start applies decisions and starts handlers. A failing Prepare/Gate/Review system closes its stage for the pass and emits a `Notice` (`:15-21`).

Everything is an `Effect`: it gets a monotonic id on add, records itself as cancelled if despawned before settling (`stage.rs:244-263`). `Effects` is the *one dispatch path*: `run(id, origin, handler, kind, consume)` records begin -> dispatch -> catch panics -> record outcome; ids continue across restarts via `continue_after` (`effects.rs:1-13`, `:33-105`). Every effect has a `Decision` - first decision wins, names the `Decider` (Person or Plugin), and is applied as the `Outcome` at Start (`stage.rs:401-439`). This is human-in-the-loop and policy-as-gate unified in one primitive: `Decider::Person` answers a question, `Decider::plugin("protected-paths")` refuses a call. An `Outcome` can also cancel a running handler when applied late (`:347-354`). Rig-core's `EffectRecord` keeps id, handler key, kind, outcome, stream events, parent, and who decided (`rig-core/src/effect/mod.rs:798+`, `:883+`); `Disposition` distinguishes `Ran`, `AnsweredBeforeStart`, `AnsweredWhileRunning` (`:903+`).

Retry is a policy resource with four verdicts: `Overflow` (shrink context), `Retry(duration)`, `GaveUp(reason)`, `Final`; it honours provider `retry_after`, caps asked waits, and jitters exponential backoff (`crates/rig-ecs/src/retry.rs:12-105`). Context overflow is a *recoverable* verdict, not an error - a direct lesson for long security-tool outputs.

Recovery is explicit: restore reads the session strictly, refuses it whole if unreadable, sets aside a torn last line, and does not restore retired agents or their spawned children (`restore.rs:1-6`). Only crashes (or plugin-permitted `CarryOn`) leave unfinished turns; their work is re-spawned as ordinary `Restored` stage entities, gated like any other, then stopped as a user stop would be, with `Interrupted` marking started/settled calls (`:8-18`). A plugin can carry work on by inserting `CarryOn` again. Session logs are append-only, per agent, with a subagent's log written before its parent's (`session_log.rs:1-13`); saved components use `ReflectSaved` with fork policies `Copy`/`Reset`/`Never` (`:35-58`).

Inbox and subagents are plugins, not kernel: message delivery modes are `Steer` (next model call), `Queue` (when turn would end, batching everything queued), and `Inform` (no answer, next call whenever) (`inbox.rs:55-73`), with unsent messages recalled to views or carried to the next turn (`:19-24`). Subagents require an explicit `Subagents` marker resource; `Origin::{Root, ChildOf, Like}` and `AgentSpec` inherit the origin's settings unless overridden (`spawn.rs:35-72`).

Rust-native trait design is excellent: `Tool` has associated `Args` (Deserialize), `Output` (`IntoToolOutput`), `Error`, plus `description`, `parameters`, `annotations()` (`ToolAnnotations`) and `footprint(&args) -> Touches` - "what a call may read and change, so a host runs the calls of one reply that touch different things side by side" (`rig-core/src/tool/contextual.rs:32-76`). Capability metadata is declared by the tool and consumed by host policy and scheduling; errors are normalized only at the erased dispatch boundary so authors keep typed `?` propagation (`:45-51`).

### 5.2 Strengths

- The best separation of *kernel vs plugin* of the four: no view, no filesystem in the kernel; store and model catalog injected.
- One dispatch path with ids, decisions, deciders, records and replay (`GateSystems::FromRecord`, `stage.rs:207-217`): the cleanest unification of policy, approval, audit and replay.
- Fixed-point pipeline with explicit phases gives deterministic, inspectable ordering without a graph compiler.
- Recovery is designed as "settle half-done work as ordinary effects" - no special crash-only code path.
- Rust-native, ergonomic tool trait with footprint annotations for concurrency/approval decisions.
- The pinned commit's focus - minimal compaction on turns, queue and retries - shows the team deliberately keeps compaction at the *Fit* phase, outside the kernel.

### 5.3 Weaknesses

- Bevy ECS is a heavyweight dependency for a CLI/local kernel; entity/component/observer semantics have no trivial analogue in plain Rust structs.
- Stage ordering rules are subtle (ambiguous sets, phases, holds, supersession); a smaller kernel needs fewer moving parts.
- Very new API (`0.x`, replaces an older unrelated `rig-ecs` - README:34); churn risk is high.
- Reflection-based saved components and typed serde boundaries add complexity that BugFound's plain SQLite structs do not need.
- The single-dispatch-path design assumes all work can be modeled as an effect; long-running security scans need progress/heartbeat modeling (Rig uses Bevy timers, not Rust async directly).

### 5.4 Adopt / adapt / reject for BugFound

- **Adopt (pattern) - kernel/plugin boundary:** define `bugfound-kernel` as pure orchestration with injected `Store`, `Policy`, `ToolRegistry`, `Model` traits; keep CLI/desktop/engagement-specific code outside. This matches BugFound's ADR-001 dependency rule and the evidence matrix's "modules retained but not production-wired" honesty.
- **Adopt (pattern) - one effect path:** give every durable unit a monotonic `EffectId`, a `Decision`, a `Decider`, and an append-only record. BugFound's `event.rs`/`step.rs` already have pieces; unify them. Every tool call, LLM step, approval, and subagent message should flow through one `KernelEffect::dispatch(...)` that records start/outcome. This is the single highest-value change.
- **Adopt (pattern) - gate as policy:** port `Stage::Gate` semantics: before a risky tool runs, a gate can `Allow`, `Hold`, or `Refuse(decider, reason)`. This subsumes `ask`/`full_auto` and gives BugFound a place for ROE scope checks, in-scope target checks, and destructive-action denial with an auditable decider.
- **Adapt - stage pipeline without Bevy:** implement a small fixed-point loop with ~5 phases over the existing SQLite state: `Admit` (load session/claim) -> `Prepare` (assemble messages, compact) -> `Gate` (policy/approval/footprint) -> `Run` (one LLM call, tool dispatch) -> `Commit` (append events, projections, budgets). Run until no work moved; persist in a final `Persist` step. Do not adopt ECS entities.
- **Adapt - restore/reconcile:** add a startup pass that finds sessions with a live claim but no terminal event, and settles their half-done steps as ordinary `Interrupted` outcomes (rather than a special recovery code path), with a `CarryOn` opt-in for safe read-only work.
- **Adapt - `Footprint`/`Touches` on BugFound tools:** extend the existing risk label with read/write scope so the gate can decide whether two calls in one step may run in parallel and whether a call needs approval. The existing tool trait/registry is the natural home.
- **Adapt - delivery modes:** BugFound's retained `inbox` module should expose `Steer`/`Queue`/`Inform` semantics explicitly (it currently has no production call site). Map them to engagement control: steers interrupt at step boundaries, queues run when the session would go idle, informs do not wake a session.
- **Adapt - compaction as a phase, not in the loop:** keep `Runner::build_llm_messages` compaction at a `Prepare/Fit` boundary; log the compaction event so eval can see it.
- **Reject:** Bevy/ECS dependency, reflection-based saved components, `wasm32` target concerns, and the 7-stage ordering machinery verbatim.

---

## 6. Cross-cutting design rules for the BugFound kernel

### 6.1 Multi-agent orchestration

- Prefer **opt-in subagents** (Rig's `Subagents` marker, Goose's explicit subagent tool) over a global always-available delegation tool. BugFound removed subagents in an earlier revision; reintroduce them behind an engagement option with an explicit allowlist and per-subagent budget.
- Every subagent call must be an effect with a parent id (Rig `Effect::parent`, Temporal parent/child pointer). Reports must be able to reconstruct the delegation tree from durable records.
- Subagent cancellation must be tied to the parent's token (Goose `AbortOnDropHandle`), and a subagent that ends must emit a notification effect to the parent instead of writing the parent's state directly.
- Reject LangGraph-style unrestricted subgraphs for v1; use a flat parent/child tree with depth limits.

### 6.2 Task graphs

- Represent the WSTG playbook as an explicit **small graph**: node = durable task/hypothesis, edge = prerequisite, conditional router = "if finding confirmed -> verifier/report else -> next target". LangGraph's `StateGraph` is the semantic model.
- Reducers must be commutative for coverage/findings (LangGraph `(Value, Value) -> Value`); parallel playbooks must not overwrite each other. BugFound already has `record_coverage` - give it reducer semantics.
- Dynamic task insertion mid-engagement must be allowed (Temporal workflows cannot easily do this; don't copy that restriction).

### 6.3 Durable execution

- One authority: append-only durable facts (BugFound `event.rs`/`trace_events`). All other tables are projections with a tested rebuild path (Temporal history/mutable-state split).
- One transaction per boundary: "action executed + event recorded + projection updated" must be atomic (Temporal transactional outbox; Rig `Persist` schedule). No unrecorded side effects.
- One unit of work: one LLM call per step, reload state before each step (Goose `StateMachine::run` reload-per-iteration; BugFound already reloads history).
- Replay must not re-emit side effects: record the *outcome* of a streamed/tool effect, not just the request, and answer recorded effects from the record in the Gate phase (`effects.rs:9-12`, `GateSystems::FromRecord`).

### 6.4 Cancellation and recovery

- Per-session/engagement `CancellationToken`-style token checked at each step boundary (Goose), with terminal reasons `Completed | Interrupted | Failed | Aborted` preserved in durable state (Temporal close status; BugFound already has classified outcomes).
- On cancel, emit synthetic interruption results for pending tool calls so history stays coherent (Goose `finalize`). Do not leave a `waiting_approval` row pending indefinitely - resolve it as `cancelled`.
- Startup reconcile pass: claims without terminal events are settled as `Interrupted` effects, not silently reused (Rig restore + BugFound's existing claim/lease recovery).
- Fencing: include owner generation in every state write predicate, and document it as a fence (Temporal `RangeID`, BugFound guarded transitions).
- Distinguish graceful stop (token cancel + finalize) from crash (no finalize, reconcile on boot), exactly as Rig does.

### 6.5 Rust-native trait design

- Small traits, associated types, no `any`: `KernelEffect` (id, kind, parent, recorded outcome), `KernelOp` (`NotApplicable | Applied(effects, status)`), `Capability` (footprint/annotations), `KernelStore` (load/commit/rebuild).
- Tool-authored errors stay typed and are normalized only at the dispatch boundary (Rig `Tool::Error` -> `ToolExecutionError`).
- Metadata (risk, scope, idempotency key) is declared on the tool/effect, consumed by policy - not hard-coded in the Runner.
- Prefer enums with explicit verdicts (`Retry`, `GaveUp`, `Overflow`, `Final`) over booleans; every "no" should carry a reason a report can quote.

---

## 7. Prioritized adoption backlog for BugFound

| Priority | Change | Source pattern | Why |
| --- | --- | --- | --- |
| P0 | Unify all side effects under one `dispatch + EffectId + record + Decider` path | Rig `effects.rs`, `stage.rs:401-439` | Auditability, replay, approval traceability; biggest leverage |
| P0 | Treat the event log as the source of truth; add tested rebuild of projections | Temporal history/mutable-state | Crash correctness and reproducible evidence |
| P0 | Transactional outbox: tool result + trace event + projection in one SQLite txn | Temporal `history-service.md:318-322` | No unrecorded security-relevant actions |
| P1 | `KernelOp` trait for planner/verifier/report phases | Goose `Operation` | Composable phases without touching Runner |
| P1 | Typed approval decisions with idempotency and `Decider` identity | Goose `tool_confirmation.rs`, Rig `Decider` | Reports can cite who approved what |
| P1 | Per-session token + finalize that closes pending calls | Goose `machine.rs`, `active_run.rs` | Coherent aborts; no zombie approvals |
| P1 | Startup reconcile that settles half-done steps as ordinary effects | Rig `restore.rs` | Simpler, testable crash recovery |
| P2 | Small fixed-point phase pipeline (Admit/Prepare/Gate/Run/Commit/Persist) | Rig `Stage` | Deterministic ordering, policy hook |
| P2 | Task graph with reducers + conditional routing for WSTG playbooks | LangGraph `StateGraph`, `apply_writes` | Parallel playbooks without lost updates |
| P2 | `RetryPolicy` with context-overflow verdict + idle vs run timeout | Rig `retry.rs`, LangGraph `TimeoutPolicy` | Long scans survive; oversized outputs recover |
| P2 | `Steer`/`Queue`/`Inform` delivery modes on the retained inbox module | Rig `inbox.rs`, Goose `steer.rs` | Wire the retained-but-unused modules honestly |
| P3 | Opt-in subagents with parent effects, token cascade, depth/budget limits | Rig `spawn.rs`, Goose `subagent_handler.rs` | Reintroduce delegation safely |
| Reject | ECS/Bevy engine, channel-version machinery, Temporal server stack, LLM-as-gate | - | Disproportionate complexity for a local kernel |

---

## 8. Evidence index (quick lookup)

- **LangGraph:** `graph/state.py:131-145` (nodes/reducers/compile), `:928`, `:982`, `:1079-1090` (edges/routing); `types.py:428-447` (RetryPolicy), `:462-490` (TimeoutPolicy), `:594-656` (Interrupt), `:843` (Command); `pregel/_algo.py:235-255` (deterministic apply_writes), `:350` (prepare_next_tasks); `pregel/_loop.py:216-223`, `:288-295` (checkpoint/pending writes); `checkpoint/base/__init__.py:93-124`, `:140-147`, `:199`; `prebuilt/interrupt.py:11-26`, `:87-105`.
- **Temporal:** `docs/architecture/README.md:24-35`; `docs/architecture/history-service.md:77-86`, `:98-119`, `:252-295`, `:318-322`; `service/history/api/update_workflow_util.go:14-34`, `:70-125`; `signalworkflow/api.go:16-125`; `queryworkflow/api.go:78-125`; `chasm/AGENTS.md:8-33`; `common/backoff/retrypolicy.go`.
- **Temporal (WHN):** `service/history/workflow/workflow_heartbeat_notification.go:15-75` (buffered-input eligibility, rollout, early worker wakeup); `updateworkflow/api.go:124,220,434` (WHN dispatch call sites).
- **Goose:** `oi-kit-agent/src/machine.rs:55-73`, `:169-227`, `:248-321`; `operation.rs:93-145`, `:174-217`; `agents/state_machine/mod.rs:1-6`; `tool_confirmation.rs:14-82`, `:97-184`; `tool_approval.rs:29-121`; `session.rs:29-100`; `ops_retry.rs:69-78`; `active_run.rs:26`, `:105-116`; `subagent_handler.rs:99-177`.
- **Rig:** `rig-ecs/README.md:3-32`; `src/lib.rs:10-12`, `:135-168`, `:182-265`; `stage.rs:1-21`, `:87-163`, `:165-238`, `:244-263`, `:347-354`, `:401-439`; `effects.rs:1-13`, `:33-105`; `retry.rs:12-105`; `restore.rs:1-18`; `session_log.rs:1-13`, `:35-58`; `inbox.rs:55-73`; `spawn.rs:35-72`; `rig-core/src/effect/mod.rs:798+`, `:883+`, `:903+`; `rig-core/src/tool/contextual.rs:32-76`.

---

### Bottom line

For a universal Rust kernel, **Rig supplies the shape** (kernel/plugin split, one effect dispatch path, gates with deciders, restore-as-ordinary-effects), **Temporal supplies the correctness contract** (facts as the authority, projections derived, outbox, fences, idempotency), **Goose supplies the composition and cancellation protocol** (`Operation` verdicts, token + finalize, message-backed approval), and **LangGraph supplies the task-graph and policy vocabulary** (conditional edges, reducers, interrupt/resume, retry/timeout policies). BugFound already has the right primitives - sessions, steps, tools, policy, approvals, budgets, events, leases. The next increment is not more features; it is *one effect path, one authority, one transition function* around what already exists.
