# 02 — PentAGI Source Analysis (patterns only; no code copy)

> **About these notes.** These are point-in-time analyses of third-party reference
> projects, kept for design input. They describe the reference projects at the
> snapshots examined and are not claims about the current BugFound code; verify
> current behavior in `crates/`.

**Reference:** `D:\Github\BugFound\research\pentagi`
**Commit:** `cffed9485aa1cca70762cd08a57ac62a80406258` (branch `main`, clean tree)
**Language/stack:** Go backend (`backend/pkg/...`), TypeScript/React frontend, PostgreSQL + pgvector, Docker, Graphiti, Langfuse/OpenTelemetry.
**Evidence convention:** `ROOT` = `D:\Github\BugFound\research\pentagi`. All paths below are absolute with `ROOT` as the base; `:N` is a 1‑based source line verified against the commit above. Documentation (`backend/docs/flow_execution.md`) was used only as a map; every claim below is backed by the cited source (or explicitly marked as doc‑only).

**Target:** `D:\Github\BugFound\crates\bugfound-*` (Rust: `core`, `engagement`, `llm`, `tools`, `store`, `policy`, `cli`, `desktop`).

---

## Executive summary

PentAGI is a *durable-plan-plus-agent-loop* system. A long-lived **Flow** owns ordered **Tasks**; each Task owns LLM-generated, dynamically **refined ordered Subtasks**; each Subtask is executed by a **Primary Agent** whose only legal output is **tool calls**, with specialists reached as *tools* (not as independent concurrent agents). Self-correction is layered and bounded: JSON repair, retry-with-delay, reflector-on-unstructured-output, repeated-call detection, execution-monitor mentor, and hard iteration caps. Memory is split between **pgvector knowledge documents** (reusable) and **Graphiti episodic graphs** (what happened), with provenance on every write. Tool execution is container-isolated with an explicit capability allow-list. Persistence is a rich relational log of chains, tool calls, and per-category logs, mirrored to Langfuse spans and GraphQL subscriptions.

The single most transferable idea for BugFound is **"plan as durable ordered rows + one bounded tool-call loop per step + explicit barrier tool for completion + layered bounded recovery"**, integrated with BugFound's existing policy/budget/scope enforcement rather than replacing it. The most dangerous thing to copy is the code and the VXControl dependency/license tangle (see §7).

---

## 1. Flow / Task / Subtask / Action architecture

### 1.1 Entities and state machines

| Entity | Evidence | Structure / states |
|---|---|---|
| Flow (DB) | `ROOT/backend/pkg/database/models.go:939-954` | `ID, Status, Title, Model, ModelProviderName, Language, Functions json.RawMessage, UserID, CreatedAt/UpdatedAt/DeletedAt (soft delete), TraceID, ModelProviderType, ToolCallIDTemplate` |
| Flow (API) | `ROOT/backend/pkg/graph/model/models_gen.go:207-216` | Exposes `Terminals`, `Provider`, timestamps. |
| Task (DB) | `ROOT/backend/pkg/database/models.go:1078-1087` | `ID, Status, Title, Input, Result, FlowID` |
| Task (API) | `ROOT/backend/pkg/graph/model/models_gen.go:510-520` | Adds `Subtasks []*Subtask`. |
| Subtask (DB) | `ROOT/backend/pkg/database/models.go:1066-1076` | `ID, Status, Title, Description, Result, TaskID, Context string` (context added by `ROOT/backend/migrations/sql/20250412_181121_subtask_context copy.sql`) |
| Subtask (API) | `ROOT/backend/pkg/graph/model/models_gen.go:492-501` | No `Context` exposed to API. |
| Action = tool call | `ROOT/backend/pkg/database/models.go:1100-1109` (`Toolcall`), `ROOT/backend/pkg/tools/registry.go:56-67,98-141` | **There is no "Action" table.** An Action is an `llms.ToolCall` persisted as a `toolcalls` row with lifecycle `received → running → finished/failed` (`20241026_115120_initial_state.sql:193-214`). Tools are typed into 8 categories (environment, search_network, search_vector_db, agent, store_agent_result, store_vector_db, barrier, none). |
| Status enums | `ROOT/backend/migrations/sql/20241026_115120_initial_state.sql:109,155,174,193` and `ROOT/backend/pkg/database/models.go:149-157` | `flow/task/subtask`: `created, running, waiting, finished, failed`. `toolcall`: `received,running,finished,failed`. Go constants: `FlowStatus*` at `models.go:151-157`; `SubtaskStatus*` at `models.go:524-527`. |
| Message chain | `ROOT/backend/pkg/database/models.go:979-997` | `Msgchain{Type, Model, ModelProvider, UsageIn/Out, UsageCache*, UsageCost*, DurationSeconds, Chain json.RawMessage, FlowID, TaskID, SubtaskID}` — the *serialized conversation* is a durable row, not an in-memory object. |
| Chain types | `ROOT/backend/pkg/database/models.go:194-212` | 15 types: primary_agent, reporter, generator, refiner, reflector, enricher, adviser, coder, memorist, searcher, installer, pentester, summarizer, tool_call_fixer, assistant. Note: the old `fixer` type from migration `20250103_..._new_msgchain_type_fixer.sql` is superseded by `tool_call_fixer`. |

**Dependencies:** `database` (sqlc-generated `Querier`), `graph/model` (GraphQL), `tools` (type mapping).

**Strengths:** Typed, durable, user-scoped entities; soft deletion; chain snapshots allow restart continuity; explicit `waiting` state models human-in-the-loop without mixing it into `running`.

**Weaknesses:** Status is duplicated across three levels with manual back-propagation (easy to desync — guards exist for stale/deleted rows at `task.go:248-262`, `subtask.go:193-207`); `Chain` is an opaque JSON blob — no schema evolution; replanning is not transactional (explicit TODOs at `subtasks.go:90` and `:146`).

**Adaptation:** Map Flow→engagement, Task→work item/hypothesis, Subtask→session step, Action→BugFound event/tool record. Keep BugFound's guarded state transitions (`transition_state_owned`) as the *only* write path; add a `plan_revision` column and atomic "delete-planned + insert-new" in one SQLite transaction. Persist the tool-call record with the `received/running/finished/failed` lifecycle and link it to the existing tamper-evident event hash chain.

### 1.2 Lifecycle and scheduling

**Flow creation** — `ROOT/backend/pkg/controller/flows.go:276-307`: `CreateFlow` reserves a DB row *before* preparing, publishes `FlowCreated`, then asynchronously `prepareFlow` (`:310-354`, with timeout and abort-on-close). Failure path `failFlow` (`:356-383`) writes a user-visible report message, sets `FlowStatusFailed`, republishes. Image/language choice happens in `ROOT/backend/pkg/providers/providers.go:320-344` (LLM prompts `PromptTypeImageChooser`, `PromptTypeLanguageChooser`).

**FlowWorker** — interface `ROOT/backend/pkg/controller/flow.go:36-56`, struct `:58-79` (`input chan flowInput`, per-task cancellable context `taskST`, `taskWG`, report goroutines, Docker client).
Scheduler loop `ROOT/backend/pkg/controller/flow.go:1288-1351`: on startup it resumes every incomplete/non-waiting task (`"continue after loading"`), then blocks on `fw.input`. `processInput` (`:1353-1407`) first looks for a **waiting** task and delivers input to it; otherwise sets Flow→`running`, creates a fresh cancel context **before** `CreateTask` (comment at `:1372-1380` explains a real race with `Stop()`), then `execTask` (`:1448-1492`) wraps `task.Run` in a Langfuse span.

**TaskWorker** — `ROOT/backend/pkg/controller/task.go:242-300` (`SetStatus` maps status and back-propagates to Flow: `running→FlowStatusRunning`, `waiting→FlowStatusWaiting`, `finished/failed→FlowStatusWaiting`), `:341-376` (`Run`: loop `PopSubtask → st.Run → RefineSubtasks` while subtask count `< TasksNumberLimit+3`; empty queue ends planning), `:382-422` (`writeResult`: reporter → `Finished`/`Failed` + Markdown report log). `TasksNumberLimit` is the "max 15 subtasks" rule consumed at `provider.go:383` and `:475`.

**SubtaskWorker** — interface `ROOT/backend/pkg/controller/subtask.go:22-39`, struct `:41-47`; `NewSubtaskWorker` calls `PrepareAgentChain` (`:49-78`); `LoadSubtaskWorker` (`:80-134`) resets a persisted `running` subtask back to `created` on restart (": if subtask is running, it means that it was not finished by previous run → start from beginning"). `Run` (`:294-353`): `SetStatus(running)` → `EnsureChainConsistency` → `PerformAgentChain` → map `PerformResult{Waiting,Done,Error}` to `SubtaskStatus{Waiting,Finished,Failed}`. `handleInterrupting` (`:355-376`) uses a fresh 5s context to force `Waiting` after cancellation.

**Subtask controller (ordering + refinement)** — `ROOT/backend/pkg/controller/subtasks.go`:
- `GenerateSubtasks` (`:70-104`): an **explicit empty plan** means "execute the original request as one subtask"; a `nil` result is an error (`:76-88`).
- `RefineSubtasks` (`:106-160`): fetches planned subtasks, calls LLM refiner; a *model* failure (`ErrAgentModelCall`) is **advisory** while a `created` subtask remains (`:114-125`); otherwise deletes **all `created` subtasks** and recreates from the new plan (`:133-157`), invalidating cached workers (`:144`, `:218-230`).
- `PopSubtask` (`:162-188`): takes `GetTaskPlannedSubtasks(...)[0]`.
- SQL: `ROOT/backend/sqlc/models/subtasks.sql:48-55` — planned = `status IN ('created','waiting')`, `ORDER BY s.id ASC`; completed = everything else (`:57-64`). **Order is insertion/ID order**, i.e. the Generator's list order is the execution order; the Refiner's delete-and-reinsert renumbers it.

**Generator / Refiner prompts** — `ROOT/backend/pkg/providers/provider.go:353-434` (Generator context includes task, tasks, subtasks, tool names, `N=TasksNumberLimit`; prompt is progressively truncated by halving the subtask history when over `msgGeneratorSizeLimit`, `:405-416`); `:436-541` (Refiner context: planned vs completed subtasks, dynamic `N = max(15 - completed, 0)`, and conditionally injects an execution-state summary and message-log summary, `:497-523`). Performers: `ROOT/backend/pkg/providers/performers.go:96-176` (generator, `subtask_list` barrier-like result tool), `:189-375` (refiner, `subtask_patch` delta ops applied via `applySubtaskOperations` at `:349`).

**Completion/failure chain:** `done` barrier → `PerformResultDone/Error` (`provider.go:812-846`) → subtask status (`subtask.go:338-347`) → back-propagation to task/flow; queue empty → Reporter (`ROOT/backend/pkg/providers/performers.go:22-95`, `provider.go:543-634`) → `TaskStatusFinished/Failed` (`task.go:389-394`).

**Strengths:** Ordered durable plan; clean resume semantics; advisory degradation on refiner LLM failure; bounded replanning (`≤15`); explicit human-in-the-loop state; restart recovery.
**Weaknesses:** Delete-and-recreate invalidates all planned IDs and worker caches (costly, loses identity/provenance); plan order is purely numeric with no explicit dependency edges; no transactional replan; the whole orchestration depends on LLM calls for titles/image/plan/refine/report — latency and cost.
**Adaptation:** Keep the ordered-plan + refine loop but make it *deterministic-first*: BugFound already has coverage ledger + hypothesis planner (`README.md:48-53`), so use LLM only to propose deltas and validate them against scope/budget; store plan rows with `seq`, `revision`, `status`, and **reuse IDs** via a SQLite `UPSERT` rather than delete/recreate. Preserve `running→created` reset semantics for crash recovery; preserve "empty plan ⇒ run original request once".

---

## 2. Primary Agent and specialists

### 2.1 Primary Agent (orchestrator of a Subtask)

**Evidence:** `ROOT/backend/pkg/providers/provider.go:708-928`.
- Loads chain (`:724-734`), obtains specialist handlers — adviser, coder, installer, memorist, pentester, subtask searcher (`:736-770`).
- Builds `tools.PrimaryExecutorConfig` (`:796-910`) wiring `Barrier` callback with two tools: `FinalyToolName` (done: validates `Done`, writes subtask result, emits a `MsglogTypeReport`, sets `PerformResultDone`/`Error`, `:812-890`) and `AskUserToolName` (`:892-905`, `PerformResultWaiting`).
- `GetPrimaryExecutor` (`:912`) then `performAgentChain` (`:918-920`).
- Chain preparation `ROOT/backend/pkg/providers/provider.go:636-705`: prepares execution context, writes it into `subtasks.context` (`:657-670`), renders `PromptTypePrimaryAgent` with all delegation tool names (`:672-691`), restores/creates the chain.

**Execution path (the tool loop):** `ROOT/backend/pkg/providers/performer.go:58-280` — detailed in §3.

### 2.2 Specialists

Role definitions (docs `ROOT/backend/docs/flow_execution.md:24-37`) confirmed in source:

| Agent | Performer | Executor config | Tools/delegation |
|---|---|---|---|
| Generator | `performers.go:96-176` | `tools.go:290-295` | memorist, searcher, `subtask_list` |
| Refiner | `performers.go:189-375` | `tools.go:297-302` | memorist, searcher, `subtask_patch` |
| Reporter | `performers.go:22-95` | `tools.go:318-322` | `report_result` |
| Coder | `performers.go:377-467` | `tools.go:259-268` | adviser, installer, memorist, searcher, `code_result` |
| Installer | `performers.go:468-552` | `tools.go:249-257` | adviser, memorist, searcher, `maintenance_result` |
| Pentester | `performers.go:609-704` | `tools.go:270-280` | adviser, coder, installer, memorist, searcher, `hack_result`; optional planner (`:668-677`) |
| Searcher | `performers.go:706-767` | `tools.go:282-288` | memorist, `search_result` |
| Memorist | `performers.go:553-608` | `tools.go:304-309` | `search_result` (vector search) |
| Enricher | `performers.go:768-824` | `tools.go:311-316` | `enricher_result` |
| Adviser / Mentor / Planner | `performers.go:825-884` (`performPlanner`), `:887-968` (`performMentor`) | via `AdviceToolName` | called *inside* other agents' loops; not a standalone chain in normal flow |
| Reflector | `performer.go:611-774` | `performSimpleChain` | corrective human-style message |
| Assistant | `ROOT/backend/pkg/providers/assistant.go:1-...` | `tools.go:215-234` | `UseAgents` flag toggles delegation; optional FlowManager callbacks |

Executor factories: `ROOT/backend/pkg/tools/tools.go:811` (assistant), `:997` (primary), `:1070` (installer), `:1174` (coder), `:1296` (pentester), `:1430` (searcher), `:1507` (generator), `:1577` (refiner), `:1647` (memorist), `:1722` (enricher), `:1811` (reporter).

**Handoff / communication:** delegation is *synchronous tool invocation* inside the same loop — a specialist returns a structured `*_Result` tool call, its text is captured by a closure (e.g. `hackResult` at `performers.go:654-660`) and returned to the caller as a tool response. Inter-agent lineage is propagated via `tools.PutAgentContext` (`ROOT/backend/pkg/tools/context.go:9-34`): `ParentAgentType ← CurrentAgentType`, shifted on each nested call; used for agent logs and vector-store logs. Searcher priority is memory → web (unified `web_search` with a per-mode engine fallback table in `ROOT/backend/pkg/tools/web_search.go:143-210`, `NewInternalEngine` at `:202`) → browser for a specific URL.

**Strengths:** Capability-scoped tool sets per role (least privilege by construction); synchronous, structured handoff with typed result objects; lineage tracking; no free-form agent-to-agent chat to get lost.
**Weaknesses:** Deep synchronous nesting multiplies LLM calls and latency; delegation is prompt-governed (a model can ignore a specialist); adviser doubles as mentor/planner (single point of failure); role boundaries rely on prompt discipline.
**Adaptation:** Use BugFound's tool registry to create *role-scoped registries* (a Pentester role sees only recon/exploit-scoped tools, gated again by `bugfound-policy` scope + approval — defense in depth, not prompt-only). Implement handoff as a tool that starts a **child session/step** with a copied-but-redacted context, returns a typed result event, and stamps parent/child IDs in the event chain. Keep it synchronous and bounded.

---

## 3. Reflection / self-correction

**Constants** — `ROOT/backend/pkg/providers/performer.go:29-42`: `maxRetriesToCallSimpleChain=3`, `maxRetriesToCallAgentChain=3`, `maxRetriesToCallFunction=3`, `repeatEchoLimit=4096`, `maxReflectorCallsPerChain=3`, `maxGeneralAgentChainIterations=100`, `maxLimitedAgentChainIterations=20`, `maxAgentShutdownIterations=3`, `maxSoftDetectionsBeforeAbort=4`, `delayBetweenRetries=5s`.

| Mechanism | Evidence | Behavior |
|---|---|---|
| Per-agent iteration cap | `performer.go:99-121` | General agents (assistant/primary/pentester/coder/installer) 100; others 20; overridable but floored at `maxAgentShutdownIterations*2`. At the cap → `ErrAgentModelCall`. |
| Graceful termination | `performer.go:124-137` | In the last 3 iterations, injects a synthetic "too close to iteration limit" message so the model calls a barrier tool instead of being killed. |
| Chain window compaction | `performer.go:138-148` (`compactChainForWindow`) | Pre-call compaction of long chains. |
| Tool-call JSON sanitization | `performer.go:478-488` | Invalid JSON args → `"{}"` so the fixer can regenerate; control chars stripped via `cast.SanitizeJSONControlChars`. |
| Tool-arg fixer | `performer.go:355-395` (call at `:386`, `fixToolCallArgs`) | On tool error fetch schema, ask `tool_call_fixer` agent to repair arguments, retry; short-circuits on `context.Canceled` and `tools.ErrFlowStateGuard` (`:363-375`). |
| Reflector on unstructured output | `performer.go:162-189` + `:611-774` | If a non-assistant agent returns no tool call, the Reflector acts as the *user*, injects corrective guidance (reminding about barrier tools), then re-calls the original chain; max 3 iterations (`:637-652`), recursion guarded by a context flag (`:760-770`, `helpers.go:71-84`). |
| Caller-reflector on exhaustion | `performer.go:500-514`, `:776-829` | After 3 failed model calls, invokes the Reflector with the accumulated errors instead of a hard failure; `markReflectorRetry` prevents recursive reflector calls. |
| Repeating-call detection | `helpers.go:86-160` (`repeatingDetector`, threshold 3 at `:29`), `performer.go:323-348` | Compares consecutive calls after stripping the `message` arg and sorting args (`:138-160`); on repeat, echoes the *previous tool answer* (up to 4096 bytes, `:126-136`) so the model sees the diagnosis; hard abort after `3+4` repeats (`performer.go:324-328`). |
| Execution monitor / Mentor | `helpers.go:162-197` (`executionMonitor`), `performer.go:397-412`, `performers.go:887-968` | After N same-tool or M total calls (config `EXECUTION_MONITOR_*`, wired at `ROOT/backend/pkg/providers/providers.go:399-403,449-453,543-547,596-600`), invokes the Adviser as "mentor" with recent messages, executed tool calls, subtask description and last tool result; response wrapped as `<original_result>` + `<mentor_analysis>` (`helpers.go:1129+`); counters reset. |
| Planner | `performers.go:825-884` | Optional (`AGENT_PLANNING_STEP_ENABLED`) adviser-generated 3–7 step plan wrapped in `<task_assignment>` before specialist execution. |
| Chain consistency | `ROOT/backend/pkg/providers/provider.go:950-966` (`EnsureChainConsistency`) | After interruption, adds default responses to unresponded tool calls so the chain stays valid. |
| Summarization | `performer.go:256-278`, `ROOT/backend/pkg/csum/chain_summary.go` | Chain summarization; errors swallowed with a Langfuse warning event; LRU cache described in doc at `flow_execution.md:905`. |

**Strengths:** Orthogonal layers (args → call → output → loop → budget); every recovery path is *bounded*; repeated-call response preserves diagnostic information (a thoughtful fix to a real failure mode, documented in `helpers.go:119-125`); state guards avoid pointless retries.
**Weaknesses:** Complex control flow with two different reflector entry points plus recursion flags — subtle to reason about; "mentor" and "reflector" are LLM calls, so recovery itself can fail or be prompted; consecutive-only repeat detection misses A→B→A cycles; many knobs (limits are split between constants, config, and doc).

**Adaptation:** In `bugfound-core`, implement a small **recovery pipeline** after every tool call: (1) normalize args and detect repeats over a *sliding window* (not just consecutive) and return the prior result verbatim; (2) on `ErrToolArgs`, repair once against the tool's JSON schema with a bounded sub-call; (3) on model output with no tool call, emit a corrective user message with the registered terminal tools, max 2–3 times; (4) at step-budget thresholds, ask the planner/adviser for a progress review or force a terminal decision; (5) finish with an explicit terminal tool mapped to BugFound's session state. Reuse existing budgets (`README.md:26-29`) as the hard cap — do not duplicate limits.

---

## 4. Memory (working / long-term / episodic / retrieval)

### 4.1 Working memory
Serialized message chain per agent type in `msgchains.chain` (`database/models.go:979-997`); restored on restart (`provider.go:697-703`, `performers.go:213-284` for refiner which rebuilds a chain from AST sections — `ROOT/backend/pkg/cast/chain_ast.go`). Execution context injected into prompts/subtask context (`provider.go:657-691`).

### 4.2 Long-term semantic memory (pgvector)
- Store: `ROOT/backend/pkg/database/knowledge/vectorstore/vectorstore.go:9-18` — `pgvector` with collection `"langchain"`, pgxpool.
- API: `ROOT/backend/pkg/database/knowledge/knowledge.go:35-59` (interface; admin + user-scoped reads/writes), `:23-27` (`defaultSearchThreshold=0.2`, `defaultSearchLimit=10`), `:61-95` (store with `maxEmbeddingBytes` default 8192 and truncation before embedding, full text kept).
- Metadata/provenance: `knowledgeMeta` at `:99-114` — `doc_type, user_id, flow_id, task_id, subtask_id, question, description, guide_type, answer_type, code_lang, part_size, total_size, manual`. Doc types: guide/answer/code/memory (see `ROOT/backend/pkg/graph/model/models_gen.go:272-288`).
- Search: `doSearch` `:340-427` — embeds query, does parameterized SQL cosine-distance search with user ownership + threshold + limit, then Go-side filters for multi-value enums/FlowID/Manual (`:429-454`). Two-layer filtering avoids SQL injection and keeps enum logic readable.
- Embeddings: `ROOT/backend/pkg/providers/embeddings/embedder.go:26-84` — pluggable openai/ollama/mistral/jina/huggingface/googleai/voyageai/none; `wrapper.go`.

### 4.3 Episodic memory (Graphiti)
- Client: `ROOT/backend/pkg/graphiti/client.go:41-53` (`enabled`, timeout, **permanent process-lifetime disable on failed health check** — 3 attempts, 2s backoff), `:55-81` health check, `:96-118` `awaitCall` (ctx-bounded wait, not bounded work), `:120-185` search APIs: temporal-window, entity-relationships, diverse, episode-context, **successful-tools**, recent-context, entity-by-label.
- Retrieval tool: `ROOT/backend/pkg/tools/graphiti_search.go:334-...` (handlers for each mode, e.g. `handleEpisodeContextSearch` at `:478`, `handleSuccessfulToolsSearch` at `:505`).
- Writes: `ROOT/backend/pkg/providers/performer.go:979-1008` (`storeToGraphiti` attaches `GroupID`, `Observation{ID, TraceID, Time}`), `:1011-1089` (agent responses, with author `("<agent> Agent")`, `SourceDescription` containing flow/task/subtask and template-rendered content), `:1091-1197` (tool executions with tool name, args, description, success/failure status, result, task/subtask scope). Agent-tool calls are deliberately excluded from Graphiti writes at `performer.go:218-222`.
- Templates: `ROOT/backend/pkg/templates/graphiti/agent_response.tmpl`, `tool_execution.tmpl`.

### 4.4 Auto-storage on tool execution
`ROOT/backend/pkg/tools/executor.go:597-683` (`storeToolResult`): allowed tools list at `ROOT/backend/pkg/tools/registry.go:154-172` (terminal, file, search engines, agent delegation tools); anonymizes via `vxcontrol/cloud/anonymizer` replacer (`executor.go:22,609`), chunks with `textsplitter.NewRecursiveCharacter` (2000 chars/100 overlap, code blocks + heading hierarchy, `:611-617`), attaches provenance metadata (`user_id, flow_id, task_id, subtask_id, tool_name, tool_description, doc_type, part_size, total_size`, `:622-641`), writes to pgvector and a `vecstorelogs` row with parent/current agent context (`:647-680`). Large terminal/browser results (>16KB) are summarized instead (`executor.go:29,354-372`).

**Strengths:** Clear separation of reusable knowledge (guide/answer/code) vs episodic history (memory/Graphiti) — the prompt guidance at `flow_execution.md:731-735` reflects a deliberate design decision; strong provenance; anonymization at the storage boundary; parameterized search.
**Weaknesses:** Embedding provider can be `none` and knowledge store then silently degrades (`knowledge.go:69-72`); Graphiti health failure is sticky for the process (`client.go:48-53`); no explicit memory-invalidation/TTL policy; heavy external service dependency (Graphiti server, embedding API).

**Adaptation:** In `bugfound-store`, add three tiers over SQLite: (1) *working* = existing session messages/events; (2) *episodic* = existing `trace_events`/timeline plus a `tool_result` event carrying `{session_id, task_id, tool_name, status, args_hash, result_excerpt}` — this is the Graphiti pattern without the service; (3) *semantic* = optional embeddings with `doc_type, engagement_id, task_id, source_event_id, part_size, total_size` provenance, filtered by scope before retrieval. Retrieve memory **before** external tools and gate every recalled item through `bugfound-policy` scope checks (prompt-injection resistance). Do not import `vxcontrol/graphiti-go-client`.

---

## 5. Tool execution and sandbox

### 5.1 Executor pipeline
`ROOT/backend/pkg/tools/executor.go:141-158` (`customExecutor`: DB, msg log, anonymizer replacer, tool-call log, pgvector store, vector log, definitions/handlers/barriers, summarizer). `Execute` (`:283-414`): dispatch by name → unknown-tool response (`:291-294`) → unmarshal args with a repair hint (`:296-299`) → choose Langfuse observation type by tool category (`:301-316`) → message log (`:320-328`) → `toolcalls` row (`:330-334`) → handler with sanitize/summarize/truncate (`:341-380`) → auto-store to memory (`:394-396`) → update message result on a detached, timeout-bounded context (`:398-409`). Tool arguments are capped at 1KB per value (`executor.go:31`, `:552-554`); results at 16KB (`executor.go:29`).

### 5.2 Terminal / Docker
- Terminal tool: `ROOT/backend/pkg/tools/terminal.go:26-41` (container prefix, **3h hard timeout**, +5s grace, 500ms quick check), `:82-99` timeout normalization (never unbounded), `:200-260` `ContainerExecCreate` with stdout/stderr attached and optional detach, `:263-...` `getExecResult` with timeout, partial output capture, terminal-log write, and a suggested `timeout <n> <cmd>` hint (`:313-323`).
- Docker client: `ROOT/backend/pkg/docker/client.go:32-36` (`/work`, port base 28000), `RunContainer` `:242-441`: DB container record, image pull with default-image fallback (`:297-323`), deterministic hostname (CRC32), `/work` workdir, tenant labels, `RestartPolicyOnFailure` max 5 (`:346-349`), per-flow volume bind (`:351-364`), **PidsLimit 2048** (`:374-380`), JSON log rotation 10m×5 (`:382-388`), port bindings/network (`:390-435`). Cleanup: `StopContainer :737`, `KillFlowCommands :766`, `RemoveContainer :842`, `Cleanup :876`.
- Capability policy: `ROOT/backend/pkg/docker/worker_spec.go:18-44` — `CapDrop: ["ALL"]` plus explicit allow list `CHOWN, DAC_OVERRIDE, FSETID, FOWNER, NET_RAW, SETGID, SETUID, SETFCAP, SETPCAP, NET_BIND_SERVICE, SYS_CHROOT, KILL, AUDIT_WRITE, SYS_PTRACE` (+`NET_ADMIN` if configured); entrypoint `tail -f /dev/null`. Rationale and the deliberate *omission* of `no-new-privileges` are documented at `client.go:368-372` and in `backend/docs/docker.md`.
- Container reuse/file sync: `ROOT/backend/pkg/tools/tools.go:481-544` (`Prepare`: probe/reuse existing container or rebuild, then `syncMissingFiles` at `:553+` — one exec to find missing files, one tar stream to copy).
- Sandbox probe: `ROOT/backend/pkg/docker/sandbox.go:22-35,48-100` — embedded JSON-lines probe script validates that the runtime really enforces the expected authorization plugin before trusting it; daemon guide `ROOT/backend/examples/guides/worker_node.md`.
- Web isolation: browser/scraper is a separate container; private-vs-public target scraper selection is described in `flow_execution.md:929-946`.

**Strengths:** Default-deny capabilities; resource bounds (pids, log size, exec timeouts); deterministic per-flow workdir/ports; outbound result caps and summarization; startup verification of the sandbox; cleanup paths.
**Weaknesses:** `NET_RAW`/`SYS_PTRACE` and optional `NET_ADMIN`/host-network mode are intentionally permissive for pentest fidelity — a hostile model has a large surface; restart-on-failure can resurrect a stopped workload; no `no-new-privileges`; proxy/secret handling depends on the anonymizer; container isolation is heavyweight for a local desktop tool.
**Adaptation:** Keep the *pattern*, not Docker. BugFound already has stronger default posture for local use (`README.md:30-35`: workspace confinement, 512KB read cap, 8KB truncation, shell allowlist/no chaining, DNS pinning, private-IP blocking). Add: (a) explicit per-tool timeout with partial-output capture and a model-readable "command timed out, use `timeout`" hint; (b) a `toolcalls`-style lifecycle row with status and duration; (c) a startup self-check that verifies `bugfound-policy` is actually enforcing before `full_auto` runs (analogous to the sandbox probe); (d) bounded output summarization over the existing 8KB truncation. Do not grant container capabilities to BugFound; the policy layer is the boundary.

---

## 6. Persistence and observability

**Schema** — `ROOT/backend/migrations/sql/20241026_115120_initial_state.sql`: roles/privileges/users/prompts (`:3-107`), flows (`:109-130`), containers (`:132-153`), tasks (`:155-172`), subtasks (`:174-191`), toolcalls (`:193-214`), msgchains (`:216-250`), termlogs (`:252-264`), msglogs (`:266-283`), screenshots (`:285-295`), `update_modified_column()` trigger (`:297+`). Added later: agentlogs/vecstorelogs/searchlogs (`20241130_183411_new_type_logs.sql:15,36,60`), assistant logs (`20250331_200137_assistant_mode.sql:114,139`), flow `trace_id` (`20250102_152614_flow_trace_id.sql`), subtask `context`, knowledge tables (`20260501_120000_knowledge.sql:27,37`), tracking/indices (`20260129_120000_add_tracking_fields.sql:164`), tool-call ID hash index (`20260720_...`), autovacuum tuning (`20260721_...`).

**Go models:** `ROOT/backend/pkg/database/models.go` — Flow `:939`, Msgchain `:979`, Msglog `:999`, Searchlog `:1053` (initiator/executor agent types + engine/query/result), Termlog `:1089`, Toolcall `:1100`, Screenshot `:1043`. Generated queries in `ROOT/backend/pkg/database/*.sql.go` via sqlc.

**Logging architecture:** Controller/Worker pattern per log category (`ROOT/backend/pkg/controller/{alog,aslog,alog...}.go`, e.g. `tclog.go`, `vslog.go`, `slog.go`) with per-flow workers publishing GraphQL subscriptions (`graph/subscriptions/...`); documented at `flow_execution.md:466-560`.

**Tracing:** `ROOT/backend/pkg/observability/obs.go:81-96` (Observer interface: `Flush/Shutdown/NewObservation/NewSpan`), `:149-203` init, `:204-280` `Flush/Shutdown/Drain` (concurrent bounded drain), `ROOT/backend/pkg/observability/lfclient.go:26-62` (Langfuse client). Every major step creates spans/agents/evaluators: `performAgentChain` span (`performer.go:67`), primary-agent Langfuse agent with flow/task/subtask/image/lang metadata (`provider.go:778-793`), reflector agent+evaluator (`performer.go:672-712`), per-tool observations (`executor.go:42-140,172-262`), `flowWorker.execTask` span (`flow.go:1449-1489`). Message chains record token usage and cost (`models.go:984-996`), and analytics derive durations from chain types (`ROOT/backend/pkg/database/converter/analytics.go:21-141`).

**Strengths:** Every user-visible action is a durable row with flow/task/subtask FK and soft-delete cascade; per-category logs avoid a single giant table; token/cost/duration recorded per chain; OpenTelemetry + Langfuse give both system and LLM-level tracing; real-time subscription fan-out.
**Weaknesses:** Many tables and parallel log workers increase write amplification; `Chain` JSON is opaque; trace/correlation relies on convention; observability sinks can fail independently (mitigated by `Drain`).

**Adaptation:** BugFound already has an event hash chain and trace-event export (`README.md:50-52,70-71`). Add: a `tool_calls` table with `{id, session_id, task_id, call_id, name, status, args, result, duration_ms, created_at}`; `agent_chains` snapshots keyed by `(session_id, step_id, agent_role)` for resume; token/cost accounting on each LLM step; a stable `trace_id` propagated into every event and tool call; and route events to the desktop UI via the existing channel/event bus instead of GraphQL.

---

## 7. License nuance — what is safe vs dangerous

**Facts (verified):**
- `ROOT/LICENSE`: plain MIT, Copyright 2025 PentAGI Development Team.
- `ROOT/NOTICE`: "Licensed under MIT License. See LICENSE and EULA" **and** "This software integrates VXControl Cloud SDK ... licensed under **AGPL-3.0 with a special exception for this official PentAGI project**."
- `ROOT/README.md:4231-4245`: says PentAGI is MIT; third-party deps "MIT-compatible"; then says "While the VXControl Cloud SDK code is MIT licensed, accessing VXControl Cloud Services ... requires a separate License Key and compliance with Terms of Service" — **this contradicts the NOTICE on the SDK's license**.
- `ROOT/EULA.md:5-21`: source is MIT; EULA governs use of the product as a whole (source, Docker images, web UI); MIT prevails for source in conflict; use is a revocable, non-transferable license; no sublicensing beyond MIT. `:23-31` acceptable-use/authorized-testing restrictions; `:33-49` user bears GDPR/third-party/LLM-provider responsibility; `:59-67` liability caps; `:69-71` indemnification; `:73-91` termination, UK governing law/arbitration.
- `ROOT/backend/go.mod:58-60`: `github.com/vxcontrol/cloud v1.0.1`, `github.com/vxcontrol/graphiti-go-client v0.9.0`, `github.com/vxcontrol/langchaingo v0.1.14-update.8` — **VXControl forks of core libraries** (`anonymizer` is imported at `ROOT/backend/pkg/tools/executor.go:22`). `ROOT/licenses/README.md:28-43` claims all deps are MIT-compatible.
- `ROOT/research/README.md` note (BugFound's own policy): clones are reference-only; "Jangan salin kode langsung ke BugFound tanpa memeriksa lisensi dan atribusi."

**Safe:** Study architecture, state machines, prompt-tool contracts, limits, schemas, and failure modes; reimplement ideas independently in Rust. MIT permits copying source with attribution, but the AGPL/NOTICE contradiction and EULA make that a poor choice.
**Dangerous:** (1) Copying Go source verbatim or near-verbatim into `bugfound-*`; (2) importing `github.com/vxcontrol/*` modules — the Cloud SDK is AGPL-3.0 and its "special exception" is granted to the **official PentAGI project**, not to BugFound; (3) assuming the README's "SDK code is MIT" overrides the NOTICE; (4) treating the EULA's acceptable-use, revocation, indemnification, or UK-law terms as if they did not exist; (5) copying prompt templates verbatim (they are part of the MIT source, but copying invites attribution/EULA disputes and offers no technical advantage); (6) assuming `licenses/README.md`'s "MIT-compatible" blanket statement is legally sufficient due diligence.
**Concrete rule for BugFound:** patterns only; original code; no VXControl imports; keep an attribution note in research docs (not in production code) that ideas were informed by PentAGI, and have the license audit (`docs/research/10_license_audit.md`) record the README/NOTICE/EULA contradiction explicitly.

---

## 8. Cross-cutting adaptation map for BugFound

| PentAGI pattern | BugFound target crate | Concrete adaptation |
|---|---|---|
| Ordered durable Subtask plan + delta Refiner | `bugfound-engagement`, `bugfound-store` | `plan` rows with `seq`/`revision`; atomic revision swap; deterministic coverage-ledger planner first, LLM proposes deltas; keep `≤N` bound and "empty plan ⇒ one step". |
| Three-level status with back-propagation + guarded transitions | `bugfound-core` | Reuse `transition_state_owned`; add explicit `waiting_approval`/`waiting_input` mapping; one function owns cross-entity status propagation. |
| One bounded tool loop per step + barrier tool | `bugfound-core` | Terminal tool → session state; step = `llm.stream` continuation from reloaded history; budgets are the hard cap; no unbounded in-memory loops. |
| Capability-scoped specialist executors | `bugfound-core`, `bugfound-tools`, `bugfound-policy` | Role-scoped registries + policy gates; child-session handoff with typed result event; parent/child lineage in the event hash chain. |
| Layered bounded recovery (arg fixer, reflector, repeat detector, mentor) | `bugfound-core`, `bugfound-llm` | Sliding-window repeat detection echoing previous result; schema-based single repair; corrective user message ≤3; planner review at budget thresholds; forced terminal decision. |
| Provenance-rich memory (pgvector + Graphiti) | `bugfound-store` | Working/episodic/semantic tiers; every memory row carries `session/task/engagement/tool/source_event_id`; scope-filter on retrieval; no Graphiti dependency. |
| Tool-call lifecycle + timeouts + partial output | `bugfound-tools`, `bugfound-store` | `tool_calls` table; per-tool timeout with partial output; existing 8KB truncation + summarization; startup self-check that policy is enforcing before `full_auto`. |
| Chain snapshots, token/cost, spans, subscriptions | `bugfound-store`, `bugfound-desktop`, `bugfound-cli` | `(session, step, role)` chain snapshots; usage on each LLM step; stable `trace_id` on all events; stream events to existing desktop tabs. |
| License hygiene | docs/audit | Patterns only; no VXControl imports; document README/NOTICE/EULA contradiction. |

---

### Appendix — highest-value source files
`ROOT/backend/pkg/providers/performer.go` (agent loop/reflection), `ROOT/backend/pkg/providers/provider.go` (plan/generate/refine/report), `ROOT/backend/pkg/providers/performers.go` (specialists/mentor/planner), `ROOT/backend/pkg/providers/helpers.go` (detectors), `ROOT/backend/pkg/controller/{flow,task,subtask,subtasks,tasks}.go` (scheduling/lifecycle), `ROOT/backend/pkg/tools/{executor,terminal,registry,tools}.go` + `ROOT/backend/pkg/docker/{client,worker_spec,sandbox}.go` (execution/sandbox), `ROOT/backend/pkg/database/knowledge/knowledge.go` + `ROOT/backend/pkg/graphiti/client.go` + `ROOT/backend/pkg/providers/embeddings/embedder.go` (memory), `ROOT/backend/migrations/sql/*` + `ROOT/backend/pkg/observability/*` (persistence/tracing), `ROOT/{LICENSE,NOTICE,EULA.md,README.md}` + `ROOT/backend/go.mod` (license).
