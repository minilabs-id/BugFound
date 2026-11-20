# 11 Current gap analysis: AgentBug vs. the master vision

Date: 2026-11-20. Mode: READ-ONLY review of crates/agentbug-*, README.md,
docs/PRODUCTION_PLAN.md, docs/HARDENING_PLAN.md, docs/REMAINING_GAPS.md,
docs/TOOLS_CONTROL_HARDENING.md, docs/architecture.md, docs/research and eval/.
No code was modified; no tests were executed. Test counts are declared test
functions counted from source (215 workspace-wide), not a pass/fail claim.
Severity legend: Critical means the advertised mechanism cannot work in
production; High means a core pillar of the vision is absent or inverted;
Medium means partial or incorrect implementation, or material doc drift;
Low is polish; Deferred is consciously out of scope per REMAINING_GAPS.md.


---



## 0. Executive verdict (brutal)

AgentBug is **not** a Universal Agent Kernel with a Bug Bounty Domain Engine
plugged in. It is one vertically integrated, single-process bug-bounty harness.
The crates marketed as reusable infrastructure (agentbug-core, agentbug-tools,
agentbug-policy, agentbug-store) are saturated with bounty-domain concepts:
findings, CVSS/CWE, scope/ROE, WSTG playbooks, canaries, coverage, hypotheses,
clues, report rendering and target extraction. There is no seam at which the
domain could be removed without rewriting the core.
More seriously, the **verification pillar is functionally broken in the real
product path**. The "independent canary oracle" requires the captured response
to contain a canary that the HTTP tool mints internally but **never sends in the
request** (Section 2). Every verifier test passes only because the tests manually
splice the canary into synthetic response bytes. Against a live target the
verifier cannot promote a single finding, so a production engagement's report
will always contain zero verified findings. This is not a "deferred feature"; it
is a shipped feature that fails closed so hard that it never opens.
Multi-agent orchestration, reflection, and memory layers do not exist. Provider
"abstraction" is one trait with one OpenAI-compatible HTTP implementation and a
side-channel for token usage. The tool runtime is a static in-process registry
with PATH-scanning adapters, not a dynamic, capability-negotiated tool layer.
Permission/sandbox is a solid policy layer plus defense-in-depth string checks,
explicitly not an OS sandbox. Program intelligence is a fixed nine-item WSTG
checklist, a static CWE/WSTG table, heuristic brief parsing and a CVSS v3.1
scorer. Reporting is a good local Markdown renderer with no submission path (by
design). Observability is durable events plus eval-trace scaffolding, not
production telemetry. Evaluation is scaffolding with **no recorded results and
no executed baseline**, and the only end-to-end smoke test runs the offline,
zero-tool LLM.

The prototype is genuinely hardened in the areas it advertises as hardened
(leases, atomic approvals, durable budgets, egress controls, redaction, shell
allowlist, tamper-evident event chain). The gap is architectural and functional,
not a lack of small fixes.

---



## 1. Vision scorecard

- Kernel vs domain separation: Absent / High. No seam; core, tools, policy and store are the domain engine.
- Agent runtime: Implemented and tested. Bounded step loop, leases, approvals,
  budgets, recovery.
- Multi-agent orchestration: Missing / High. Subagent removed; one Runner, one
  session, no teams or graphs.
- Reflection and self-critique: Missing / High. No critic, no review step, no
  revision loop.
- Memory layers: Partial / Medium. Durable messages plus heuristic compaction;
  no episodic or semantic memory, no retrieval.
- Provider abstraction: Partial / Medium. Llm trait plus one OpenAI-shaped
  client; no streaming or native providers.
- Tool runtime: Partial / Medium. Static typed registry plus PATH adapters; no
  MCP, discovery or schema validation.
- Permission and sandbox: Partial / Medium. Strong policy, scope and egress
  blocks, but no OS sandbox.
- Program intelligence: Partial / Medium. Nine static WSTG tasks, static
  knowledge base, heuristic plus LLM scope parse.
- Verification: Broken in production / Critical. Canary never transmitted; tests
  use synthetic captures.
- Reporting and submission: Partial / Deferred. Canonical local report;
  submission intentionally absent.
- Observability: Partial / Medium. Durable events, trace_events, hash chain,
  in-memory bus; no OTel or metrics.
- Evaluation: Scaffolding only / High. Scorer, exporter and drivers exist; zero
  results, no baseline, offline e2e.

---



## 2. CRITICAL: the verification oracle is unsatisfiable in production

Severity: Critical. This is the single most important finding in this report.
Evidence chain, all verified in code:

1. crates/agentbug-tools/src/lib.rs:940-951 - canary_for(request) hashes request
   bytes plus nanoseconds into a token "agentbug-canary-" plus 64 hex digits.
2. crates/agentbug-tools/src/lib.rs:953-960 - build_capture stores that token as
   HttpCapture.canary. It does not add it to the request or the response.
3. crates/agentbug-tools/src/lib.rs:1056-1088 - the outgoing request is built from
   caller-supplied method, URL, headers and body. No canary header, query
   parameter or body injection exists; request_repr is built from the same
   inputs at lines 1082-1088.
4. crates/agentbug-tools/src/lib.rs:1125-1160 - the captured response is status
   plus observed headers plus redacted body. The canary is never present unless
   the remote server independently emitted that exact random token.
5. crates/agentbug-tools/src/lib.rs:1252-1261 - ValidatePoCTool replays caller
   headers and body verbatim and forwards the capture; it also never injects a
   canary.
6. crates/agentbug-engagement/src/lib.rs:2184-2187 - the verifier accepts a
   finding only when response.contains(canary) AND has_success_status(response).
7. crates/agentbug-engagement/src/lib.rs:2935-2965 and 2978-2985 - verifier tests
   construct captures by hand with a response string that manually includes the
   canary. That is why the suite is green while the product cannot validate a
   real finding.
Impact: verify_findings (lines 2163-2249) promotes nothing, so
store.verified_findings (line 1039) is empty and build_canonical_report
(lines 1046-1054 and 2265-2374) reports zero verified findings on every real
engagement. The "self-grading prevention" property is achieved vacuously: the
system is independent of the LLM because it rejects everything. Claims in
HARDENING_PLAN.md H-04 (lines 88-100) and PRODUCTION_PLAN.md matrix row 10 about
a working authoritative verifier are therefore false in production.
Recommended next action (P0): decide the oracle semantics explicitly, then make
them real. For reflected-input classes, inject a canary header or parameter into
the outgoing request inside HttpRequestTool and verify its reflection in the
stored response. For non-reflected classes, replace the canary check with an
independently controlled ground-truth signal (canary server or manifest-declared
marker) plus per-class validation. Add an integration test that drives a real
HTTP tool against a local server and asserts a finding is promoted without any
hand-built ToolCapture. Keep the "no LLM-supplied bytes" invariant.

---



## 3. HIGH: Universal Kernel versus Bug Bounty Domain Engine, no separation

There is no kernel crate and no domain crate. The dependency direction is
inverted from the vision: the supposed kernel depends on every concrete domain
adapter. Evidence:

- crates/agentbug-core/Cargo.toml:19-22 - core depends on agentbug-llm,
  agentbug-tools, agentbug-policy and agentbug-store (all concrete).
- crates/agentbug-tools/Cargo.toml:18 - the tool runtime depends on
  agentbug-policy, which is the bounty scope engine.
- crates/agentbug-policy/src/lib.rs:38-54 defines ScopeConfig with engagement,
  in_scope and out_of_scope; lines 168-223 define parse_scope_brief; lines
  341-363 require network actions to be in engagement scope. A generic
  permission engine cannot be extracted without deleting these.
- crates/agentbug-core/src/lib.rs:67-76 - goal_digest binds runs to a scope
  summary; lines 163-201 - prioritize_targets expands wildcard scope and ranks
  by Hypothesis.
- crates/agentbug-core/src/lib.rs:377-549 - persist_bounty_tool_result dispatches
  on finding/asset/artifact/task/clue names and reads severity, cvss, cwe,
  vuln_type, canary, engagement_id and playbook_id. Domain orchestration lives
  in the runner.
- crates/agentbug-core/src/lib.rs:1020-1048 - the stall guard counts confirmed
  findings plus assets plus artifacts; lines 1763-1771 emit "No new findings
  ... concluding playbook".
- crates/agentbug-core/src/lib.rs:1298-1304 - the system prompt says "You are
  AgentBug, a universal agent core" immediately followed by "Engagement scope:
  ... Never probe out-of-scope targets." The kernel prompt is domain-injected.
- crates/agentbug-core/src/lib.rs:2123-2193 - extract_policy_target knows asset,
  fqdn, subdomain and endpoint, and parses shell commands for URLs.
- crates/agentbug-tools/src/lib.rs:76-103 - ToolOptions carries scope, ROE
  user-agent, max RPS and allowed HTTP methods (ROE policy in tool config).
- crates/agentbug-tools/src/lib.rs:2044-2087 and 2115-2131 - the "universal"
  registry registers SaveFindingTool, RecordAssetTool, ValidatePoCTool,
  HttpFuzzTool, PayloadForgeTool, KnowledgeLookupTool, ReportWriterTool,
  TaskPutTool, CluePutTool, vuln_scan and a gated browser CLI adapter.
- crates/agentbug-tools/src/lib.rs:2870-2988 - bundled WSTG and CWE knowledge
  base and knowledge_lookup.
- crates/agentbug-tools/src/lib.rs:3010-3178 - ReportFinding, ReportInput and
  render_canonical_report (CVSS, CWE, PoC, evidence hash, scope and ROE) live
  in the tool crate.
- crates/agentbug-store/src/lib.rs:270-380 - one monolithic SQLite schema mixing
  session primitives with findings, assets, coverage, hypotheses, engagements,
  tasks, clues, evidence, reports and trace_events.

Impact: the kernel cannot be reused for a non-security agent, cannot be tested
without bounty semantics, and every domain change ripples through core and
tools. The vision's "universal kernel" is currently a label, not an
architecture.
Recommended next action (P1): establish a seam rather than a big-bang rewrite.
-a Define kernel traits for Policy, Tool, Store and Model with generic
  ActionRequest and ToolSpec; move scope/ROE, finding/report and WSTG into
  agentbug-engagement or a new agentbug-domain crate.
-b Replace persist_bounty_tool_result, prioritize_targets, evidence_count and
  the scope-bearing system prompt in core with an injected domain Observer or
  Planner trait implemented by engagement.
-c Split the domain tables into a separate store extension.
-d Enforce with a CI dependency check: core must not import policy domain types
  or mention finding, scope, cvss or cwe.
Verified NOT gaps (do not re-report): ToolOptions.allowed_methods is implemented
and enforced (tools/src/lib.rs:1007-1016); B1 capture bytes are stored via
attach_capture (core/src/lib.rs:450-463); approvals are a single
park_with_approval transaction (core/src/lib.rs:2048-2049); B12 goal lock uses
SHA-256 plus injection regex (core/src/lib.rs:67-111).

---



## 4. Gap catalog by vision dimension


### 4.1 Agent runtime: genuinely implemented and tested

Bounded one-LLM-call-per-step loop with durable reloaded history
(core/src/lib.rs:1750-2109), claims/leases and guarded transitions
(lines 688-707 and 1150-1233), atomic approval park/resume
(lines 1586-1725 and 2000-2075), crash recovery (670-686), durable budgets and
rate/cooldown/duplicate guards (773-803, 939-969, 1050-1105), injection
detection and goal/scope lock (82-111, 833-852). There are 41 integration tests
in core/tests/runner_integration.rs and 12 unit tests in core/src/lib.rs.
No action beyond the kernel refactor and verifier fix.

### 4.2 Multi-agent orchestration: missing, High

Evidence: README.md:180-182 and docs/architecture.md:48-57 confirm subagent,
skill and usage were removed. core/src/lib.rs:1750-2109 is a single sequential
loop. Engagement creates "a fresh Runner per task"
(engagement/src/lib.rs:875-962) with no delegation, inter-agent messages, role
specialization or graph scheduler. inbox.rs and execution.rs are single-session
coordination, not multi-agent.

Impact: parallel planner/scanner/verifier agents, task handoffs and a shared
blackboard do not exist. The "planner" is a static list of nine WSTG tasks
(engagement/src/lib.rs:839-845 and 1899-1940).
Next action: if the vision requires it, add a domain-level orchestrator that
spawns scoped sub-sessions with typed handoff artifacts; keep it out of the
kernel and add tests for concurrent execution and budget sharing. Do not mistake
ExecutionCoordinator (process-global, session-keyed) for orchestration; it is
cancellation and wake bookkeeping only.


### 4.3 Reflection: missing, High

No reflect, critic, self-review or revision concept exists in crates (verified by
search; only "Reflected XSS" strings and is_self_graded_marker exist). The runner
appends tool output as untrusted text and immediately continues
(core/src/lib.rs:1516-1523 and 1948-1999). There is no second-pass review of a
draft finding, no challenge of a hypothesis and no quality gate except the
broken canary oracle.
Impact: no self-correction, no false-positive reduction before reporting, no
metacognitive loop. Combined with Section 2 the system has no functioning
quality signal.

Next action: add a bounded reflection step in the domain layer, a second LLM
call with a critic rubric over the candidate finding plus captured bytes that
emits a typed verdict; keep it advisory and measure it against the eval manifest
before claiming value.


### 4.4 Memory layers: partial, Medium

Exists: durable message history in SQLite (store/src/lib.rs:258), CompactionV2
summarization with preserved tail and orphan tool-result pruning
(core/src/compaction.rs:39-141), durable hypotheses, clues, coverage, findings
and assets tables (store/src/lib.rs:277-361), and a goal lock
(core/src/lib.rs:70-76).
Missing: no episodic memory across sessions or engagements, no semantic or
vector store, no retrieval-augmented recall, no importance or freshness scoring,
no per-target prior knowledge surviving a new engagement. Compaction is
truncation-based (compaction.rs:104-113 caps old messages at 400 chars and the
summary at 6000), not memory consolidation. CompactionV2::should_compact
(lines 79-81) exists but the runner uses a fixed 32 KB byte heuristic
(lines 40-47).

Next action: define memory as a domain service with provenance and TTL; add a
retrieval step to the planner. Keep raw history as the immutable log.

### 4.5 Provider abstraction: partial, Medium

Evidence: Llm trait at llm/src/lib.rs:90-112; the only implementation is
LlmClient (114-377), hard-wired to /v1/chat/completions with an OpenAI tool
envelope (242-297), one base_url and api_key (16-39), model discovery that
returns the first id (226-240), and token usage smuggled through
Arc Mutex Option TokenUsage (118-119, 312-323, 366-376).

Missing: streaming, native Anthropic/Gemini/local adapters, stopReason,
toolChoice, structured error channel, preference-based model selection and
content blocks. Prior research agrees in
docs/research/05_mcp_provider_abstraction.md:41-49 and 282-303.
Impact: "LLM-agnostic" means any provider that imitates OpenAI chat completions;
cost, latency and feature portability are limited.

Next action: make ChatResponse provider-neutral (content blocks, stop reason,
inline usage, typed tool errors), add streaming, add at least one non-OpenAI
adapter behind the trait, and remove the side-channel usage mutex.


### 4.6 Tool runtime: partial, Medium

Evidence: static ToolRegistry as BTreeMap of String to Arc Tool with
register/get/specs (tools/src/lib.rs:105-151); compile-time built-ins plus PATH
discovery (2149-2272). Two divergent ToolSpec types (tools 30-36 versus llm
69-74) are converted lossily in the runner (core/src/lib.rs:1838-1847), dropping
risk metadata.
input_schema is sent to the model but arguments are never schema-validated at
the boundary; the runner only JSON-parses them (llm/src/lib.rs:425-432). Tool
results are flattened to one untrusted text string (core/src/lib.rs:1517-1523),
so the model gets no typed success or error channel. Prior research at
docs/research/05_mcp_provider_abstraction.md:305-329 documents the same lack of
namespacing, discovery, change notification, output schema and remote provider.

Impact: no dynamic capability negotiation, no safe third-party tool ecosystem,
no model-correctable errors, no input validation beyond per-tool ad hoc checks.
Next action: unify the tool descriptor, validate arguments against the declared
JSON Schema once at the runner boundary, add a typed result/error channel, and
design an MCP-style connector with discovery and namespacing before adding
external providers. Treat tool-supplied risk strings as untrusted hints, not
security decisions (core/src/lib.rs:762-771 and 866-871).


### 4.7 Permission and sandbox: partial, good policy, no OS boundary

Evidence: PolicyEngine::evaluate with allow/ask/deny, tool and target
allow-deny lists, destructive default-deny and scope enforcement
(policy/src/lib.rs:298-394 and 425-457); risk-aware approvals
(core/src/lib.rs:854-883 and 890-969); shell allowlist limited to echo and
whoami with metacharacter and path rejection (tools/src/lib.rs:165-208).
Also present: private and reserved IPv4/IPv6 blocking (tools 210-250), DNS
pinning (1027-1050), no redirects (1041), proxy validation (1020), output
truncation (153-163), redaction at egress (core 398-402 and 1517-1523).

Limits: README.md:170-184 and REMAINING_GAPS.md:20-21 state plainly this is not
an OS sandbox, prompt injection remains a design-level threat, and credentials
must come from the environment. The shell allowlist is so restrictive that
shell_exec is effectively a no-op; real command execution is delegated to gated
external adapters.

Next action: keep the policy layer, add OS-level isolation at deployment, and
add adversarial tests for the hand-written IP parser.

### 4.8 Program intelligence: partial, Medium

Evidence: heuristic scope and ROE extraction (engagement/src/lib.rs:1366-1430
and 1574-1678), optional LLM extraction with deterministic intersection that
cannot widen scope (1433-1494 and 783-805), nine static WSTG playbooks
(839-845 and 1899-1940), a full CVSS v3.1 base scorer with reference-vector
tests (1945-2075; engagement/tests/engagement_integration.rs:56-62), CWE mapping
(2077-2117), and a static WSTG and CWE keyword table
(tools/src/lib.rs:2870-2988).
Missing: no learned or adaptive playbook selection from evidence (the planner
mirrors tasks; prioritize_targets is a wildcard-expansion helper), no technology
fingerprinting driving test selection, no coverage of business-logic or
client-side classes beyond prompts, and ROE is limited to a few parsed fields
(ua_marker, max_rps, allow_fuzzing, allow_state_change, allow_disclosure).
Unparsed safety constraints abort the run (engagement/src/lib.rs:718-732): safe
but brittle.

Next action: make hypotheses first-class and score-driven, add
technology-aware playbook selection, and extend ROE parsing with recognised
constraint types plus a review UI instead of hard abort.

### 4.9 Verification: broken, Critical

See Section 2. Beyond the unsatisfiable canary: verification is a generic
2xx plus substring check (engagement 2251-2263) with no vulnerability-class
semantics, no re-request against a controlled oracle, no differential or timing
analysis, no confirmation that the finding claim matches captured evidence.
validate_poc is correctly advisory only (tools 1279-1282), which means the only
authoritative gate is the broken verifier. is_self_graded_marker (2260-2263) is
a fragile heuristic that rejects any HTML response lacking the canary.

Next action: P0 from Section 2, then per-class validators, an independent
ground-truth source, and end-to-end tests on local vulnerable testbeds.

### 4.10 Reporting and submission: partial, submission intentionally deferred

Evidence: canonical Markdown renderer with all required sections, evidence
hash, CVSS/CWE and PoC (tools/src/lib.rs:3010-3178); report built only from
verified findings (engagement 2265-2374); report written locally with SHA-256
recorded in the store (1055-1071); redaction at report egress (2311-2372).

No submission path exists anywhere in crates (verified by search: only "never
submit" strings at engagement/src/lib.rs:875, 953 and 1828). This matches
README.md:73-77 and REMAINING_GAPS.md:15 and is a deliberate design decision,
not a bug. Report it as Deferred, but note that a "complete bug bounty platform"
vision without any submission or review workflow has a missing end-to-end link:
an operator must manually review and submit.
Next action: if the vision eventually includes submission, add it as an explicit
opt-in domain adapter with human confirmation and an audit trail; keep it out
of the kernel.


### 4.11 Observability: partial, Medium

Evidence: durable events and trace_events tables (store/src/lib.rs:266 and 371),
tamper-evident event chain plus CLI verify-log (PRODUCTION_PLAN matrix row 11),
run_start/action/finding/verifier/usage trace events with run_id
(engagement/src/lib.rs:545-567, 612-638, 2216-2235), in-memory EventBus with
pub/sub, drain and replay (core/src/event.rs:40-185) wired into
Runner::log_event (core/src/lib.rs:611-623), CLI logs/tokens/status and desktop
Logs/Tools tabs.
Missing: no OpenTelemetry spans or metrics, no tracing context propagation, no
alerting, no dashboards, no request-level latency or throughput metrics, no
long-term aggregation. EventBus is process-local and duplicates the durable
chain without a single authority for consumers.

Next action: designate the durable chain as sole source of truth, add typed
event schemas and an OTLP exporter, emit tool and LLM latency plus budget
metrics.


### 4.12 Evaluation: scaffolding only, High

Evidence: eval/score.py (report structure plus recall, precision, FPR,
reproducibility and tokens-per-finding, stdlib only), eval/export_trace.py,
Windows and POSIX drivers, a golden manifest example, and one offline synthetic
fixture under eval/results/example-synthetic, all explicitly labelled "not a
result". README.md:150-168, PRODUCTION_PLAN.md:15-16 and 148-150, and
REMAINING_GAPS.md:16 and 18 agree: no results asserted, and the plain-agent
baseline is a plan, not a recorded result.
Critical weakness: eval/e2e_test.ps1:83-131 runs engage --brief-only and then an
offline full engagement (no API key, so OfflineLlm at
engagement/src/lib.rs:2384-2411 issues no tool calls and validates nothing),
then checks report headings and score.py --strict format checks. No Rust
integration test performs brief to plan to real tool execution to verification
to report. The nine tests in engagement/tests/engagement_integration.rs are
pure-function tests: scope parsing, ROE, CVSS, options, playbook count.

Impact: the harness can never fail a claim about detection quality because no
real detection has been run; combined with Section 2 its verifier would fail
every real finding anyway.
Next action: run the benchmark on local vulnerable testbeds, record results with
replay and manifest, execute the baseline, and add a Rust end-to-end test with a
local HTTP server that asserts a tool capture is promoted and appears in the
report. Until then keep the honest "hardened prototype, no benchmark results"
label.

---



## 5. Documentation versus code drift (verified)

D1 (Medium): README.md:180-182, architecture.md:48-57 and
PRODUCTION_PLAN.md:72-79 say inbox, execution and event have no production call
site and that wake coalescing is not implemented. Actual code:
core/src/lib.rs:611-623 publishes to EventBus, 628-650 drains Inbox,
1150-1213 and 1773-1789 use ExecutionCoordinator, and execution.rs:115-132
implements wake/take_wake. They are wired into the runner, though not into
multi-agent orchestration.

D2 (Low): architecture.md:74 says token/cost come from API usage and never from
a len/4 estimate. Actual code: core/src/lib.rs:144-146 estimate_tokens is used
at 1807-1818 for the pre-call token budget and at 1869-1873 as the fallback
when provider usage is absent.
D3 (Critical, already reported): HARDENING_PLAN.md:88-100 H-04 claims a working
independent verifier. Code works only for hand-built captures (Section 2).

D4 (Low): PRODUCTION_PLAN.md:4-5 and REMAINING_GAPS.md:57-58 say 180+ tests;
215 declared test functions were counted. Harmless, but the number must come
from the gate, as the docs themselves say.

D5 (Medium): core/src/step.rs:1-2 is presented as a retained module but is
explicitly "additive; Runner keeps its own inline implementation" and duplicates
reload_history and build_tool_specs; effectively dead code.

Next action: fix docs for D1, D2 and D5 as part of the kernel refactor; fix code
for D3. Add a docs-versus-code check to the verification gate so every feature
matrix row names a symbol that exists.

---



## 6. What is genuinely implemented and tested (do not regress)

- Durable sessions, leases, guarded transitions and stale-session recovery
  (core/src/lib.rs:670-707 and 1150-1233), 41 runner integration tests.
- Atomic approval park and resume with durable expiry, deferred tool-call
  batches and a full guard-chain re-run after approval
  (core/src/lib.rs:890-969, 1586-1725, 2000-2075).
- Durable budgets, duplicate and cooldown guards, injection detection and
  goal/scope lock (core/src/lib.rs:773-803, 939-969, 1050-1105, 82-111).
- Tool hardening actually present: shell allowlist, path checks, private IP
  blocking, DNS pinning, no redirects, proxy validation, method gate and output
  truncation (tools/src/lib.rs:165-250 and 1007-1168).
- Redaction at report, CLI and tool egress, and SHA-256 evidence bytes
  (core/src/lib.rs:398-402 and 1517-1523; engagement/src/lib.rs:2143-2156).
- Tamper-evident event chain, canonical report renderer, CVSS v3.1 scorer and
  trace/export/score scaffolding.
- Fail-closed brief ingestion with deterministic and LLM scope intersection and
  ROE translation (engagement/src/lib.rs:689-805 and 1574-1678).
- No submission path, by design (README.md:73-77).

---



## 7. Intentionally deferred (per REMAINING_GAPS.md, not actionable gaps)

Real browser engine (only a gated Playwright CLI adapter at
tools/src/lib.rs:2124-2131), clustering and distributed sessions, live
submission, performance benchmark, maintained fuzz corpus, baseline comparison
and OS sandbox. Do not "fix" these without an explicit product decision; do
report them honestly when claiming maturity.


---



## 8. Prioritized next actions

1. P0: make verification real (Section 2). Inject the canary into the outgoing
   request or replace the oracle with controlled ground truth; add a local-server
   integration test that promotes a finding end-to-end; re-run eval/score.py
   --strict on a real report.
2. P1: establish the kernel/domain seam (Section 3). Move bounty concepts out
   of core and tools into engagement/domain; inject domain observer and planner
   traits; add a CI dependency and keyword guard.
3. P1: record one real benchmark result and run the baseline (Section 4.12) so
   evaluation can fail a claim instead of only formatting a report.
4. P2: add reflection and a real multi-agent orchestrator as domain services
   (Sections 4.2 and 4.3), with typed handoffs and a shared budget.
5. P2: provider-neutral request/response plus streaming, and a unified,
   schema-validated tool descriptor and connector boundary (Sections 4.5 and
   4.6).
6. P2: memory service and program-intelligence adaptivity (Sections 4.4 and
   4.8). P3: OTLP observability (Section 4.11) and docs/code drift cleanup
   (Section 5).

Until P0 and P1 land, the honest label remains hardened prototype: a single
node, local-only bug-bounty harness with an unsatisfiable verifier, not a
universal agent kernel with a working domain engine.

