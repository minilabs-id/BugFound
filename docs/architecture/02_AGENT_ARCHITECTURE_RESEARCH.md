# 02 — Agent Architecture & Security-Domain Research (BugFound V3)

> Status: research input for the V3 blueprint. No source code was changed for
> this document. Access date for every source: **2026-11-26**.
>
> Reading key: **[FACT]** = directly supported by the cited source.
> **[INTERPRETATION]** = design inference for BugFound, not a claim from the
> source. Sources are numbered in §6; failed retrievals are listed in §7 and
> are **not** used as evidence.

---

## 1. Why this research was done

BugFound V3 must move from a fixed workflow executor to an **agent-driven
hybrid**: the agent chooses the next investigation step from evidence, while a
deterministic harness enforces scope/ROE/permission/budget/approval and an
evidence verifier decides what is actually proven. The research below maps
each of those four responsibilities to primary-source patterns.

## 2. Agent architecture patterns

### 2.1 ReAct — interleaved reasoning and action [FACT]
*ReAct: Synergizing Reasoning and Acting in Language Models*, Shunyu Yao et
al., arXiv:2210.03629 (ICLR). [S01] Reasoning traces induce, track and update
action plans and handle exceptions; actions query external sources for
information. On knowledge-intensive and decision tasks it reduced hallucination
vs. chain-of-thought and improved success by 34% / 10% absolute on ALFWorld /
WebShop with only one or two examples.

**[INTERPRETATION]** BugFound's loop is `observe → reason about the next step →
one harness-gated tool call → observe`. The reasoning trace belongs in the
audit log, not in the model's private state.

### 2.2 Reflexion — verbal feedback + episodic memory [FACT]
*Reflexion*, Noah Shinn et al., arXiv:2303.11366. [S02] Agents reflect on task
feedback verbally and keep reflective text in an episodic memory buffer; no
weight updates. Reported 91% pass@1 HumanEval vs 80% for GPT-4.

**[INTERPRETATION]** Verifier rejections ("not reproducible", "out of scope",
"duplicate") must be written back as structured reflections into the
investigation ledger so later steps avoid repeating them.

### 2.3 Plan-and-Solve / Plan-and-Execute [FACT]
*Plan-and-Solve Prompting*, Lei Wang et al., arXiv:2305.04091 (ACL 2023). [S03]
Devise a plan that divides the task into subtasks, then carry them out.
LangChain's *Plan-and-Execute Agents* [S06]: a planner emits a multi-step plan,
executors each take one step + tools, and a **re-planning prompt** decides
whether to finish or produce a follow-up plan. Benefits: cheaper/faster (no
large-model call per tool invocation) and better whole-task completion. ReWOO
uses variable bindings so later steps consume earlier outputs without an
intermediate LLM; LLMCompiler streams a DAG of dependent tasks with a joiner
that replans/finishes (paper-reported 3.6× speedup).

**[INTERPRETATION]** Persist `Plan` and `Replan` artifacts: step id, hypothesis,
technique id, target, dependencies, expected evidence. Independent passive
recon steps can be scheduled as a DAG **by the harness**, not by the model.

### 2.4 When tree search is worth it [FACT]
*Tree of Thoughts*, Yao et al., arXiv:2305.10601 (NeurIPS 2023) [S04];
*Language Agent Tree Search*, Andy Zhou et al., arXiv:2310.04406 [S05]. Both
explore multiple reasoning paths, self-evaluate and backtrack, using external
feedback (ToT: 4% → 74% on Game of 24; LATS: 92.7% pass@1 HumanEval).

**[INTERPRETATION]** Default to single-path plan-and-execute. Branch search only
for high-value ambiguous branches (competing exploitability hypotheses), and
cap branching with harness budgets.

### 2.5 Workflows vs agents; simplicity as a rule [FACT]
Anthropic, *Building effective agents* [S07]: a **workflow** orchestrates LLMs
and tools through predefined code paths; an **agent** dynamically directs its
own process and tool use. Recommendation: start with the simplest solution;
agentic systems trade latency and cost for performance. Patterns include
prompt chaining with programmatic **gates**, routing, parallelization
(sectioning and **voting**), orchestrator-workers, and evaluator-optimizer.
Agents gain **ground truth from the environment** at each step, may pause for
human feedback, and should include **stopping conditions such as max
iterations**. Three principles: simplicity, **transparency via explicit
planning steps**, careful **agent–computer interface** design. In their
SWE-bench work, more effort went into tool design than the overall prompt;
requiring absolute file paths removed a recurring error.

**[INTERPRETATION]** Split the responsibility: the *harness* is workflow-driven
(deterministic gates, budgets, approvals); the *agent inside it* is native-loop
for step selection. Use parallel voting for high-severity candidates and
evaluator-optimizer for the verifier.

### 2.6 Tool calling — contract, cost, and deferred loading [FACT]
OpenAI, *Function calling* [S08]: a five-step application↔model loop
(request with tools → tool call → app executes → output with `call_id` → final
or more calls), JSON Schema definitions, `strict` mode. Best practices: clear
descriptions, enums to prevent invalid states, **do not ask the model to fill
arguments you already know**, **fewer than ~20 tools available at the start of
a turn**, tool definitions are billed as input tokens, `tool_choice` controls
selection. OpenAI, *Tool search* [S13]: dynamically search/load tools, preserve
prompt cache by appending discovered tools, keep namespaces small, **validate
returned schemas and expose only trusted definitions** in client mode.
Anthropic, *Code execution with MCP* [S19]: loading all tool definitions and
passing intermediate results through the model wasted tokens; presenting MCP
servers as code APIs/filesystem with progressive disclosure reduced one
workflow from **150,000 → 2,000 tokens (98.7%)**. Caveat: agent-generated code
needs sandboxing, resource limits and monitoring.

**[INTERPRETATION]** The domain engine is a versioned catalog exposed with
deferred loading / progressive disclosure (MCP tools plus a code-mode view).
Raw evidence is filtered and redacted **in the harness** before it reaches the
model.

### 2.7 Runtime choice [FACT]
OpenAI Agents SDK primitives: agents (instructions + tools), handoffs /
agents-as-tools, guardrails, built-in loop, tracing, sessions, MCP, HITL [S09].
Runtime comparison [S12]: managed Agents API (OpenAI-owned harness, automatic
compaction), Agents SDK (application owns storage/approvals/runtime), Responses
API (application owns loop and state).

**[INTERPRETATION]** Because the differentiator is an application-owned
deterministic harness, BugFound should stay with an SDK/Responses-style control
plane, not a fully managed harness. Tracing export can inspire the audit-log
schema.

### 2.8 Approvals, checkpointing, resume [FACT]
OpenAI Agents SDK, *Human-in-the-loop* [S10]: tools declare
`needs_approval=True` or a callable rule; callable rules **fail closed** on
missing/malformed arguments; approvals surface as interruptions; `RunState`
can be serialized and resumed. Security rules: keep approval state
server-side, authenticate and authorize the reviewer, validate decision IDs
against server-owned pending items, use an **atomic owner-checked transition**
against replay, treat tool names/args as untrusted display content. Key caveat:
**an approval permits execution, it does not guarantee exactly-once execution**
— use idempotency keys and reconcile uncertain outcomes.

**[INTERPRETATION]** Every active security test needs a stable idempotency key,
replay protection and durable, project-scoped "always" decisions that can
never override a configured deny.

### 2.9 Guardrails as deterministic gates [FACT]
OpenAI Agents SDK, *Guardrails* [S11]: input, output and **tool** guardrails on
every guarded invocation; tripwires raise dedicated exceptions and halt.
**Blocking** input guardrails prevent the agent from consuming tokens or
causing side effects; parallel guardrails do not. Tool input guardrails can run
pre-approval. Output tripwires persist completed tool-call items for replay
while withholding rejected output.

**[INTERPRETATION]** Map: scope/ROE check = blocking input guardrail; per-tool
authorization = tool guardrail; "is this proven?" = output tripwire that blocks
finding promotion.

### 2.10 MCP as the tool/domain boundary [FACT]
MCP spec 2025-06-18 [S14][S15]: JSON-RPC 2.0; tools are **model-controlled**;
servers **MUST** validate inputs, apply access controls, rate limit and
sanitize outputs; clients **SHOULD** show tool inputs to the user before
calling, validate results, implement timeouts and **log tool usage for audit**;
`outputSchema`/`structuredContent` enable strict validation; tool annotations
are untrusted unless from a trusted server.

**[INTERPRETATION]** A BugFound domain MCP server is viable, but the confirmation
UI and the final authorization decision stay in the harness, never in the
model.

### 2.11 Context engineering, compaction, long-running agents [FACT]
Anthropic, *Effective context engineering* [S16]: **context rot** — recall
degrades as tokens grow; aim for the smallest high-signal token set; system
prompts at the "right altitude"; minimal tool sets; just-in-time retrieval via
lightweight identifiers and progressive disclosure; hybrid up-front + on-demand
retrieval. Compaction summarizes near-limit conversations while preserving
decisions and unresolved work; **tool-result clearing is the safest light-touch
form**; structured notes persist memory outside context; subagents return
condensed 1–2k-token summaries.
Anthropic, *Effective harnesses for long-running agents* [S17]: compaction
alone is insufficient; failures are one-shotting and premature "done". An
initializer creates a progress file and a JSON feature list initially all
`passes: false`; later agents work on **one feature at a time**, leave clean
state, self-verify end-to-end, and only mark `passes` after testing.
Anthropic, *Claude Code best practices* [S18]: conservative permissions;
`--dangerously-skip-permissions` only inside a container without internet.

**[INTERPRETATION]** BugFound needs a persistent `investigation.json` (asset
inventory, hypothesis ledger, technique coverage, `confirmed` flags), a
`progress.md`, a lab restart script, and a compaction prompt tuned on real
traces. Only the verifier may set `confirmed`.

### 2.12 Deterministic harness primitives in practice [FACT]
OpenCode *Permissions* [S21]: ordered rules with `action`, `resource`, `effect`
∈ `allow|deny|ask`; **last matching rule wins**; no match ⇒ `ask`; for
multi-resource operations **any deny denies, else any ask asks, else allow**;
"allow always" saves durable **project-scoped** rules that **never override a
configured deny**; global policy can hard-deny.
Anthropic, *Beyond permission prompts* [S20]: read-only + prompts caused
approval fatigue; sandboxing uses **both filesystem and network isolation**
("without network isolation a compromised agent could exfiltrate SSH keys;
without filesystem isolation it could escape"); OS primitives cover
subprocesses; egress proxy enforces domain allowlists; internal result: **84%
fewer permission prompts**.

**[INTERPRETATION]** Adopt ordered allow/deny/ask semantics with deny winning,
and dual FS + egress isolation for the lab. Do not carry over V1 field names
from unrelated tools.

## 3. Security-domain research

### 3.1 WSTG as a technique catalog, not a checklist [FACT]
OWASP WSTG Foreword [S22]: "View this guide as a **set of techniques**… **Avoid
treating the guide as a checklist**"; "**continuously re-prioritize**";
automation gives breadth, the guide gives "depth and judgment"; "running a tool
is usually fast. **Investigating and verifying each finding takes time**."
WSTG v4.2 *Penetration Testing Methodologies* [S24] summarizes PTES 7 phases
and NIST SP 800-115 technique families (review; target identification and
analysis; **target vulnerability validation**; planning; execution;
post-testing).

**[INTERPRETATION]** Domain records are technique objects with id, preconditions,
inputs, expected artifact, safe bounds, CWE/OWASP mappings and benefits/
limitations. Phase names are metadata for filtering, never an execution order.

### 3.2 Reporting, evidence, scope [FACT]
WSTG v4.2 *Reporting* [S25]: scope, limitations, timeline, disclaimer; each
finding needs reference ID, title, likelihood/exploitability, impact, rating
with documented values, description + **how to exploit**, **masked sensitive
data**, remediation, references; CVSS may be required; appendices carry
**cleaned (not dumped)** tool output.

**[INTERPRETATION]** This is the verifier's output contract: `finding_id`,
`scope_ref`, `steps_to_reproduce`, `observed_evidence_hash`, `masked_artifacts`,
`limitations`, `severity + vector`, `remediation`, `retest_status`.

### 3.3 Requirement/risk catalogs [FACT]
ASVS 5.0.0 [S26] (published 2025-05-30): versioned requirement IDs
(`v5.0.0-1.2.5`), machine-readable CSV/JSON. OWASP API Top 10 2023 [S27]:
API1 BOLA … API10 Unsafe Consumption. OWASP Top 10 **2025** [S28][S29]: A01
Broken Access Control … A10 Mishandling of Exceptional Conditions. CWE [S30]:
weakness list updated 3–4×/year, REST API, external mappings.

**[INTERPRETATION]** Pin catalog versions in every finding so results stay
auditable as catalogs evolve.

### 3.4 NIST guidance [FACT]
NIST SP 800-115 [S31] (September 2008, Scarfone et al.): planning and conducting
technical tests, analyzing findings, mitigation strategies; emphasizes
technique families with **benefits and limitations**. NIST SP 800-218 SSDF v1.1
[S32] (February 2022): root-cause reduction and common vocabulary.
**Limitation:** the PDFs could not be fetched; only official landing pages were
read — no PDF-level detail is claimed.

### 3.5 Authorization, disclosure, handling [FACT]
FIRST/NTIA *Multi-Party Vulnerability Coordination* v1.1 [S33]: finder should
provide clear documentation and artifacts supporting verification; secure
communication, acknowledgment, safe harbor, **Principle of Least Exposure**,
sufficient auditing/logging. FIRST *TLP v2.0* [S34]: TLP:RED / AMBER(+STRICT) /
GREEN / CLEAR; source marks the label; wider sharing needs explicit permission;
labels appear in document headers/footers.

**[INTERPRETATION]** Engagements carry a machine-readable ROE object (targets,
exclusions, allowed test classes, time window, rate/budget ceilings, TLP label,
safe-harbor text, approval contacts). Evidence artifacts inherit the TLP label.
**No dedicated HackerOne/Bugcrowd ROE article could be retrieved** — platform-
specific ROE rules remain unevidenced here.

### 3.6 Scoring and validation [FACT]
CVSS v4.0 spec v1.2 [S35]: Base/Threat/Environmental/Supplemental groups;
CVSS-B/BE/BT/BTE; consumers must receive **score and vector string**. CVSS v3.1
[S36]: Base/Temporal/Environmental; Temporal includes Exploit Code Maturity and
**Report Confidence** ("Reasonable" requires reproducible with at least one
impact verified; "Unknown" covers intermittent/non-reproducible).

**[INTERPRETATION]** Store `cvss_version`, `vector`, `score`, nomenclature and a
confidence class; never emit `unproven`/`inconclusive` as a bare numeric
severity.

### 3.7 Prompt injection and tool misuse [FACT]
OWASP LLM01:2025 Prompt Injection [S37]: direct and indirect variants; RAG and
fine-tuning do not fully mitigate; mitigations include **define expected output
formats and validate with deterministic code**, least privilege with
application-owned tokens, **human approval for high-risk actions**, segregating
external content, adversarial testing. OWASP Agentic Top 10 2026 ASI02 [S39]:
tool misuse via over-scoped tools, unvalidated shell/DB input, loop
amplification, MCP descriptor poisoning, indirect-injection → tool pivot,
typosquatting; mitigations include per-tool least-privilege profiles, **action-
level authentication and approval with dry-run/diff preview**, sandboxes and
egress controls, **Policy Enforcement Middleware ("intent gate")** treating
planner output as untrusted, adaptive tool budgeting, short-lived credentials,
**immutable logs**.

**[INTERPRETATION]** These are the strongest direct sources for the BugFound
harness: model/planner output is untrusted input; every action is authorized,
budgeted, sandboxed, logged and (for high impact) human-approved.

## 4. Need → evidence → design implication

| BugFound need | Sources | Implication |
| --- | --- | --- |
| Agent chooses next step | S01, S03, S06, S07, S04/S05 | `NextStep {hypothesis, technique_id, target, rationale, expected_evidence}`; one tool call; replan each observation; harness-set stop limits |
| Domain engine supplies knowledge | S22–S30, S13–S15, S19 | Versioned technique catalog with preconditions/safe bounds/mappings; deferred MCP exposure; dynamic priority, never a fixed order |
| Deterministic harness | S07, S10, S11, S15, S20, S21, S37, S39, S33, S25 | Machine-readable ROE; ordered deny-wins rules; dual FS+egress isolation; blocking scope guardrail; per-tool authorization; cost/rate ceilings; human approval with dry-run; immutable audit log; idempotency |
| Evidence verifier | S25, S35, S36, S33, S02, S17 | `observed → reproducible → proven/inconclusive/rejected`; requires repro steps + artifact hashes + mappings; vector + confidence + TLP; rejection written back to memory; only verifier sets `confirmed` |
| Continuity / resume | S16, S17, S18, S10 | `investigation.json`, `progress.md`, lab restart script, git checkpoints; subagent digests 1–2k tokens; authenticated version-checked resume |
| Audit / eval | S07, S09, S11, S15, S39 | Append-only log keyed `(run_id, step_id, call_id)` capturing plan, policy decision, tool args, redacted output, verdict, approver identity |

## 5. Recommended control flow [INTERPRETATION]

```
[ROE / scope] ──► Harness policy engine (ordered allow/deny/ask, budgets, TLP)
                        ▲
User objective ─► Planner/Agent ─(NextStep, untrusted)─► Intent Gate (PEP/PDP)
                     ▲                                       │
                     │                                  Sandbox: FS + egress allowlist
                     │                                       │
                     └─ observation/reflection ◄── Domain Engine (MCP, deferred tools)
                                                             │
                                    artifacts ──► Evidence Verifier ──► ledger/report
                                                  (CVSS + CWE + confidence + TLP)
```

Stopping conditions: harness iteration/time/token/cost ceilings; compaction
thresholds; completion when all hypotheses are `proven|rejected|inconclusive`;
tripwire on out-of-scope action or malformed approval arguments.

## 6. Sources (all accessed 2026-11-26)

| ID | Title | Author / org | URL | Status |
| --- | --- | --- | --- | --- |
| S01 | ReAct: Synergizing Reasoning and Acting in LMs | Yao et al. / arXiv | https://arxiv.org/abs/2210.03629 | ok |
| S02 | Reflexion: Language Agents with Verbal RL | Shinn et al. / arXiv | https://arxiv.org/abs/2303.11366 | ok |
| S03 | Plan-and-Solve Prompting | Wang et al. / arXiv ACL | https://arxiv.org/abs/2305.04091 | ok |
| S04 | Tree of Thoughts | Yao et al. / arXiv NeurIPS | https://arxiv.org/abs/2305.10601 | ok |
| S05 | Language Agent Tree Search | Zhou et al. / arXiv | https://arxiv.org/abs/2310.04406 | ok |
| S06 | Plan-and-Execute Agents | LangChain Team | https://blog.langchain.com/planning-agents/ | ok |
| S07 | Building effective agents | Anthropic Engineering | https://www.anthropic.com/engineering/building-effective-agents | ok; 2026 note points to Managed Agents docs (not retrieved) |
| S08 | Function calling | OpenAI | https://platform.openai.com/docs/guides/function-calling | ok (partial read) |
| S09 | OpenAI Agents SDK intro | OpenAI | https://openai.github.io/openai-agents-python/ | ok |
| S10 | Human-in-the-loop | OpenAI Agents SDK | https://openai.github.io/openai-agents-python/human_in_the_loop/ | ok |
| S11 | Guardrails | OpenAI Agents SDK | https://openai.github.io/openai-agents-python/guardrails/ | ok |
| S12 | Agents | OpenAI developers | https://developers.openai.com/api/docs/guides/agents | ok |
| S13 | Tool search | OpenAI developers | https://developers.openai.com/api/docs/guides/tools-tool-search | ok |
| S14 | MCP Specification 2025-06-18 — Overview | MCP | https://modelcontextprotocol.io/specification/2025-06-18/basic | ok |
| S15 | MCP Specification — Tools | MCP | https://modelcontextprotocol.io/specification/2025-06-18/server/tools | ok |
| S16 | Effective context engineering for AI agents | Anthropic | https://www.anthropic.com/engineering/effective-context-engineering-for-ai-agents | ok |
| S17 | Effective harnesses for long-running agents | Anthropic | https://www.anthropic.com/research/effective-harnesses-for-long-running-agents | ok |
| S18 | Claude Code: best practices for agentic coding | Anthropic | https://www.anthropic.com/research/claude-code-best-practices | ok; moved to code.claude.com (not retrieved) |
| S19 | Code execution with MCP | Anthropic | https://www.anthropic.com/research/code-execution-with-mcp | ok |
| S20 | Beyond permission prompts | Anthropic | https://www.anthropic.com/engineering/claude-code-sandboxing | ok |
| S21 | Permissions | OpenCode | https://opencode.ai/docs/permissions/ | ok |
| S22 | WSTG Foreword (latest) | OWASP | https://owasp.org/www-project-web-security-testing-guide/latest/00-Foreword/ | ok; subpages redirected |
| S24 | WSTG v4.2 Penetration Testing Methodologies | OWASP | https://owasp.org/www-project-web-security-testing-guide/v42/3-The_OWASP_Testing_Framework/1-Penetration_Testing_Methodologies | ok |
| S25 | WSTG v4.2 Reporting | OWASP | https://owasp.org/www-project-web-security-testing-guide/v42/5-Reporting/ | ok |
| S26 | OWASP ASVS 5.0.0 | OWASP | https://owasp.org/www-project-application-security-verification-standard/ | ok |
| S27 | OWASP API Security Top 10 2023 | OWASP | https://owasp.org/API-Security/editions/2023/en/0x11-t10/ | ok |
| S28 | OWASP Top 10 project page | OWASP | https://owasp.org/www-project-top-ten/ | ok |
| S29 | OWASP Top 10:2025 | OWASP | https://owasp.org/Top10/2025/ | ok |
| S30 | About CWE | MITRE | https://cwe.mitre.org/about/index.html | ok |
| S31 | NIST SP 800-115 landing page | NIST CSRC | https://csrc.nist.gov/pubs/sp/800/115/final | ok (landing only) |
| S32 | NIST SP 800-218 SSDF v1.1 landing | NIST CSRC | https://csrc.nist.gov/pubs/sp/800/218/final | ok (landing only) |
| S33 | Multi-Party Vulnerability Coordination v1.1 | NTIA + FIRST | https://www.first.org/global/sigs/vulnerability-coordination/multiparty/guidelines | ok |
| S34 | Traffic Light Protocol v2.0 | FIRST | https://www.first.org/tlp/ | ok |
| S35 | CVSS v4.0 Specification v1.2 | FIRST | https://www.first.org/cvss/v4.0/specification-document | ok (partial read) |
| S36 | CVSS v3.1 Specification | FIRST | https://www.first.org/cvss/v3.1/specification-document | ok (partial read) |
| S37 | LLM01:2025 Prompt Injection | OWASP GenAI | https://genai.owasp.org/llmrisk/llm01-prompt-injection/ | ok |
| S38 | OWASP LLM Top 10 (2025) | OWASP GenAI | https://genai.owasp.org/llm-top-10/ | ok |
| S39 | ASI02: Tool Misuse and Exploitation | OWASP GenAI | https://genai.owasp.org/agentic-applications-2026/asi02-tool-misuse-and-exploitation/ | ok |
| S40 | Agentic Applications Top 10 2026 | OWASP GenAI | https://genai.owasp.org/top-10-for-agentic-applications-2026/ | ok |
| S41 | HackerOne Platform Documentation index | HackerOne | https://docs.hackerone.com/ | ok (index only) |

## 7. Failed or unusable retrievals (no facts used)

- NIST SP 800-115 / SP 800-218 PDFs — PDF content type unsupported by fetch.
- OpenAI Responses API reference — response too large.
- HackerOne scope article, HackerOne "good scope", Bugcrowd ROE resource,
  OWASP Bug Bounty Programs community page — HTTP 404 / redirect.
- Anthropic Managed Agents docs and current Claude Code best-practices docs —
  referenced by retrieved pages but not fetched.

## 8. Caveats

Vendor docs reflect then-current model names/features; cite them for
**patterns**, not model-specific guarantees. WSTG "latest" is being
restructured; v4.2 URLs are the stable citation. Catalog versions drift; pin
them. No primary bug-bounty platform ROE text was obtainable, so V3's ROE
object is grounded in WSTG scope/limitations, FIRST coordination guidance and
TLP — platform-specific rules must be marked unevidenced until sourced.
