# 05 - MCP as a blueprint for BugFound provider abstraction and dynamic tools

> **About these notes.** These are point-in-time analyses of third-party reference
> projects, kept for design input. They describe the reference projects at the
> snapshots examined and are not claims about the current BugFound code; verify
> current behavior in `crates/`.

Status: research notes. Patterns only, no code has been copied.

Reference repository: D:\Github\BugFound\research\mcp
(modelcontextprotocol/specification), commit
8a18b4b3292b9f9b3aee73f6325f9f62f19a89f9.

Spec revisions consulted: 2026-07-28 (the current stable revision at that
commit) and draft (direction only). Every path beginning "research/mcp/" is
relative to the reference root above; every other path is relative to
D:\Github\BugFound. Line numbers are from those exact files.

---

## Executive summary

The 2026-07-28 MCP revision is a stateless, per-request, capability-negotiated
JSON-RPC protocol. Its most transferable ideas for BugFound are not the wire
format itself but four architectural patterns:

1. Capability negotiation and discovery as data, not handshakes. Every request
   carries protocol version and client capabilities in _meta; servers advertise
   capabilities, versions and usage instructions through a dedicated
   server/discover operation. Capability sets are explicitly open.
2. Provider-neutral LLM invocation. MCP's (now deprecated) sampling feature
   still contains the most explicit cross-provider model in the spec: content
   blocks, three tool-choice modes, balanced tool-use/tool-result messages,
   stopReason, and preference-based model selection (cost/speed/intelligence
   priorities plus advisory hints) rather than hard-coded model names.
3. Structured, validated tool contracts. Tools declare a JSON Schema
   inputSchema (2020-12 by default) and an optional outputSchema; results carry
   both human-readable content and machine-readable structuredContent, with a
   split between protocol errors and model-correctable execution errors.
4. Explicit trust boundaries. Tool annotations and server identity are declared
   untrusted; authorization is OAuth 2.1 with audience-bound tokens,
   least-privilege scopes and step-up; token passthrough and confused-deputy
   behavior are forbidden; SSRF guidance mandates private-range blocking and
   DNS pinning.

BugFound already independently reimplements several of these patterns well:
untrusted-tool-output wrapping, SSRF defenses, scope policy, rate limiting and
capture canaries. Its actual gaps are concentrated in (a) the
Llm trait being an OpenAI-shaped single-endpoint interface with a side-channel
for token usage, (b) two divergent ToolSpec types with lossy conversion and no
schema validation, (c) a static in-process registry whose "plugins" are
PATH-scan/command templates with no discovery, namespacing or change
notification, and (d) a self-declared risk string that is used as a security
decision input even though MCP explicitly warns that such hints are untrusted.

A critical trajectory note: as of 2026-07-28 MCP deprecates sampling and roots
in favor of direct LLM-provider integration and passing paths via tool
parameters/resource URIs, and replaces server-initiated requests with the
multi-round-trip request (MRTR) pattern. BugFound should borrow the
cross-provider request/response shape from sampling but the interactive
control-flow from MRTR/elicitation, and must not build new features on the
deprecated primitives.

---

## 1. MCP protocol primitives

### 1.1 Architecture, lifecycle and message patterns

- MCP is explicitly stateless: hosts own multiple 1:1 client/server connections;
  every request is self-contained and carries its own version and capabilities
  (research/mcp/docs/specification/2026-07-28/architecture/index.mdx:7-12,
  :49-83). Servers must not infer context from prior requests on the same
  connection; cross-request state must use an explicit identifier
  (.../basic/index.mdx:182-209).
- There is no negotiation handshake in the current revision: the client sends a
  request with _meta, the server accepts or rejects that individual request, and
  a UnsupportedProtocolVersionError (-32022) lists supported versions for retry
  (.../basic/versioning.mdx:7-27, :41-78).
- JSON-RPC result objects are polymorphic via resultType: "complete" or
  "input_required"; unrecognized values are invalid, and an absent value is
  treated as "complete" for backward compatibility (.../basic/index.mdx:55-85).
- Three message patterns: request/response, multi-round-trip requests (MRTR),
  and subscribe/notify (.../basic/index.mdx:174-181).
- MRTR is a breaking change in this revision: it replaces server-initiated
  JSON-RPC requests. A server answers a supported client request with an
  InputRequiredResult containing inputRequests (elicitation / sampling / roots)
  plus an opaque requestState that the client echoes on a new request with a new
  JSON-RPC id (.../basic/patterns/mrtr.mdx:7-14, :25-52, :124-180, :249-257).
  Supported carriers are prompts/get, resources/read and tools/call (:182-192).
- requestState is attacker-controlled and, if it influences authorization or
  resource access, must be integrity-protected (HMAC/AEAD) and carry the
  authenticated principal, a short TTL and a request identifier to bound replay
  (.../basic/patterns/mrtr.mdx:231-243, :269-272).

Pattern for BugFound: a tool/plugin should be able to suspend and ask the host
for more information (user confirmation, credentials, another model call)
without the plugin holding a durable session of its own. The host owns the
human-in-the-loop and replays state; state blobs must be bound to the session
and expire.

### 1.2 Capability discovery and negotiation

- Clients attach io.modelcontextprotocol/protocolVersion (required), clientInfo
  (optional) and clientCapabilities (required) to every request; a missing
  required field is -32602. Servers must not rely on undeclared capabilities and
  return MissingRequiredClientCapabilityError (-32021) naming what is missing
  (.../basic/index.mdx:320-393).
- server/discover returns supportedVersions, capabilities, serverInfo,
  natural-language instructions for the LLM, and cache hints (ttlMs,
  cacheScope); a single call can replace probing tools/list, prompts/list and
  resources/list (.../server/discover.mdx:7-9, :33-59, :62-86, :88-108).
  serverInfo is self-reported and must not drive security decisions (:103-108).
- Capability maps are open sets: "any client/server can define its own,
  additional capabilities", with an extensions map keyed by reverse-DNS
  identifiers and per-extension settings (research/mcp/schema/2026-07-28/
  schema.ts:712-787, :789-879; .../basic/versioning.mdx:80-127). If one side
  lacks an extension, the other must fall back to core behavior or reject
  (versioning.mdx:124-127).
- Capabilities unlock features progressively; servers declare tools, resources,
  prompts with listChanged, and clients declare elicitation
  (.../architecture/index.mdx:117-175; .../server/tools.mdx:45-74;
  .../client/elicitation.mdx:49-81).

Pattern for BugFound: discovery returns a descriptor -- identity, supported
protocol/handler versions, declared capabilities, operator-facing instructions,
cache lifetime -- and capability use is gated on what the other side actually
declared, per interaction, not on a startup assumption.

### 1.3 The three server primitives and their control model

The spec defines an explicit control hierarchy
(research/mcp/docs/specification/2026-07-28/server/index.mdx:15-21):

| Primitive | Control | BugFound analogue |
| --- | --- | --- |
| Prompts | User-controlled templates | system prompt assembled in crates/bugfound-core/src/lib.rs:1298-1304 (host-controlled) |
| Resources | Application-controlled context | durable store / findings / artifacts |
| Tools | Model-controlled actions | ToolRegistry (crates/bugfound-tools/src/lib.rs:111-151) |

- Tools are discovered with tools/list (paginated, cacheable) and invoked with
  tools/call; the advertised set may vary by the authorization presented on the
  request but must not vary per connection, and ordering should be deterministic
  for prompt-cache stability (.../server/tools.mdx:45-74, :78-133, :135-172).
- Tools are "model-controlled", but the spec insists on a human in the loop and
  clear UI/confirmation (.../server/tools.mdx:21-43).
- MCP has no protocol session, so stateful tools must return explicit handles; a
  handle is "a name, not a capability" and must be re-authorized on every call
  (.../server/tools.mdx:683-737).
- Two error channels: protocol errors (unknown tool, malformed request, server
  error -> JSON-RPC error) and tool execution errors (API failure,
  validation/business error -> result with isError: true) so the model can
  self-correct (.../server/tools.mdx:738-785).

### 1.4 Structured tool schemas

- A tool definition contains name, title, description, icons, inputSchema,
  optional outputSchema and optional annotations
  (.../server/tools.mdx:280-307; schema.ts:1983-2030). inputSchema must be a
  JSON Schema object with type "object" at the root; 2020-12 is the default
  dialect; full 2020-12 vocabulary (composition, conditionals, $ref, $defs) is
  allowed (schema.ts:1991-2012; .../basic/index.mdx:247-294).
- Results may carry unstructured content blocks (text, image, audio, resource
  links, embedded resources) and a JSON structuredContent value conforming to
  outputSchema; clients should validate it
  (.../server/tools.mdx:404-507, :509-631).
- Security rules for schemas: never auto-fetch network $refs (default off;
  allowlist hosts, reject loopback/link-local/private, timeouts, size limits,
  logging); reject unresolved external refs rather than treating schemas as
  permissive; bound composition keywords and schema depth to avoid validator
  DoS (.../basic/index.mdx:299-318).
- Tool name rules and collision guidance: names are server-scoped,
  case-sensitive, restricted character set; clients/proxies aggregating
  multiple servers should prefix names with a server identifier, and
  serverInfo.name is not guaranteed unique (.../server/tools.mdx:309-332).
- Server tool-list changes are signaled via a
  notifications/tools/list_changed notification on a subscriptions/listen
  stream (.../server/tools.mdx:236-248, :250-278).

Pattern for BugFound: one normalized tool descriptor with a stable identity,
input and output schemas, display metadata and hint annotations; results carry
both a text rendering and validated structured data; tool names are namespaced
by origin; schema validation is a boundary responsibility with SSRF/DoS guards.

### 1.5 Sampling, roots and elicitation (client features)

- Sampling lets a server ask the client's LLM for generation nested inside
  another operation, keeping model access/keys with the client
  (.../client/sampling.mdx:19-24). It is deprecated in 2026-07-28; new
  implementations should integrate directly with LLM provider APIs
  (:7-17; .../deprecated.mdx:22-31).
- Still valuable as a pattern: request content blocks (text/image/audio), a
  tools array plus toolChoice modes auto/required/none
  (:48-52, :163-247, :471-477), parallel tool use across providers
  (:479-487), strict tool_use/tool_result balancing and tool-result-only
  messages for provider compatibility (:375-457), stopReason values
  (endTurn, stopSequence, maxTokens, toolUse) (:643-659), and preference-based
  model selection via normalized costPriority, speedPriority,
  intelligencePriority plus advisory hints that clients map to equivalent
  models from their own providers (:559-604).
- Roots expose filesystem roots as informational guidance, not access control,
  and are also deprecated in 2026-07-28
  (.../client/roots.mdx:19-24, :7-16).
- Elicitation is current and has two modes: in-band form mode with a
  deliberately restricted flat JSON Schema (primitives, enums, defaults -- no
  nested objects), and out-of-band URL mode for secrets/credentials/OAuth that
  must never pass through the client
  (.../client/elicitation.mdx:12-15, :104-239, :322-383). A three-action
  response model (accept / decline / cancel) makes explicit refusal a
  first-class outcome (:434-467). Security rules bind requests to user
  identity and defend against phishing (:593-671).

Pattern for BugFound: model requests should express preferences, not vendor
model IDs; user approval should be a typed outcome (approve / decline / cancel),
not a binary gate; secrets should not transit the model-visible tool channel.

### 1.6 Transports and extensions

- A transport is a binding, not semantics: it frames/delivers JSON-RPC messages,
  carries request metadata, and signals cancellation. Protocol semantics are
  identical across bindings; standard bindings are stdio and Streamable HTTP,
  and custom transports must preserve the message format, patterns and
  per-request metadata model (.../basic/transports/index.mdx:7-25, :60-79).
  Metadata may be mirrored into HTTP headers for intermediaries, but the body
  is the source of truth (:38-50). Cancellation is binding-specific (cancelled
  notification on stdio, closing the response stream on HTTP) with shared
  protocol rules (:52-58).
- Extensions (Tasks for durable async operations, Skills over MCP, MCP Apps for
  interactive UI) are opt-in, independently versioned, and negotiated through
  the extensions capability map (.../index.mdx:75-89;
  .../basic/versioning.mdx:80-127).

Pattern for BugFound: keep the agent core independent of how a tool provider is
reached; define a thin connector boundary with explicit cancellation and
metadata propagation, and let optional capabilities be advertised rather than
assumed.

---

## 2. Security, delegation and authorization semantics

- Trust and safety principles: explicit user consent and control, data privacy,
  and "tools represent arbitrary code execution"; tool descriptions and
  annotations must be treated as untrusted unless from a trusted server
  (.../index.mdx:91-126; .../server/tools.mdx:304-307; schema.ts:1904-1915 --
  all ToolAnnotations are hints and must not drive decisions about untrusted
  servers).
- Clients must show inputs before calls, validate results before passing them
  to the LLM, implement timeouts and audit logging
  (.../server/tools.mdx:787-803).
- Authorization is OAuth 2.1 plus RFC 8707 Resource Indicators, RFC 9728
  Protected Resource Metadata, PKCE, RFC 9207 issuer validation, and
  least-privilege scopes surfaced in WWW-Authenticate; insufficient-scope
  responses trigger a step-up flow that unions prior and newly required scopes
  (.../basic/authorization/index.mdx:8-45, :97-134, :136-214, :215-253,
  :345-425).
- Tokens must be audience-bound to the MCP server; the server must reject tokens
  issued for other resources; token passthrough is forbidden and upstream API
  tokens are separate tokens held by the server
  (.../basic/authorization/security-considerations.mdx:14-23, :116-131;
  .../authorization/index.mdx:301-317).
- Confused deputy: proxy servers using a static client ID must obtain per-client
  consent before forwarding to a third-party authorization server
  (security-considerations.mdx:107-114;
  docs/docs/2026-07-28/tutorials/security/security_best_practices.mdx:27-282).
- SSRF guidance mirrors BugFound's own HTTP hardening: enforce HTTPS, block
  private/loopback/link-local/metadata ranges (including IPv4-mapped IPv6 and
  numeric encodings), do not blindly follow redirects, pin DNS to avoid
  TOCTOU/DNS-rebinding, and prefer egress proxies
  (security_best_practices.mdx:355-507). Note the spec warns "avoid implementing
  IP validation manually" because of encoding tricks -- BugFound's hand-written
  parser is unusually thorough but is exactly the kind of code this guidance
  cautions about.
- State handles must not be treated as authentication; bind them to the verified
  principal and expire them (security_best_practices.mdx:522-563).

Net security pattern for an agent runtime: the host is the policy decision
point; plugin-supplied metadata is untrusted input; capabilities/credentials are
scoped, audience-bound and non-transferable; interactive flows bind state to an
authenticated principal with TTL and replay protection; network egress is
validated at a single choke point.

---

## 3. Current BugFound architecture (evidence)

### 3.1 Llm trait and client -- an OpenAI-shaped interface

- LlmConfig is a single endpoint: base_url, api_key, optional default_model,
  timeout_ms (crates/bugfound-llm/src/lib.rs:16-39). validate_base_url only
  checks http/https + host (:41-54).
- ChatMessage is flat strings plus OpenAI-style tool_calls (:56-67); ToolSpec is
  {name, description, parameters} (:69-74); ToolCall is {id, name, arguments}
  (:76-81); ChatResponse is {content, tool_calls, model} with no stopReason, no
  usage, no content blocks (:83-88).
- The trait is resolve_model() -> String, chat(model, messages, tools) and a
  default chat_with_usage that discards usage (:90-112). LlmClient stores usage
  in Arc<Mutex<Option<TokenUsage>>> (:114-139), sets it in chat (:312-323) and
  takes it in chat_with_usage (:366-376).
- api_base() appends /v1 (:141-148); model discovery probes /v1/models and
  /models (:150-223); resolve_model returns the configured model or simply the
  first discovered id (:226-240).
- chat posts to /chat/completions with a hard-coded OpenAI tool envelope (type
  function, function.arguments as a JSON string) (:242-297) and bespoke
  retry/backoff (:299-364). parse_chat_response reads choices[0].message,
  rejects finish_reason of length/content_filter, parses tool_calls, and uses
  the response model or a fallback (:379-458). No provider-neutral stop reasons,
  tool-choice modes, or structured/model-correctable error channel exist.

### 3.2 ToolRegistry, ToolSpec, ToolOptions

- Tools-side ToolSpec is {name, description, input_schema, risk} with a free-form
  risk string (:30-36); ToolResult is {ok, output, structured} (:38-44);
  HttpCapture + capture_from_structured provide a canary-backed
  evidence channel (:46-74).
- ToolOptions is an operator-supplied config struct (proxy, trusted local
  targets, enable_external_tools, external_commands, scope_in/out, auto-detect,
  user agent, max RPS, allowed methods, shared rate window) (:76-103).
- Tool trait: spec() and run(Value) -> Result<ToolResult> (:105-109).
  ToolRegistry is a BTreeMap<String, Arc<dyn Tool>> with register,
  register_alias, get, specs -- all synchronous, in-process, with no versioning,
  namespace or discovery (:111-151).
- Security is implemented per tool in code: shell allowlist (:165-201), blocked
  IP ranges (:210-250), numeric-host decoding (:259-324), scope matching
  (:429-494), DNS pinning (:520-539), proxy validation (:833-865), and the
  central HTTP gate in HttpRequestTool::run (:992-1168) plus advisory PoC
  validation (:1173-1317) and per-step revalidation in PipelineTool
  (:1660-1776).
- "Plugins" are compile-time built-ins plus external_tool_availability() PATH
  scanning (:2149-2184), register_external_adapters command templates
  (:2186-2247) and register_command_adapters driven by the external_commands
  map (:2249-2272), all assembled in try_default_registry_with_options
  (:2030-2132). There is no remote tool provider, no tools/list-style discovery,
  no change notification and no response schema.

### 3.3 Runner wiring and policy

- Runner holds Arc<dyn Llm>, a ToolRegistry, a PolicyEngine, AgentConfig and an
  owner id (crates/bugfound-core/src/lib.rs:577-609).
- Tool metadata is used for security decisions: is_network_tool inspects the
  risk string and tool-name substrings (:762-771); budget_gate (:773-803);
  auto_approve_allowed treats certain risk values as dangerous (:854-883);
  pre_execute_guards checks goal lock, policy, injection flags, target drift,
  duplicates, cooldowns and budgets (:890-969).
- The system prompt is a hard-coded string plus scope text (:1298-1304). Model
  resolution calls resolve_model() once at session start (:1274-1290).
- Tools are converted to the LLM spec inline in the runner, dropping risk and
  any other metadata (:1838-1847), and again in a duplicate helper
  build_tool_specs (crates/bugfound-core/src/step.rs:53-64, itself marked
  additive while the runner "keeps its own inline implementation" at :1-3).
- Tool results are flattened to text: tool_message_text emits a single
  untrusted_tool_output string built only from result.output; the structured
  field is not surfaced to the model or schema-validated
  (crates/bugfound-core/src/lib.rs:1517-1523). Errors from guards are returned
  as free-form text (:971-1006, :2076-2080), so the model has no typed
  "correctable error" channel.
- Approval is a durable park/resume with four guard markers
  (.../lib.rs:51-65, :2000-2075), but there is no elicitation-style
  accept/decline/cancel and no integrity-protected, expiring request state for
  plugin-initiated input.
- Execution coordination is process-global and session-keyed, with wake
  coalescing, interruption and stop-ack (crates/bugfound-core/src/execution.rs:
  12-18, :45-75, :100-181).
- Policy is local config: Mode::{Ask, FullAuto}, Decision::{Allow, Ask, Deny},
  scope matching, allowed/denied tools and budgets
  (crates/bugfound-policy/src/lib.rs:5-20, :38-166, :225-253).
- Wiring happens at startup in CLI/desktop; the single LlmConfig and single
  ToolOptions are constructed once and passed in
  (crates/bugfound-cli/src/main.rs:548-586;
  crates/bugfound-desktop/src/worker.rs:85-110). Workspace dependencies contain
  no JSON Schema validator and no provider SDKs (Cargo.toml:19-40).

---

## 4. Concrete gaps and how MCP informs them

| # | Gap in BugFound (evidence) | MCP pattern to borrow (evidence) | Direction |
| --- | --- | --- | --- |
| G1 | Provider interface is one OpenAI-compatible endpoint; chat hard-codes /chat/completions and the function envelope; ChatResponse lacks stop reason, content blocks and tool-choice (bugfound-llm/src/lib.rs:16-39, :242-297, :83-88). | Cross-API sampling model: content blocks, toolChoice modes, stopReason, parallel tool use, strict tool_use/tool_result balance (client/sampling.mdx:375-487, :643-659). | Define a provider-neutral request/response model with thin adapters; do not expose function-shaped structs in the core trait. |
| G2 | Model resolution = configured string or first id from /v1/models (bugfound-llm/src/lib.rs:150-240). | Preference-based selection: normalized cost/speed/intelligence priorities + advisory hints resolved by the host (client/sampling.mdx:559-604). | Let callers express a ModelPreference; each provider adapter maps it to a concrete model. |
| G3 | Token usage travels through Arc<Mutex<Option<TokenUsage>>> (bugfound-llm/src/lib.rs:114-139, :312-323, :366-376), unsafe under concurrent calls and absent from ChatResponse. | Usage belongs to the response envelope; MCP results are self-contained (basic/index.mdx:55-85, :182-209). | Return usage in the response; delete the mutex side channel. |
| G4 | Two divergent ToolSpec types and two lossy conversions that drop risk, schema metadata and any future fields (bugfound-tools/src/lib.rs:69-74 vs 30-36; bugfound-core/src/lib.rs:1838-1847; bugfound-core/src/step.rs:53-64). | One Tool descriptor with inputSchema, outputSchema, annotations, _meta (server/tools.mdx:280-332; schema.ts:1983-2030). | Unify on one internal descriptor; provider-specific mapping lives at the adapter edge. |
| G5 | ToolResult.structured is not sent to the model and no output schema exists; results are flattened (bugfound-tools/src/lib.rs:38-44; bugfound-core/src/lib.rs:1517-1523). | structuredContent + outputSchema with client-side validation (server/tools.mdx:404-507, :509-631). | Validate and surface structured output; keep the untrusted text wrapper for prose. |
| G6 | input_schema is a raw json! value; LLM arguments go straight to tool.run() with no schema validation (bugfound-tools/src/lib.rs:613 etc.; bugfound-core/src/lib.rs:1948); no JSON Schema dependency (Cargo.toml:19-40). | 2020-12 default dialect, validation on both sides, $ref/DoS guards (basic/index.mdx:247-318; server/tools.mdx:787-803). | Validate arguments at the tool boundary and outputs against outputSchema, with the spec's SSRF/DoS constraints. |
| G7 | ToolRegistry is a static in-process map; "external tools" are PATH scans and command templates; no discovery, namespace, versioning, listChanged or async registration (bugfound-tools/src/lib.rs:111-151, :2149-2272). | server/discover + paginated tools/list + listChanged notifications; server-scoped names with prefix disambiguation (server/discover.mdx:7-86; server/tools.mdx:45-74, :236-248, :309-332). | Introduce a tool-provider boundary with a discovery descriptor (versions, capabilities, instructions, TTL), namespaced tool ids and dynamic list/invoke. |
| G8 | Self-reported risk string drives approvals and budget classification, including for command-backed adapters (bugfound-tools/src/lib.rs:31-36, :2089-2131; bugfound-core/src/lib.rs:762-771, :854-883). | All ToolAnnotations (incl. title, hints) are untrusted; clients must not make tool-use decisions on them from untrusted servers (schema.ts:1904-1915; server/tools.mdx:304-307). | Treat risk as a hint only; keep authorization in a host-owned policy keyed by tool origin/identity, not by a tool-provided string. |
| G9 | Single host API key is the only credential; third-party tool calls inherit no scoped identity (bugfound-llm/src/lib.rs:16-24; bugfound-cli/src/main.rs:549-561). | Audience-bound tokens, RFC 8707 resource indicators, least-privilege scopes, step-up, token-passthrough forbidden, per-client consent (basic/authorization/index.mdx:97-134, :215-317, :345-425; security-considerations.mdx:107-131; security_best_practices.mdx:27-353). | Separate LLM-provider credentials from tool-provider credentials; scoped, non-transferable tokens; do not forward the host key to a plugin/upstream. |
| G10 | No handshake: capabilities are assumed at startup in CLI/desktop; no optional-feature negotiation or instructions field (bugfound-cli/src/main.rs:548-586; bugfound-desktop/src/worker.rs:85-110). | Per-request capability metadata, server/discover, open extensions map with fallback (basic/index.mdx:366-393; server/discover.mdx:33-59; basic/versioning.mdx:80-127). | Add a discovery/descriptor step and gate optional features on declared capabilities with explicit fallback. |
| G11 | Approval is binary park/resume with free-form text; no typed decline/cancel; no integrity-protected expiring state for plugin-initiated input (bugfound-core/src/lib.rs:51-65, :971-1006, :2000-2075). | MRTR requestState (HMAC/AEAD + principal + TTL + request id) and elicitation accept/decline/cancel (basic/patterns/mrtr.mdx:231-243, :249-257; client/elicitation.mdx:434-467, :593-671). | Model interactive tool flows as suspend/resume with typed outcomes and bounded, authenticated state; secrets via out-of-band URL, not in tool args. |
| G12 | Only local subprocess bindings exist for external tools (bugfound-tools/src/lib.rs:2249-2272). | Transport is a binding with metadata mirroring and explicit cancellation; stdio and Streamable HTTP are standard (basic/transports/index.mdx:7-25, :38-58, :60-79). | Put a connector trait under the registry so stdio/HTTP/in-process providers share one contract. |
| G13 | Guard denials are text strings; no stable model-correctable error category (bugfound-core/src/lib.rs:971-1006, :2076-2080). | Split protocol errors from isError:true execution errors intended for self-correction (server/tools.mdx:738-785). | Add a normalized error taxonomy and surface correctable errors to the model without leaking policy internals. |

### What BugFound already does that aligns with MCP

- Untrusted-output framing: tool_message_text wraps output as untrusted data
  (bugfound-core/src/lib.rs:1517-1523) -- matches the "validate results before
  passing to LLM" and untrusted-annotation rules (server/tools.mdx:787-803,
  :304-307).
- SSRF defenses: blocked ranges, numeric-host decoding, no-redirect clients and
  DNS pinning (bugfound-tools/src/lib.rs:210-250, :259-324, :760-780,
  :520-539) -- mirror security_best_practices.mdx:355-507.
- Scope policy and rate limiting: ScopeConfig.check_target
  (bugfound-policy/src/lib.rs:138-165), scope_target_allowed
  (bugfound-tools/src/lib.rs:479-494), obey_rate_limit (:807-831) and
  duplicates/cooldowns (bugfound-core/src/lib.rs:241-263, :939-960) -- mirror
  least-privilege scopes and "servers must rate limit tool invocations"
  (server/tools.mdx:787-793).
- Capture canary (bugfound-tools/src/lib.rs:940-960,
  bugfound-core/src/lib.rs:450-463) is an BugFound-specific strengthening:
  MCP's structuredContent is server-produced and has no equivalent anti-spoof
  canary; keep this when adding structured results.

---

## 5. Recommended target architecture (patterns, not code)

1. Provider-neutral LLM port. Replace the current trait surface with a
   request/response model expressed in content blocks, ModelPreference,
   ToolChoice, StopReason, structured usage and typed errors. Concrete providers
   become adapters that translate to/from their wire format; the core does not
   construct an OpenAI-shaped payload. Keep resolve_model behind the adapter
   and resolve preferences there.
2. One tool descriptor, many bindings. A normalized descriptor (identity,
   namespace/origin, version, display metadata, inputSchema, outputSchema, hint
   annotations) is the only type shared between core and providers. In-process
   tools, command adapters and future MCP/stdio/HTTP providers all expose
   discover(), list() and invoke() through one port, with a capability/version
   descriptor and cache TTL. Names are namespaced by origin.
3. Boundary validation. Validate every model-produced argument against the
   tool's input schema before execution; validate tool output against its
   output schema; bound schema depth/composition and do not fetch remote $refs.
4. Host-owned authorization. Move risk classification out of the tool's
   self-report and into host policy keyed by tool origin and operation.
   Treat all plugin-supplied metadata as untrusted. Keep the existing scope,
   budget, cooldown and injection guards, but express their denials as typed,
   model-correctable errors.
5. Credential isolation. Distinct LLM-provider and tool/upstream credentials;
   scoped, audience-bound, expiring tokens; no passthrough; out-of-band secret
   entry for sensitive values.
6. Interactive flows as MRTR. Plugin requests for extra input become a
   host-mediated suspend/resume with accept/decline/cancel outcomes and an
   integrity-protected {principal, TTL, request id} state blob. Do not build on
   MCP sampling/roots (deprecated) even though their content shapes are a useful
   reference for the provider port.
7. Capability-gated optional features. Advertise and negotiate optional
   capabilities/extensions per interaction with documented fallback, mirroring
   the per-request _meta model.

---

## 6. Evidence index (quick reference)

MCP reference root: D:\Github\BugFound\research\mcp\, commit
8a18b4b3292b9f9b3aee73f6325f9f62f19a89f9:

- schema/2026-07-28/schema.ts:712-787, 789-879, 1904-1958, 1983-2030, 2523
- docs/specification/2026-07-28/index.mdx:7-11, 27-46, 48-89, 91-126
- docs/specification/2026-07-28/architecture/index.mdx:7-12, 49-83, 85-115, 117-175
- docs/specification/2026-07-28/server/index.mdx:15-21
- docs/specification/2026-07-28/server/tools.mdx:21-74, 78-172, 174-248,
  280-332, 404-507, 509-631, 683-737, 738-803
- docs/specification/2026-07-28/server/discover.mdx:7-9, 33-59, 62-108
- docs/specification/2026-07-28/client/sampling.mdx:7-17, 19-52, 163-247,
  375-487, 559-659
- docs/specification/2026-07-28/client/roots.mdx:7-24, 135-159
- docs/specification/2026-07-28/client/elicitation.mdx:12-15, 49-81, 104-239,
  322-383, 434-467, 593-671
- docs/specification/2026-07-28/basic/index.mdx:25-85, 109-181, 182-234,
  247-318, 320-453
- docs/specification/2026-07-28/basic/versioning.mdx:7-78, 80-127, 129-186
- docs/specification/2026-07-28/basic/transports/index.mdx:7-25, 27-58, 60-89
- docs/specification/2026-07-28/basic/patterns/mrtr.mdx:7-52, 54-192, 199-272
- docs/specification/2026-07-28/basic/authorization/index.mdx:8-45, 97-134,
  136-253, 301-317, 345-444
- docs/specification/2026-07-28/basic/authorization/security-considerations.mdx:14-131
- docs/docs/2026-07-28/tutorials/security/security_best_practices.mdx:27-353,
  355-507, 522-563
- docs/specification/2026-07-28/deprecated.mdx:22-41

BugFound current code root: D:\Github\BugFound\:

- crates/bugfound-llm/src/lib.rs:9-112, 114-148, 150-240, 242-458
- crates/bugfound-tools/src/lib.rs:30-151, 165-250, 259-324, 415-539,
  597-643, 737-780, 807-865, 992-1168, 1173-1317, 1517-1776, 2026-2281
- crates/bugfound-core/src/lib.rs:51-88, 577-609, 762-969, 971-1006,
  1235-1356, 1517-1561, 1810-2098
- crates/bugfound-core/src/step.rs:1-64
- crates/bugfound-core/src/execution.rs:12-238
- crates/bugfound-policy/src/lib.rs:5-20, 38-166, 225-253
- crates/bugfound-cli/src/main.rs:548-586
- crates/bugfound-desktop/src/worker.rs:85-110
- Cargo.toml:19-40
