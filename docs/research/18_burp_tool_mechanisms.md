# 18 — Burp Suite tool mechanisms, reconstructed from authoritative sources

Status: research artifact for the next tool-layer build phase. No benchmark claim.
Sources are local research clones under `/research/` (git-ignored; never part of
AgentBug source):

- `research/burp-extender-api` — PortSwigger's published Extender API (42 Java
  interfaces). Licence: Burp Suite Professional Licence Agreement. We study the
  **contracts**, not copy code.
- `research/zaproxy` — OWASP ZAP, Apache 2.0. Open-source implementation of the
  same concepts; sections from this source are appended when the parallel
  research completes.

## 0. Corrections to common assumptions (verified against the API)

These names do **not** exist in the published API and must not be used in the
design:

| Assumed | Actual |
|---|---|
| `IIntruderAttack.getBaseRequest()` | `getRequestTemplate()` (`IIntruderAttack.java:29`) |
| payload factory `getNewInstance` | `createNewInstance(IIntruderAttack)` (`IIntruderPayloadGeneratorFactory.java:39`) |
| `duplicateIssue` | `consolidateDuplicateIssues(existing, new)` (`IScannerCheck.java:80-82`) |
| `isInScope` on a message | `IBurpExtenderCallbacks.isInScope(URL)` (`IBurpExtenderCallbacks.java:818`) |
| attack-type enum | none; sniper/battering ram only in Javadoc (`IIntruderPayloadGenerator.java:34-47`) |
| severity/confidence enums | `String` with documented literals (`IScanIssue.java:48-63`) |
| `TOOL_COLLABORATOR` | flags stop at `TOOL_EXTENDER` (`IBurpExtenderCallbacks.java:34-74`) |

## 1. Universal message model

`IHttpRequestResponse.java` has exactly ten methods: `getRequest`/`setRequest`
(`:27,:34`), `getResponse`/`setResponse` (`:41,:48`), `getComment`/`setComment`
(`:56,:63`), `getHighlight`/`setHighlight` (`:72,:81`),
`getHttpService`/`setHttpService` (`:90,:100`). Payload positions are raw byte
offsets `int[2]{start,end}` via `IHttpRequestResponseWithMarkers` and
`applyMarkers(...)` (`IBurpExtenderCallbacks.java:1093-1096`), which must be
sequential and non-overlapping (`:1081-1089`). `IHttpService` is
`host`/`port`/`protocol` (`IHttpService.java:23,:30,:38`).

Headless Rust equivalent: `RequestResponse { request: Vec<u8>, response:
Option<Vec<u8>>, service: HttpService, comment, highlight }` plus
`Vec<(usize,usize)>` markers. Entirely local.

## 2. Proxy

`IProxyListener.processProxyMessage(boolean messageIsRequest,
IInterceptedProxyMessage message)` (`IProxyListener.java:34-36`). The seven
intercept actions (`IInterceptedProxyMessage.java:26-57`):
`ACTION_FOLLOW_RULES=0`, `ACTION_DO_INTERCEPT=1`, `ACTION_DONT_INTERCEPT=2`,
`ACTION_DROP=3`, and `*_AND_REHOOK = 0x10..0x12` which re-invoke the listener.
Default action is `FOLLOW_RULES` (`:77-88`). Correlation id is
`getMessageReference()` (`:67`). The message is mutable via
`getMessageInfo().setRequest/setResponse/...` (`:75`). Global toggle:
`setProxyInterceptionEnabled` (`IBurpExtenderCallbacks.java:1003`). History:
`getProxyHistory()` (`:849`).

Cross-tool hook: `IHttpListener.processHttpMessage(int toolFlag, boolean
messageIsRequest, IHttpRequestResponse messageInfo)` (`IHttpListener.java:34-37`)
— fired for **every** tool, before a request is sent and after a response arrives.

Key property: **interception is independent of scope**. Scope only gates which
targets are allowed; interception is a per-message decision. Headless port keeps
`FOLLOW_RULES`/`DONT_INTERCEPT`/`DROP` as policy decisions; the UI-only "present
to user" and rehook actions are dropped.

## 3. Repeater

No listener, no programmatic send, no result accessor. `sendToRepeater(...)` only
opens a UI tab and "will not be issued until the user initiates this action"
(`IBurpExtenderCallbacks.java:563-580`). The headless analogue is simply an
`http_request` tool built on `makeHttpRequest` semantics.

## 4. Intruder

`IIntruderAttack`: `getHttpService()` (`:22`) and `getRequestTemplate()` (`:29`).
The template is a byte buffer with marker positions. Attack types are UI
scheduling policies, not API enums; the only hints are `getNextPayload(baseValue)`
receiving `null` for battering ram (`IIntruderPayloadGenerator.java:34-37`) and
`reset()` being called when one generator serves multiple positions — the sniper
case (`:44-47`).

Lifecycle:
`registerIntruderPayloadGeneratorFactory` (`IBurpExtenderCallbacks.java:392`) →
`createNewInstance(attack)` (`IIntruderPayloadGeneratorFactory.java:39`) → loop
`hasMorePayloads()` (`:29`) / `getNextPayload(baseValue)` (`:40`) → optional
`reset()` → payload processor chain → splice bytes into the template at offsets
(high-to-low to avoid shifting offsets) → send to `attack.getHttpService()`.

Processor: `processPayload(byte[] current, byte[] original, byte[] base)`
(`IIntruderPayloadProcessor.java:41-44`); `current` is the accumulated value,
`original` the unprocessed payload, `base` the original value at the position;
returning `null` **skips** the payload (`:37-39`).

Rust traits to mirror:
```
PayloadGenerator { has_more(); next(base:&[u8])->Vec<u8>; reset(); }
PayloadProcessor { name(); process(current, original, base) -> Option<Vec<u8>>; }
```
Attack modes to invent explicitly: sniper (one position at a time, `reset` per
position), battering ram (one payload across all positions, base `None`),
pitchfork (parallel generators, no reset), cluster bomb (cartesian product).

## 5. Scanner

`IScannerCheck` (`IScannerCheck.java:21-83`):
- `doPassiveScan(base)` (`:35`) — **must not send any request** (`:25-28`).
- `doActiveScan(base, insertionPoint)` (`:57-59`) — called once **per insertion
  point**; must use `point.buildRequest(payload)`. Raw, non-encoded payloads are
  submitted; the insertion point owns encoding (`IScannerInsertionPoint.java:139-143`).
- `consolidateDuplicateIssues(existing, new)` (`:80-82`): `-1` report existing,
  `0` report both, `1` report new. Called for issues on the same URL path
  (`IScannerCheck.java:61-69`).

`IScannerInsertionPoint` types (`IScannerInsertionPoint.java:26-113`): URL param,
body param, cookie, XML, XML attr, multipart attr, JSON, AMF, header, URL path
folder / filename, parameter-name variants, entire body, user-provided,
extension-provided, unknown. Methods: `getInsertionPointName` (`:121`),
`getBaseValue` (`:130`), `buildRequest(byte[] payload)` (`:149`),
`getPayloadOffsets` (`:165`, may be `null` for serialized structures),
`getInsertionPointType` (`:173`). Provider hook:
`getInsertionPoints(base)` (`IScannerInsertionPointProvider.java:36-37`).

Issue model (`IScanIssue.java:23-123`): URL, name, type, severity
(`High|Medium|Low|Information|False positive`, `:55`), confidence
(`Certain|Firm|Tentative`, `:63`), backgrounds/details, `IHttpRequestResponse[]`
messages (markers where applicable, `:109-112`), service. Text is subject to an
HTML whitelist (`:19-21`).

Scanner queue items expose `getStatus`, `getNumRequests`, `getNumErrors`,
`getNumInsertionPoints`, `issues`, `cancel` (`IScanQueueItem.java:25-80`) —
the natural place for graceful termination and budget accounting.

## 6. Session handling & scope

`ISessionHandlingAction.performAction(IHttpRequestResponse currentRequest,
IHttpRequestResponse[] macroItems)` (`ISessionHandlingAction.java:48-50`) may
issue its own requests and mutate `currentRequest`; `macroItems` is `null` when
the action does not follow a macro (`:41-46`). Cookie jar semantics
(`IBurpExtenderCallbacks.java:892-917`): keyed by domain+name; `null` value
deletes; non-matching cookie is added. Macro definitions are **not** exposed by
the API (config JSON only), so a headless port must own them.

Prefix reads (`getSiteMap`, `getScanIssues`) use literal case-sensitive text
match (`IBurpExtenderCallbacks.java:854-858,:868-872`). Scope changes notify
`IScopeChangeListener.scopeChanged()` (`IScopeChangeListener.java:24`).
Out-of-scope active scans ask the user (`IBurpExtenderCallbacks.java:641-643`)
— in AgentBug this becomes the deterministic fail-closed policy gate, never an
LLM/auto-approval decision.

## 7. Collaborator (OOB)

`createBurpCollaboratorClientContext()` (`IBurpExtenderCallbacks.java:1133`),
`generatePayload(includeLocation)` and `fetch*CollaboratorInteractions`
(`IBurpCollaboratorClientContext.java:35-86`). Interaction properties
(`IBurpCollaboratorInteraction.java:21-31`): `interaction_id`, `type`,
`client_ip`, `time_stamp`, DNS `query_type`/`raw_query` (Base64), HTTP
`protocol`/`request`/`response` (Base64). This is the only mechanism with no
purely-local substitute; **deferred** (requires an external listener + polling).

## 8. Parsing / analysis helpers (fully local, high value)

`IExtensionHelpers` (367 lines): `analyzeRequest`/`analyzeResponse`,
`getRequestParameter`, `buildHttpMessage` (adds/updates Content-Length, `:213`),
`buildHttpRequest(URL)` using Spider request headers (`:223`),
`addParameter`/`removeParameter`/`updateParameter` (URL/body/cookie only,
`:231-264`), `toggleRequestMethod` (`:278`), `makeScannerInsertionPoint`
(`:338-342`), `analyzeResponseVariations` (`:353`) and
`analyzeResponseKeywords` (`:366`). Content types (`IRequestInfo.java:26-50`):
none, URL-encoded, multipart, XML, JSON, AMF, unknown. Parameter types
(`IParameter.java:20-45`): URL, body, cookie, XML, XML attr, multipart attr,
JSON, with byte offsets (`:76-103`). Cookies (`ICookie.java:30-60`): domain/path
may be null, expiry null for session cookies.

## 9. Privilege map for the AgentBug port

| Local (no egress) | Outbound | External OOB |
|---|---|---|
| message model, markers, service/param/cookie structs, parsers/builders, response variations/keywords, issue model + dedup, cookie jar, scope, generator/processor traits, passive scan, comparer/decoder, history/site map, config | active scan, Intruder execution, spider/crawl, session macros, `http_request` | Collaborator |

GUI-bound and intentionally dropped: interception UI, rehook user prompts,
context menus, message-editor tabs, suite tabs, `sendTo*` handoffs, `issueAlert`.

## 10. Planned AgentBug tool slice (first implementation phase)

1. `http_request` — Repeater-equivalent: method, url, headers, body, cookies,
   redirect policy; emits full raw request/response bytes into the existing
   evidence/capture binding. Must go through the unchanged fail-closed scope
   gate and an explicit operator acknowledgement for state-changing methods.
2. `http_diff` / `analyze_response` — Comparer + `analyzeResponseVariations`/
   `analyzeResponseKeywords` equivalents; local, safe, no gate.
3. `decode` — Decoder equivalent (url/base64/hex), local, no gate.
4. `fuzz_request` — bounded Intruder: template + positions + generator + capped
   request count, attack modes sniper/battering ram. Active requests require
   the same ack, and every request is recorded for replay.
5. Deferred: Collaborator/OOB, Sequencer, live intercepting proxy, spider.

Outcome on any ack-gated path stays `incomplete`; no auto-submit, no new
`chat_full` call site in core, no domain vocabulary in `agentbug-core/src`.

## 11 — Cross-check with OWASP ZAP (Apache 2.0 source)

Authoritative in-tree evidence from `research/zaproxy` (sparse clone:
`extension/ascan/**`, `parosproxy/paros/network/**`, `extension/httppanel/**`).
The ZAP core engine classes (`Scanner`, `HostProcess`, `Plugin`, `Variant*`,
`Alert`) are **not** in the sparse clone; claims about them are marked
out-of-tree.

### 11.1 Active-scan gate (the analogue of AgentBug's ROE gate)

`ExtensionActiveScan.java:302-327`: `Control.getSingleton().getMode()` —
`safe` → `InvalidParameterException("Scans are not allowed in Safe mode")`;
`protect` → every start node must be `isIncludedInScope()`, else exception;
`standard`/`attack` allowed. `ActiveScanAPI.java:939-955` repeats the gate with
`MODE_VIOLATION`. Entering `safe` calls `stopAllScans()`
(`ExtensionActiveScan.java:619-628`), as does `destroy()` (`:631-637`).
Attack mode in a UI prompts with `showYesNoRememberDialog` and remembers the
answer (`AttackModeScanner.java:150-193`) — the closest ZAP equivalent to
AgentBug's hash-scoped operator acknowledgement (`ENG:756-822`).

Lesson: the "may I attack?" decision is a **mode/scope gate outside the tool**,
never a property of the tool itself. AgentBug already matches this with
`engagement build_tools` withholding (`ENG:3415-3438`) and `ToolOptions`.

### 11.2 Insertion points (`VariantFactory`)

`VariantFactory.createVariants(ScannerParam, HttpMessage)`
(`ASCAN/VariantFactory.java:68-165`) builds one variant per enabled parameter
location, driven by `ScannerParam` bitmasks:

- `TARGET_QUERYSTRING` → `VariantURLQuery` (`:75-89`), plus OData/Ddn variants
  by RPC flags.
- `TARGET_POSTDATA` → `VariantFormQuery`, `VariantMultipartFormParameters`,
  `VariantXMLQuery`, `VariantJSONQuery`, `VariantGWTQuery`,
  `VariantDirectWebRemotingQuery` (`:92-116`).
- `TARGET_HTTPHEADERS` → `VariantHeader` (`:118-132`) — added if
  `isScanHeadersAllRequests()` **or** the heuristic "raw query non-empty or
  body non-empty", notably applied only to dynamic pages.
- `TARGET_URLPATH` → `VariantURLPath` (`:134-136`).
- `TARGET_COOKIE` → `VariantCookie(isEncodeCookieValues())` (`:138-140`).
- `RPC_CUSTOM` / `RPC_USERDEF` / `TARGET_PLAINBODY` → custom, user-defined,
  plain-body variants (`:143-160`).

Parameter data model: `HtmlParameter.Type {cookie, form, url, header, multipart}`
and `Flags {anticsrf, session, structural}` (`NET/HtmlParameter.java:25-38`).
`HttpMessage.getFormParams()` returns empty unless `Content-Type` starts with
form-urlencoded (`:898-906`); `getCookieParams()` merges request `Cookie` and
response `Set-Cookie`/`Set-Cookie2` (`:935-946`). Writers rebuild the raw message:
`HttpRequestHeader.setGetParams` (`:684-733`), `setCookieParams` (`:765-793`).

Lesson: insertions are **byte-offset aware and location-typed**. AgentBug's
`HttpFuzzTool` only rewrites URL query/markers (`TOOLS:3933-3964`); an
`enumerate_insertion_points` tool is the missing bridge from recon to fuzz.

### 11.3 Skip decisions and audit trail

`ScanFilter.isFiltered(StructuralNode) -> FilterResult`
(`ASCAN/filters/ScanFilter.java:32-35`). `AbstractGenericScanFilter`
(`:38-120`) uses INCLUDE/EXCLUDE collections with a matcher; empty data means
`NOT_FILTERED` (`:82-84`). `FilterCriteria` documents **INCLUDE evaluated before
EXCLUDE; include wins on conflict** (`FilterCriteria.java:22-36`) — the same
specificity principle AgentBug now applies in `scope_target_allowed`.
`FilterResult` carries a human-readable `reason` (`FilterResult.java:30-59`),
and `ActiveScan.filteredMessage` records URI + reason (`ActiveScan.java:258-260`)
as the audit trail.

Lesson: every skip must produce a **reason string**, not a silent drop. AgentBug
already does this with `denial_result` (`TOOLS:948-964`) and audit Action events
(`ENG:1038-1063`).

### 11.4 Message model / re-send / graceful stop

`HttpMessage` holds request/response header+body plus history/session refs
(`NET/HttpMessage.java:101-146`); `cloneRequest()` copies wire bytes only
(`:998-1013`). `HttpSender.sendAndReceive(msg, followRedirect)` selects
`FOLLOW_REDIRECTS`/`NO_REDIRECTS` configs (`NET/HttpSender.java:160-162,:367-369`),
with `setMaxRedirects` default 100 (`:487-498`), `setMaxRetriesOnIOError` default
3 (`:474-485`), and `HttpSender.ACTIVE_SCANNER_INITIATOR = 2` (`:130`) tagging
scanner traffic. Cookie/state knobs: `setUseGlobalState` (`:256-286`),
`setUseCookies` (`:288-297`), `setRemoveUserDefinedAuthHeaders` (`:453-472`).

Graceful termination is cooperative, never a kill: `stopScan()` → `super.stop()`
and cancel stats future (`ActiveScan.java:213-219`); plugins poll `!isStop()`
at safe boundaries (`ScriptsActiveScanner.java:157,180,214`); entering safe
mode stops all scans. Concurrency is bounded — `ActiveScanController` uses a
`ReentrantLock` + map for parallel scans (`:58-96`), attack mode caps
`scannerCount = 4` (`AttackModeScanner.java:259-260,290-324`).

Lesson: AgentBug's `request_stop` + `wait_while_paused` already match this; no
new cancellation primitive is needed.

### 11.5 What AgentBug already has (do not rebuild)

- `HttpRequestTool` (`TOOLS:1053-1275`): scheme allowlist, method gate, proxy
  validation, scope/host validation, DNS pin, transmitted canary scrubbed from
  model-visible output, rate limit, timeout/body caps, `none` redirect policy,
  authoritative `capture` in `structured`. This is stronger than ZAP's
  `evidence` string + `HistoryReference`: AgentBug binds SHA-256 of raw bytes.
- `HttpFuzzTool` (`TOOLS:3929-4088`): marker/param substitution with hard caps
  `MAX_FUZZ_WORDLIST = 200`, `MAX_FUZZ_REQUESTS = 200` (`TOOLS:24-28`),
  GET/HEAD/POST only (`:4003-4005`).
- Fail-closed tool withholding (`ENG:3411-3438`): fuzz requires
  `roe.allow_fuzzing && options.allow_intrusive`; `http_request` and
  `validate_poc` withheld when `!roe.allow_state_change`.
- Central `ToolOptions.allowed_methods` (`:1087-1096`), `max_rps`, and
  `roe.max_requests -> max_network_calls` (`:2405-2415`).

### 11.6 Concrete safe gap to close next

Pure, local, no acknowledgement required:
1. `enumerate_insertion_points` — VariantFactory equivalent; URL/form/cookie/
   header/path/multipart params with byte offsets and the `VariantHeader`
   dynamic-page heuristic. `risk: "read"`.
2. `http_diff` / `analyze_response` — Comparer + `analyzeResponseVariations`/
   `analyzeResponseKeywords` equivalents; variant/invariant attribute counters.
3. `decode` — Decoder equivalent (url/base64/hex), fully local.

Remains gated (do not expose as ordinary LLM tools):
- full active-scan orchestrator (target walk + rule loop),
- body/header/path mutation variants beyond current marker fuzz,
- authenticated/session-context scanning and policy-strength escalation
  (`AttackStrength.INSANE`, threshold `OFF`),
- Collaborator/OOB and live intercepting proxy.
