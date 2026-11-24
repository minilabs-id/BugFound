# 06 - OWASP Methodology: WSTG, ASVS, API Security Top 10 -> BugFound

> **About these notes.** These are point-in-time analyses of third-party reference
> projects, kept for design input. They describe the reference projects at the
> snapshots examined and are not claims about the current BugFound code; verify
> current behavior in `crates/`.

Read-only research deliverable. No implementation code was modified. Source clones are
local, shallow, and git-ignored (research/README.md); record their commits when citing
this document.

## 0. Source corpus and pinned commits

| Source | Local path prefix | Pinned commit (HEAD at research time) | Notes |
| --- | --- | --- | --- |
| OWASP WSTG | research/owasp-wstg/latest/ | 4126c29f4f585cc2b19897f90f9f252a9e36f4c8 | "Publish Latest 2026-11-18 (#687)". Also stable/, v41/, v42/ retained; USE latest/ - it contains the new Bug Bounty and Human-AI sections. |
| OWASP ASVS | research/owasp-asvs/5.0/ | 82fb2f41cdb623e0b11e4d9a6b97c4306c1d119c | "Appendix C: fix RFC 5248, RFC 7539, FIPS 186-4 label and FIPS 203/204/205 draft links (#3446)". ASVS 5.0.0; older 1.0-4.0 trees present. |
| OWASP API Security Top 10 | research/owasp-api-security/editions/2023/en/ | 33cea37b2ffde3e2e62f6b5d79a029a22a846633 | "Merge pull request #178 from phoenix766/docs/pt-pt-guid-authorization-note". editions/2019/ is the previous edition; VERSION says 2.7.0 (site tooling, not the edition). |

Current implementation inspected (no changes made): crates/bugfound-engagement/src/lib.rs,
crates/bugfound-tools/src/lib.rs, crates/bugfound-store/src/lib.rs, docs/report-format.md,
docs/engagement.md, docs/REMAINING_GAPS.md, eval/score.py.

## 1. WSTG - what the guide actually says

### 1.1 Testing framework: six activities, not a sequence
latest/3-The_OWASP_Testing_Framework/0-The_Web_Security_Testing_Framework.md
- Sec Overview / Sec Testing Activities: six recurring activities - Requirements and Policy
  Review; Design, Architecture and Threat Modeling; Code-Level Review and Analysis;
  Dynamic and Penetration Testing; Continuous Integration Pipeline Testing; Continuous and
  Crowd-Sourced Testing. Explicitly "no fixed sequence or gated workflow"; activities feed
  back into each other; testing is an iterative cycle.
- Sec Matching Activity to Cadence: table maps each activity to cadence, owner and examples
  (ASVS/Cheat Sheets, Threat Dragon/pytm/STRIDE, SAST/SCA/secret scanning, ZAP/Burp,
  HackerOne/Bugcrowd, SIEM/re-scanning).
- Sec Where to Start: choose by risk profile; framework "is not a checklist to complete in
  order".
- Implication: a static flat task list cannot express cadence, feedback loops, or
  activity-to-owner/cadence metadata. The engagement runs nine playbooks once, in
  enumeration order, then stops.

### 1.2 Test categories and definitions
latest/4-Web_Application_Security_Testing/README.md lists 4.0-4.13;
latest/4-Web_Application_Security_Testing/00-Introduction_and_Objectives/README.md:
- Sec What is a Test? "an action to demonstrate that an application meets the security
  requirements of its stakeholders."
- Sec The Approach in Writing this Guide: tests must be Consistent, Reproducible,
  Rigorous, Under quality control.
- Sec What Is the OWASP Testing Methodology?: black-box basis; model = Tester + Tools and
  methodology + Application (the black box).
- Sec Passive Testing / Sec Active Testing: passive = understand logic and map all access
  points (headers, parameters, cookies, APIs); "input points found in this phase represent
  targets for testing"; keeping a call tree is useful during active testing. Active tests
  split into 12 categories: Information Gathering, Configuration and Deployment Management,
  Identity Management, Authentication, Authorization, Session Management, Injection, Error
  Handling, Weak Cryptography, Business Logic, Client-side, API Testing. latest/ adds a
  13th chapter, WebAssembly Testing.
- Implication: "access points discovered during passive testing become targets" is exactly
  a coverage-ledger edge; current BugFound has no task that consumes the asset inventory
  to generate follow-up hypotheses.

### 1.3 Test-case anatomy and controlled tests
Representative:
latest/4-Web_Application_Security_Testing/05-Authorization/04-Insecure_Direct_Object_References.md
- Stable ID (WSTG-ATHZ-04), Summary, Test Objectives, How to Test, References; many files
  also include Remediation (e.g. 08-Error_Handling/01-Improper_Error_Handling.md,
  10-Business_Logic/03-Integrity_Checks.md, 12-API_Testing/03-Excessive_Data_Exposure.md).
- IDOR "How to Test" is a controlled differential experiment: AT LEAST TWO USERS owning
  different objects, plus (if relevant) users with different privileges; obtain a
  reference the tester is not supposed to access, replay it, and check whether the object
  is returned or changed. Scenarios: parameter to database row, parameter to operation,
  parameter to file, parameter to application functionality.
- latest/4-Web_Application_Security_Testing/10-Business_Logic/00-Introduction_to_Business_Logic.md
  Sec Business Limits and Restrictions / Sec Challenges of Logic Testing: finite-state and
  abuse cases; "what happens if the user goes from step 1 straight to step 3?"; examples of
  price tampering, resource holding, points/credits after cancellation. Explicitly:
  automation cannot detect these; they require context and developer/business intent.
- latest/4-Web_Application_Security_Testing/12-API_Testing/00-API_Testing_Overview.md:
  API technology space (REST, SOAP, GraphQL, gRPC, WebSockets); REST method-to-CRUD mapping;
  note that PUT is not always idempotent - test by repeating the request and comparing
  state. This is a concrete differential/state-invariant test pattern.
- 12-API_Testing/ also contains 02-API_Broken_Object_Level_Authorization.md,
  03-Excessive_Data_Exposure.md, 04-API_Broken_Function_Level_Authorization.md,
  09-Inbound_Webhooks.md, 10-gRPC.md, 99-GraphQL.md - a much richer API taxonomy than
  BugFound's single wstg-api task.

### 1.4 Bug-bounty guidance
latest/3-The_OWASP_Testing_Framework/1-Bug_Bounty_Programs.md
- Sec Overview: bounty is complementary, continuous, crowd-sourced, often black-box.
- Sec How This Differs from Traditional Penetration Testing (table): time-boxed vs
  continuous; single team vs crowd; white/gray-box vs black-box; negotiated SOW vs
  unilaterally defined scope; custom rules vs standard terms; fixed fee vs pay-per-finding;
  FORMAL CONSULTANCY REPORT vs PER-FINDING SUBMISSION.
- Sec Applying WSTG Techniques Within a Bug Bounty Program: techniques still apply; what
  changes is selection and timing. Bounty researchers work reactively, cast a wider net,
  run automation in parallel and follow promising leads.
- Sec Reporting Under a Bounty Program: MINIMUM REQUIRED = reproduction steps, impact,
  remediation; "demonstrating reachability - not just the flaw itself - is critical";
  severity rubric (CVSS or program-specific) must be clarified; SCOPE CLARITY - a report
  on an out-of-scope third party, staged/test environment, or deprecated branch is rejected
  regardless of validity; re-read scope regularly because it can change mid-program.
- Sec Designing a Program: in-scope targets, legal safe harbor, rules of engagement
  (permitted techniques; prohibit social engineering, DoS, destruction/exfiltration beyond
  PoC; INCREASINGLY POLICIES ON AI-GENERATED OR AI-ASSISTED REPORTS), disclosure timeline,
  reward tiers; publish security.txt (RFC 9116).
- Implication: scope re-validation and reachability are first-class report fields.
  BugFound enforces fail-closed scope per network action (docs/engagement.md Sec 2) but
  does not capture "reachability" or report-eligibility as report concepts (its brief
  parser deliberately discards reward-eligibility lines as NON_ACTIONABLE).

### 1.5 Human-AI collaborative testing (directly relevant to an autonomous agent)
latest/3-The_OWASP_Testing_Framework/2-Human-AI_Collaborative_Testing.md
- Sec Overview: AI accelerates candidate generation, request chaining, triage, report
  normalization; knowing what/why/how and interpreting results stays human.
- Sec Case in Point: "HTTP Terminator" - 30,000 request-smuggling vectors; value came from
  a human-designed methodology, deterministic constraints preventing combinatorial
  explosion, and human filtering of true positives.
- Sec Where AI Assists Today: large-scale candidate/payload generation; anomaly and
  response triage (deviation from baseline); chaining and orchestration; report drafting
  and normalization. "In each case, a human tester must validate the output before
  treating anything as a confirmed finding or shipping it in a report."
- Sec The Human's Role: scope and methodology design; tool direction and constraint;
  output validation and filtering; ACCOUNTABILITY (only a human authorizes a report);
  context and judgment (business logic and threat model not inferable from scanning).
- Sec Risks and Limitations: false positives/hallucinations; over-trusting automated
  triage (a business-logic bug may score below a cosmetic XSS); PROMPT INJECTION via
  application responses ingested into tool reasoning; tool opacity; program policies on
  AI-assisted submissions (disclose, reject, or ban).
- Implication: BugFound already echoes this (tool-captured bytes, canary replay,
  "operator review required", no auto-submit), but has no artifact recording
  AI-suggested vs human-confirmed, no prompt-injection note tied to tool output, and no
  AI-assistance disclosure field in the report.

### 1.6 Reporting expectations
latest/5-Reporting/01-Reporting_Structure.md
- Sec 1 Introduction: version control, ToC, team, scope, limitations (out-of-bounds,
  broken functionality, lack of cooperation/time/access), timeline, disclaimer ("point in
  time", no warranty of full coverage).
- Sec 2 Executive Summary: objective/business need, key findings in business context,
  strategic non-technical recommendations; avoid jargon.
- Sec 3 Findings: Findings Summary table (Ref ID / Title / Risk Level); Findings Details -
  reference ID, likelihood/exploitability (ease, working exploit code, access required,
  attacker motivation), impact, risk level with VALUES DEFINED IN AN APPENDIX, detailed
  description (mask sensitive data: passwords, PII, card details), remediation, additional
  resources; "enough information for the engineer reading this report to take action".
- Sec Human Factors: phishing/info leakage, auth/recovery UX, 2FA fallback, social
  engineering exposure, session/credential handling; technical controls first, then
  process/training; identify fix owner and short-term mitigations.
- Sec Reproducible Test Artifacts: curl commands, PoC forms, HAR files, simple automation
  scripts - "help developers quickly validate and retest".
- Sec Appendices: methodology, severity/risk rating explanations, cleaned tool output,
  checklist of all tests conducted (WSTG checklists).
- Sec About This Section: guidance, not strict rules; best fit for consultancy reports,
  "may be overkill for internal or bug bounty reports" - keep bounty submissions lean but
  retain repro/impact/remediation.
- latest/5-Reporting/02-Naming_Schemes.md: CPE, SWID (ISO/IEC 19770-2:2015), PURL;
  recommendation table by asset type; SWID preferred over deprecated CPE for new work.
  Useful as a STABLE ASSET-IDENTIFIER pattern, not a finding taxonomy.
- latest/6-Appendix/G-Penetration_Testing_Methodologies.md: NIST SP 800-115 phases
  (Review; Target Identification/Analysis; Vulnerability Validation; Planning/Execution;
  Post-Testing), OSSTMM, PTES/PCI, MITRE ATT&CK adversary emulation; Sec Summary says
  Section 3 describes WHEN/WHICH techniques, Appendix G describes HOW.
- 6-Appendix/D-Fuzzing.md and E-Encoded_Injection.md are companion technique references
  (BugFound has no curated corpus - docs/REMAINING_GAPS.md Sec 1).

## 2. ASVS 5.0 - level, requirement, and coverage patterns

### 2.1 Structure and levels
5.0/en/0x03-What-is-the-ASVS.md
- Sec Scope: security outcomes WITHIN THE PRODUCT; WAFs/LB/proxies count only for specific
  controls; DNS/backup are out of scope; "no such thing as scope for attackers".
- Sec Security / Sec Verification: every requirement must reduce likelihood or impact and
  must yield a FAIL or PASS decision.
- Sec Requirement: only "must" requirements, verifiable, technology-neutral.
- Sec Documented security decisions: documentation requirements are always the FIRST
  SECTION OF A CHAPTER and always pair with an implementation requirement; verifying the
  document and verifying the implementation are two separate activities.
- Sec Application Security Verification Levels: L1 ~20% (minimum/basic first-layer
  defenses; not necessarily black-box testable), L2 ~50% (implement ~70% cumulatively for
  compliance), L3 ~30% (defense in depth / hard-to-implement). Levels are
  priority/risk-reduction based; organizations may pull higher-level items earlier.
- Sec How to use the ASVS / Sec The structure: ~350 requirements in 17 chapters and
  sections; filter out irrelevant chapters (e.g. V3 web frontend for machine-to-machine
  APIs, V10 OAuth, V17 WebRTC). Sec Forking the ASVS: domain-specific forks encouraged IF
  TRACEABILITY IS MAINTAINED; start from L1.
- Sec How to Reference ASVS Requirements: chapter.section.requirement (e.g. 1.11.3),
  versioned form v5.0.0-1.2.5 (lowercase v); unversioned IDs imply "latest", which is
  fragile. Requirement lists are available in CSV/JSON for programmatic use.
- Sec Use cases: architecture guidance, secure coding reference, GUIDE FOR AUTOMATED UNIT
  AND INTEGRATION TESTS (build abuse-case tests per requirement), training, procurement.
- 5.0/en/0x04-Assessment_and_Certification.md
  - Sec Verification reporting: unlike pentests "by exception", an ASVS-style report
    includes SCOPE, A SUMMARY OF ALL REQUIREMENTS CHECKED, THE EXCEPTIONS, and resolution
    guidance; NON-APPLICABLE REQUIREMENTS MUST BE NOTED (e.g. session management in
    stateless APIs).
  - Sec Scope of Verification: state which Level is attempted and what was INCLUDED, with
    rationale for exclusions.
  - Sec Verification Mechanisms: disclose and ideally repeat methods; evidence = work
    papers, screenshots, scripts, testing logs; "TESTABLE USING AUTOMATION != RUNNING AN
    OFF THE SHELF TOOL"; cannot verify business logic/access control with generic tools.
  - Sec Role of Penetration Testing: black-box discouraged even at old L1; prefer
    documentation/source-led hybrid testing.
- 5.0/en/0x13-V4-API-and-Web-Service.md: requirement table columns are
  "| # | Description | Level |" (e.g. 4.1.1 L1 Content-Type, 4.2.1 L2 request-smuggling
  framing, 4.3.1 L2 GraphQL query-cost DoS, 4.3.2 L2 disable prod introspection,
  4.4.1 L1 WSS). Sec Control Objective warns V4 cannot be tested in isolation - auth,
  session, input validation chapters also apply to APIs. Direct argument for a
  cross-chapter coverage matrix rather than one "API" playbook.
- 5.0/docs_en/OWASP_Application_Security_Verification_Standard_5.0.0_en.csv header:
  chapter_id,chapter_name,section_id,section_name,req_id,req_description,L.
  Also .flat.json, .json, .legacy.*, .xml, .cdx.json (CycloneDX).
  5.0/mappings/README.md documents version IDs v4.0.3, v5.0.be, v5.0 and mapping files
  (mapping_v4.0.3_to_v5.0.0.yml, etc.) plus v5.0.be_cwe_mapping.json.
- Pattern to adopt: MACHINE-READABLE, VERSIONED REQUIREMENT ROWS WITH A LEVEL COLUMN AND
  STABLE IDS, plus cross-version mappings - the natural backbone of a coverage ledger.

## 3. API Security Top 10 (2023) - categories and testing implications

editions/2023/en/0x11-t10.md is the canonical list; 0x10-api-security-risks.md defines the
rating vocabulary: Threat Agents (API-specific) x Exploitability (Easy/Average/Difficult)
x Weakness Prevalence x Detectability x Technical Impact (Severe/Moderate/Minor) x
Business Impact (organization-specific). Each risk file uses fixed sections:
Threat agents/Attack vectors | Security Weakness | Impacts table, "Is the API Vulnerable?",
"Example Attack Scenarios", "How To Prevent", "References" (CWE/Cheat Sheets). That
structure is already a hypothesis-template sketch.

| Risk (file under editions/2023/en/) | Testing implication (from "Is the API Vulnerable?" / scenarios) |
| --- | --- |
| 0xa1-broken-object-level-authorization.md / API1 BOLA | Every endpoint taking an ID needs an object-level check; manipulate IDs in path/query/header/body; use another user's object; comparing session user ID to the ID is insufficient; distinguish from BFLA (endpoint you shouldn't reach at all). CWE-285/639. |
| 0xa2-broken-authentication.md / API2 | Credential stuffing/brute force without lockout or CAPTCHA; weak passwords; tokens in URL; sensitive change without password confirmation; JWT alg:none, unsigned/expired tokens; microservices reachable without auth; GraphQL batching to defeat rate limits; treat reset/forgot as login. CWE-204/307. |
| 0xa3-broken-object-property-level-authorization.md / API3 | Merge of 2019 Excessive Data Exposure + Mass Assignment. Inspect responses for sensitive properties; fuzz hidden properties; replay with extra fields (total_stay_price, blocked); check side effects when property is not echoed; schema-based response validation as defense. CWE-213/915. |
| 0xa4-unrestricted-resource-consumption.md / API4 | Check missing/inappropriate caps: timeouts, memory, file descriptors/processes, upload size, batch operations, records-per-page, third-party spend; vary these while measuring status/time/length; GraphQL batching amplification; billing alerts. CWE-770/400/799. |
| 0xa5-broken-function-level-authorization.md / API5 | Regular user -> admin endpoints; method swap GET->DELETE; guess admin URLs; DO NOT INFER ADMIN FROM PATH (admins may live under /api/users); deny-by-default grants. CWE-285. |
| 0xa6-unrestricted-access-to-sensitive-business-flows.md / API6 | Not necessarily an implementation bug: understand the business model, find flows harmful when automated (scalping, spam, reservations, referral abuse); test device fingerprinting, CAPTCHA/human detection, non-human timing patterns (add-to-cart then purchase in under 1s); B2B/machine APIs often unprotected. |
| 0xa7-server-side-request-forgery.md / API7 | Any client-supplied URI (URL image fetch, webhook test, custom SSO, URL preview); localhost/internal ports, timing-based port scan, cloud metadata 169.254.169.254; basic (response returned) vs blind (no feedback); allowlist schemes/ports/origins, disable redirects, do not return raw responses. CWE-918. |
| 0xa8-security-misconfiguration.md / API8 | Missing hardening, unpatched systems, unnecessary verbs/features, chain desync, missing TLS, missing Cache-Control, bad CORS, stack traces; Log4Shell-style header injection; response-schema enforcement including errors. CWE-2/16/209/319/388/444/942. |
| 0xa9-improper-inventory-management.md / API9 | "Documentation blindspot" (environment, who has network access, version, no retirement plan) and "data flow blindspot" (sensitive third-party flows without justification/inventory); old beta host without rate limiting; deprecated versions on same DB; auto-generate docs in CI. CWE-1059. |
| 0xaa-unsafe-consumption-of-apis.md / API10 | Third-party data trusted more than user input; unencrypted integrations; no validation/sanitization of returned data; blind redirects (308 -> attacker); no timeouts/resource limits; SQLi payload stored in third party then pulled. CWE-20/200/319. |

Crosswalk to WSTG latest/4-Web_Application_Security_Testing/12-API_Testing/ and ASVS
5.0/en/0x13-V4-API-and-Web-Service.md: API1 -> WSTG 12-API 02 / ASVS V8; API2 -> WSTG 04
/ ASVS V6, V18; API3 -> WSTG 12-API 03 / ASVS V14; API4 -> ASVS V4/V13; API5 -> WSTG 05 /
ASVS V8; API6 -> WSTG 10-BUSL / ASVS V2; API7 -> WSTG 07-Injection 19 / ASVS V4;
API8 -> WSTG 02 / ASVS V13; API9 -> WSTG 01 / ASVS V13; API10 -> WSTG 12-API 09 / ASVS V4.

## 4. Mapping to BugFound (five workstreams)

### 4.1 Playbook taxonomy
Current: wstg_playbooks() in crates/bugfound-engagement/src/lib.rs Sec Planner returns NINE
(id, one-sentence task statement) pairs: wstg-info, wstg-config, wstg-authz, wstg-auth,
wstg-session, wstg-injection, wstg-business, wstg-api, wstg-client. IDs are custom (wstg-*),
not real WSTG test IDs. crates/bugfound-tools/src/lib.rs KNOWLEDGE_BASE has TWELVE WSTG
category rows (WSTG-INFO-01, CONF, IDNT, ATHN, ATHZ, SESS, INPV, ERRH, CRYP, BUSL, CLNT,
APIT) with keyword lists and CWE hints - the tool's taxonomy is already richer than the
planner's. knowledge_lookup scores by count of query words contained in
id + category + keywords, returns matches sorted by score; no objectives, steps,
verification, or cross-standard IDs.

Recommended taxonomy (data-model guidance, no code copy):
1. Keep a TWO-LEVEL PLAYBOOK RECORD: category (WSTG 4.1-4.13 + WebAssembly) -> test (stable
   WSTG test ID, e.g. WSTG-ATHZ-04). Add the three WSTG categories the planner lacks:
   Identity Management, Error Handling, Weak Cryptography; plus WebAssembly as an
   "if applicable" branch.
2. Attach CROSS-STANDARD TAGS to each test: ASVS req_id + L + versioned v5.0.0-<id>; API
   risk API<n>:2023 where relevant; CWE hints from the existing KNOWLEDGE_BASE; WSTG ID.
   This turns the flat list into a facet index.
3. Split wstg-api into at least BOLA/BFLA, object-property/mass assignment, resource
   consumption, SSRF/webhooks, misconfiguration, inventory, unsafe consumption, and
   GraphQL/gRPC - matching WSTG 12-API and API1-API10.
4. Add an explicit HUMAN-AI COLLABORATION playbook/guardrail section derived from WSTG
   Sec 3.2: AI-suggested candidates require human validation, scope decisions and
   accountability remain human, prompt injection via tool output is a listed risk.
5. Record cadence/owner metadata from WSTG Sec 3.1 so "playbook planned/blocked/skipped"
   can be explained, not just counted.

### 4.2 Hypothesis templates
Current: the planner calls store.add_hypothesis(id, statement) with the SAME SENTENCE as
the task statement (bugfound-engagement Sec Planner); Hypothesis has only
(id, session_id, statement, status='open', created_at) (bugfound-store schema and
add_hypothesis); no production code calls set_hypothesis_status (only store tests do), so
all nine hypotheses remain "open" forever. docs/report-format.md Appendix C expects a
hypothesis list, but the production renderer render_canonical_report (bugfound-tools Sec
Canonical renderer) emits no hypotheses section.

Recommended structured hypothesis (fields, not implementation):
id (stable test ID) | category | claim (falsifiable) | preconditions (identity/role,
object ownership, state) | attack vector (parameter/endpoint/method) | controlled setup
(two-user differential, before/after state, baseline response) | expected observation if
vulnerable | falsification criterion | WSTG ID | ASVS req id(s)+L | API risk id | ROE
limits (methods, rps, no state change) | required evidence/oracle | status
(open|planned|tested|refuted|confirmed|blocked|not-applicable).

Concrete patterns to seed templates from the sources:
- IDOR/BOLA: "With user A authenticated, request an object ID owned by user B (and a
  second ID owned by an admin); vulnerable if A receives/modifies B's object. Refuted if
  every cross-owner request is denied identically to a nonexistent ID." (WSTG 4.5.04;
  API1).
- BFLA: "Send the same function as anonymous, regular, and admin user; vary method
  GET->DELETE; vulnerable if regular reaches an admin function. Do not infer admin from
  path." (API5).
- Property-level: "Replay a legitimate write with one extra field; vulnerable if the extra
  property is persisted or changes behavior even when not echoed." (API3).
- Business logic: "Finite-state abuse - skip step 2 of a 3-step flow, replay, or use
  negative/duplicated quantities; vulnerable if an invariant (total price, points, stock)
  is violated." (WSTG 4.10 intro; API6). Mark as human-context-dependent per WSTG Sec 3.2.
- Resource/SSRF: "Vary page size/batch count and measure status/time/length; use a
  controlled internal target for URI-fetch features, including redirect chains."
  (API4/API7; ASVS 4.2/4.3).
- Idempotency: "Repeat PUT; refuted if the resource ends in the same state, no duplicate
  created." (WSTG 12-API overview Sec HTTP Methods).

### 4.3 Coverage ledger
Current: coverage(id, session_id, target, method, path, created_at,
UNIQUE(session_id,target,method,path)) - an ACCESS LOG of target/method/path only;
coverage_count is a raw row count; engagement mirrors runner-session rows onto the
engagement id. No requirement IDs, no status, no N/A, no link to hypotheses/findings or
evidence. docs/report-format.md Sec Coverage wants a Result column
(covered / blocked / skipped: reason), which the renderer does not produce.

Recommended ledger (patterns from ASVS Sec 2 above):
- Key rows by STANDARD IDENTIFIER + VERSION: v5.0.0-V8.2.1, WSTG-ATHZ-04, API1:2023 (plus
  the target/parameter where applicable). Keep existing target/method/path rows as a
  separate "access log" facet.
- Status vocabulary: planned | tested | verified | refuted | blocked | not-applicable with
  MANDATORY RATIONALE for not-applicable (ASVS 5.0 Sec Verification reporting); e.g. "no
  session management - stateless API", "no OAuth used", "no GraphQL endpoint discovered".
- Store level (L1/L2/L3) and allow level-scoped views; an engagement declares its target
  level, and the report states what was INCLUDED and why anything was excluded.
- Link each ledger row to hypothesis ID(s), finding ID(s), tool-capture evidence hash,
  and the ROE decision that blocked it. This makes coverage auditable rather than a count.
- Use the ASVS CSV/JSON shape (chapter_id,chapter_name,section_id,section_name,req_id,
  req_description,L) and published cross-version mappings as seeds for a VERSIONED,
  FORKABLE ledger; a local fork must preserve traceability of IDs.

### 4.4 Verification criteria
Current: verify_findings (bugfound-engagement Sec Verifier) is a deterministic replay
oracle: requires tool capture, SHA-256 digest check, response containing the tool's own
canary, and a 2xx status; rejects self-graded <html echoes and findings whose
title/description claim forbidden techniques under ROE; LLM-supplied response is advisory
only. Strengths: provenance and anti-hallucination. Gaps: the oracle is essentially
"canary echoed with 2xx", which fits reflected-input PoCs but not most differential,
stateful, or blind classes; it cannot confirm an IDOR (needs role differential), a mass
assignment (needs before/after object state), a business-logic invariant, blind SSRF
(out-of-band), or excessive-data-exposure (needs schema/field comparison).

Recommended per-hypothesis verification criteria (declare the oracle in the hypothesis):
- PROVENANCE ORACLE (already implemented): stored tool bytes + canary + digest.
- DIFFERENTIAL ORACLE: paired requests across two identities/roles or two object owners,
  with a negative control (nonexistent ID); verdict depends on the DIFFERENCE.
- STATE-INVARIANT ORACLE: snapshot before and after a request; assert the business
  invariant (price, balance, points, stock, blocked flag) - includes re-testing
  idempotency by repetition.
- SCHEMA/FIELD ORACLE: compare response fields against the endpoint's declared/expected
  schema; extra sensitive property = signal (API3).
- TIMING/OUT-OF-BAND ORACLE: response-time baseline for blind SSRF/resource classes;
  controlled internal listener where ROE permits.
- NEGATIVE-CONTROL / N/A ORACLE: record why a test could not be executed (ROE, no
  credentials, no third-party API) rather than silently skipping.
- Keep HUMAN ACCOUNTABILITY explicit (WSTG Sec 3.2): verifier result = machine verdict,
  report status = candidate -> verified -> operator-confirmed; do not auto-promote.
- Reflect ASVS: L1 technical checks may be automatable, but L2/L3 and business logic /
  access control need documentation/source-led hybrid verification; "testable using
  automation != running an off the shelf tool". Generic http_fuzz output alone must not
  satisfy a requirement.

### 4.5 Report quality
Current canonical renderer (bugfound-tools Sec render_canonical_report) emits:
"<engagement> - Security Assessment Report"; Executive Summary (program + counts + one
paragraph); Scope & ROE; Methodology (one fixed paragraph); Findings (### F-001, fields
ID/Severity/CVSS/Vector/CWE/Asset/Verified/Evidence SHA-256, description, Steps,
"Proof of Concept" = "Evidence bytes pinned by SHA-256", Impact, Remediation); Coverage
(list); Timeline; Appendices A Evidence Integrity, B References.

docs/report-format.md (reference template, checked by eval/score.py Sec
REQUIRED_SECTIONS) requires more: severity count table, per-finding OWASP field and CWE
name, Status (candidate/verified/operator-confirmed), PoC as a redacted view of
tool-captured bytes with canary, an Evidence block (SHA-256, artifact path, capture
source, canary, redacted request/response), a Coverage Result column, Appendices A Asset
inventory, B Artifact index, C HYPOTHESES, D Glossary, E Reproduction command, plus a
metadata header (Engagement ID, Program URL, Generated UTC, Model, Run mode, Report
status). eval/score.py checks only the seven top-level headings, so missing detail is not
caught.

Concrete gaps and fixes:
1. RENDERER/TEMPLATE DRIFT - reconcile render_canonical_report with docs/report-format.md;
   add the OWASP field, severity table, Status, Evidence block, Coverage Result, and
   Appendices A-E (especially Hypotheses). Use WSTG Sec 5 fields as the source of truth.
2. REACHABILITY (WSTG bug-bounty Sec Reporting) - add an explicit "reachability / how an
   attacker gets to the vulnerable endpoint" subfield; a reachable-nil finding should be
   closed, not reported.
3. SCOPE CLARITY IN THE REPORT - include fail-closed refusals and re-validation note
   (scope can change mid-program); mark out-of-scope, staging, third-party, deprecated
   branches as exclusions.
4. SEVERITY RUBRIC - state which rubric (CVSS v3.1 per current bands, or program-specific
   Critical/High/Medium/Low) and define risk values in an appendix (WSTG Sec 3.2/Appendices).
5. REPRODUCIBLE ARTIFACTS - emit the actual redacted curl/PoC reference and artifact path,
   not just the hash; WSTG recommends curl commands, PoC forms, HAR, scripts.
6. LIMITATIONS / POINT-IN-TIME DISCLAIMER AND HUMAN FACTORS - add limitations (no real
   browser, no state changes authorized, no OS sandbox, no clustering - see
   docs/REMAINING_GAPS.md Sec 1), and a short human-factors note from WSTG Sec Human Factors
   where relevant.
7. N/A REQUIREMENTS - ASVS-style by-exception reporting: list checked requirements,
   exceptions, N/A with rationale, and resolution guidance; disclose testing methods and
   note repeatability.
8. AI ASSISTANCE DISCLOSURE - WSTG Sec 3.2 and bug-bounty Sec Designing a Program require
   checking program policy; add a report field stating AI-assisted testing was used and
   that a human reviewer must confirm before submission. Keep "local report only, no
   auto-submit" design constraint.

## 5. Gap inventory of the current 9-playbook implementation

| # | Gap | Evidence (current state) | Source anchor for fix | Priority |
| --- | --- | --- | --- | --- |
| G1 | Taxonomy too narrow: 9 custom IDs vs 12-13 WSTG categories; no Identity Mgmt, Error Handling, Weak Crypto, WebAssembly; API collapsed into one task | wstg_playbooks() | WSTG 4.0-4.13, 4.10, 4.12 | High |
| G2 | Knowledge base and planner disagree (12 vs 9); lookup is keyword+score only, no objectives/steps/verification | KNOWLEDGE_BASE + knowledge_lookup | WSTG test-case anatomy | High |
| G3 | Hypotheses are single sentences equal to task text; never transition from open; absent from report | add_hypothesis(id, statement); no production set_hypothesis_status; renderer has no hypothesis section | WSTG Sec Test Objectives; ASVS verification reporting | High |
| G4 | Coverage ledger is a target/method/path row count, not requirement-keyed; no N/A, status, level, or evidence links | coverage schema; coverage_count | ASVS Sec Levels, Sec Verification reporting, CSV/JSON | High |
| G5 | Verification oracle only covers reflected canary + 2xx; no differential/stateful/blind oracles; no per-hypothesis criteria | verify_findings | WSTG IDOR/BUSL controls; API1/3/4/6/7 | High |
| G6 | No ASVS or API Security Top 10 content anywhere in repo (grep: zero hits in *.md / *.rs) | repo-wide grep | ASVS 5.0; API Top 10 2023 | Medium-High |
| G7 | Report renderer drift vs docs/report-format.md (no OWASP field, severity table, Status, Evidence block, Coverage Result, Appendices A-E) | render_canonical_report vs template | WSTG Sec 5 Reporting; ASVS Sec Verification reporting | High |
| G8 | No reachability field; report-eligibility/qualifier lines are explicitly discarded by the brief parser | NON_ACTIONABLE list | WSTG bug-bounty Sec Reporting | Medium |
| G9 | No explicit human-AI accountability artifact / prompt-injection warning tied to tool output / AI-assistance disclosure | system prompt + verifier only | WSTG Sec 3.2 Human-AI; bug-bounty AI policies | Medium |
| G10 | No asset naming scheme (SWID/CPE/PURL) or stable requirement IDs for cross-run correlation | assets table has only kind/value | WSTG 5.2 Naming Schemes; ASVS versioned IDs | Low-Medium |
| G11 | Passive-to-active feedback loop absent: discovered access points do not generate new tasks/hypotheses | execution loop runs a fixed list once | WSTG Sec Passive Testing; Sec Testing Activities feedback | Medium |
| G12 | Business-logic/API6 tests conflict with ROE default (state changes denied) but no documented "how to test safely within ROE" path | ROE fail-closed; validate_poc filtered | WSTG bug-bounty Sec ROE; API6 mitigation layers | Medium |

## 6. Next steps for the parent session (research output only)

1. Promote the pinned commits into a research-provenance note in the repo docs (no code
   copy from the OWASP repos; respect their licenses - research/README.md).
2. Draft a playbook/hypothesis record schema with the fields in Sec 4.2 and a seeded
   catalog using WSTG test IDs, ASVS v5.0.0-<id> + L, and API<n>:2023 facets (Sec 4.1).
3. Design the coverage ledger as a versioned requirement matrix with N/A rationale and
   evidence links (Sec 4.3), independent of the existing access log.
4. Add per-hypothesis verification criteria and keep the deterministic canary oracle as
   the provenance floor, not the whole verdict (Sec 4.4).
5. Reconcile docs/report-format.md, render_canonical_report, and eval/score.py so the
   checked headings and required detail agree; add WSTG/ASVS report fields (Sec 4.5).
6. Re-run the canonical verification gate (PRODUCTION_PLAN.md Sec 4) after any code change;
   this document recommends, it does not change code.
