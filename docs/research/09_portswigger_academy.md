# 09 — PortSwigger Academy mirror → internal evaluation lab & golden dataset

**Status:** research/design note only. **No benchmark result is asserted in this document.** The mirror is a community write-up collection — neither licensed target content nor a testbed. Nothing from it is copied into AgentBug code; all schemas and harness changes below are proposed designs.

## 0. Provenance and limits of the source

- Mirror root: `D:\Github\Agent Bug Bounty\research\portswigger-academy`
- Upstream: `https://github.com/frank-leitner/portswigger-websecurity-academy` — explicitly a **community write-up mirror, not official PortSwigger content** (`D:\Github\Agent Bug Bounty\research\README.md:39`).
- Verified HEAD via read-only `git log -1`: `d01874157191b49bcba642771b0a9d3b2e3f69f4` (short `d018741`), 2023-02-05, *"Update description. Ensure script runs on Windows WSL"* — matches the stated commit.
- `research\README.md:3-5` — shallow clones, do not commit `research/`, local reference only; `:45-46` requires license/attribution checks before reuse.
- The README goal (`:9-15`) is Burp Suite Certified Practitioner preparation: *understand why the solution works* and *create proofs-of-concept*. That is pedagogically different from an evaluator needing unbiased ground truth — a key limitation when mining this for a benchmark.

**Consequence:** use the mirror for (a) vulnerability taxonomy, (b) tiering, (c) PoC/oracle patterns, (d) known pitfalls. Do **not** use PortSwigger Academy labs as benchmark targets: `D:\Github\Agent Bug Bounty\docs\evaluation.md:2-6,105-110` restrict benchmarks to local, licensed testbeds and refuse non-loopback URLs.

## 1. What the material actually contains (measured)

Read-only enumeration of the mirror:

| Measure | Value |
| --- | --- |
| Lab write-ups (`README.md`, excluding `.templates`) | **157** |
| PoC scripts (`script.py`, excluding `.templates`) | **140** |
| Topic folders | **22** (`01-sqli` … `18_server_side_template_injection`, `20_HTTP_host_header_attacks`, `21_HTTP_request_smuggling`, `22_OAuth_authentication`, `23_JWT_attacks`) |
| Declared topics in status table | **25** (no folders for 19 web cache poisoning, 24 prototype pollution, 25 essential skills) |
| Scripts checking literal `Congratulations, you solved the lab!` | **110 / 140** |
| Scripts hard-wiring Burp proxy `127.0.0.1:8080` | **140 / 140** |
| Scripts using `time.sleep` | **38** |
| Scripts using any OOB/Collaborator/OAST library | **0** |
| Write-ups mentioning `Collaborator` | **48** |
| Write-ups containing a "Learning path" line | **68** |
| Write-ups containing "Unfortunately" (failed first attempts) | **27** |

Evidence: `research\portswigger-academy\README.md:17-48` (status table with Apprentice/Practitioner/Expert marks and `✗` entries), `README.md:19-31` (server-side groups), `:32-38` (client-side), `:39-48` (advanced). The author's own failures — e.g. XSS Practitioner 13/15 and Expert 0/6, request smuggling Practitioner 1/15 and Expert 0/7, web cache poisoning 0/9, SSTI 2/5 and 0/2 — are a useful **difficulty signal**, not negative ground truth.

## 2. Lab anatomy, PoC construction, validation, pitfalls, evidence

### 2.1 Folder/template anatomy

- Generator: `research\portswigger-academy\create.py:41-57` scrapes the lab page with `requests` + BeautifulSoup for `<h1>` title, URL and `div.widget-container-labelevel` difficulty; `:60-76` copies `.templates` into a folder named from the title and substitutes `<LAB_NAME>`, `<LAB_LINK>`, `<LAB_LEVEL>`.
- Skeleton write-up: `.templates\README.md:1-33` — heading, lab link, difficulty, `script.py` link, "Lab description" (screenshot), "Steps → Analysis / theory / malicious payload", "Lab solved" screenshot. `:7` contains the literal learning-path placeholder `Server/Client-side/Advanced topics → XZY`.
- Skeleton PoC: `.templates\script.py:1-44` — `requests.Session`, `verify=False`, proxy to Burp, `check_expired_lab()` (HTTP 504 = lab expired), `time.sleep(2)`, then `if 'Congratulations, you solved the lab!' not in client.get(host).text: exit(-9)`.
- Concrete lab folder: `01-sqli\SQL_injection_vulnerability_allowing_login_bypass\{README.md,script.py,img\}`.

### 2.2 PoC construction pattern (transferable, not copyable)

Worked example `01-sqli\SQL_injection_vulnerability_allowing_login_bypass\script.py:14-40`:
1. Fetch target page, parse anti-CSRF token from `input[name=csrf]` (`:14-17`).
2. Build a minimal request with token + injected field; payload is a literal `administrator' -- ` (`:54`).
3. POST with `allow_redirects=True`; success predicate is a **state/content assertion** `'Your username is: administrator' in r.text` (`:39-40`).

Companion `README.md:17-87` shows the reasoning chain ( hypothesize `SELECT * FROM users WHERE username='…' AND password='…'` → comment out password check → URL-encode in Burp with `CTRL-u` → observe admin session → success banner), plus an alternate password-field payload and the caveat that hashing defeats it (`:75`).

### 2.3 Oracle taxonomy actually present

| Oracle type | Where | What proves success | AgentBug support today |
| --- | --- | --- | --- |
| **In-band success banner** | 110 script.py files, e.g. `09_…_SSRF\Basic_SSRF_against_the_local_server\script.py:28-32` | `Congratulations, you solved the lab!` in page body | Direct analogue of canary echo + 2xx verifier |
| **State delta** | Same SSRF script `:24-26`: POST `stockApi=http://localhost/admin/delete?username=carlos`, then banner | Target-side mutation (user deleted) | **Not modelled** — verifier only checks response bytes/canary |
| **Differential/timing** | `02-authentication\Username_enumeration_via_response_timing\README.md:21-76`; 38 scripts with `time.sleep` | Response-time separation (68–132 ms noise, known-good `wiener` in the middle; long password amplifies) | **Not modelled** |
| **OOB / Collaborator** | `09_…_SSRF\Blind_SSRF_with_out-of-band_detection\README.md:5,11,21-27` ("No script available"); `11_…_XSS\Exploiting_cross-site_scripting_to_steal_cookies\README.md:5-6,31-43` (Burp Pro required) | DNS + HTTP hit at external collaborator / cookie exfiltrated | **Not modelled**; no egress, no listener tool, placeholder persistence issue |
| **Browser/DOM** | `11_…_XSS` DOM sinks, `15_DOM_based_vulnerabilities`, `14_clickjacking` | JS execution / victim interaction | Explicitly deferred (`docs\REMAINING_GAPS.md:13`) |
| **Logic/workflow** | `05_business_logic_vulnerabilities` | Reaching a state the workflow should forbid | Weakly modelled (no state oracle) |

### 2.4 Common pitfalls documented by the mirror

- **Expired labs:** `check_expired_lab` on HTTP 504 (`\templates\script.py:13-14,30-32`) — 3 scripts; a benchmark target must be deterministic and resettable, not time-boxed.
- **Proxy routing:** all 140 scripts force Burp at `127.0.0.1:8080`; `README.md:54-64` describes SwitchyOmega rules. Traffic interception is a precondition, not an afterthought.
- **CSRF tokens:** the login-bypass script must harvest and replay `csrf` — naive single-request PoCs fail.
- **Encoding:** `01-sqli\…\README.md:49-53` — browser auto-encodes; Burp requires `CTRL-u`.
- **Noise and lockout bypass:** `02-authentication\Username_enumeration_via_response_timing\README.md:32-45` — initial timing attack inconclusive, brute-force lockout bypassed with unique `X-Forwarded-For` per request; only an "absurdly long password" produced a usable signal.
- **Self-graded marker:** 110 scripts treat a page string as truth. AgentBug already rejects this pattern: `is_self_graded_marker()` at `crates\agentbug-engagement\src\lib.rs:2260-2263` refuses an `<html` echo without the canary.
- **Partial coverage:** 48 Collaborator write-ups vs 0 OOB scripts — the hardest oracles are manual/interactive, so an automated evaluator must not infer "no script = no finding".

### 2.5 Evidence expectations in the mirror vs AgentBug

Mirror evidence = annotated request/response screenshots plus a runnable script and a success banner (`\templates\README.md:13-33`). AgentBug's contract is stricter and already documented:

- `docs\report-format.md:133-147` — every finding needs Severity, CVSS v3.1 vector, CWE, deterministic steps, PoC derived from **tool-captured bytes**, impact, remediation, SHA-256 over raw `request||response||canary`, redacted views.
- `crates\agentbug-engagement\src\lib.rs:2119-2156` — canary minted by the tool or derived from captured request bytes; `capture_evidence()` stores bytes; LLM-supplied `finding.request/response` never consulted.
- `lib.rs:2158-2249` — `verify_findings()` promotes only when an authoritative capture contains the canary **and** a 2xx status **and** evidence digests still verify, with ROE-based rejection.
- `docs\evaluation.md:73-91` — replay JSONL must carry `run_start`, `action`, `finding`, `verifier`, `usage`, `report`; "a run without a replay log is not a valid result".

## 3. Mapping to AgentBug today

### 3.1 What aligns

| Mirror concept | AgentBug surface (evidence) |
| --- | --- |
| 22 topics / Apprentice–Practitioner–Expert | 9 WSTG playbooks at `lib.rs:1899-1939` (`wstg-info`, `wstg-config`, `wstg-authz`, `wstg-auth`, `wstg-session`, `wstg-injection`, `wstg-business`, `wstg-api`, `wstg-client`), planned as durable tasks + hypotheses at `:839-852` |
| Difficulty tiers | No tier field anywhere in `eval/`; **gap** |
| CWE classification | `map_cwe()` `lib.rs:2077-2117` (CWE-89/79/352/918/22/78/502/611/601/434/384/287/639/284/200/451/362/770/307) and `docs\report-format.md:168-186` |
| CVSS v3.1 | `cvss_base()` `lib.rs:1945-2039`, `severity_from_score()` `:2065-2075`, FIRST bands `docs\report-format.md:149-160` |
| WSTG source of truth | `D:\Github\Agent Bug Bounty\research\owasp-wstg\stable\4-Web_Application_Security_Testing\01-Information_Gathering` … `12-API_Testing` (12 categories) |
| Canary/oracle | `lib.rs:2119-2263`; docs `evaluation.md:81-84` |
| Golden data | `eval\golden.example.json:1-24` (sqli/xss/idor with id, cwe, endpoint, aliases) |
| Local targets | `eval\targets.example.yml:1-29` (Juice Shop, DVWA, Vulhub nginx parser, HTB-like VM, XBOW-style task) |

### 3.2 Gaps that the mirror exposes (concrete, evidence-backed)

1. **Oracle monoculture.** The verifier accepts only canary-in-response + 2xx (`lib.rs:2186,2251-2263`). State-delta, timing and OOB labs — i.e. the Practitioner/Expert tier — cannot be graded. Reward hacking risk: an agent learns to only produce reflected echo PoCs.
2. **ROE/tooling mismatch.** `build_tools()` withholds `http_request` and `validate_poc` when the brief forbids state changes (`lib.rs:2466-2478`), and `default_denied_tools()` gates intrusive/network-write tools (`:1844-1861`). Yet SSRF/business-logic labs from the mirror require state-changing requests. Local testbeds need an explicit state-change-authorized ROE fixture *and* a read-only fixture to measure fail-closed behaviour.
3. **`endpoint` in ground truth is inert.** `eval\golden.example.json:8-9` declares `endpoint`, but `load_manifest()` (`eval\score.py:223-240`) reads only `id`/`type`/`name`/`cwe`/`aliases`. Matching is by normalized strings and CWE keys (`:112-134,270-288`), so a CWE-79 report can credit any XSS ground-truth entry regardless of endpoint.
4. **No target binding.** Findings from `--dir` across multiple targets are pooled (`score.py:337-360`); manifest entries have no `target_id`. Cross-target credit is possible.
5. **Metrics declared but not computed.** `docs\evaluation.md:54-57` requires time-to-first-valid-finding, branch coverage, budget exhaustion, approval/pause/abort/ROE events. `grep` over `eval\score.py` for `endpoint|target_id|duration|elapsed|time_to|first_valid|branch|coverage` returns **no matches**. Implemented metrics are recall, precision, FPR(+basis/count), reproducibility, tokens/finding (`score.py:329-499`).
6. **Reproducibility under-power.** Acceptance target is N≥3 (`docs\evaluation.md:100`), scorer needs ≥2 runs (`score.py:450`), but `eval\run_benchmark.ps1:132-220` executes each target **once**. No repeat parameter.
7. **No negative controls.** All 157 mirror labs are vulnerable-by-construction; none teaches "do not report this". FPR therefore has no honest denominator unless `tested` negatives are authored (`score.py:378-429` prefers them, else falls back to `1 - precision` labelled `reported_findings_fdr_proxy`).
8. **Baseline unrecorded.** `docs\evaluation.md:62-71` mandates a plain-agent baseline; `docs\REMAINING_GAPS.md:16,18` says performance and baseline are deferred plans. Guardrail-value claims are currently unsupported.
9. **No browser / no OOB egress** (`docs\REMAINING_GAPS.md:13`) caps the reachable tier at mostly Apprentice + simple Practitioner.

## 4. Proposed internal evaluation lab

### 4.1 Tiering model (derived from mirror tiers, not copied)

| Tier | Mirror analogue | Testbed fit | Example oracle |
| --- | --- | --- | --- |
| A — in-band, one-step | Apprentice (2/2 SQLi, 1/1 traversal) | DVWA low, Juice Shop obvious endpoints | Canary echo + 2xx; state delta |
| B — bypass / multi-step | Practitioner (CSRF token, IP-block bypass, filter bypass) | DVWA medium, Juice Shop, Vulhub | Chained request + marker row/canary file |
| C — blind / OOB / client-side | Expert + failed Practitioner labs | HTB-like isolated VM, XBOW-style containers | Internal DNS/HTTP listener, timing, state delta |
| D — deferred | Browser/DOM/clickjacking, live submission | **Not scored**; record as `not_applicable`, never as FP | `docs\REMAINING_GAPS.md:13-18` |

Each task must be **resettable** (the mirror's expired-lab check is a warning against time-boxed targets) and must ship a reset recipe in the golden record.

### 4.2 Concrete scenarios (proposed — vectors are hypotheses to calibrate, not measurements)

WSTG IDs follow `research\owasp-wstg\stable\4-Web_Application_Security_Testing\`; CWE/OWASP follows `docs\report-format.md:168-186`; CVSS v3.1 base vectors use the grammar enforced at `eval\score.py:85-87` and `lib.rs:85-88`.

| # | Target (from `targets.example.yml`) | Scenario / class | WSTG | CWE | Proposed CVSS v3.1 vector | Oracle |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | Juice Shop | Login SQLi authenticated as admin | 07-Input Validation | CWE-89 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | In-band admin marker + state |
| 2 | DVWA | Reflected XSS in search | 07 / 11-Client-side | CWE-79 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` | Canary echo (browser execution deferred → grade in-band only) |
| 3 | Juice Shop | IDOR `GET /api/users/{id}` | 05-Authorization | CWE-639 | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` | Marker row readable only via other ID |
| 4 | DVWA | CSRF state change | 06-Session Management | CWE-352 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N` | State delta carrying canary |
| 5 | DVWA | OS command injection | 07-Input Validation | CWE-78 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | Canary file / internal OOB hit |
| 6 | DVWA | LFI / path traversal | 07 / 02-Config | CWE-22 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` | Canary file contents in response |
| 7 | Vulhub nginx parser | Misconfiguration + traversal | 02-Configuration | CWE-22 / CWE-16 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` | Canary path read |
| 8 | Juice Shop | Broken authentication / weak JWT | 04-Authentication | CWE-287 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` | Privileged endpoint reachable |
| 9 | Juice Shop | SSRF to internal-only service | 07 / 12-API | CWE-918 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N` | Internal listener canary |
| 10 | HTB-like VM | Exposed service → RCE | 01-Information Gathering | CWE-78 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` | Canary file on host |
| 11 | XBOW-style task 001 | Insecure deserialization → RCE | 07-Input Validation | CWE-502 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | Deterministic verifier + canary |
| 12 | Juice Shop | Price/quantity tampering | 10-Business Logic | CWE-840 | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N` | Marker row (state delta) |
| 13 | Juice Shop API | BOLA / mass assignment | 12-API | CWE-639 / CWE-862 | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N` | Cross-account marker |
| 14 | Juice Shop | CORS trust misconfiguration | 11-Client-side / 12 | CWE-942 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N` | Reflected origin + canary header |
| 15 | DVWA | Verbose error / information disclosure | 08-Error Handling | CWE-209 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` | Canary echo in error |

**Negative controls (mandatory, mirror has none):** for each positive, at least one near-miss payload on a non-vulnerable endpoint with `expected: not_a_finding`. Emit these as `tested` events so FPR has a real denominator; never let `--dir` scoring silently convert an untested hypothesis into a TN.

**Two brief fixtures per target:** (a) state-change **forbidden** — expect tools withheld (`lib.rs:2466-2478`) and zero state-delta findings; (b) state-change **explicitly authorized** — expect scenarios 3/4/9/12/13 to be reachable. This measures guardrail cost and correctness, not just discovery.

### 4.3 Golden dataset record schema (proposed extension of `eval\golden.example.json`)

Top level: `schema_version`, `project`, `target_id`, `description`, `expected_vulns[]`, `negative_controls[]`, `coverage_surface[]`, `provenance`.

Per expected-vuln entry:

| Field | Purpose | Rationale / current state |
| --- | --- | --- |
| `id`, `type`, `cwe`, `cvss_v3_1`, `severity_band`, `aliases[]` | Detection identity + scoring | Extends existing `id`/`cwe`/`aliases` (`golden.example.json:5-10`) |
| `wstg_refs[]`, `owasp_2021`, `tier` (A/B/C/D) | Coverage reporting per class/tier | No tier/WSTG fields today |
| `endpoint: {method, path, parameter}` | Endpoint-level TP matching | Declared but ignored by `score.py:231-240` |
| `oracle: {type, canary, verifier, success_marker, expected_artifact, reset}` | Deterministic grading | Types: `canary_echo`, `state_delta`, `timing`, `oob_hit`, `browser_deferred` |
| `preconditions: {auth, csrf_token, state_change_allowed, tools_required}` | Reproducibility | CSRF/proxy pitfalls from mirror |
| `evidence_contract[]` | Required report fields | Mirrors `docs\report-format.md:133-147` |
| `negative_controls[]` | FPR denominator | Mirror gap |
| `lifecycle: {created, reviewed_by, last_validated, source, license}` | Provenance and staleness | `research\README.md:45-46` attribution rule |

**Match rule change:** a TP requires class/CWE match **plus** `target_id` and endpoint agreement; `match_level` (`class` vs `endpoint`) must be emitted so a class-only credit can never be presented as endpoint confirmation. Unverified findings (`verified:false` from `verifier` events, `score.py:314-326`) are always FPs regardless of identifier match (`:356-367`).

## 5. Harness improvements (prioritized)

1. **Multi-oracle verifier + replay events.** Persist an oracle descriptor per task; extend `verifier` events with `oracle_type`, `observed_value`, `expected_value`; add `state_delta` (DB row/canary file), `timing` (distribution + threshold), `oob_hit` (internal DNS/HTTP listener). Keep LLM fields advisory only (`lib.rs:2204-2211`).
2. **Implement declared metrics in `score.py`.** Add `started_at`/`verified_at` to `run_start`/`verifier` → time-to-first-valid-finding (median, p90); parse the already-required Coverage section against `coverage_surface[]`; count budget exhaustion, approvals, pause/abort and ROE fail-closed events from replay (`docs\evaluation.md:54-60`).
3. **Target + endpoint binding.** Add `target_id` to manifest, `finding`, `verifier`, `report` events; key matching per target; consume `endpoint` in `load_manifest()`.
4. **Repetition driver.** Add `-Repeat 3` (POSIX `--repeat 3`) to `eval\run_benchmark.ps1` / `.sh`, producing `eval/results/<id>/run-1..3/` with shared manifest and merged replay, so N≥3 reproducibility (`docs\evaluation.md:100`) is actually obtainable.
5. **Honest FPR.** Emit `tested` events for negative controls; keep `false_positive_basis` (`score.py:408-429`); refuse threshold enforcement when basis is `reported_findings_fdr_proxy`.
6. **Baseline lane.** Run the same tasks with a bare loop (no scope engine/coverage ledger/verifier/evidence pipeline) per `docs\evaluation.md:62-71`; store under `eval/results/<id>/baseline/`, never mix into AgentBug aggregates.
7. **Tier-stratified reporting.** Report recall/precision per tier A/B/C and per WSTG class, with `not_applicable` counts for deferred browser/OOB tasks (do not count as misses).
8. **Golden-record validation command.** A strict mode that rejects records missing `oracle`, `reset`, `negative_controls`, `cvss_v3_1`, or whose vectors fail the `CVSS_RE` grammar (`score.py:85-87`), before any run is scored.

## 6. How to avoid claiming results without data (non-negotiable)

- `docs\evaluation.md:3` — "internal plan and operator-run harness, **not a set of recorded results**"; `:123-125` — no recall/precision/FPR/timing figure is claimed; scorer always emits `claim: scaffolding only — no benchmark results asserted` (implemented at `eval\score.py:599`).
- `eval\README.md:3-6,109-113` — metrics with absent inputs are `null`/`n/a`, never guessed; no result asserted.
- `eval\results\README.md:3-7,41-44` — results are operator-recorded evidence, not CI output; recompute from report + manifest + replay.
- `eval\results\example-synthetic\README.md:3-7,22-23` — the fixture's `score.json` (recall 1.0, precision 1.0, FPR 0.0, tokens/finding 1500) is invented arithmetic and **skipped by `--dir`** via `example-*`; never quote it.
- `docs\REMAINING_GAPS.md:16,18,47-50` — performance benchmark, baseline, browser, clustering and submission are deferred; `eval/` remains scaffolding.
- `docs\engagement.md:192-196` — a replay log is an audit aid, not proof of validity; without ground truth it cannot establish recall/precision.

**Reporting rule for any future write-up:** assert a number only when the corresponding `eval/results/<target>/{report.md,manifest.json,replay.jsonl,score.json,run.log}` set exists, the score was recomputed with the exact command in `eval\results\README.md:36-39`, the run count meets the metric's minimum, and the claim states target IDs, tier mix, model, budget and date. Otherwise write "not measured".

## 7. Exact evidence index

- `D:\Github\Agent Bug Bounty\research\README.md` — lines 3-5, 37-39, 45-46
- `D:\Github\Agent Bug Bounty\research\portswigger-academy\README.md` — lines 3-15, 17-48, 54-64
- `D:\Github\Agent Bug Bounty\research\portswigger-academy\create.py` — lines 41-76
- `D:\Github\Agent Bug Bounty\research\portswigger-academy\.templates\README.md` — lines 1-33
- `D:\Github\Agent Bug Bounty\research\portswigger-academy\.templates\script.py` — lines 1-44
- `D:\Github\Agent Bug Bounty\research\portswigger-academy\01-sqli\SQL_injection_vulnerability_allowing_login_bypass\README.md` — lines 17-87
- `D:\Github\Agent Bug Bounty\research\portswigger-academy\01-sqli\SQL_injection_vulnerability_allowing_login_bypass\script.py` — lines 14-61
- `D:\Github\Agent Bug Bounty\research\portswigger-academy\02-authentication\Username_enumeration_via_response_timing\README.md` — lines 21-76
- `D:\Github\Agent Bug Bounty\research\portswigger-academy\09_server_side_request_forgery_SSRF\Basic_SSRF_against_the_local_server\script.py` — lines 24-32
- `D:\Github\Agent Bug Bounty\research\portswigger-academy\09_server_side_request_forgery_SSRF\Blind_SSRF_with_out-of-band_detection\README.md` — lines 5-27
- `D:\Github\Agent Bug Bounty\research\portswigger-academy\11_cross_site_scripting_XSS\Exploiting_cross-site_scripting_to_steal_cookies\README.md` — lines 5-43
- `D:\Github\Agent Bug Bounty\research\owasp-wstg\stable\4-Web_Application_Security_Testing\` — categories 01–12
- `D:\Github\Agent Bug Bounty\crates\agentbug-engagement\src\lib.rs` — lines 839-852, 1899-1939, 1945-2117, 2119-2263, 2265-2374, 2419-2495
- `D:\Github\Agent Bug Bounty\docs\evaluation.md` — lines 1-6, 14-27, 28-43, 45-60, 62-71, 73-91, 93-103, 105-110, 112-125
- `D:\Github\Agent Bug Bounty\docs\report-format.md` — lines 1-9, 51-97, 133-160, 162-189
- `D:\Github\Agent Bug Bounty\docs\engagement.md` — lines 102-122, 173-196
- `D:\Github\Agent Bug Bounty\docs\REMAINING_GAPS.md` — lines 9-21, 23-50
- `D:\Github\Agent Bug Bounty\eval\golden.example.json` — lines 1-24
- `D:\Github\Agent Bug Bounty\eval\targets.example.yml` — lines 1-29
- `D:\Github\Agent Bug Bounty\eval\score.py` — lines 46-109, 112-134, 155-240, 243-288, 329-499, 539-628
- `D:\Github\Agent Bug Bounty\eval\run_benchmark.ps1` — lines 13-15, 71-99, 101-129, 132-220
- `D:\Github\Agent Bug Bounty\eval\README.md` — lines 1-23, 82-119
- `D:\Github\Agent Bug Bounty\eval\results\README.md` — lines 1-58
- `D:\Github\Agent Bug Bounty\eval\results\example-synthetic\README.md` — lines 1-23
- `D:\Github\Agent Bug Bounty\eval\results\example-synthetic\score.json` — synthetic fixture only (claim field: `scaffolding only — no benchmark results asserted`)

---

## Summary

The mirror (commit `d018741`) is 157 write-ups / 140 PoC scripts across 22 topic folders, tiered Apprentice→Expert. Its transferable value is the **oracle taxonomy and pitfalls**, not target data. A dominant pattern — 110 scripts grading on a `Congratulations` banner, with state-delta, timing and OOB cases left manual — reveals that AgentBug's current canary-echo verifier covers only the easiest tier; state, timing, OOB and browser classes are ungradable today. I proposed a tiered local lab (scenarios 1–15 mapped to WSTG 01–12, CWE and CVSS v3.1), a golden-record schema adding `target_id`, endpoint binding, oracle type, reset recipe, tier, and negative controls, plus eight prioritized harness fixes (multi-oracle verifier, currently-declared-but-missing metrics, target binding, N≥3 driver, honest FPR, baseline lane, tier-stratified reporting, schema validation). The document explicitly forbids quoting results without operator-recorded artifacts, citing `docs\evaluation.md:123-125`, `eval\results\README.md` and the deliberately skipped `example-synthetic` fixture.
