# Remaining gaps (honest scope, 2026-11-20)

This document separates **what the prototype does** from **what is deliberately
deferred** and **what was fixed in the B1–B14 remaining-gap pass**. It exists so
no reader has to infer maturity from an optimistic status line. Call sites and
tests for shipped features are in [`PRODUCTION_PLAN.md`](PRODUCTION_PLAN.md) §2;
the verification gate that must be re-run is §4 of that document.

## 1. Deferred product scope (not implemented, not advertised)

| Gap | Honest status | What an operator must do instead |
| --- | --- | --- |
| **Real browser** | There is no headless-browser engine, DOM renderer, or JavaScript execution. "Browser" adapters are external CLI adapters only, gated and unavailable by default. | Use the provided `http_*` / `dns_lookup` tools on in-scope assets; browser-driven findings are out of scope. |
| **Clustering / distributed sessions** | Session execution stays process-local. Claims, approvals and budget counters are SQLite-backed, but there is no cross-node placement, fencing, or exactly-once execution. | Run a single node on an isolated host/VM; do not scale out by pointing two processes at the same engagement. |
| **Live submission** | There is no submission path to HackerOne, Bugcrowd, Intigriti, email, or any third party. This is a design decision, not a pending feature. | Review and submit the local report yourself after operator confirmation. |
| **Performance benchmark** | No latency, throughput, or load benchmark is shipped. The eval harness records detection metrics only when an operator supplies ground truth and replay. | Do not quote any "faster/cheaper" claim; record your own timings if needed. |
| **Fuzz corpus** | No curated, versioned fuzz corpus or seed set is included. `http_fuzz` is a bounded, opt-in tool, not a maintained corpus. | Build and license your own wordlists/seed inputs for local testbeds. |
| **Baseline comparison** | The plain-agent baseline described in `docs/evaluation.md` §5 is a plan, not a recorded result. | Run the baseline yourself on identical tasks before claiming guardrail value. |

Related honest limits: no OS sandbox (isolate the host), prompt injection is
still a design-level threat, and API credentials must come from the environment.

## 2. Fixes landed in the B1–B14 pass

The IDs below follow `docs/B1_B14_FIX_PLAN.md`. They are fixes, not new product
scope; each must still be verified by the gate in `PRODUCTION_PLAN.md` §4.

| ID | Area | What changed |
| --- | --- | --- |
| B1 | Store / tools / core | Authoritative tool capture: `attach_capture` / `get_capture` persist raw request and response bytes plus canary; the verifier reads stored bytes instead of LLM-supplied fields. |
| B2 | Core | Stop flags are physically cleared with `clear_session_flag` on resume, so pause/resume cannot re-abort a session. |
| B3 | Store / core | `park_with_approval` makes approval + pending calls + parking one transaction; `resolve_approval` checks expiry. |
| B4 | Tools | `ToolOptions.allowed_methods` is implemented and enforced by `HttpRequestTool` (WS-TOOLS). |
| B5 | Tools / engagement | `validate_poc` is classified `network-write` and filtered out when the ROE disallows state change; it is not an authoritative acceptance gate. |
| B6 | Tools | `DnsLookupTool` honours `ToolOptions` (scope and blocked IPs) and a strict numeric host parser rejects hex/octal/decimal obfuscation. |
| B7 | Tools | `trusted_local_targets` bypasses only the syntactic block; the resolved IP is still verified. |
| B8 | Tools | Proxy handling rejects `0.0.0.0`. |
| B9 | Tools | `recon_pipeline` revalidates every target and kills adapter process trees. |
| B10 | Tools | External adapters enforce scope for every placeholder (including `{url}`), not just a subset. |
| B11 | Core | `task_put` / `clue_put` are persisted to tasks/clues; `expire_stale_approvals()` runs at startup. |
| B12 | Core | Goal lock uses SHA-256 plus an injection-detector regex. |
| B13 | Engagement / CLI / desktop | `run_start`, `finding`, `action`, `usage` and `verifier` trace events carry `run_id` and real API token counts; config forwards allowed/denied tools and targets plus budget aliases. |
| B14 | Docs / eval | Golden manifest example, offline synthetic example result, e2e report-content + `score.py --strict` checks, trace exporter joined into the replay, and doc mismatch cleanup. |

## 3. What is *not* changed by this pass

B1–B14 close the specific gaps enumerated above. They do not turn AgentBug into
an OS sandbox, add a browser, enable live submission, add clustering, or create
a benchmark result. `eval/` remains scaffolding: an operator must run real
engagements and record artifacts in `eval/results/`.

## 4. Verification

Run the gate in `PRODUCTION_PLAN.md` §4 (fmt, clippy, tests, release build,
`python -m py_compile eval/score.py`, `python eval/score.py --strict`, and the
Windows wiring scripts). Record the actual output; do not copy a test count from
a document. The current suite is 180+ tests, but the authoritative number is
whatever `cargo test --workspace` prints at verification time.
