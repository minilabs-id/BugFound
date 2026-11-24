# Scope boundaries

This document separates behavior present in the code from behavior that is not
implemented. It is a scope description, not a maturity verdict. Check the call
sites in `PRODUCTION_PLAN.md` §3 when this document is read.

## 1. Not implemented

| Area | Current state | What an operator does instead |
| --- | --- | --- |
| Browser engine | No DOM renderer or JavaScript engine. Browser adapters are external CLI adapters and are off by default. | Use `http_request`, `http_probe` and `dns_lookup` on in-scope assets. |
| Distributed execution | Session state is local to one process. Claims, approvals and budgets are SQLite-backed; there is no cross-node placement or fencing. | Run one process on an isolated host. |
| Submission | No code path sends a report to a platform, email or third party. | Review the local report and submit it manually. |
| Performance benchmark | No latency, throughput or load measurement is shipped. | Record timings separately if needed. |
| Fuzz corpus | `http_fuzz` is a bounded tool with caps; no curated corpus is included. | Supply your own wordlists for a local lab. |
| Baseline comparison | No recorded baseline run exists in `eval/results/`. | Run a baseline lane on identical tasks before comparing. |

Related limits: there is no OS sandbox, prompt injection remains a design
concern, and API credentials are read from the environment.

## 2. Change log

The entries below record code changes. `PRODUCTION_PLAN.md` §3 maps each to a
call site and test.

| Change | Area | What changed in code |
| --- | --- | --- |
| B1 | Store / tools / core | `attach_capture` / `get_capture` persist raw bytes and canary; the verifier reads stored bytes. |
| B2 | Core | `clear_session_flag` removes stop flags on resume. |
| B3 | Store / core | `park_with_approval` groups approval, pending calls and state change in a transaction; `resolve_approval` checks expiry. |
| B4 | Tools | `ToolOptions.allowed_methods` is enforced by `HttpRequestTool`. |
| B5 | Tools / engagement | `validate_poc` is classified `network-write` and withheld when the ROE disallows state change. |
| B6 | Tools | `DnsLookupTool` honours `ToolOptions`; numeric host parsing rejects obfuscated addresses. |
| B7 | Tools | `trusted_local_targets` bypasses the syntactic local-name check; the resolved IP is still checked. |
| B8 | Tools | Proxy validation rejects `0.0.0.0`. |
| B9 | Tools | `recon_pipeline` revalidates targets and kills process trees on timeout. |
| B10 | Tools | External adapters apply scope to every URL placeholder. |
| B11 | Core | `task_put` / `clue_put` persist rows; `expire_stale_approvals()` runs at startup. |
| B12 | Core | Goal lock uses SHA-256 and an injection-detector expression. |
| B13 | Engagement / CLI / desktop | Trace events carry `run_id` and API token counts; config forwards tool/target lists and budget aliases. |
| B14 | Docs / eval | Golden manifest example, synthetic fixture, report-content check, trace exporter. |
| Scope prefixes | Engagement / policy / tools | Relative prefixes are anchored to the program apex before scope intersection. |
| Path exclusions | Policy / tools | Path-scoped out-of-scope rules apply to the named path, not to the bare host. |
| Oracle parity | Tools | `oracle_proof_gap` matches the confirm paths in the engagement verifier. |
