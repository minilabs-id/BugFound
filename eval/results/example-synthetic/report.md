# BugFound Engagement Report — SYNTHETIC EXAMPLE

- Engagement ID: example-synthetic
- Program URL: http://127.0.0.1:8080/ (invented local testbed)
- Generated (UTC): 2026-11-20T00:00:00Z
- Model: synthetic-fixture
- Run mode: full_auto
- Report status: SYNTHETIC FIXTURE — not a real engagement, not a benchmark result

## Executive Summary

This report is an offline documentation fixture with one invented reflected-XSS
finding. It demonstrates the canonical section layout and the fields that
`eval/score.py --strict` checks. No real target was tested and no finding here
is valid. An operator must run a real engagement and record the artifacts under
`eval/results/` before any detection metric can be discussed.

| Severity | Count |
| --- | --- |
| Critical | 0 |
| High | 0 |
| Medium | 1 |
| Low | 0 |
| None / Informational | 0 |

## Scope & ROE

- Program: Synthetic Local Testbed (invented)
- Authorized targets: 127.0.0.1:8080 (invented)
- Excluded targets: all others
- ROE source: invented brief, snapshot synthetic-snapshot
- ROE constraints honored: rate limit 10 rps, no state-changing requests
- Fail-closed decisions: none (synthetic fixture)

## Methodology

Passive enumeration of an invented loopback endpoint, one deterministic probe,
and a recorded proof-of-concept. Captured request and response bytes are stored
as artifacts; the verifier replays those bytes against a canary oracle. No real
tool execution occurred in the generation of this fixture.

## Findings

### F-001 — Reflected query parameter echoed without encoding

- Severity: Medium
- CVSS v3.1 Base Score: 6.1
- CVSS v3.1 Vector: `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N`
- CWE: CWE-79 — Improper Neutralization of Input During Web Page Generation
- OWASP: A03 Injection
- Affected asset: http://127.0.0.1:8080/search (invented)
- Status: candidate (synthetic; not verified against a real target)

**Steps to reproduce**

1. Send `GET /search?q=%3Cb%3Efixture%3C%2Fb%3E` to the invented endpoint.
2. Observe the decoded marker in the HTML response body.
3. Record the raw request and response bytes as the evidence artifact.

**Proof of concept**

`GET /search?q=%3Cb%3Efixture%3C%2Fb%3E HTTP/1.1` — the marker is reflected
verbatim. This payload is illustrative; the fixture stores no real HTTP bytes.

**Impact**

In a real application an unencoded reflected parameter can lead to script
execution in a victim's browser. No real impact exists in this fixture.

**Remediation**

Context-aware output encoding and a restrictive Content-Security-Policy; re-test
by replaying the stored request bytes and checking that the marker is escaped.

**Evidence**

- SHA-256: 1111111111111111111111111111111111111111111111111111111111111111
- Artifact path: `evidence/f-001-request-response.bin`
- Request: `<redacted synthetic request>`
- Response: `<redacted synthetic response>`

## Coverage

| Target | Method | Paths / actions exercised | Result |
| --- | --- | --- | --- |
| 127.0.0.1:8080 | synthetic probe | /search | covered (invented) |

## Timeline

- 2026-11-20T00:00:00Z [run_start] synthetic run began
- 2026-11-20T00:00:01Z [finding] invented finding recorded

## Appendices

### Appendix A — Asset inventory

- host = 127.0.0.1:8080 (invented)

### Appendix B — Artifact index

- request/response `evidence/f-001-request-response.bin` (sha256: 1111111111111111111111111111111111111111111111111111111111111111)

### Appendix C — Hypotheses

- [tested-rejected] open redirect ( invented negative )

### Appendix D — Glossary

- PoC, CWE, CVSS, ROE: see `docs/report-format.md`.

### Appendix E — Reproduction command

`bugfound engage --url http://127.0.0.1:8080/ --cwd <engagement-dir>` (not run
for this fixture).
