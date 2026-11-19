# MiniBug Standard Report Format

Every engagement report conforms to this canonical template. The local report is a
draft for human review — MiniBug never submits it (see `docs/engagement.md`).

## Template

Copy this template verbatim; keep the section order and headings. Replace bracketed
placeholders. The heading names matter: `eval/score.py` checks for them.

~~~markdown
# MiniBug Engagement Report

- Engagement ID: <id>
- Program URL: <program-url>
- Generated (UTC): <YYYY-MM-DDTHH:MM:SSZ>
- Model: <provider/model>
- Run mode: <ask | full_auto>
- Report status: <draft — operator review required>

## Executive Summary

<2–4 sentences: what was authorized, what was tested, how many findings by severity,
and the overall risk posture. State explicitly that findings are unverified until a
deterministic verifier and operator review confirm them.>

| Severity | Count |
| --- | --- |
| Critical | <n> |
| High | <n> |
| Medium | <n> |
| Low | <n> |
| None / Informational | <n> |

## Scope & ROE

- Program: <name>
- Authorized targets: <in-scope hosts, apps, IP ranges>
- Excluded targets: <out-of-scope assets>
- ROE source: <program URL / imported brief>, snapshot <brief_snapshot_id>
- ROE constraints honored: <rate limits, prohibited techniques, timing windows>
- Fail-closed decisions: <targets refused because scope/ROE was absent or ambiguous>

## Methodology

<Describe the approach: passive recon, in-scope enumeration, hypothesis-driven
testing, safe validation/PoC only, deterministic verification. List tool classes used
(e.g. http_request, dns_lookup, save_artifact) and note that intrusive tools were
gated or not used. Reference the playbooks/hypotheses where relevant.>

## Findings

### F-001 — <concise title>

- Severity: <Critical | High | Medium | Low | None>
- CVSS v3.1 Base Score: <0.0–10.0>
- CVSS v3.1 Vector: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
- CWE: <CWE-XXX — Name>
- OWASP: <A0X — Category>
- Affected asset: <host / endpoint / parameter>
- Status: <candidate | verified | operator-confirmed>

**Steps to reproduce**

1. <numbered, deterministic step>
2. <numbered, deterministic step>
3. <observed result>

**Proof of concept**

`<request / payload / minimal script — secrets redacted>`

**Impact**

<What an attacker achieves; confidentiality/integrity/availability consequences.>

**Remediation**

<Concrete, prioritized fix and verification step.>

**Evidence**

- SHA-256: `<64 hex chars>`
- Artifact path: `<relative path under --cwd>`
- Request: `<redacted request>`
- Response: `<redacted response>`

<Repeat one `### F-00N` block per finding.>

## Coverage

| Target | Method | Paths / actions exercised | Result |
| --- | --- | --- | --- |
| <target> | <method> | <paths> | <covered / blocked / skipped: reason> |

## Timeline

- <YYYY-MM-DDTHH:MM:SSZ> [<event.kind>] <redacted event message>
- <YYYY-MM-DDTHH:MM:SSZ> [<event.kind>] <redacted event message>

## Appendices

### Appendix A — Asset inventory

- <kind> = <redacted value>

### Appendix B — Artifact index

- <kind> <relative path> (sha256: <hash>)

### Appendix C — Hypotheses

- [<status>] <hypothesis statement>

### Appendix D — Glossary

- CVSS, CWE, OWASP, PoC, ROE: <short definitions>

### Appendix E — Reproduction command

`minibug engage --url <program-url> --cwd <engagement-dir>`
~~~

## Finding field contract

Each `### F-...` block **must** contain all of the following. `score.py` flags missing
fields:

| Field | Rule |
| --- | --- |
| Severity | One of `Critical`, `High`, `Medium`, `Low`, `None`. |
| CVSS v3.1 Vector | Base metrics only: `CVSS:3.1/AV:/AC:/PR:/UI:/S:/C:/I:/A:`. Use temporal/environmental metrics only if explicitly labeled as such. |
| CWE | `CWE-<number>` plus a short name. Choose the most specific applicable CWE. |
| Steps to reproduce | Numbered, deterministic, no secrets. |
| PoC | Minimal reproducible payload/request. |
| Impact | Concrete security consequence, not a generic claim. |
| Remediation | Actionable fix plus a re-test step. |
| Evidence hash | SHA-256 over the raw captured evidence bytes, stored as a separate artifact; report the redacted view. Redaction must never alter the meaning of the proof. |

## CVSS v3.1 severity bands (FIRST)

| Rating | Base score range |
| --- | --- |
| None | 0.0 |
| Low | 0.1 – 3.9 |
| Medium | 4.0 – 6.9 |
| High | 7.0 – 8.9 |
| Critical | 9.0 – 10.0 |

Source: FIRST — Common Vulnerability Scoring System v3.1 specification. The severity
label in a finding must agree with the base score computed from its vector.

## CWE / OWASP mapping guidance

Use CWE for the technical weakness and OWASP Top 10 (2021) for the risk category.
Pick the **most specific** CWE that fits the root cause; if several apply, list the
primary CWE in the `CWE:` field and secondary ones in impact/remediation.

| Common class | Primary CWE | OWASP Top 10 2021 |
| --- | --- | --- |
| SQL injection | CWE-89 | A03 Injection |
| Cross-site scripting (XSS) | CWE-79 | A03 Injection |
| Command / OS injection (RCE) | CWE-78 | A03 Injection |
| IDOR / direct object reference | CWE-639 | A01 Broken Access Control |
| Missing / broken authorization | CWE-862 / CWE-863 | A01 Broken Access Control |
| Path traversal | CWE-22 | A01 Broken Access Control |
| Open redirect | CWE-601 | A01 Broken Access Control (no dedicated 2021 category; was A10 in 2017) |
| CSRF | CWE-352 | A01 Broken Access Control |
| SSRF | CWE-918 | A10 Server Side Request Forgery |
| Authentication bypass | CWE-287 | A07 Identification and Authentication Failures |
| Weak credential handling | CWE-521 / CWE-798 | A07 Identification and Authentication Failures |
| Sensitive data exposure | CWE-200 / CWE-312 | A02 Cryptographic Failures |
| Security misconfiguration | CWE-16 / CWE-1188 | A05 Security Misconfiguration |
| Vulnerable / outdated component | CWE-1104 | A06 Vulnerable and Outdated Components |
| Missing rate limit / resource exhaustion | CWE-770 | A04 Insecure Design |
| Business-logic flaw | CWE-840 | A04 Insecure Design |
| Deserialization | CWE-502 | A08 Software and Data Integrity Failures |

When a finding does not map cleanly, keep the CWE and mark OWASP as `N/A — no 2021
category`; do not force a misleading category.
