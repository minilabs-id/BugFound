# ADR-V3-004 — WSTG/ASVS/CWE as a versioned technique catalog, not a workflow

- Status: **Proposed** (design gate)
- Date: 2026-11-26
- Related: ADR-V3-001, S13/S19/S22–S30, `03_...md` G8

## Context
`wstg_playbooks()` hard-codes nine playbooks and a static role map
(`engagement/lib.rs:3414-3453`, `roles.rs:42-48`). This makes WSTG an execution
order. OWASP explicitly warns against treating WSTG as a checklist and
recommends continuous re-prioritisation [S22]. Loading every technique/schema
up front is also expensive: tool definitions are billed as input tokens [S08],
and progressive disclosure cut one MCP workflow from 150k to 2k tokens [S19].

## Options
1. Keep hard-coded playbooks; tune prompts.
2. Load all standards into every prompt as a reference document.
3. Versioned technique catalog with metadata, deferred lookup and planner scoring.

## Decision
Option 3. Each catalog record: stable id, version, preconditions, inputs,
expected artifact, safe bounds, benefits/limitations, technique family, and
version-pinned mappings (`v5.0.0-…`, `2023-API1`, `2025-A05`, CWE version, CVSS
version). Phases are metadata for filtering, never execution order. Exposure is
in-process with tool search, or MCP if a separate boundary becomes necessary —
either way with deferred loading and schema validation.

## Reasons
- WSTG foreword and methodology support technique-based, continuously
  re-prioritised use [S22][S24].
- ASVS/API Top 10/OWASP Top 10/CWE provide machine-readable, versioned IDs [S26–S30].
- Tool search and code-mode patterns keep context small [S13][S19].

## Trade-offs
- Requires maintaining catalog data and versions.
- Planner must learn to select techniques from metadata — evaluate with M1/M3.
- MCP adds deployment complexity; defer unless reuse justifies it.

## Consequences / risks
- Catalog drift: pin versions in plans and findings; never silently upgrade.
- Tool-descriptor poisoning: treat catalog/tool annotations as untrusted [S15][S39].
- Removing a static playbook must not remove a capability — acceptance test in
  Phase P3.

## Status / gate
Proposed; Phase P3. Gate: coverage on fixtures unchanged while technique order
differs from the static baseline.
