# ADR-002: SQLite as Authoritative Store (PostgreSQL/pgvector Deferred)

- Status: Accepted (R1). Documentation-only; no code changes.
- Date: 2026-11-20
- Basis: research `12`, `14`, `15`, `16`; `docs/REMAINING_GAPS.md`

## Context

SQLite (WAL, bundled `rusqlite`) is the single source of truth for sessions,
messages, approvals, budgets, events, findings, coverage, hypotheses, evidence,
reports and `trace_events` (`docs/architecture.md:8,27-29`; `Cargo.toml:28`;
`config/agentbug.example.toml:47-48`). Deployment is single-host
(`docs/deployment.md:91,190-192,268`). PentAGI uses PostgreSQL+pgvector
(research `02_pentagi_analysis.md:14,144-161`).

## Problem

Decide whether to adopt PostgreSQL/pgvector now for relational richness,
vector search and future horizontal scale, or keep embedded SQLite and defer.

## Alternatives considered

1. PostgreSQL + pgvector now — rejected: external service, ops surface,
   contradicts single-node isolated-host deployment (`REMAINING_GAPS.md:14`).
2. **SQLite now + optional embeddings/provenance over SQLite — accepted.**
3. SQLite + separate vector service (Qdrant) — rejected: new dependency/license
   surface; research `15_dependency_analysis.md:20-27`.
4. SQLite authoritative + outbox to Postgres later — noted as future path.

## Recommendation

Keep SQLite as authoritative store. Document pgvector/Postgres as a deferred,
trigger-based migration. Not on the R1/R2 critical path.

## Technical justification

- research `12:56`: "Keep SQLite; add outbox/fence/plan revision patterns rather
  than replacing the store."
- research `15:22`: "Keep SQLite/rusqlite for now. ADR-002 decides
  PostgreSQL/pgvector later."
- research `16:37`: PostgreSQL/pgvector explicitly deferred.
- `REMAINING_GAPS.md:14`: clustering explicitly deferred; single node on
  isolated host — so the main argument for Postgres has no current consumer.
- research `03:131`: SqliteSaver is "a lightweight single-process
  implementation… fine for a local kernel."

## Trade-offs

- Pro: zero external service, single-file backup, bundled build, WAL durability,
  minimal dependency/license surface.
- Con: single-writer WAL, no native ANN index, no horizontal scale or
  multi-tenancy; semantic memory needs application-level similarity.

## Implementation consequences

Documentation only. Record the invariant any future store must preserve:
durable claims/leases, atomic approvals, event hash chain, evidence digests
(`store/src/lib.rs:1144-1240,2165-2210`). Semantic memory, when added, is
"optional embeddings over SQLite" unless this ADR is revisited.

## What would invalidate this decision

- Clustering/multi-node or concurrent writers.
- Multi-tenancy or hosted service needing isolation the embedded DB cannot give.
- A measured (benchmarked) need for large-scale similarity search.
- Compliance/operator requirement for a managed network-accessible database.
