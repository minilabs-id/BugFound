# 15 — Dependency Analysis

## Current AgentBug runtime dependencies

`anyhow`, `serde`, `serde_json`, `tokio`, `tracing`, `tracing-subscriber`, `reqwest`, `rusqlite`, `clap`, `toml`, `uuid`, `async-trait`, `futures`, `url`, `chrono`, `sha2`, `eframe`, `egui`, `base64`, `regex`.

## Reference dependency signals

| Reference | Stack signal | Relevance |
| --- | --- | --- |
| OpenCode | Effect TS, custom schema, provider abstractions | pattern-level only; do not import |
| PentAGI | Go, PostgreSQL+pgvector, Graphiti, Docker, VXControl forks | **avoid VXControl imports** (license) |
| Temporal | Go server + SDKs | pattern-level; reject server stack |
| LangGraph | Python graph runtime | vocabulary/pattern only |
| Goose | Rust | closest Rust peer; study Operation/cancellation |
| Rig | Rust | closest kernel peer; study effect/decider shape |
| Strix | Python, Caido proxy artifacts | pattern-level |
| CAI | Python, dual license | research-only; no code/prompt copy |

## Dependency decisions

- **Keep** SQLite/rusqlite for now. ADR-002 decides PostgreSQL/pgvector later.
- **Keep** reqwest; add no new HTTP stack.
- **Keep** tokio; prefer structured concurrency and cancellation tokens.
- **Add only with justification**: JSON Schema validation crate (tool schema boundary), tracing/OTel exporter (observability), embedding client (semantic memory, optional).
- **Reject** Graphiti, VXControl SDK, Langfuse dependency, Docker SDK for core.
- **Reject** UI framework changes; eframe/egui stays replaceable behind event bus.

## License gate

CI already runs `cargo deny check`. Add a policy note that `research/` clones are never vendored into distributions; restricted references (PentAGI VXControl, CAI proprietary, HackerOne/PortSwigger mirrors) are learning-only. See `10_license_audit.md`.
