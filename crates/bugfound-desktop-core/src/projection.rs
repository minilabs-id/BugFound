//! The only path from the store to the webview. Every string that can contain
//! user or tool data is redacted here, on the Rust side, before serialization.

use crate::config::AppConfig;
use crate::dto::{AppSnapshot, BudgetSnapshot, SessionSummary, SettingsSnapshot};
use bugfound_store::{redact, Store};

/// Maximum sessions sent in the initial snapshot. The full history is loaded
/// on demand by `session.history` in a later phase.
const INITIAL_SESSION_LIMIT: usize = 50;

pub fn app_snapshot(store: &Store, config: &AppConfig) -> anyhow::Result<AppSnapshot> {
    let sessions = store
        .list_sessions(INITIAL_SESSION_LIMIT)?
        .into_iter()
        .map(|session| SessionSummary {
            id: session.id,
            title: truncate(&redact(&session.goal), 80),
            state: session.state,
            model: session.model.map(|m| redact(&m)),
            created_at: session.created_at,
            updated_at: session.updated_at,
        })
        .collect();

    let budgets = config.effective_budgets();
    let settings = SettingsSnapshot {
        mode: config.agent.mode.clone(),
        // The workspace is an operator-controlled local path; redact anyway so
        // an accidentally pasted secret cannot leak into the renderer.
        workspace: redact(&workspace_from_config(config)),
        base_url_configured: !config.llm.base_url.trim().is_empty(),
        api_key_source: api_key_source(&config.llm.api_key),
        default_model: config.llm.default_model.as_ref().map(|m| redact(m)),
        storage_path: redact(&config.storage.path),
        budgets: BudgetSnapshot {
            max_steps: budgets.max_steps,
            max_tool_calls: budgets.max_tool_calls,
            max_network_calls: budgets.max_network_calls,
            requests_per_minute: budgets.requests_per_minute,
            max_tokens: budgets.max_tokens,
        },
    };

    Ok(AppSnapshot {
        product: "BugFound".into(),
        version: env!("CARGO_PKG_VERSION").into(),
        status: "ready".into(),
        startup_warnings: Vec::new(),
        sessions,
        settings,
    })
}

/// Workspace is not part of `AppConfig`; it lives in UI state until Phase 5
/// moves it into config. Keep the default here so `app.ready` is stable.
fn workspace_from_config(_config: &AppConfig) -> String {
    ".".into()
}

fn api_key_source(raw: &str) -> String {
    let raw = raw.trim();
    if raw.is_empty() {
        "missing".into()
    } else if raw.starts_with("env:") {
        "env".into()
    } else {
        "literal".into()
    }
}

fn truncate(text: &str, max_chars: usize) -> String {
    if text.chars().count() <= max_chars {
        return text.to_string();
    }
    let mut out: String = text.chars().take(max_chars.saturating_sub(1)).collect();
    out.push('…');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_key_source_never_returns_the_value() {
        assert_eq!(api_key_source("sk-live-1234"), "literal");
        assert_eq!(api_key_source("env:OPENAI_API_KEY"), "env");
        assert_eq!(api_key_source("  "), "missing");
    }

    #[test]
    fn truncate_keeps_the_ellipsis_within_the_limit() {
        let out = truncate("abcdefghij", 5);
        assert_eq!(out.chars().count(), 5);
        assert!(out.ends_with('…'));
    }

    #[test]
    fn snapshot_never_serializes_a_secret() {
        let dir = std::env::temp_dir().join(format!("bf-phase0-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Store::open(dir.join("bf.db")).expect("open temp store");

        let mut config = AppConfig::default();
        config.llm.api_key = "sk-live-DO-NOT-LEAK".into();

        let snapshot = app_snapshot(&store, &config).expect("snapshot");
        let json = serde_json::to_string(&snapshot).expect("serialize");

        assert_eq!(snapshot.settings.api_key_source, "literal");
        assert!(
            !json.contains("DO-NOT-LEAK"),
            "secret crossed the IPC boundary"
        );

        drop(store);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
