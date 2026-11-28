//! Shared desktop application state and view-model layer.
//!
//! The Tauri shell owns one `AppState` for the whole process. The webview never
//! opens SQLite itself and never receives an API key.

pub mod commands;
pub mod config;
pub mod dto;
pub mod projection;
pub mod runtime;

use bugfound_store::Store;
use config::AppConfig;
use runtime::RuntimeHandle;
use std::path::PathBuf;
use std::sync::Mutex;

pub const CONFIG_FILE: &str = "bugfound.toml";
pub const PRODUCT_VERSION: &str = env!("CARGO_PKG_VERSION");
/// Marker used to detect that `open_store` degraded to a disposable store.
/// A config-driven retention pass must never run against that store.
const STORAGE_FALLBACK_MARKER: &str = "Running with an in-memory store";

pub struct AppState {
    pub config_path: PathBuf,
    pub config: Mutex<AppConfig>,
    /// One connection for the whole app. `Store` is `Clone + Send + Sync`.
    pub store: Store,
    /// Startup problems that would otherwise crash the app. Every entry is
    /// surfaced in the UI; nothing here is silently swallowed.
    pub startup_warnings: Vec<String>,
    /// Long-lived operator runtime (chat, steer, stop, approvals).
    pub runtime: RuntimeHandle,
}

impl AppState {
    /// Never panic on operator config/DB problems. A malformed `bugfound.toml`
    /// falls back to defaults, and an unreadable DB falls back to memory, with
    /// both reasons reported to the UI. Existing files are left untouched.
    pub fn load() -> Self {
        // E24: prefer the platform config directory, with the legacy cwd file
        // as a read fallback so existing installations keep their settings.
        let config_path = crate::config::config_dir().join(CONFIG_FILE);
        let config_path = if config_path.exists() {
            config_path
        } else {
            PathBuf::from(CONFIG_FILE)
        };
        let (config, config_warning) = match AppConfig::load(&config_path) {
            Ok(config) => (config, None),
            Err(error) => (
                AppConfig::default(),
                Some(format!(
                    "could not read {} ({error}). Using default settings; the file was left untouched.",
                    config_path.display()
                )),
            ),
        };
        let db_path = crate::config::resolve_db_path(&config.storage.path);
        let (store, storage_warning) = open_store(&db_path.to_string_lossy());
        let mut startup_warnings = Vec::new();
        if let Some(warning) = config_warning {
            startup_warnings.push(warning);
        }
        if let Some(warning) = storage_warning {
            startup_warnings.push(warning);
        }
        // D17: operator-controlled retention runs before the runtime is built,
        // so every surface sees the same already-pruned store.
        apply_retention(&store, config.storage.retention_days, &mut startup_warnings);
        let mut runtime = RuntimeHandle::new(store.clone());
        // E1: `abort_at` reopens the DB by path, so only a file-backed store
        // can be used to abort an engagement from `stop`.
        if config.storage.path != ":memory:" {
            runtime = runtime.with_db_path(&db_path);
        }
        Self {
            config_path,
            config: Mutex::new(config),
            store,
            startup_warnings,
            runtime,
        }
    }
}

/// Never rewrite a DB we cannot open: the operator may still want to recover
/// it. Degrade to a disposable in-memory store and report the reason upward.
fn open_store(path: &str) -> (Store, Option<String>) {
    match Store::open(path) {
        Ok(store) => (store, None),
        Err(error) => {
            let fallback = Store::open(":memory:").expect("open in-memory fallback store");
            (
                fallback,
                Some(format!(
                    "could not open {path} ({error}). {STORAGE_FALLBACK_MARKER}; the file was left untouched."
                )),
            )
        }
    }
}

/// The four store operations the startup retention pass needs. Keeping them
/// behind a small seam lets unit tests exercise pruning decisions (including a
/// tampered chain) without raw SQL access to the store's private connection.
trait RetentionStore {
    fn list_sessions(&self, limit: usize) -> anyhow::Result<Vec<bugfound_store::Session>>;
    fn prune_events_before(&self, session_id: &str, cutoff: &str) -> anyhow::Result<usize>;
    fn verify_event_chain(&self, session_id: &str) -> anyhow::Result<bool>;
    fn prune_trace_events_before(&self, session_id: &str, cutoff: &str) -> anyhow::Result<usize>;
}

impl RetentionStore for Store {
    fn list_sessions(&self, limit: usize) -> anyhow::Result<Vec<bugfound_store::Session>> {
        Store::list_sessions(self, limit)
    }
    fn prune_events_before(&self, session_id: &str, cutoff: &str) -> anyhow::Result<usize> {
        Store::prune_events_before(self, session_id, cutoff)
    }
    fn verify_event_chain(&self, session_id: &str) -> anyhow::Result<bool> {
        Store::verify_event_chain(self, session_id)
    }
    fn prune_trace_events_before(&self, session_id: &str, cutoff: &str) -> anyhow::Result<usize> {
        Store::prune_trace_events_before(self, session_id, cutoff)
    }
}

/// UTC RFC3339 cutoff `days` days before now. Kept std-only because the
/// desktop-core manifest does not declare `chrono`; the emitted string is the
/// same canonical `YYYY-MM-DDTHH:MM:SS+00:00` form the store parses.
fn retention_cutoff(days: usize) -> String {
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let days = days.min((i64::MAX / 86_400) as usize) as i64;
    let seconds = seconds.saturating_sub(days.saturating_mul(86_400));
    let day = seconds.div_euclid(86_400);
    let second_of_day = seconds.rem_euclid(86_400) as u32;
    // Howard Hinnant's civil-from-days conversion (epoch 1970-01-01).
    let z = day + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let dom = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    if month <= 2 {
        year += 1;
    }
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}+00:00",
        year,
        month,
        dom,
        second_of_day / 3600,
        (second_of_day % 3600) / 60,
        second_of_day % 60
    )
}

/// Startup retention pass. `retention_days == 0` and the in-memory fallback
/// store are both hard no-ops, so an unreadable DB is never rewritten and an
/// operator who never opted in never loses audit history.
fn apply_retention(store: &Store, retention_days: usize, warnings: &mut Vec<String>) {
    if retention_days == 0
        || warnings
            .iter()
            .any(|warning| warning.contains(STORAGE_FALLBACK_MARKER))
    {
        return;
    }
    // `AppConfig::load` parses without validating; an out-of-range value must
    // never become an accidental mass deletion at startup.
    if retention_days > 36_500 {
        warnings.push(format!(
            "retention: storage.retention_days = {retention_days} exceeds the 36500 cap; no rows were pruned."
        ));
        return;
    }
    let cutoff = retention_cutoff(retention_days);
    prune_sessions_before(store, &cutoff, warnings);
}

/// Prune audit events, re-verify the hash chain, then prune trace events for
/// every session. Each failure is reported and only affects that session: no
/// other rows are touched.
fn prune_sessions_before<S: RetentionStore>(store: &S, cutoff: &str, warnings: &mut Vec<String>) {
    let sessions = match store.list_sessions(usize::MAX) {
        Ok(sessions) => sessions,
        Err(error) => {
            warnings.push(format!(
                "retention: could not list sessions ({error}); no rows were pruned."
            ));
            return;
        }
    };
    for session in sessions {
        let id = session.id;
        if let Err(error) = store.prune_events_before(&id, cutoff) {
            // The store refuses to prune a chain that does not verify; keep
            // both the audit log and the trace log intact for that session.
            warnings.push(format!(
                "retention: could not prune audit events for session {id} ({error}); nothing was deleted for that session."
            ));
            continue;
        }
        match store.verify_event_chain(&id) {
            Ok(true) => {}
            Ok(false) => {
                warnings.push(format!(
                    "retention: event chain for session {id} is invalid after prune; trace events were not pruned."
                ));
                continue;
            }
            Err(error) => {
                warnings.push(format!(
                    "retention: could not verify event chain for session {id} ({error}); trace events were not pruned."
                ));
                continue;
            }
        }
        // Trace rows are scoped by `trace_events.engagement_id`, the same
        // session id used for audit events. Pass it deliberately: a different
        // scope would either miss rows or delete another session's traces.
        if let Err(error) = store.prune_trace_events_before(&id, cutoff) {
            warnings.push(format!(
                "retention: could not prune trace events for session {id} ({error})."
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_db_degrades_to_memory_without_touching_the_file() {
        let dir = std::env::temp_dir().join(format!("bf-degraded-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let bad = dir.join("bad.db");
        std::fs::write(&bad, b"not a sqlite database").expect("write bad file");

        let (store, error) = open_store(bad.to_str().expect("utf8 path"));

        assert!(error.is_some(), "degraded reason must be reported");
        assert!(store.list_sessions(1).is_ok(), "fallback store must work");
        assert_eq!(
            std::fs::read(&bad).expect("read bad file"),
            b"not a sqlite database",
            "the original file must not be modified"
        );

        drop(store);
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn test_session(id: &str) -> bugfound_store::Session {
        bugfound_store::Session {
            id: id.to_string(),
            goal: String::new(),
            state: String::new(),
            model: None,
            owner_id: None,
            lease_expires_at: None,
            created_at: String::new(),
            updated_at: None,
        }
    }

    /// In-memory double for the four store calls in the retention pass. Rows
    /// are `(session id, RFC3339 created_at)` pairs so timestamp semantics can
    /// be tested without opening a SQLite connection.
    struct FakeStore {
        sessions: Vec<bugfound_store::Session>,
        events: std::cell::RefCell<Vec<(String, String)>>,
        traces: std::cell::RefCell<Vec<(String, String)>>,
        broken_chain: bool,
        verified: std::cell::RefCell<Vec<String>>,
        trace_pruned: std::cell::RefCell<Vec<String>>,
    }

    impl FakeStore {
        fn new() -> Self {
            Self {
                sessions: Vec::new(),
                events: Default::default(),
                traces: Default::default(),
                broken_chain: false,
                verified: Default::default(),
                trace_pruned: Default::default(),
            }
        }
    }

    impl RetentionStore for FakeStore {
        fn list_sessions(&self, _limit: usize) -> anyhow::Result<Vec<bugfound_store::Session>> {
            Ok(self.sessions.clone())
        }
        fn prune_events_before(&self, session_id: &str, cutoff: &str) -> anyhow::Result<usize> {
            if self.broken_chain {
                return Err(anyhow::anyhow!(
                    "event chain for session {session_id} is invalid; refusing prune"
                ));
            }
            let mut events = self.events.borrow_mut();
            let before = events.len();
            events.retain(|(id, stamp)| id != session_id || stamp.as_str() >= cutoff);
            Ok(before - events.len())
        }
        fn verify_event_chain(&self, session_id: &str) -> anyhow::Result<bool> {
            self.verified.borrow_mut().push(session_id.to_string());
            Ok(!self.broken_chain)
        }
        fn prune_trace_events_before(
            &self,
            session_id: &str,
            cutoff: &str,
        ) -> anyhow::Result<usize> {
            self.trace_pruned.borrow_mut().push(session_id.to_string());
            let mut traces = self.traces.borrow_mut();
            let before = traces.len();
            traces.retain(|(id, stamp)| id != session_id || stamp.as_str() >= cutoff);
            Ok(before - traces.len())
        }
    }

    #[test]
    fn retention_cutoff_is_accepted_by_the_store() {
        let store = Store::open(":memory:").expect("open store");
        let session = store
            .create_session("cutoff format")
            .expect("create session");
        let cutoff = retention_cutoff(30);
        assert_eq!(cutoff.len(), 25, "unexpected cutoff: {cutoff}");
        assert!(cutoff.ends_with("+00:00"));
        store
            .prune_events_before(&session.id, &cutoff)
            .expect("the generated cutoff must parse as RFC3339 in the store");
    }

    #[test]
    fn retention_zero_is_a_no_op() {
        let store = Store::open(":memory:").expect("open store");
        let session = store
            .create_session("zero retention")
            .expect("create session");
        store
            .add_event(&session.id, "info", "step", "kept")
            .expect("add event");
        let mut warnings = Vec::new();

        apply_retention(&store, 0, &mut warnings);

        assert!(warnings.is_empty(), "disabled retention must stay silent");
        assert_eq!(
            store
                .list_events(&session.id, usize::MAX)
                .expect("list events")
                .len(),
            1,
            "no event may be deleted when retention is disabled"
        );
    }

    #[test]
    fn retention_skips_an_in_memory_fallback_store() {
        let store = Store::open(":memory:").expect("open store");
        let mut warnings = vec![format!(
            "could not open db ({STORAGE_FALLBACK_MARKER}); file left untouched"
        )];

        apply_retention(&store, 30, &mut warnings);

        assert_eq!(warnings.len(), 1, "no extra retention warning expected");
        assert_eq!(
            store
                .list_sessions(usize::MAX)
                .expect("list sessions")
                .len(),
            0
        );
    }

    #[test]
    fn retention_prunes_only_events_before_cutoff() {
        const CUTOFF: &str = "2026-01-03T00:00:00+00:00";
        let mut fake = FakeStore::new();
        fake.sessions = vec![test_session("s1"), test_session("s2")];
        *fake.events.borrow_mut() = vec![
            ("s1".into(), "2026-01-01T00:00:00+00:00".into()),
            ("s1".into(), "2026-01-02T00:00:00+00:00".into()),
            ("s1".into(), "2026-01-04T00:00:00+00:00".into()),
            ("s2".into(), "2026-01-04T00:00:00+00:00".into()),
        ];
        *fake.traces.borrow_mut() = vec![
            ("s1".into(), "2026-01-01T00:00:00+00:00".into()),
            ("s1".into(), "2026-01-04T00:00:00+00:00".into()),
            ("s2".into(), "2026-01-04T00:00:00+00:00".into()),
        ];
        let mut warnings = Vec::new();

        prune_sessions_before(&fake, CUTOFF, &mut warnings);

        assert!(warnings.is_empty(), "unexpected warnings: {warnings:?}");
        assert_eq!(
            *fake.events.borrow(),
            vec![
                ("s1".into(), "2026-01-04T00:00:00+00:00".into()),
                ("s2".into(), "2026-01-04T00:00:00+00:00".into()),
            ]
        );
        assert_eq!(
            *fake.traces.borrow(),
            vec![
                ("s1".into(), "2026-01-04T00:00:00+00:00".into()),
                ("s2".into(), "2026-01-04T00:00:00+00:00".into()),
            ]
        );
        assert_eq!(
            *fake.verified.borrow(),
            vec!["s1".to_string(), "s2".to_string()]
        );
        assert_eq!(
            *fake.trace_pruned.borrow(),
            vec!["s1".to_string(), "s2".to_string()]
        );
    }

    #[test]
    fn retention_warns_on_a_broken_chain_without_deleting_anything() {
        let mut fake = FakeStore::new();
        fake.sessions = vec![test_session("s1")];
        fake.broken_chain = true;
        *fake.events.borrow_mut() = vec![("s1".into(), "2026-01-01T00:00:00+00:00".into())];
        *fake.traces.borrow_mut() = vec![("s1".into(), "2026-01-01T00:00:00+00:00".into())];
        let mut warnings = Vec::new();

        prune_sessions_before(&fake, "2026-01-03T00:00:00+00:00", &mut warnings);

        assert_eq!(warnings.len(), 1);
        assert!(
            warnings[0].contains("refusing prune"),
            "unexpected warning: {}",
            warnings[0]
        );
        assert_eq!(fake.events.borrow().len(), 1, "audit log must survive");
        assert_eq!(fake.traces.borrow().len(), 1, "trace log must survive");
        assert!(
            fake.trace_pruned.borrow().is_empty(),
            "trace prune must be skipped after a failed audit prune"
        );
    }

    #[test]
    fn retained_chain_is_valid_after_prune() {
        let store = Store::open(":memory:").expect("open store");
        let session = store
            .create_session("chain after prune")
            .expect("create session");
        store
            .add_event(&session.id, "info", "step", "old")
            .expect("add event");
        store
            .add_event(&session.id, "info", "step", "also old")
            .expect("add event");
        let mut warnings = Vec::new();

        prune_sessions_before(&store, "2999-01-01T00:00:00+00:00", &mut warnings);

        assert!(warnings.is_empty(), "unexpected warnings: {warnings:?}");
        assert!(
            store
                .list_events(&session.id, usize::MAX)
                .expect("list events")
                .is_empty(),
            "both events are before the cutoff"
        );
        assert!(
            store
                .verify_event_chain(&session.id)
                .expect("verify event chain"),
            "the retained chain must still verify"
        );
    }
}
