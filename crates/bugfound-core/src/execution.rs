//! Process-global execution coordination keyed by session id.
//!
//! A runner can check `is_cancelled` between steps; an external caller can
//! `interrupt` a session to request cancellation. Wakeups coalesce so that a
//! burst of prompts produces at most one pending wake per session.

use bugfound_store::Store;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, OnceLock};
use tokio::sync::Notify;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionState {
    Idle,
    Running,
    Waiting,
    Interrupted,
}

impl ExecutionState {
    pub fn is_active(&self) -> bool {
        matches!(self, Self::Running | Self::Waiting)
    }
}

/// Scope of a coalesced wake. `Input` subsumes `Steer` so a queued prompt
/// arriving after a steer cannot be lost by narrowing the pending wake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WakeScope {
    Steer,
    Input,
}

impl WakeScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Steer => "steer",
            Self::Input => "input",
        }
    }

    fn widen(self, other: Self) -> Self {
        match (self, other) {
            (Self::Input, _) | (_, Self::Input) => Self::Input,
            _ => Self::Steer,
        }
    }
}

#[derive(Clone)]
struct RuntimeState {
    state: ExecutionState,
    cancel_requested: bool,
    wake_pending: Option<WakeScope>,
    generation: u64,
}

impl Default for RuntimeState {
    fn default() -> Self {
        Self {
            state: ExecutionState::Idle,
            cancel_requested: false,
            wake_pending: None,
            generation: 0,
        }
    }
}

/// Tracks which sessions are active in this process and their cancellation
/// flags. Cloning shares the same global-ish state.
#[derive(Clone)]
pub struct ExecutionCoordinator {
    inner: Arc<Mutex<HashMap<String, RuntimeState>>>,
    notify: Arc<Notify>,
    /// Stores used to persist cross-process stop flags, keyed by session id.
    /// A runner registers its own store when it claims a session, so one
    /// session's interrupt can never write into another session's database.
    session_stores: Arc<Mutex<HashMap<String, Store>>>,
    /// Sessions whose stop flag has already been honored by a finished run.
    /// A fresh `resume` clears this so a new stop request is observed again.
    stop_acked: Arc<Mutex<HashSet<String>>>,
}

static GLOBAL: OnceLock<ExecutionCoordinator> = OnceLock::new();

/// Legacy key used by the deprecated single-store registration API.
const LEGACY_STORE_KEY: &str = "*";

impl Default for ExecutionCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

impl ExecutionCoordinator {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            notify: Arc::new(Notify::new()),
            session_stores: Arc::new(Mutex::new(HashMap::new())),
            stop_acked: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    /// Bind a session to the store that owns its durable stop flag. Called by
    /// the runner when it claims the session, not when a `Runner` is built.
    pub fn register_store_for_session(&self, session_id: &str, store: Store) {
        self.session_stores
            .lock()
            .unwrap()
            .insert(session_id.to_string(), store);
    }

    /// Legacy single-store registration. Kept as a compatibility alias for
    /// callers that have not moved to [`Self::register_store_for_session`];
    /// the store is used only as a fallback for sessions without their own.
    #[deprecated(note = "use register_store_for_session(session_id, store) instead")]
    pub fn register_store(&self, store: Store) {
        self.session_stores
            .lock()
            .unwrap()
            .insert(LEGACY_STORE_KEY.to_string(), store);
    }

    /// Mark a session's stop flag as consumed. Called by the runner when it
    /// finishes, so a later resume is not blocked by a stale flag.
    pub fn ack_stop(&self, session_id: &str) {
        self.stop_acked
            .lock()
            .unwrap()
            .insert(session_id.to_string());
    }

    pub fn is_stop_acked(&self, session_id: &str) -> bool {
        self.stop_acked.lock().unwrap().contains(session_id)
    }

    /// The process-wide coordinator.
    pub fn global() -> &'static Self {
        GLOBAL.get_or_init(Self::new)
    }

    /// Mark a session as actively running. Returns `true` when it was not
    /// active before. Any previous cancellation request is cleared.
    pub fn resume(&self, session_id: &str) -> bool {
        let mut inner = self.inner.lock().unwrap();
        let state = inner.entry(session_id.to_string()).or_default();
        let was_active = state.state.is_active();
        state.state = ExecutionState::Running;
        state.cancel_requested = false;
        state.generation += 1;
        self.notify.notify_waiters();
        // A fresh run starts with a clean stop-flag slate.
        self.stop_acked.lock().unwrap().remove(session_id);
        !was_active
    }

    /// Coalescing wake signal. Returns `true` only when a wake was not already
    /// pending for this session.
    pub fn wake(&self, session_id: &str) -> bool {
        self.wake_scoped(session_id, WakeScope::Steer)
    }

    /// Coalescing, scope-aware wake. Returns `true` only when no wake was
    /// pending; a later broader wake widens the pending scope.
    pub fn wake_scoped(&self, session_id: &str, scope: WakeScope) -> bool {
        let mut inner = self.inner.lock().unwrap();
        let state = inner.entry(session_id.to_string()).or_default();
        let fresh = state.wake_pending.is_none();
        state.wake_pending = Some(match state.wake_pending {
            Some(current) => current.widen(scope),
            None => scope,
        });
        self.notify.notify_waiters();
        fresh
    }

    pub fn take_wake(&self, session_id: &str) -> bool {
        self.take_wake_scoped(session_id).is_some()
    }

    pub fn take_wake_scoped(&self, session_id: &str) -> Option<WakeScope> {
        let mut inner = self.inner.lock().unwrap();
        inner
            .get_mut(session_id)
            .and_then(|state| state.wake_pending.take())
    }

    /// Request cancellation. The session becomes inactive immediately so
    /// `await_idle` can complete; a runner still observes the flag through
    /// `is_cancelled` before its next step. Returns `true` if a live run was
    /// actually interrupted.
    pub fn interrupt(&self, session_id: &str) -> bool {
        // Persist the stop request to the store that owns THIS session so
        // runners in other processes observe it at their next step boundary.
        // A missing registration is a bug: warn and skip the durable write
        // rather than silently writing a flag into an unrelated database.
        {
            let guard = self.session_stores.lock().unwrap();
            match guard
                .get(session_id)
                .or_else(|| guard.get(LEGACY_STORE_KEY))
            {
                Some(store) => {
                    if let Err(e) = store.set_session_flag(session_id, crate::STOP_REQUESTED_FLAG) {
                        tracing::warn!(
                            error=%e,
                            session=session_id,
                            "failed to persist interrupt stop flag"
                        );
                    }
                }
                None => {
                    tracing::warn!(
                        session = session_id,
                        "no store registered for session; interrupt stop flag not persisted"
                    );
                }
            }
        }
        let mut inner = self.inner.lock().unwrap();
        let state = inner.entry(session_id.to_string()).or_default();
        let was_active = state.state.is_active();
        let already_cancelled = state.cancel_requested;
        state.cancel_requested = true;
        state.state = ExecutionState::Interrupted;
        self.notify.notify_waiters();
        was_active && !already_cancelled
    }

    pub fn is_cancelled(&self, session_id: &str) -> bool {
        self.inner
            .lock()
            .unwrap()
            .get(session_id)
            .is_some_and(|state| state.cancel_requested)
    }

    pub fn clear_cancel(&self, session_id: &str) {
        if let Some(state) = self.inner.lock().unwrap().get_mut(session_id) {
            state.cancel_requested = false;
        }
    }

    /// Record a terminal or parked state. Non-interrupted states clear the
    /// cancellation flag so a later resume starts clean.
    pub fn finish(&self, session_id: &str, state: ExecutionState) {
        let mut inner = self.inner.lock().unwrap();
        let current = inner.entry(session_id.to_string()).or_default();
        current.state = state;
        if state != ExecutionState::Interrupted {
            current.cancel_requested = false;
        }
        self.notify.notify_waiters();
    }

    pub fn mark_waiting(&self, session_id: &str) {
        self.finish(session_id, ExecutionState::Waiting);
    }

    pub fn state(&self, session_id: &str) -> ExecutionState {
        self.inner
            .lock()
            .unwrap()
            .get(session_id)
            .map(|state| state.state)
            .unwrap_or(ExecutionState::Idle)
    }

    pub fn is_active(&self, session_id: &str) -> bool {
        self.state(session_id).is_active()
    }

    /// Sorted list of currently active session ids.
    pub fn active(&self) -> Vec<String> {
        let mut ids: Vec<String> = self
            .inner
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, state)| state.state.is_active())
            .map(|(id, _)| id.clone())
            .collect();
        ids.sort();
        ids
    }

    pub fn generation(&self, session_id: &str) -> u64 {
        self.inner
            .lock()
            .unwrap()
            .get(session_id)
            .map(|state| state.generation)
            .unwrap_or(0)
    }

    /// Wait until a session is no longer active. Already-idle sessions return
    /// immediately.
    pub async fn await_idle(&self, session_id: &str) {
        loop {
            let notified = self.notify.notified();
            tokio::pin!(notified);
            // Enable before checking so a concurrent `finish` cannot slip
            // between the check and registration.
            notified.as_mut().enable();
            if !self.is_active(session_id) {
                return;
            }
            notified.await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn interrupt_sets_cancel_flag_and_releases_active_state() {
        let coordinator = ExecutionCoordinator::new();
        assert!(coordinator.resume("s-a"));
        assert!(coordinator.is_active("s-a"));
        assert_eq!(coordinator.active(), vec!["s-a".to_string()]);

        assert!(coordinator.interrupt("s-a"));
        assert!(coordinator.is_cancelled("s-a"));
        assert!(!coordinator.is_active("s-a"));
        coordinator.await_idle("s-a").await;
        assert!(!coordinator.interrupt("s-a"));

        // A fresh resume clears the stale cancellation.
        assert!(coordinator.resume("s-a"));
        assert!(!coordinator.is_cancelled("s-a"));
        coordinator.finish("s-a", ExecutionState::Idle);
        assert!(coordinator.active().is_empty());
    }

    #[tokio::test]
    async fn wake_calls_coalesce_and_await_idle_is_immediate_when_idle() {
        let coordinator = ExecutionCoordinator::new();
        assert!(coordinator.wake("s-b"));
        assert!(!coordinator.wake("s-b"));
        assert!(coordinator.take_wake("s-b"));
        assert!(!coordinator.take_wake("s-b"));

        coordinator.await_idle("never-started").await;
        assert_eq!(coordinator.state("never-started"), ExecutionState::Idle);
    }
}

#[test]
fn scoped_wake_coalesces_and_widens() {
    let coordinator = ExecutionCoordinator::new();
    assert!(coordinator.wake_scoped("s-scope", WakeScope::Steer));
    assert!(!coordinator.wake_scoped("s-scope", WakeScope::Steer));
    assert_eq!(
        coordinator.take_wake_scoped("s-scope"),
        Some(WakeScope::Steer)
    );
    assert!(coordinator.wake_scoped("s-scope", WakeScope::Steer));
    assert!(!coordinator.wake_scoped("s-scope", WakeScope::Input));
    assert_eq!(
        coordinator.take_wake_scoped("s-scope"),
        Some(WakeScope::Input)
    );
    assert!(coordinator.take_wake_scoped("s-scope").is_none());
}
