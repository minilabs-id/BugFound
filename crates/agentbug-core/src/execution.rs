//! Process-global execution coordination keyed by session id.
//!
//! A runner can check `is_cancelled` between steps; an external caller can
//! `interrupt` a session to request cancellation. Wakeups coalesce so that a
//! burst of prompts produces at most one pending wake per session.

use std::collections::HashMap;
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

#[derive(Clone)]
struct RuntimeState {
    state: ExecutionState,
    cancel_requested: bool,
    wake_pending: bool,
    generation: u64,
}

impl Default for RuntimeState {
    fn default() -> Self {
        Self {
            state: ExecutionState::Idle,
            cancel_requested: false,
            wake_pending: false,
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
}

static GLOBAL: OnceLock<ExecutionCoordinator> = OnceLock::new();

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
        }
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
        !was_active
    }

    /// Coalescing wake signal. Returns `true` only when a wake was not already
    /// pending for this session.
    pub fn wake(&self, session_id: &str) -> bool {
        let mut inner = self.inner.lock().unwrap();
        let state = inner.entry(session_id.to_string()).or_default();
        let fresh = !state.wake_pending;
        state.wake_pending = true;
        self.notify.notify_waiters();
        fresh
    }

    pub fn take_wake(&self, session_id: &str) -> bool {
        let mut inner = self.inner.lock().unwrap();
        inner
            .get_mut(session_id)
            .map(|state| std::mem::take(&mut state.wake_pending))
            .unwrap_or(false)
    }

    /// Request cancellation. The session becomes inactive immediately so
    /// `await_idle` can complete; a runner still observes the flag through
    /// `is_cancelled` before its next step. Returns `true` if a live run was
    /// actually interrupted.
    pub fn interrupt(&self, session_id: &str) -> bool {
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
