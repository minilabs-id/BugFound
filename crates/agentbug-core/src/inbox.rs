//! Durable-style prompt inbox with priority promotion and wake coalescing.
//!
//! Items are admitted first, then promoted at a safe step boundary, then
//! delivered. This module is an additive in-memory view; the durable message
//! store remains the source of truth for delivered prompts.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InboxKind {
    User,
    Steer,
    Control,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Delivery {
    /// May take priority when the session reaches a promotable boundary.
    Steer,
    /// Waits its turn in FIFO order.
    Queued,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ItemState {
    Pending,
    Steered,
    Delivered,
    Cancelled,
}

#[derive(Debug, Clone)]
pub struct InboxItem {
    pub id: String,
    pub session_id: String,
    pub kind: InboxKind,
    pub payload: Value,
    pub delivery: Delivery,
    /// Unix timestamp in milliseconds.
    pub created_at: u64,
    state: ItemState,
}

impl InboxItem {
    /// Serialized payload, useful for writing to a durable event log.
    pub fn payload_json(&self) -> String {
        self.payload.to_string()
    }

    pub fn status(&self) -> &'static str {
        match self.state {
            ItemState::Pending => "pending",
            ItemState::Steered => "steered",
            ItemState::Delivered => "delivered",
            ItemState::Cancelled => "cancelled",
        }
    }

    pub fn is_pending(&self) -> bool {
        matches!(self.state, ItemState::Pending | ItemState::Steered)
    }
}

#[derive(Default)]
struct Inner {
    items: HashMap<String, InboxItem>,
    order: HashMap<String, Vec<String>>,
    wakes: HashMap<String, bool>,
}

/// In-memory inbox shared between producers and the runner.
#[derive(Clone, Default)]
pub struct Inbox {
    ids: Arc<AtomicU64>,
    inner: Arc<Mutex<Inner>>,
}

static GLOBAL: OnceLock<Inbox> = OnceLock::new();

impl Inbox {
    pub fn new() -> Self {
        Self::default()
    }

    /// Process-wide inbox used by external producers and the `Runner`.
    pub fn global() -> &'static Self {
        GLOBAL.get_or_init(Self::new)
    }

    /// Admit a new item. The payload accepts a string, a `Value`, or anything
    /// convertible to a `serde_json::Value`.
    pub fn enqueue(
        &self,
        session_id: &str,
        kind: InboxKind,
        payload: impl Into<Value>,
        delivery: Delivery,
    ) -> InboxItem {
        let seq = self.ids.fetch_add(1, Ordering::Relaxed) + 1;
        let item = InboxItem {
            id: format!("in-{seq:016x}"),
            session_id: session_id.to_string(),
            kind,
            payload: payload.into(),
            delivery,
            created_at: now_millis(),
            state: ItemState::Pending,
        };
        let mut inner = self.inner.lock().unwrap();
        inner
            .order
            .entry(session_id.to_string())
            .or_default()
            .push(item.id.clone());
        inner.items.insert(item.id.clone(), item.clone());
        item
    }

    /// Select the next item for a session. Steer-delivery items win when the
    /// session is at a promotable boundary; otherwise the oldest queued item is
    /// selected. The item is marked as steered but is not yet consumed.
    pub fn promote(&self, session_id: &str, promotable: bool) -> Option<InboxItem> {
        let mut inner = self.inner.lock().unwrap();
        let ids = inner.order.get(session_id)?.clone();
        let steer_id = if promotable {
            ids.iter().find(|id| {
                inner.items.get(*id).is_some_and(|item| {
                    item.state == ItemState::Pending && item.delivery == Delivery::Steer
                })
            })
        } else {
            None
        };
        let chosen = steer_id.or_else(|| {
            ids.iter().find(|id| {
                inner.items.get(*id).is_some_and(|item| {
                    item.state == ItemState::Pending && item.delivery == Delivery::Queued
                })
            })
        })?;
        let item = inner.items.get_mut(chosen)?;
        item.state = ItemState::Steered;
        Some(item.clone())
    }

    /// Promote and consume in one step, for callers that do not need a separate
    /// delivery phase.
    pub fn promote_and_deliver(&self, session_id: &str, promotable: bool) -> Option<InboxItem> {
        let item = self.promote(session_id, promotable)?;
        self.deliver(&item.id)
    }

    /// Mark a promoted (or pending) item as delivered and return it.
    pub fn deliver(&self, item_id: &str) -> Option<InboxItem> {
        let mut inner = self.inner.lock().unwrap();
        let item = inner.items.get_mut(item_id)?;
        if !item.is_pending() {
            return None;
        }
        item.state = ItemState::Delivered;
        Some(item.clone())
    }

    /// Cancel a pending or steered item. Idempotent: returns whether it was
    /// actually cancelled.
    pub fn cancel(&self, item_id: &str) -> bool {
        let mut inner = self.inner.lock().unwrap();
        let Some(item) = inner.items.get_mut(item_id) else {
            return false;
        };
        if !item.is_pending() {
            return false;
        }
        item.state = ItemState::Cancelled;
        true
    }

    /// Items that have not been delivered or cancelled, in admission order.
    pub fn list_pending(&self, session_id: &str) -> Vec<InboxItem> {
        let inner = self.inner.lock().unwrap();
        let Some(ids) = inner.order.get(session_id) else {
            return Vec::new();
        };
        ids.iter()
            .filter_map(|id| inner.items.get(id))
            .filter(|item| item.is_pending())
            .cloned()
            .collect()
    }

    pub fn get(&self, item_id: &str) -> Option<InboxItem> {
        self.inner.lock().unwrap().items.get(item_id).cloned()
    }

    /// Signal that a session needs attention. Multiple calls collapse into one
    /// pending wake; returns `true` only for the first call after a take.
    pub fn wake(&self, session_id: &str) -> bool {
        let mut inner = self.inner.lock().unwrap();
        let slot = inner.wakes.entry(session_id.to_string()).or_default();
        let fresh = !*slot;
        *slot = true;
        fresh
    }

    /// Consume a pending wake signal.
    pub fn take_wake(&self, session_id: &str) -> bool {
        let mut inner = self.inner.lock().unwrap();
        inner
            .wakes
            .get_mut(session_id)
            .map(std::mem::take)
            .unwrap_or(false)
    }

    pub fn has_wake(&self, session_id: &str) -> bool {
        self.inner
            .lock()
            .unwrap()
            .wakes
            .get(session_id)
            .copied()
            .unwrap_or(false)
    }

    pub fn clear_wake(&self, session_id: &str) {
        self.inner.lock().unwrap().wakes.remove(session_id);
    }
}

fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn promotion_prefers_steers_then_fifo_and_delivery_consumes() {
        let inbox = Inbox::new();
        let first = inbox.enqueue("s", InboxKind::User, "first", Delivery::Queued);
        let steer = inbox.enqueue("s", InboxKind::Steer, "steer", Delivery::Steer);
        let second = inbox.enqueue("s", InboxKind::User, "second", Delivery::Queued);

        assert_eq!(inbox.promote("s", true).unwrap().id, steer.id);
        assert_eq!(inbox.promote("s", false).unwrap().id, first.id);
        assert_eq!(inbox.list_pending("s").len(), 3);

        assert!(inbox.deliver(&steer.id).is_some());
        assert!(inbox.deliver(&first.id).is_some());
        assert!(inbox.cancel(&second.id));
        assert!(inbox.list_pending("s").is_empty());
        assert!(inbox.deliver(&steer.id).is_none());
    }

    #[test]
    fn wake_calls_coalesce() {
        let inbox = Inbox::new();
        assert!(inbox.wake("s"));
        assert!(!inbox.wake("s"));
        assert!(!inbox.wake("s"));
        assert!(inbox.has_wake("s"));
        assert!(inbox.take_wake("s"));
        assert!(!inbox.take_wake("s"));
        assert!(inbox.wake("s"));
        inbox.clear_wake("s");
        assert!(!inbox.has_wake("s"));
    }

    #[test]
    fn payload_accepts_strings_and_json() {
        let inbox = Inbox::new();
        let text = inbox.enqueue("s", InboxKind::User, "hello", Delivery::Queued);
        let json = inbox.enqueue(
            "s",
            InboxKind::Control,
            serde_json::json!({"a": 1}),
            Delivery::Queued,
        );
        assert_eq!(text.payload.as_str(), Some("hello"));
        assert_eq!(json.payload["a"], 1);
        assert!(text.payload_json().contains("hello"));
    }
}
