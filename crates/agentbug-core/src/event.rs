//! In-memory event bus and projections for session-scoped events.
//!
//! This is an additive capability: it never touches the durable event chain in
//! `agentbug_store`. It provides a fast, in-process publish/subscribe surface
//! plus a small fold abstraction for turning a stream of events into state.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

/// A typed, session-scoped event.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Event {
    pub id: String,
    pub session_id: String,
    pub kind: String,
    pub payload_json: String,
    /// Unix timestamp in milliseconds.
    pub created_at: u64,
}

impl Event {
    /// Decode the payload into a concrete type.
    pub fn payload<T: serde::de::DeserializeOwned>(&self) -> serde_json::Result<T> {
        serde_json::from_str(&self.payload_json)
    }
}

pub type EventListener = Arc<dyn Fn(&Event) + Send + Sync>;

#[derive(Default)]
struct Inner {
    all: HashMap<String, Vec<Event>>,
    undrained: HashMap<String, Vec<Event>>,
    subscribers: HashMap<String, Vec<(usize, EventListener)>>,
    next_subscription: usize,
}

/// In-memory publish/subscribe bus keyed by session id.
///
/// Cloning an `EventBus` shares the same underlying state.
#[derive(Clone)]
pub struct EventBus {
    ids: Arc<AtomicU64>,
    inner: Arc<Mutex<Inner>>,
}

static GLOBAL: OnceLock<EventBus> = OnceLock::new();

impl Default for EventBus {
    fn default() -> Self {
        Self::new()
    }
}

impl EventBus {
    pub fn new() -> Self {
        Self {
            ids: Arc::new(AtomicU64::new(0)),
            inner: Arc::new(Mutex::new(Inner::default())),
        }
    }

    /// Process-wide bus shared by every `Runner` and its external observers.
    pub fn global() -> &'static Self {
        GLOBAL.get_or_init(Self::new)
    }

    /// Publish an event to a session. Live subscribers are notified with the
    /// full event; the event is also retained for `drain` and `replay`.
    pub fn publish(&self, session_id: &str, kind: &str, payload_json: &str) -> Event {
        let seq = self.ids.fetch_add(1, Ordering::Relaxed) + 1;
        let event = Event {
            id: format!("evt-{seq:016x}"),
            session_id: session_id.to_string(),
            kind: kind.to_string(),
            payload_json: payload_json.to_string(),
            created_at: now_millis(),
        };
        let listeners: Vec<EventListener> = {
            let mut inner = self.inner.lock().unwrap();
            inner
                .all
                .entry(session_id.to_string())
                .or_default()
                .push(event.clone());
            inner
                .undrained
                .entry(session_id.to_string())
                .or_default()
                .push(event.clone());
            inner
                .subscribers
                .get(session_id)
                .map(|subs| subs.iter().map(|(_, listener)| listener.clone()).collect())
                .unwrap_or_default()
        };
        for listener in listeners {
            listener(&event);
        }
        event
    }

    /// Convenience wrapper that serializes a JSON payload.
    pub fn publish_json(&self, session_id: &str, kind: &str, payload: &serde_json::Value) -> Event {
        self.publish(session_id, kind, &payload.to_string())
    }

    /// Register a live listener for a session. Returns a subscription id that
    /// can be passed to `unsubscribe`.
    pub fn subscribe(
        &self,
        session_id: &str,
        listener: impl Fn(&Event) + Send + Sync + 'static,
    ) -> usize {
        let mut inner = self.inner.lock().unwrap();
        inner.next_subscription += 1;
        let id = inner.next_subscription;
        inner
            .subscribers
            .entry(session_id.to_string())
            .or_default()
            .push((id, Arc::new(listener)));
        id
    }

    pub fn unsubscribe(&self, session_id: &str, subscription: usize) -> bool {
        let mut inner = self.inner.lock().unwrap();
        let Some(subs) = inner.subscribers.get_mut(session_id) else {
            return false;
        };
        let before = subs.len();
        subs.retain(|(id, _)| *id != subscription);
        subs.len() != before
    }

    /// Return (and clear) events published since the last `drain` for a session.
    pub fn drain(&self, session_id: &str) -> Vec<Event> {
        self.inner
            .lock()
            .unwrap()
            .undrained
            .remove(session_id)
            .unwrap_or_default()
    }

    /// Return all retained events for a session without consuming them.
    pub fn replay(&self, session_id: &str) -> Vec<Event> {
        self.inner
            .lock()
            .unwrap()
            .all
            .get(session_id)
            .cloned()
            .unwrap_or_default()
    }

    /// Replay events starting at `offset` in publication order.
    pub fn replay_since(&self, session_id: &str, offset: usize) -> Vec<Event> {
        self.replay(session_id).into_iter().skip(offset).collect()
    }

    pub fn len(&self, session_id: &str) -> usize {
        self.inner
            .lock()
            .unwrap()
            .all
            .get(session_id)
            .map_or(0, Vec::len)
    }

    pub fn is_empty(&self, session_id: &str) -> bool {
        self.len(session_id) == 0
    }

    pub fn pending_len(&self, session_id: &str) -> usize {
        self.inner
            .lock()
            .unwrap()
            .undrained
            .get(session_id)
            .map_or(0, Vec::len)
    }
}

/// Fold a stream of events into a state struct.
pub trait Projection {
    type State: Default;

    /// Apply a single event to the accumulated state.
    fn apply(state: &mut Self::State, event: &Event);

    /// Fold an ordered event slice from `Default::default()`.
    fn fold(events: &[Event]) -> Self::State
    where
        Self: Sized,
    {
        let mut state = Self::State::default();
        for event in events {
            Self::apply(&mut state, event);
        }
        state
    }
}

/// Free-function wrapper around [`Projection::fold`].
pub fn fold_events<P: Projection>(events: &[Event]) -> P::State {
    P::fold(events)
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
    fn replay_and_drain_are_independent() {
        let bus = EventBus::new();
        bus.publish("s", "created", "{}");
        bus.publish("s", "step", "{\"n\":1}");
        bus.publish("other", "created", "{}");

        assert_eq!(bus.len("s"), 2);
        assert_eq!(bus.pending_len("s"), 2);
        assert_eq!(bus.drain("s").len(), 2);
        assert!(bus.drain("s").is_empty());
        // Draining does not remove the historical record.
        assert_eq!(bus.replay("s").len(), 2);
        assert_eq!(bus.replay_since("s", 1)[0].kind, "step");
        assert!(bus.is_empty("missing"));
    }

    #[test]
    fn subscribers_see_published_events() {
        let bus = EventBus::new();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let captured = Arc::clone(&seen);
        let sub = bus.subscribe("s", move |event| {
            captured.lock().unwrap().push(event.kind.clone());
        });

        bus.publish("s", "first", "{}");
        assert!(bus.unsubscribe("s", sub));
        bus.publish("s", "second", "{}");
        assert_eq!(seen.lock().unwrap().as_slice(), &["first".to_string()]);
        assert!(!bus.unsubscribe("s", sub));
    }

    struct CountTicks;
    impl Projection for CountTicks {
        type State = usize;
        fn apply(state: &mut Self::State, event: &Event) {
            if event.kind == "tick" {
                *state += 1;
            }
        }
    }

    #[test]
    fn projection_folds_events_into_state() {
        let bus = EventBus::new();
        bus.publish("s", "tick", "{}");
        bus.publish("s", "other", "{}");
        bus.publish("s", "tick", "{}");
        assert_eq!(fold_events::<CountTicks>(&bus.replay("s")), 2);
    }
}
