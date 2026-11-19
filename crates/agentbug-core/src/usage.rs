//! Additive in-memory usage view. The durable store keeps its own token usage
//! accounting; this tracker only provides a fast per-session summary.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct UsageSummary {
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
    pub total_tokens: u64,
    pub cost_usd: f64,
    pub records: usize,
}

#[derive(Clone, Default)]
pub struct UsageTracker {
    inner: Arc<Mutex<HashMap<String, UsageSummary>>>,
}

impl UsageTracker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record(&self, session: &str, prompt: u64, completion: u64, cost: f64) {
        let mut inner = self.inner.lock().unwrap();
        let summary = inner.entry(session.to_string()).or_default();
        summary.prompt_tokens += prompt;
        summary.completion_tokens += completion;
        summary.total_tokens = summary.prompt_tokens + summary.completion_tokens;
        summary.cost_usd += cost;
        summary.records += 1;
    }

    pub fn summary(&self, session: &str) -> UsageSummary {
        self.inner
            .lock()
            .unwrap()
            .get(session)
            .copied()
            .unwrap_or_default()
    }

    pub fn sessions(&self) -> Vec<String> {
        let mut ids: Vec<String> = self.inner.lock().unwrap().keys().cloned().collect();
        ids.sort();
        ids
    }

    /// Aggregate across every tracked session.
    pub fn total(&self) -> UsageSummary {
        self.inner
            .lock()
            .unwrap()
            .values()
            .fold(UsageSummary::default(), |mut total, item| {
                total.prompt_tokens += item.prompt_tokens;
                total.completion_tokens += item.completion_tokens;
                total.total_tokens += item.total_tokens;
                total.cost_usd += item.cost_usd;
                total.records += item.records;
                total
            })
    }

    pub fn reset(&self, session: &str) {
        self.inner.lock().unwrap().remove(session);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aggregates_by_session() {
        let tracker = UsageTracker::new();
        tracker.record("a", 10, 5, 0.25);
        tracker.record("a", 20, 7, 0.75);
        tracker.record("b", 3, 1, 0.01);

        let a = tracker.summary("a");
        assert_eq!(a.prompt_tokens, 30);
        assert_eq!(a.completion_tokens, 12);
        assert_eq!(a.total_tokens, 42);
        assert_eq!(a.records, 2);
        assert!((a.cost_usd - 1.0).abs() < 1e-9);

        assert_eq!(tracker.summary("missing"), UsageSummary::default());
        assert_eq!(tracker.sessions(), vec!["a".to_string(), "b".to_string()]);
        assert_eq!(tracker.total().total_tokens, 46);
        tracker.reset("a");
        assert_eq!(tracker.summary("a"), UsageSummary::default());
    }
}
