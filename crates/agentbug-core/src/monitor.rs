//! Background operational monitor: bounded live/durable observation, a small
//! controller surface, and a hash-chained JSONL journal.
//!
//! Deliberately domain-agnostic. All identifiers and kinds are neutral; no
//! effectiveness metric is computed here. Every emitted record states that
//! it is operational telemetry and asserts no benchmark result.

use crate::event::{Event, EventBus};
use agentbug_store::Store;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashSet, VecDeque};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub const JOURNAL_CLAIM: &str =
    "operational telemetry only; no effectiveness or benchmark result asserted";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MonitorState {
    Stopped,
    Running,
    Paused,
}

#[derive(Debug, Clone)]
pub struct MonitorConfig {
    pub ring_capacity: usize,
    pub tick_period: Duration,
    pub replay_batch: usize,
    pub journal_dir: PathBuf,
}

impl Default for MonitorConfig {
    fn default() -> Self {
        Self {
            ring_capacity: 256,
            tick_period: Duration::from_secs(2),
            replay_batch: 200,
            journal_dir: PathBuf::from("eval/work/monitor"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Observation {
    pub seq: u64,
    pub ts_ms: u64,
    pub source: String,
    pub kind: String,
    pub level: String,
    pub text: String,
    pub latency_ms: u64,
    pub hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct BucketView {
    pub retained: usize,
    pub total: u64,
    pub dropped: u64,
    pub last_ts_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MonitorSnapshot {
    pub key: String,
    pub observed_seq: u64,
    pub total_observed: u64,
    pub total_suppressed: u64,
    pub total_dropped: u64,
    pub paused: bool,
    pub buckets: BTreeMap<String, BucketView>,
    pub recent: Vec<Observation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthReport {
    pub key: String,
    pub evaluated_at: String,
    pub monitor_state: MonitorState,
    pub paused: bool,
    pub session_state: String,
    pub observed_seq: u64,
    pub observed_total: u64,
    pub durable_events: usize,
    pub live_replay_events: usize,
    pub events_by_kind: BTreeMap<String, usize>,
    pub chain_valid: bool,
    pub steps_used: usize,
    pub tool_calls_used: usize,
    pub network_calls_used: usize,
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
    pub cost_usd: f64,
    pub trace_records: usize,
    pub latency_p50_ms: u64,
    pub latency_p95_ms: u64,
    pub latency_max_ms: u64,
    pub no_benchmark_claim: bool,
    pub claim: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JournalLine {
    pub v: u32,
    pub ts: String,
    pub run_id: String,
    pub key: String,
    pub event: String,
    pub state: MonitorState,
    pub snapshot: MonitorSnapshot,
    pub health: Option<HealthReport>,
    pub prev_hash: String,
    pub hash: String,
    pub no_benchmark_claim: bool,
    pub claim: String,
}

#[derive(Debug, Clone)]
struct Ring {
    cap: usize,
    items: VecDeque<Observation>,
    total: u64,
    dropped: u64,
}

impl Ring {
    fn new(cap: usize) -> Self {
        Self {
            cap: cap.max(1),
            items: VecDeque::new(),
            total: 0,
            dropped: 0,
        }
    }

    fn push(&mut self, observation: Observation) {
        self.total += 1;
        if self.items.len() == self.cap {
            self.items.pop_front();
            self.dropped += 1;
        }
        self.items.push_back(observation);
    }
}

#[derive(Debug)]
struct SessionRing {
    buckets: BTreeMap<String, Ring>,
    recent_keys: VecDeque<String>,
    key_index: HashSet<String>,
    last_event_ms: u64,
    total_observed: u64,
    total_suppressed: u64,
    total_dropped: u64,
    last_seq: u64,
}

impl SessionRing {
    fn new() -> Self {
        Self {
            buckets: BTreeMap::new(),
            recent_keys: VecDeque::new(),
            key_index: HashSet::new(),
            last_event_ms: 0,
            total_observed: 0,
            total_suppressed: 0,
            total_dropped: 0,
            last_seq: 0,
        }
    }
}

struct JournalState {
    path: PathBuf,
    last_hash: String,
    seen: VecDeque<String>,
}

struct MonitorInner {
    state: Mutex<MonitorState>,
    run_id: String,
    next_seq: AtomicU64,
    by_key: Mutex<BTreeMap<String, SessionRing>>,
    tracked: Mutex<BTreeSet<String>>,
    paused: Mutex<BTreeSet<String>>,
    subscriptions: Mutex<BTreeMap<String, usize>>,
    journal: Mutex<JournalState>,
    config: MonitorConfig,
    store: Store,
    bus: EventBus,
}

/// Thread-safe handle. All controller methods are idempotent where stated.
#[derive(Clone)]
pub struct Monitor {
    inner: Arc<MonitorInner>,
    task: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>,
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339()
}

fn classify(kind: &str, level: &str) -> &'static str {
    let lower = kind.to_ascii_lowercase();
    if level.eq_ignore_ascii_case("error") || lower.contains("error") || lower.contains("denied") {
        "error"
    } else if lower.contains("verdict") || lower.contains("validated") {
        "verdict"
    } else if lower.contains("tool") || lower.contains("action") {
        "tool"
    } else if lower.contains("result") || lower.contains("saved") {
        "result"
    } else {
        "tool"
    }
}

fn truncate_text(text: &str) -> String {
    text.chars().take(300).collect()
}

fn observation_hash(key: &str, kind: &str, level: &str, text: &str, ts_ms: u64) -> String {
    let digest = Sha256::digest(
        format!(
            "{key}|{kind}|{level}|{}|{}",
            truncate_text(text),
            ts_ms / 1000
        )
        .as_bytes(),
    );
    format!("{:x}", digest)
}

impl Monitor {
    pub fn new(store: Store, bus: EventBus, config: MonitorConfig) -> Self {
        let run_id = uuid::Uuid::new_v4().to_string();
        let _ = std::fs::create_dir_all(&config.journal_dir);
        let journal_path = config.journal_dir.join(format!("monitor-{run_id}.jsonl"));
        let journal = JournalState {
            path: journal_path,
            last_hash: String::new(),
            seen: VecDeque::with_capacity(4096),
        };
        Self {
            inner: Arc::new(MonitorInner {
                state: Mutex::new(MonitorState::Stopped),
                run_id,
                next_seq: AtomicU64::new(0),
                by_key: Mutex::new(BTreeMap::new()),
                tracked: Mutex::new(BTreeSet::new()),
                paused: Mutex::new(BTreeSet::new()),
                subscriptions: Mutex::new(BTreeMap::new()),
                journal: Mutex::new(journal),
                config,
                store,
                bus,
            }),
            task: Arc::new(Mutex::new(None)),
        }
    }

    pub fn state(&self) -> MonitorState {
        *self.inner.state.lock().unwrap()
    }

    pub fn start(&self) -> Result<()> {
        {
            let mut state = self.inner.state.lock().unwrap();
            if *state == MonitorState::Running || *state == MonitorState::Paused {
                return Ok(());
            }
            *state = MonitorState::Running;
        }
        let mut handle = self.task.lock().unwrap();
        if handle.is_some() {
            return Ok(());
        }
        self.append_journal("lifecycle", "monitor", None, None);
        let weak = Arc::downgrade(&self.inner);
        let period = self.inner.config.tick_period;
        *handle = Some(tokio::spawn(async move {
            loop {
                tokio::time::sleep(period).await;
                let Some(inner) = weak.upgrade() else {
                    break;
                };
                if *inner.state.lock().unwrap() != MonitorState::Running {
                    continue;
                }
                Monitor::tick_inner(&inner);
            }
        }));
        Ok(())
    }

    pub async fn stop(&self) -> Result<()> {
        {
            let mut state = self.inner.state.lock().unwrap();
            if *state == MonitorState::Stopped {
                return Ok(());
            }
            *state = MonitorState::Stopped;
        }
        if let Some(handle) = self.task.lock().unwrap().take() {
            handle.abort();
        }
        let subscriptions = std::mem::take(&mut *self.inner.subscriptions.lock().unwrap());
        for (session_id, id) in subscriptions {
            let _ = self.inner.bus.unsubscribe(&session_id, id);
        }
        self.append_journal("lifecycle", "monitor", None, None);
        Ok(())
    }

    pub fn track(&self, key: &str) {
        if key.trim().is_empty() {
            return;
        }
        self.inner.tracked.lock().unwrap().insert(key.to_string());
        self.subscribe(key);
        self.ensure_ring(key);
    }

    pub fn pause(&self, key: &str) -> bool {
        self.inner.paused.lock().unwrap().insert(key.to_string())
    }

    pub fn resume(&self, key: &str) -> bool {
        self.inner.paused.lock().unwrap().remove(key)
    }

    pub fn is_paused(&self, key: &str) -> bool {
        self.inner.paused.lock().unwrap().contains(key)
    }

    pub fn observe(&self, key: &str, kind: &str, level: &str, text: &str) {
        self.ensure_ring(key);
        if self.is_paused(key) {
            if let Some(ring) = self.inner.by_key.lock().unwrap().get_mut(key) {
                ring.total_suppressed += 1;
            }
            return;
        }
        Monitor::accept(&self.inner, key, kind, level, text, "adapter");
    }

    pub fn snapshot(&self, key: &str) -> MonitorSnapshot {
        let by_key = self.inner.by_key.lock().unwrap();
        let Some(ring) = by_key.get(key) else {
            return MonitorSnapshot {
                key: key.to_string(),
                observed_seq: 0,
                total_observed: 0,
                total_suppressed: 0,
                total_dropped: 0,
                paused: self.is_paused(key),
                buckets: BTreeMap::new(),
                recent: Vec::new(),
            };
        };
        let mut buckets = BTreeMap::new();
        for (name, bucket) in &ring.buckets {
            buckets.insert(
                name.clone(),
                BucketView {
                    retained: bucket.items.len(),
                    total: bucket.total,
                    dropped: bucket.dropped,
                    last_ts_ms: bucket.items.back().map(|o| o.ts_ms).unwrap_or(0),
                },
            );
        }
        let mut recent: Vec<Observation> = ring
            .buckets
            .values()
            .flat_map(|bucket| bucket.items.iter().cloned())
            .collect();
        recent.sort_by_key(|o| o.seq);
        recent.truncate(16);
        MonitorSnapshot {
            key: key.to_string(),
            observed_seq: ring.last_seq,
            total_observed: ring.total_observed,
            total_suppressed: ring.total_suppressed,
            total_dropped: ring.total_dropped,
            paused: self.is_paused(key),
            buckets,
            recent,
        }
    }

    pub fn snapshot_all(&self) -> Vec<MonitorSnapshot> {
        let keys: Vec<String> = self.inner.by_key.lock().unwrap().keys().cloned().collect();
        keys.iter().map(|key| self.snapshot(key)).collect()
    }

    pub fn evaluate(&self, key: &str) -> Result<HealthReport> {
        let snapshot = self.snapshot(key);
        let session = self.inner.store.get_session(key)?;
        let durable_events = self
            .inner
            .store
            .list_events(key, self.inner.config.replay_batch)?;
        let events_by_kind = self.inner.store.event_kind_counts(key)?;
        let trace_records = self
            .inner
            .store
            .list_trace(key, self.inner.config.replay_batch)?;
        let chain_valid = self.inner.store.verify_event_chain(key)?;
        let budget = self.inner.store.budget_usage(key)?;
        let tokens = self.inner.store.token_usage(key)?;
        let latencies: Vec<u64> = snapshot
            .recent
            .iter()
            .filter(|o| o.latency_ms > 0)
            .map(|o| o.latency_ms)
            .collect();
        let (p50, p95, max) = percentile_summary(&latencies);
        let report = HealthReport {
            key: key.to_string(),
            evaluated_at: now_rfc3339(),
            monitor_state: self.state(),
            paused: snapshot.paused,
            session_state: session
                .as_ref()
                .map(|s| s.state.clone())
                .unwrap_or_default(),
            observed_seq: snapshot.observed_seq,
            observed_total: snapshot.total_observed,
            durable_events: durable_events.len(),
            live_replay_events: self.inner.bus.replay(key).len(),
            events_by_kind,
            chain_valid,
            steps_used: budget.steps_used,
            tool_calls_used: budget.tool_calls_used,
            network_calls_used: budget.network_calls_used,
            prompt_tokens: tokens.prompt_tokens,
            completion_tokens: tokens.completion_tokens,
            cost_usd: tokens.cost_usd,
            trace_records: trace_records.len(),
            latency_p50_ms: p50,
            latency_p95_ms: p95,
            latency_max_ms: max,
            no_benchmark_claim: true,
            claim: JOURNAL_CLAIM.to_string(),
        };
        self.append_journal("evaluate", key, Some(&snapshot), Some(&report));
        Ok(report)
    }

    fn ensure_ring(&self, key: &str) {
        let mut by_key = self.inner.by_key.lock().unwrap();
        by_key
            .entry(key.to_string())
            .or_insert_with(SessionRing::new);
    }

    fn subscribe(&self, key: &str) {
        let mut subscriptions = self.inner.subscriptions.lock().unwrap();
        if subscriptions.contains_key(key) {
            return;
        }
        let inner = Arc::downgrade(&self.inner);
        let observed_key = key.to_string();
        let listener = move |event: &Event| {
            let Some(inner) = inner.upgrade() else {
                return;
            };
            Monitor::accept(
                &inner,
                &observed_key,
                &event.kind,
                "info",
                &event.payload_json,
                "live",
            );
        };
        let id = self.inner.bus.subscribe(key, listener);
        subscriptions.insert(key.to_string(), id);
    }

    fn accept(inner: &MonitorInner, key: &str, kind: &str, level: &str, text: &str, source: &str) {
        if inner.paused.lock().unwrap().contains(key) {
            if let Some(ring) = inner.by_key.lock().unwrap().get_mut(key) {
                ring.total_suppressed += 1;
            }
            return;
        }
        let ts_ms = now_ms();
        let seq = inner.next_seq.fetch_add(1, Ordering::Relaxed) + 1;
        let hash = observation_hash(key, kind, level, text, ts_ms);
        let bucket = classify(kind, level).to_string();
        let mut by_key = inner.by_key.lock().unwrap();
        let ring = by_key
            .entry(key.to_string())
            .or_insert_with(SessionRing::new);
        if ring.key_index.contains(&hash) {
            ring.total_suppressed += 1;
            return;
        }
        ring.total_observed += 1;
        ring.last_seq = seq;
        let latency_ms = if ring.last_event_ms == 0 {
            0
        } else {
            ts_ms.saturating_sub(ring.last_event_ms)
        };
        ring.last_event_ms = ts_ms;
        let low_risk = agentbug_store::redact(text);
        let observation = Observation {
            seq,
            ts_ms,
            source: source.to_string(),
            kind: kind.to_string(),
            level: level.to_string(),
            text: truncate_text(&low_risk),
            latency_ms,
            hash: hash.clone(),
        };
        let cap = inner.config.ring_capacity;
        ring.buckets
            .entry(bucket.clone())
            .or_insert_with(|| Ring::new(cap))
            .push(observation.clone());
        if bucket != "latency" && observation.latency_ms > 0 {
            ring.buckets
                .entry("latency".to_string())
                .or_insert_with(|| Ring::new(cap))
                .push(Observation {
                    kind: "latency".to_string(),
                    ..observation.clone()
                });
        }
        if ring.key_index.insert(hash.clone()) {
            ring.recent_keys.push_back(hash);
            while ring.recent_keys.len() > cap * 4 {
                if let Some(old) = ring.recent_keys.pop_front() {
                    ring.key_index.remove(&old);
                }
            }
        }
    }

    fn tick_inner(inner: &MonitorInner) {
        let sessions = inner.store.list_sessions(500).unwrap_or_default();
        for session in sessions {
            let key = session.id;
            if !inner.tracked.lock().unwrap().contains(&key) {
                inner.tracked.lock().unwrap().insert(key.clone());
            }
            if !inner.subscriptions.lock().unwrap().contains_key(&key) {
                // Durable backfill alone covers sessions discovered after start;
                // live subscription for late sessions is handled by `track`.
                // Registering a listener here would require an Arc cycle.
                inner.subscriptions.lock().unwrap().insert(key.clone(), 0);
            }
            let events = inner
                .store
                .list_events(&key, inner.config.replay_batch)
                .unwrap_or_default();
            for event in events {
                let level = "info";
                Monitor::accept(inner, &key, &event.kind, level, &event.message, "durable");
            }
        }
    }

    pub(crate) fn append_journal(
        &self,
        event: &str,
        key: &str,
        snapshot: Option<&MonitorSnapshot>,
        health: Option<&HealthReport>,
    ) {
        let mut journal = self.inner.journal.lock().unwrap();
        let ts = now_rfc3339();
        let snapshot = snapshot.cloned().unwrap_or_else(|| self.snapshot(key));
        let canonical = format!(
            "1|{ts}|{}|{key}|{event}|{:?}|{}|{}",
            self.inner.run_id,
            self.state(),
            serde_json::to_string(&snapshot).unwrap_or_default(),
            journal.last_hash
        );
        let hash = format!("{:x}", Sha256::digest(canonical.as_bytes()));
        if journal.seen.contains(&hash) {
            return;
        }
        let line = JournalLine {
            v: 1,
            ts: ts.clone(),
            run_id: self.inner.run_id.clone(),
            key: key.to_string(),
            event: event.to_string(),
            state: self.state(),
            snapshot,
            health: health.cloned(),
            prev_hash: journal.last_hash.clone(),
            hash: hash.clone(),
            no_benchmark_claim: true,
            claim: JOURNAL_CLAIM.to_string(),
        };
        if let Ok(mut file) = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&journal.path)
        {
            if serde_json::to_writer(&mut file, &line).is_ok() {
                let _ = file.write_all(b"\n");
                let _ = file.flush();
            }
        }
        journal.last_hash = hash.clone();
        journal.seen.push_back(hash);
        while journal.seen.len() > 4096 {
            journal.seen.pop_front();
        }
    }
}

fn percentile_summary(samples: &[u64]) -> (u64, u64, u64) {
    if samples.is_empty() {
        return (0, 0, 0);
    }
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    let p = |fraction: f64| -> u64 {
        let index = ((sorted.len() as f64 * fraction).ceil() as usize).saturating_sub(1);
        sorted[index.min(sorted.len() - 1)]
    };
    (p(0.50), p(0.95), *sorted.last().unwrap_or(&0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ring_buffer_is_bounded_and_drops_oldest() {
        let mut ring = Ring::new(3);
        for seq in 1..=5 {
            ring.push(Observation {
                seq,
                ts_ms: seq,
                source: "test".to_string(),
                kind: "tool".to_string(),
                level: "info".to_string(),
                text: format!("entry-{seq}"),
                latency_ms: 0,
                hash: format!("h{seq}"),
            });
        }
        assert_eq!(ring.items.len(), 3);
        assert_eq!(ring.items[0].seq, 3);
        assert_eq!(ring.total, 5);
        assert_eq!(ring.dropped, 2);
    }

    #[test]
    fn snapshot_is_pure_and_session_scoped() {
        let store = Store::open(":memory:").unwrap();
        let bus = EventBus::new();
        let monitor = Monitor::new(store, bus.clone(), MonitorConfig::default());
        monitor.track("s");
        monitor.observe("s", "tool.started", "info", "first");
        monitor.observe("s", "verdict.set", "info", "second");
        let a = monitor.snapshot("s");
        let b = monitor.snapshot("s");
        assert_eq!(a, b);
        assert_eq!(a.total_observed, 2);
        assert!(a.buckets.contains_key("tool"));
        assert!(a.buckets.contains_key("verdict"));
        assert!(monitor.snapshot("other").recent.is_empty());
    }

    #[test]
    fn pause_suppresses_observation_for_one_key() {
        let store = Store::open(":memory:").unwrap();
        let bus = EventBus::new();
        let monitor = Monitor::new(store, bus, MonitorConfig::default());
        monitor.track("a");
        monitor.track("b");
        assert!(monitor.pause("a"));
        monitor.observe("a", "tool.started", "info", "only-a");
        monitor.observe("b", "tool.started", "info", "only-b");
        assert_eq!(monitor.snapshot("a").total_observed, 0);
        assert_eq!(monitor.snapshot("a").total_suppressed, 1);
        assert_eq!(monitor.snapshot("b").total_observed, 1);
        assert!(monitor.resume("a"));
    }

    #[test]
    fn evaluate_reports_no_benchmark_claim() {
        let store = Store::open(":memory:").unwrap();
        let session = store.create_session("goal").unwrap();
        store
            .add_event(&session.id, "info", "tool.allowed", "ok")
            .unwrap();
        let bus = EventBus::new();
        let dir = std::env::temp_dir().join(format!("agentbug-monitor-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let monitor = Monitor::new(
            store,
            bus,
            MonitorConfig {
                journal_dir: dir,
                ..Default::default()
            },
        );
        let report = monitor.evaluate(&session.id).unwrap();
        assert!(report.no_benchmark_claim);
        assert_eq!(report.claim, JOURNAL_CLAIM);
        assert!(report.chain_valid);
        assert_eq!(report.durable_events, 1);
        let json = serde_json::to_string(&report).unwrap();
        assert!(!json.contains("\"precision\""));
        assert!(!json.contains("\"recall\""));
        assert!(!json.contains("\"score\""));
    }
}
