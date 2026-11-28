//! V3 Phase P6+ — operator runtime commands for the Tauri shell.
//!
//! Reuses the proven core APIs (`run_goal_stream`, `chat_turn`, `steer`,
//! `request_stop`, `resume_session`) instead of duplicating the harness. All
//! events travel through a plain `mpsc` channel; the Tauri layer bridges them
//! to an ordered `tauri::ipc::Channel`.

use crate::config::{resolve_api_key, AppConfig};
use bugfound_core::execution::ExecutionCoordinator;
use bugfound_core::{build_policy_config, request_stop, AgentConfig, Runner};
use bugfound_llm::{Llm, LlmClient, LlmConfig};
use bugfound_policy::{Mode, PolicyConfig};
use bugfound_store::Store;
use serde::Serialize;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};

// E4: the dead `ApprovalRequired` variant is deliberately removed. Approvals
// are still surfaced through `pending_approvals` polling and `Status` events;
// the frontend must drop its matching `types.ts` case in a separate change.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum RuntimeEvent {
    Started { session_id: String },
    Delta { session_id: String, text: String },
    Finished { session_id: String, text: String },
    Error { text: String },
    Status { state: String },
}

enum RuntimeCommand {
    Chat {
        config: AppConfig,
        text: String,
        events: mpsc::Sender<RuntimeEvent>,
    },
    ChatSend {
        config: AppConfig,
        session: String,
        text: String,
        events: mpsc::Sender<RuntimeEvent>,
    },
    Approval {
        config: AppConfig,
        session: String,
        decision: String,
        events: mpsc::Sender<RuntimeEvent>,
    },
    EngagementStart {
        config: AppConfig,
        url: String,
        cwd: String,
        events: mpsc::Sender<RuntimeEvent>,
    },
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeStatus {
    pub active_session: Option<String>,
    pub busy: bool,
}

#[derive(Clone)]
pub struct RuntimeHandle {
    commands: mpsc::Sender<RuntimeCommand>,
    store: Store,
    /// On-disk DB location, when one exists. Engagement aborts must reopen the
    /// same file rather than an unrelated (possibly in-memory) connection.
    db_path: Option<PathBuf>,
    active: Arc<Mutex<Option<String>>>,
    busy: Arc<Mutex<bool>>,
    /// Last event sink. Synchronous control commands (`steer`) have no channel
    /// of their own, so failures are reported to the most recent UI sink.
    last_events: Arc<Mutex<Option<mpsc::Sender<RuntimeEvent>>>>,
}

impl RuntimeHandle {
    pub fn new(store: Store) -> Self {
        let (handle, receiver) = Self::new_with_receiver(store);
        handle.spawn_worker(receiver);
        handle
    }

    /// Split construction from worker startup so tests can inspect the queued
    /// command without racing the worker thread.
    fn new_with_receiver(store: Store) -> (Self, mpsc::Receiver<RuntimeCommand>) {
        let (commands, receiver) = mpsc::channel::<RuntimeCommand>();
        let handle = Self {
            commands,
            store,
            db_path: None,
            active: Arc::new(Mutex::new(None::<String>)),
            busy: Arc::new(Mutex::new(false)),
            last_events: Arc::new(Mutex::new(None)),
        };
        (handle, receiver)
    }

    /// Bind the on-disk DB location so `stop` can abort engagements durably.
    pub fn with_db_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.db_path = Some(path.into());
        self
    }

    fn spawn_worker(&self, receiver: mpsc::Receiver<RuntimeCommand>) {
        let store = self.store.clone();
        let worker_active = self.active.clone();
        let worker_busy = self.busy.clone();
        std::thread::spawn(move || {
            let runtime = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime,
                Err(_) => return,
            };
            for command in receiver {
                match command {
                    RuntimeCommand::Chat {
                        config,
                        text,
                        events,
                    } => {
                        set_busy(&worker_busy, true);
                        let (delta_tx, delta_rx) = tokio::sync::mpsc::unbounded_channel();
                        let forwarder = forward_deltas(delta_rx, &events, String::new());
                        let outcome = runtime.block_on(async {
                            let runner = build_runner(&store, &config)?;
                            let text = runner.run_goal_stream(&text, Some(delta_tx)).await?;
                            let session = newest_session(&store);
                            set_active(&worker_active, session.clone());
                            Ok((session.unwrap_or_default(), text))
                        });
                        emit_terminal(forwarder, &events, outcome);
                        set_busy(&worker_busy, false);
                    }
                    RuntimeCommand::ChatSend {
                        config,
                        session,
                        text,
                        events,
                    } => {
                        set_busy(&worker_busy, true);
                        let (delta_tx, delta_rx) = tokio::sync::mpsc::unbounded_channel();
                        let forwarder = forward_deltas(delta_rx, &events, session.clone());
                        let outcome = runtime.block_on(async {
                            let runner = build_runner(&store, &config)?;
                            let text = runner.chat_turn(&session, &text, Some(delta_tx)).await?;
                            Ok((session.clone(), text))
                        });
                        emit_terminal(forwarder, &events, outcome);
                        set_busy(&worker_busy, false);
                    }
                    RuntimeCommand::Approval {
                        config,
                        session,
                        decision,
                        events,
                    } => {
                        // E22: an approval runs a resumed turn, so busy must stay
                        // true until that turn reaches a terminal event.
                        set_busy(&worker_busy, true);
                        let (delta_tx, delta_rx) = tokio::sync::mpsc::unbounded_channel();
                        let forwarder = forward_deltas(delta_rx, &events, session.clone());
                        let outcome = runtime.block_on(async {
                            let runner = build_runner(&store, &config)?;
                            let text = runner.resume_session(&session, &decision).await?;
                            Ok((session.clone(), text))
                        });
                        // `resume_session` has no delta sink yet; holding the
                        // sender until here keeps the forwarder ordered.
                        drop(delta_tx);
                        emit_terminal(forwarder, &events, outcome);
                        set_busy(&worker_busy, false);
                    }
                    RuntimeCommand::EngagementStart {
                        config,
                        url,
                        cwd,
                        events,
                    } => {
                        set_busy(&worker_busy, true);
                        let (bridge_tx, bridge_rx) =
                            mpsc::channel::<bugfound_engagement::EngagementEvent>();
                        let forward_events = events.clone();
                        let terminal_sent = Arc::new(AtomicBool::new(false));
                        let bridge_terminal = terminal_sent.clone();
                        let bridge = std::thread::spawn(move || {
                            while let Ok(event) = bridge_rx.recv() {
                                let mapped = match event {
                                    bugfound_engagement::EngagementEvent::Started {
                                        engagement_id,
                                    } => Some(RuntimeEvent::Started {
                                        session_id: engagement_id,
                                    }),
                                    bugfound_engagement::EngagementEvent::Finished { summary } => {
                                        bridge_terminal.store(true, Ordering::SeqCst);
                                        Some(RuntimeEvent::Finished {
                                            session_id: String::new(),
                                            text: bugfound_store::redact(&summary),
                                        })
                                    }
                                    bugfound_engagement::EngagementEvent::Error { message } => {
                                        Some(RuntimeEvent::Error {
                                            text: bugfound_store::redact(&message),
                                        })
                                    }
                                    bugfound_engagement::EngagementEvent::Finding {
                                        id: _,
                                        title,
                                        severity,
                                    } => Some(RuntimeEvent::Status {
                                        state: format!(
                                            "finding [{severity}] {}",
                                            bugfound_store::redact(&title)
                                        ),
                                    }),
                                    _ => None,
                                };
                                if let Some(mapped) = mapped {
                                    let _ = forward_events.send(mapped);
                                }
                            }
                        });
                        // E19: the webview must not choose the tool workspace.
                        let workspace = match confined_workspace(&workspace_root(&config), &cwd) {
                            Ok(path) => path,
                            Err(error) => {
                                drop(bridge_tx);
                                let _ = bridge.join();
                                let _ = events.send(RuntimeEvent::Error {
                                    text: redact_error(&error),
                                });
                                set_busy(&worker_busy, false);
                                continue;
                            }
                        };
                        let db_path = PathBuf::from(&config.storage.path);
                        let result = bugfound_engagement::engage_with_options_and_loop(
                            &url,
                            &workspace,
                            &db_path,
                            engagement_options(&config),
                            crate::config::roe_options(&config),
                            crate::config::loop_options(&config),
                            bridge_tx,
                        );
                        // E3: the bridge is drained before any terminal event.
                        let _ = bridge.join();
                        if let Err(error) = result {
                            if !terminal_sent.load(Ordering::SeqCst) {
                                let _ = events.send(RuntimeEvent::Error {
                                    text: redact_error(&error),
                                });
                            }
                        }
                        set_busy(&worker_busy, false);
                    }
                }
            }
        });
    }

    pub fn status(&self) -> RuntimeStatus {
        RuntimeStatus {
            active_session: self.active.lock().ok().and_then(|value| value.clone()),
            busy: *self.busy.lock().unwrap_or_else(|error| error.into_inner()),
        }
    }

    pub fn chat(&self, config: AppConfig, text: String, events: mpsc::Sender<RuntimeEvent>) {
        self.remember_events(&events);
        if self
            .commands
            .send(RuntimeCommand::Chat {
                config,
                text,
                events,
            })
            .is_err()
        {
            self.emit_control_error(&anyhow::anyhow!("runtime worker is unavailable"));
        }
    }

    pub fn chat_send(
        &self,
        config: AppConfig,
        session: String,
        text: String,
        events: mpsc::Sender<RuntimeEvent>,
    ) {
        self.remember_events(&events);
        if self
            .commands
            .send(RuntimeCommand::ChatSend {
                config,
                session,
                text,
                events,
            })
            .is_err()
        {
            self.emit_control_error(&anyhow::anyhow!("runtime worker is unavailable"));
        }
    }

    /// E2: a durable steer needs no LLM or API key, so it bypasses the worker
    /// entirely and writes straight to the session's store.
    pub fn steer(&self, session: String, text: String) {
        if let Err(error) = bugfound_core::steer(&self.store, &session, &text) {
            self.emit_control_error(&error);
        }
    }

    /// E1: stop is synchronous. Set the durable flag and wake in-process
    /// waiters, but leave `busy` truthful: the turn is still in flight.
    pub fn stop(&self, session: String) {
        request_stop(&self.store, &session);
        let _ = ExecutionCoordinator::global().interrupt(&session);
        if let Some(db_path) = &self.db_path {
            if self.store.get_engagement(&session).ok().flatten().is_some() {
                let _ = bugfound_engagement::abort_at(db_path, &session);
            }
        }
    }

    pub fn decide(
        &self,
        config: AppConfig,
        session: String,
        decision: String,
        events: mpsc::Sender<RuntimeEvent>,
    ) {
        // E22: the worker runs a resumed turn with deltas, so `busy` must be
        // visible to the UI before the command is queued.
        set_busy(&self.busy, true);
        self.remember_events(&events);
        if self
            .commands
            .send(RuntimeCommand::Approval {
                config,
                session,
                decision,
                events,
            })
            .is_err()
        {
            set_busy(&self.busy, false);
            self.emit_control_error(&anyhow::anyhow!("runtime worker is unavailable"));
        }
    }

    pub fn engagement_start(
        &self,
        config: AppConfig,
        url: String,
        cwd: String,
        events: mpsc::Sender<RuntimeEvent>,
    ) {
        self.remember_events(&events);
        if self
            .commands
            .send(RuntimeCommand::EngagementStart {
                config,
                url,
                cwd,
                events,
            })
            .is_err()
        {
            self.emit_control_error(&anyhow::anyhow!("runtime worker is unavailable"));
        }
    }

    fn remember_events(&self, events: &mpsc::Sender<RuntimeEvent>) {
        if let Ok(mut guard) = self.last_events.lock() {
            *guard = Some(events.clone());
        }
    }

    fn emit_control_error(&self, error: &anyhow::Error) {
        let text = redact_error(error);
        let delivered = match self.last_events.lock() {
            Ok(guard) => match guard.as_ref() {
                Some(events) => events
                    .send(RuntimeEvent::Error { text: text.clone() })
                    .is_ok(),
                None => false,
            },
            Err(_) => false,
        };
        if !delivered {
            eprintln!("bugfound runtime control error: {text}");
        }
    }
}

/// E19: the workspace is operator configuration, never a webview choice.
fn workspace_root(config: &AppConfig) -> PathBuf {
    let configured = config.workspace();
    if configured.is_empty() {
        PathBuf::from(".")
    } else {
        PathBuf::from(configured)
    }
}

fn canonical_or_normalized(path: &Path) -> PathBuf {
    if let Ok(canonical) = path.canonicalize() {
        return canonical;
    }
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// Confine a webview-supplied directory to the configured workspace. Both
/// sides are canonicalized when possible so symlinks cannot escape the root.
fn confined_workspace(root: &Path, candidate: &str) -> anyhow::Result<PathBuf> {
    let root = canonical_or_normalized(root);
    let raw = PathBuf::from(candidate);
    let joined = if raw.is_absolute() {
        raw
    } else {
        root.join(raw)
    };
    let resolved = canonical_or_normalized(&joined);
    if resolved.starts_with(&root) {
        Ok(resolved)
    } else {
        anyhow::bail!("workspace path escapes the configured root: {candidate}")
    }
}

/// E19: options carry no host paths; the workspace itself is taken from
/// config via [`workspace_root`] and confined before it reaches the engine.
fn engagement_options(config: &AppConfig) -> bugfound_engagement::EngagementOptions {
    let budgets = config.effective_budgets();
    bugfound_engagement::EngagementOptions {
        mode: crate::config::parse_mode(&config.agent.mode).unwrap_or(Mode::Ask),
        max_steps: budgets.max_steps,
        max_tool_calls: budgets.max_tool_calls,
        max_network_calls: budgets.max_network_calls,
        requests_per_minute: budgets.requests_per_minute,
        max_estimated_tokens: budgets.max_tokens,
        allow_network_write: config.network.allow_network_write,
        allow_intrusive: config.network.allow_intrusive,
        auto_approve_all: config.agent.auto_approve_all,
        oob_endpoint: config.oob.endpoint.clone(),
        oob_admin_token: config.oob.admin_token(),
        resume_from_checkpoint: config.agent.resume_from_checkpoint,
        trusted_local_targets: config.network.trusted_local_targets.clone(),
        external_commands: config.external_tools.commands.clone(),
    }
}

fn set_busy(flag: &Arc<Mutex<bool>>, value: bool) {
    if let Ok(mut guard) = flag.lock() {
        *guard = value;
    }
}

fn set_active(flag: &Arc<Mutex<Option<String>>>, value: Option<String>) {
    if let Ok(mut guard) = flag.lock() {
        *guard = value;
    }
}

fn newest_session(store: &Store) -> Option<String> {
    store.list_sessions(1).ok()?.first().map(|s| s.id.clone())
}

fn redact_error(error: &anyhow::Error) -> String {
    bugfound_store::redact(&format!("{error:#}"))
}

/// E3: drain the delta forwarder before emitting a terminal event so no delta
/// can ever arrive after `Finished`/`Error`.
fn emit_terminal(
    forwarder: std::thread::JoinHandle<()>,
    events: &mpsc::Sender<RuntimeEvent>,
    outcome: anyhow::Result<(String, String)>,
) {
    let _ = forwarder.join();
    match outcome {
        Ok((session_id, text)) => {
            let _ = events.send(RuntimeEvent::Finished {
                session_id,
                text: bugfound_store::redact(&text),
            });
        }
        Err(error) => {
            let _ = events.send(RuntimeEvent::Error {
                text: redact_error(&error),
            });
        }
    }
}

/// Number of trailing characters held back for re-redaction (E5).
const REDACT_CARRY: usize = 128;

fn split_tail(text: &str, keep: usize) -> (&str, &str) {
    let total = text.chars().count();
    if total <= keep {
        return ("", text);
    }
    let byte = text
        .char_indices()
        .nth(total - keep)
        .map(|(index, _)| index)
        .unwrap_or(text.len());
    text.split_at(byte)
}

/// Stream redacted deltas with a carry window. A secret split across two SSE
/// chunks is only ever redacted on the *combined* text, and the unreleased tail
/// is flushed (re-redacted) when the source closes.
fn forward_deltas(
    mut source: tokio::sync::mpsc::UnboundedReceiver<String>,
    events: &mpsc::Sender<RuntimeEvent>,
    session: String,
) -> std::thread::JoinHandle<()> {
    let events = events.clone();
    std::thread::spawn(move || {
        let mut carry = String::new();
        while let Some(chunk) = source.blocking_recv() {
            let mut combined = carry;
            combined.push_str(&chunk);
            let redacted = bugfound_store::redact(&combined);
            let (stable, tail) = split_tail(&redacted, REDACT_CARRY);
            carry = tail.to_string();
            if !stable.is_empty() {
                let _ = events.send(RuntimeEvent::Delta {
                    session_id: session.clone(),
                    text: stable.to_string(),
                });
            }
        }
        if !carry.is_empty() {
            let _ = events.send(RuntimeEvent::Delta {
                session_id: session,
                text: bugfound_store::redact(&carry),
            });
        }
    })
}

fn build_runner(store: &Store, config: &AppConfig) -> anyhow::Result<Runner> {
    let budgets = config.effective_budgets();
    let api_key = resolve_api_key(&config.llm.api_key)?;
    let llm_config = LlmConfig {
        base_url: config.llm.base_url.clone(),
        api_key,
        default_model: config.llm.default_model.clone(),
        fallback_models: config.llm.fallback_models.clone(),
        timeout_ms: config.llm.timeout_ms,
    };
    let llm: Arc<dyn Llm + Send + Sync> = Arc::new(LlmClient::new(llm_config)?);
    let mode = crate::config::parse_mode(&config.agent.mode).unwrap_or(Mode::Ask);
    // E11/A12: both layers see the same effective budgets; `0` means unset.
    let max_steps = budgets.max_steps;
    let max_tool_calls = budgets.max_tool_calls;
    let max_network_calls = budgets.max_network_calls;
    let requests_per_minute = budgets.requests_per_minute;
    let max_estimated_tokens = budgets.max_tokens;
    let policy = PolicyConfig {
        mode,
        scope: config.scope.clone(),
        budgets: budgets.clone(),
        budget: budgets.clone(),
        rate_limits: budgets.clone(),
        rate_limit: budgets,
        ..Default::default()
    };
    let agent = AgentConfig {
        mode,
        max_steps,
        system_prompt: config.agent.system_prompt.clone(),
        max_tool_calls,
        max_network_calls,
        requests_per_minute,
        auto_approve_tools: config.agent.auto_approve_tools.clone(),
        auto_approve_all: config.agent.auto_approve_all,
        max_estimated_tokens,
        cost_per_1k_input: config.llm.cost_per_1k_input,
        cost_per_1k_output: config.llm.cost_per_1k_output,
        stall_limit: 0,
        ..Default::default()
    };
    // E19: tools run inside the operator's configured workspace, never inside
    // a path supplied by the webview.
    let cwd = canonical_or_normalized(&workspace_root(config));
    let tools = bugfound_tools::try_default_registry_with_options(
        &cwd,
        bugfound_tools::ToolOptions {
            scope_in: config.scope.in_scope.clone(),
            scope_out: config.scope.out_of_scope.clone(),
            trusted_local_targets: config.network.trusted_local_targets.clone(),
            allow_proxy: config.network.allow_proxy,
            proxy_url: config.network.proxy_url.clone(),
            external_commands: config.external_tools.commands.clone(),
            ..Default::default()
        },
    )?;
    Ok(Runner::new(
        store.clone(),
        llm,
        tools,
        build_policy_config(policy),
        agent,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    fn collect(events: &mpsc::Receiver<RuntimeEvent>) -> Vec<RuntimeEvent> {
        let mut out = Vec::new();
        while let Ok(event) = events.try_recv() {
            out.push(event);
        }
        out
    }

    #[test]
    fn runtime_event_serialization_is_tagged() {
        let event = RuntimeEvent::Delta {
            session_id: "s1".into(),
            text: "hello".into(),
        };
        let json = serde_json::to_string(&event).expect("serialize");
        assert!(json.contains("\"kind\":\"delta\""));
    }

    #[test]
    fn status_starts_idle() {
        let store = bugfound_store::Store::open(":memory:").expect("store");
        let handle = RuntimeHandle::new(store);
        let status = handle.status();
        assert!(status.active_session.is_none());
        assert!(!status.busy);
    }

    #[test]
    fn stop_sets_flag_without_queueing() {
        let store = bugfound_store::Store::open(":memory:").expect("store");
        let session = store.create_session("stop me").expect("session");
        // No worker: this proves stop is entirely synchronous.
        let (handle, receiver) = RuntimeHandle::new_with_receiver(store.clone());

        handle.stop(session.id.clone());

        assert!(
            store
                .has_session_flag(&session.id, bugfound_core::STOP_REQUESTED_FLAG)
                .expect("flag"),
            "stop must persist the durable flag before returning"
        );
        assert!(
            !handle.status().busy,
            "stop must not fabricate a terminal busy=false"
        );
        assert!(
            receiver.try_recv().is_err(),
            "stop must not enqueue a worker command"
        );
    }

    #[test]
    fn steer_works_with_empty_api_key() {
        let store = bugfound_store::Store::open(":memory:").expect("store");
        let session = store.create_session("steer me").expect("session");
        assert!(AppConfig::default().llm.api_key.is_empty());
        let (handle, _receiver) = RuntimeHandle::new_with_receiver(store.clone());

        handle.steer(session.id.clone(), "new instruction".into());

        let items = store.list_pending_inbox(&session.id).expect("inbox");
        assert!(
            items
                .iter()
                .any(|item| item.kind == "steer" && item.payload_json.contains("new instruction")),
            "steer must land in the durable inbox without an LLM client"
        );
        assert!(
            ExecutionCoordinator::global()
                .take_wake_scoped(&session.id)
                .is_some(),
            "steer must ring the step-boundary doorbell"
        );
    }

    #[test]
    fn no_delta_after_finished() {
        let (delta_tx, delta_rx) = tokio::sync::mpsc::unbounded_channel();
        let (events_tx, events_rx) = mpsc::channel();
        let forwarder = forward_deltas(delta_rx, &events_tx, "s1".into());
        delta_tx.send("streamed text".into()).expect("send delta");
        drop(delta_tx);

        emit_terminal(forwarder, &events_tx, Ok(("s1".into(), "final".into())));

        let kinds: Vec<_> = collect(&events_rx)
            .into_iter()
            .map(|event| match event {
                RuntimeEvent::Delta { .. } => "delta",
                RuntimeEvent::Finished { .. } => "finished",
                RuntimeEvent::Error { .. } => "error",
                _ => "other",
            })
            .collect();
        assert_eq!(kinds, vec!["delta", "finished"]);
    }

    #[test]
    fn secret_split_across_deltas_is_redacted() {
        let (delta_tx, delta_rx) = tokio::sync::mpsc::unbounded_channel();
        let (events_tx, events_rx) = mpsc::channel();
        let forwarder = forward_deltas(delta_rx, &events_tx, "s1".into());
        delta_tx.send("result api_key=SUPER".into()).expect("send");
        delta_tx.send("SECRETVALUE99 ok".into()).expect("send");
        drop(delta_tx);
        forwarder.join().expect("forwarder");

        let visible: String = collect(&events_rx)
            .into_iter()
            .filter_map(|event| match event {
                RuntimeEvent::Delta { text, .. } => Some(text),
                _ => None,
            })
            .collect();
        assert!(
            !visible.contains("SUPERSECRETVALUE99"),
            "split secret leaked into deltas: {visible}"
        );
        assert!(
            visible.contains("api_key"),
            "benign text must survive redaction"
        );
    }

    #[test]
    fn approval_keeps_busy_until_finished() {
        let store = bugfound_store::Store::open(":memory:").expect("store");
        let (detached, receiver) = RuntimeHandle::new_with_receiver(store.clone());
        let (events_tx, _events_rx) = mpsc::channel();
        detached.decide(
            AppConfig::default(),
            "s1".into(),
            "approve".into(),
            events_tx,
        );
        assert!(detached.status().busy, "busy must be set before enqueueing");
        match receiver.recv().expect("queued approval") {
            RuntimeCommand::Approval {
                session, decision, ..
            } => {
                assert_eq!(session, "s1");
                assert_eq!(decision, "approve");
            }
            _ => panic!("expected an Approval command"),
        }

        // A live worker emits a terminal event before clearing busy.
        let handle = RuntimeHandle::new(store);
        let (events_tx, events_rx) = mpsc::channel();
        handle.decide(
            AppConfig::default(),
            "s1".into(),
            "approve".into(),
            events_tx,
        );
        let terminal = events_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("terminal event");
        assert!(matches!(
            terminal,
            RuntimeEvent::Finished { .. } | RuntimeEvent::Error { .. }
        ));
        let deadline = Instant::now() + Duration::from_secs(5);
        while handle.status().busy && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(
            !handle.status().busy,
            "busy must clear after the terminal event"
        );
    }
}
