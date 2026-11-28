use crate::config::{resolve_api_key, AppConfig};
use anyhow::{Context, Result};
use bugfound_core::{AgentConfig, Runner};
use bugfound_engagement::EngagementEvent;
use bugfound_llm::LlmConfig;
use bugfound_policy::{Mode, PolicyConfig};
use bugfound_store::Store;
use bugfound_tools::{try_default_registry_with_options, ToolOptions};
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::Arc;
use std::thread::JoinHandle;

#[allow(dead_code)]
pub enum Job {
    Run {
        goal: String,
        cwd: String,
        mode: Mode,
    },
    Approve {
        session: String,
        decision: String,
        cwd: String,
        mode: Mode,
    },
}

#[allow(dead_code)]
pub enum JobEvent {
    Started { label: String },
    Finished { text: String },
    Error { text: String },
}

fn job_label(job: &Job) -> String {
    match job {
        Job::Run { goal, .. } => {
            let preview: String = goal.trim().chars().take(60).collect();
            format!("run: {preview}")
        }
        Job::Approve {
            session, decision, ..
        } => {
            let short: String = session.chars().take(8).collect();
            format!("{decision}: {short}")
        }
    }
}

fn policy_config(config: &AppConfig, mode: Mode) -> PolicyConfig {
    // A12: the same effective budgets feed both PolicyConfig layers.
    let budgets = config.effective_budgets();
    PolicyConfig {
        mode,
        scope: config.scope.clone(),
        allowed_tools: config.policy.allowed_tools.clone(),
        denied_tools: config.policy.denied_tools.clone(),
        allowed_targets: config.policy.allowed_targets.clone(),
        denied_targets: config.policy.denied_targets.clone(),
        budgets: budgets.clone(),
        rate_limits: budgets,
        ..Default::default()
    }
}

fn agent_config(config: &AppConfig, mode: Mode) -> AgentConfig {
    let budgets = config.effective_budgets();
    let max_steps = budgets.max_steps;
    AgentConfig {
        mode,
        max_steps,
        system_prompt: config
            .agent
            .system_prompt
            .clone()
            .or_else(|| config.agent.system.clone()),
        budgets: budgets.clone(),
        budget: budgets.clone(),
        rate_limits: budgets.clone(),
        rate_limit: budgets.clone(),
        // Resolved budgets win over legacy scalars at every layer (A12).
        max_tool_calls: budgets.max_tool_calls,
        max_network_calls: budgets.max_network_calls,
        requests_per_minute: budgets.requests_per_minute,
        auto_approve_tools: config.agent.auto_approve_tools.clone(),
        auto_approve_all: config.agent.auto_approve_all,
        max_estimated_tokens: budgets.max_tokens,
        cost_per_1k_input: config.llm.cost_per_1k_input,
        cost_per_1k_output: config.llm.cost_per_1k_output,
        ..Default::default()
    }
}

fn build_runner(config: &AppConfig, cwd: &str, mode: Mode) -> Result<Runner> {
    let api_key = resolve_api_key(&config.llm.api_key)?;
    let llm_config = LlmConfig {
        base_url: config.llm.base_url.clone(),
        api_key,
        default_model: config
            .llm
            .default_model
            .clone()
            .filter(|value| !value.trim().is_empty()),
        fallback_models: config.llm.fallback_models.clone(),
        timeout_ms: config.llm.timeout_ms,
    };
    let client = bugfound_llm::LlmClient::new(llm_config)?;

    std::fs::canonicalize(cwd)
        .with_context(|| format!("invalid or inaccessible workspace cwd '{cwd}'"))?;
    let options = ToolOptions {
        allow_proxy: config.network.allow_proxy,
        proxy_url: config.network.proxy_url.clone(),
        trusted_local_targets: config.network.trusted_local_targets.clone(),
        enable_external_tools: config.external_tools.enabled,
        external_commands: config.external_tools.commands.clone(),
        auto_detect_external: config.external_tools.auto_detect,
        scope_in: config.scope.in_scope.clone(),
        scope_out: config.scope.out_of_scope.clone(),
        ..Default::default()
    };
    let tools = try_default_registry_with_options(cwd, options)?;

    let policy = bugfound_core::build_policy_config(policy_config(config, mode));
    let agent = agent_config(config, mode);

    let store = Store::open(crate::config::resolve_db_path(&config.storage.path))?;
    bugfound_core::settle_on_boot(&store)?;
    Ok(Runner::new(store, Arc::new(client), tools, policy, agent))
}

#[allow(dead_code)]
pub fn spawn_job(config: AppConfig, job: Job, tx: Sender<JobEvent>) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let label = job_label(&job);
        let runtime = match tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
        {
            Ok(runtime) => runtime,
            Err(e) => {
                let _ = tx.send(JobEvent::Error {
                    text: format!("{e:#}"),
                });
                return;
            }
        };

        let (cwd, mode) = match &job {
            Job::Run { cwd, mode, .. } | Job::Approve { cwd, mode, .. } => (cwd.clone(), *mode),
        };
        let runner = match build_runner(&config, &cwd, mode) {
            Ok(runner) => runner,
            Err(e) => {
                let _ = tx.send(JobEvent::Error {
                    text: format!("{e:#}"),
                });
                return;
            }
        };

        let _ = tx.send(JobEvent::Started { label });
        let outcome = runtime.block_on(async {
            match &job {
                Job::Run { goal, .. } => runner.run_goal(goal).await,
                Job::Approve {
                    session, decision, ..
                } => runner.resume_session(session, decision).await,
            }
        });
        match outcome {
            Ok(text) => {
                let _ = tx.send(JobEvent::Finished { text });
            }
            Err(e) => {
                let _ = tx.send(JobEvent::Error {
                    text: format!("{e:#}"),
                });
            }
        }
    })
}

/// Engagement control signal. Kept here so the UI never has to touch the DB
/// when pausing, resuming or aborting a run (E21).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EngageAction {
    Pause,
    Resume,
    Abort,
}

/// One long-lived worker owns the Tokio runtime and the conversation Runner.
/// The UI sends commands and receives deltas/events without spawning a thread
/// per engagement or per follow-up message.
pub enum ChatCommand {
    Chat {
        config: AppConfig,
        text: String,
        cwd: String,
        mode: Mode,
    },
    Approval {
        config: AppConfig,
        session: String,
        decision: String,
        cwd: String,
        mode: Mode,
    },
    Engagement {
        config: AppConfig,
        url: String,
        cwd: String,
        options: bugfound_engagement::EngagementOptions,
        roe: bugfound_engagement::EngagementRoeOptions,
        loop_options: bugfound_engagement::EngagementLoopOptions,
    },
    /// E21: approval snapshot read off the UI thread.
    Refresh { db_path: PathBuf },
    /// E21: pause/resume/abort written off the UI thread.
    EngageAction {
        db_path: PathBuf,
        id: String,
        action: EngageAction,
    },
    /// E21: one step of the 700 ms status poll, read off the UI thread.
    PollStatus { db_path: PathBuf, id: String },
    /// E21: report file read off the UI thread.
    ReadReport { path: PathBuf },
}

#[allow(clippy::large_enum_variant)]
pub enum ChatWorkerEvent {
    Started {
        label: String,
    },
    Delta {
        text: String,
    },
    Finished {
        text: String,
    },
    Error {
        text: String,
    },
    Engagement(EngagementEvent),
    /// Result of `ChatCommand::Refresh`. `error` is set when the store could
    /// not be opened or read; the UI surfaces it as a non-fatal warning.
    Approvals {
        pending: Vec<(String, bugfound_store::Approval)>,
        error: Option<String>,
    },
    /// Result of a pause/resume/abort signal.
    EngageActionResult {
        action: EngageAction,
        result: std::result::Result<(), String>,
    },
    /// Result of one `ChatCommand::PollStatus` step.
    EngagementStatus {
        result: std::result::Result<bugfound_engagement::EngagementStatus, String>,
    },
    /// Contents of a report requested by the UI.
    Report {
        path: PathBuf,
        result: std::result::Result<String, String>,
    },
}

/// Cheap, short-lived SQLite/file operations run on a dedicated worker thread
/// rather than the UI thread (E21). This thread is separate from the job loop
/// so status polls and control signals still make progress while a chat turn
/// or an engagement is occupying the Runner.
fn handle_io_command(command: ChatCommand, events: &Sender<ChatWorkerEvent>) {
    match command {
        ChatCommand::Refresh { db_path } => {
            let mut pending = Vec::new();
            let error = match Store::open(&db_path) {
                Ok(store) => match store.list_sessions(200) {
                    Ok(sessions) => {
                        let mut failure = None;
                        for session in sessions {
                            match store.get_pending_approval(&session.id) {
                                Ok(Some(approval)) => pending.push((session.id, approval)),
                                Ok(None) => {}
                                Err(e) => {
                                    failure = Some(format!("could not read approvals: {e:#}"));
                                    break;
                                }
                            }
                        }
                        failure
                    }
                    Err(e) => Some(format!("could not list sessions: {e:#}")),
                },
                Err(e) => Some(format!("{e:#}")),
            };
            let _ = events.send(ChatWorkerEvent::Approvals { pending, error });
        }
        ChatCommand::EngageAction {
            db_path,
            id,
            action,
        } => {
            let result = match action {
                EngageAction::Pause => bugfound_engagement::pause_at(&db_path, &id),
                EngageAction::Resume => bugfound_engagement::resume_at(&db_path, &id),
                EngageAction::Abort => bugfound_engagement::abort_at(&db_path, &id),
            }
            .map_err(|e| format!("{e:#}"));
            let _ = events.send(ChatWorkerEvent::EngageActionResult { action, result });
        }
        ChatCommand::PollStatus { db_path, id } => {
            let result =
                bugfound_engagement::status_at(&db_path, &id).map_err(|e| format!("{e:#}"));
            let _ = events.send(ChatWorkerEvent::EngagementStatus { result });
        }
        ChatCommand::ReadReport { path } => {
            let result = std::fs::read_to_string(&path).map_err(|e| format!("{e:#}"));
            let _ = events.send(ChatWorkerEvent::Report { path, result });
        }
        // Job commands belong to the long-lived job thread below.
        _ => {}
    }
}

pub struct ChatWorker {
    commands: Sender<ChatCommand>,
    io_commands: Sender<ChatCommand>,
    events: Receiver<ChatWorkerEvent>,
    handle: JoinHandle<()>,
}

impl ChatWorker {
    pub fn spawn() -> Self {
        let (commands, command_rx) = mpsc::channel();
        let (io_commands, io_rx) = mpsc::channel();
        let (events, event_rx) = mpsc::channel();

        // Short I/O commands get their own thread: they must never wait behind
        // a long Chat/Engagement job, and never touch the egui UI thread (E21).
        let io_events = events.clone();
        std::thread::spawn(move || {
            while let Ok(command) = io_rx.recv() {
                handle_io_command(command, &io_events);
            }
        });

        let handle = std::thread::spawn(move || {
            let runtime = match tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime,
                Err(e) => {
                    let _ = events.send(ChatWorkerEvent::Error {
                        text: e.to_string(),
                    });
                    return;
                }
            };
            let mut conversation: Option<(Runner, String)> = None;
            while let Ok(command) = command_rx.recv() {
                match command {
                    ChatCommand::Chat {
                        config,
                        text,
                        cwd,
                        mode,
                    } => {
                        let _ = events.send(ChatWorkerEvent::Started {
                            label: "chat".into(),
                        });
                        let (delta_tx, mut delta_rx) = tokio::sync::mpsc::unbounded_channel();
                        let forward = events.clone();
                        let bridge = std::thread::spawn(move || {
                            while let Some(delta) = delta_rx.blocking_recv() {
                                let _ = forward.send(ChatWorkerEvent::Delta { text: delta });
                            }
                        });
                        let outcome = match conversation.take() {
                            Some((runner, session_id)) => {
                                let result = runtime.block_on(runner.chat_turn(
                                    &session_id,
                                    &text,
                                    Some(delta_tx),
                                ));
                                conversation = Some((runner, session_id));
                                result
                            }
                            None => match build_runner(&config, &cwd, mode) {
                                Ok(runner) => {
                                    let result = runtime
                                        .block_on(runner.run_goal_stream(&text, Some(delta_tx)));
                                    let session_id =
                                        runner.store.list_sessions(1).ok().and_then(|sessions| {
                                            sessions.first().map(|s| s.id.clone())
                                        });
                                    if let Some(id) = session_id {
                                        conversation = Some((runner, id));
                                    }
                                    result
                                }
                                Err(e) => Err(e),
                            },
                        };
                        let _ = bridge.join();
                        match outcome {
                            Ok(text) => {
                                let _ = events.send(ChatWorkerEvent::Finished { text });
                            }
                            Err(e) => {
                                let _ = events.send(ChatWorkerEvent::Error {
                                    text: format!("{e:#}"),
                                });
                            }
                        }
                    }
                    ChatCommand::Approval {
                        config,
                        session,
                        decision,
                        cwd,
                        mode,
                    } => {
                        let outcome = match build_runner(&config, &cwd, mode) {
                            Ok(runner) => {
                                runtime.block_on(runner.resume_session(&session, &decision))
                            }
                            Err(e) => Err(e),
                        };
                        match outcome {
                            Ok(text) => {
                                let _ = events.send(ChatWorkerEvent::Finished { text });
                            }
                            Err(e) => {
                                let _ = events.send(ChatWorkerEvent::Error {
                                    text: format!("{e:#}"),
                                });
                            }
                        }
                    }
                    ChatCommand::Engagement {
                        config,
                        url,
                        cwd,
                        options,
                        roe,
                        loop_options,
                    } => {
                        conversation = None;
                        let (eng_tx, eng_rx) = mpsc::channel();
                        let forward = events.clone();
                        let bridge = std::thread::spawn(move || {
                            while let Ok(event) = eng_rx.recv() {
                                let _ = forward.send(ChatWorkerEvent::Engagement(event));
                            }
                        });
                        let db = crate::config::resolve_db_path(&config.storage.path);
                        let outcome = runtime.block_on(bugfound_engagement::engage_drive(
                            &url,
                            std::path::Path::new(&cwd),
                            &db,
                            options,
                            roe,
                            loop_options,
                            eng_tx,
                        ));
                        let _ = bridge.join();
                        match outcome {
                            Ok(_) => {
                                let _ = events.send(ChatWorkerEvent::Finished {
                                    text: "engagement finished".into(),
                                });
                            }
                            Err(e) => {
                                let _ = events.send(ChatWorkerEvent::Error {
                                    text: format!("{e:#}"),
                                });
                            }
                        }
                    }
                    // I/O commands are handled by the dedicated thread above.
                    _ => {}
                }
            }
        });
        Self {
            commands,
            io_commands,
            events: event_rx,
            handle,
        }
    }

    pub fn send(&self, command: ChatCommand) {
        let target = match &command {
            ChatCommand::Refresh { .. }
            | ChatCommand::EngageAction { .. }
            | ChatCommand::PollStatus { .. }
            | ChatCommand::ReadReport { .. } => &self.io_commands,
            _ => &self.commands,
        };
        let _ = target.send(command);
    }

    pub fn try_recv(&self) -> std::result::Result<ChatWorkerEvent, mpsc::TryRecvError> {
        self.events.try_recv()
    }

    pub fn is_finished(&self) -> bool {
        self.handle.is_finished()
    }
}

#[allow(dead_code)]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_fields_and_budget_aliases_are_forwarded() {
        let config: AppConfig = toml::from_str(crate::config::POLICY_CONFIG).expect("parse config");
        let policy = policy_config(&config, Mode::FullAuto);
        assert_eq!(policy.allowed_tools, ["http_request", "dns_lookup"]);
        assert_eq!(policy.denied_tools, ["shell"]);
        assert_eq!(policy.allowed_targets, ["example.com"]);
        assert_eq!(policy.denied_targets, ["evil.example.com"]);
        assert_eq!(policy.budgets.max_steps, 11);
        assert_eq!(policy.rate_limits.max_tokens, 55);
        let agent = agent_config(&config, Mode::FullAuto);
        assert_eq!(agent.max_steps, config.effective_budgets().max_steps);
        assert_eq!(agent.mode, Mode::FullAuto);
        for alias in [
            &agent.budgets,
            &agent.budget,
            &agent.rate_limits,
            &agent.rate_limit,
        ] {
            assert_eq!(alias.max_steps, 11);
            assert_eq!(alias.max_tool_calls, 22);
            assert_eq!(alias.max_network_calls, 33);
            assert_eq!(alias.requests_per_minute, 44);
            assert_eq!(alias.max_tokens, 55);
        }
    }

    #[test]
    fn labels_describe_the_job() {
        let run = Job::Run {
            goal: "probe example.com".into(),
            cwd: ".".into(),
            mode: Mode::Ask,
        };
        assert_eq!(job_label(&run), "run: probe example.com");

        let approve = Job::Approve {
            session: "0123456789abcdef".into(),
            decision: "approve".into(),
            cwd: ".".into(),
            mode: Mode::Ask,
        };
        assert_eq!(job_label(&approve), "approve: 01234567");
    }

    #[test]
    fn refresh_command_emits_approval_snapshot_event() {
        let path =
            std::env::temp_dir().join(format!("bugfound-worker-refresh-{}.db", std::process::id()));
        let remove_db = || {
            for suffix in ["", "-wal", "-shm"] {
                let mut name = path.as_os_str().to_os_string();
                name.push(suffix);
                let _ = std::fs::remove_file(std::path::PathBuf::from(name));
            }
        };
        remove_db();
        let session = {
            let store = Store::open(&path).unwrap();
            let session = store.create_session("refresh snapshot").unwrap();
            store
                .create_approval(&session.id, "echo", "{}", "low", "test", None)
                .unwrap();
            session // drop the store so the worker opens a clean connection
        };

        let worker = ChatWorker::spawn();
        worker.send(ChatCommand::Refresh {
            db_path: path.clone(),
        });

        let mut snapshot = None;
        for _ in 0..200 {
            match worker.try_recv() {
                Ok(ChatWorkerEvent::Approvals { pending, error }) => {
                    snapshot = Some((pending, error));
                    break;
                }
                Ok(_) => {}
                Err(mpsc::TryRecvError::Empty) => {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                Err(mpsc::TryRecvError::Disconnected) => break,
            }
        }
        let (pending, error) = snapshot.expect("refresh emitted an approval snapshot");
        assert_eq!(error, None);
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].0, session.id);
        assert_eq!(pending[0].1.tool_name, "echo");
        remove_db();
    }
}
