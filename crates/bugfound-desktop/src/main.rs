mod config;
mod worker;

use bugfound_engagement::EngagementEvent;
use bugfound_policy::Mode;
use bugfound_store::redact;
use config::AppConfig;
use eframe::egui;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use worker::{ChatCommand, ChatWorker, ChatWorkerEvent, EngageAction};

const LOGO_WIDTH: usize = 304;
const LOGO_HEIGHT: usize = 392;
const LOGO_RGBA: &[u8] = include_bytes!("../../../assets/bugfound-logo.rgba");

#[derive(Clone, Copy, PartialEq, Eq)]
enum ModeChoice {
    Ask,
    FullAuto,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ChatRole {
    User,
    Agent,
    Activity,
    Notice,
}

struct ChatLine {
    role: ChatRole,
    text: String,
}

impl From<ModeChoice> for Mode {
    fn from(value: ModeChoice) -> Self {
        match value {
            ModeChoice::Ask => Mode::Ask,
            ModeChoice::FullAuto => Mode::FullAuto,
        }
    }
}

struct DesktopApp {
    config_path: PathBuf,
    config: AppConfig,
    worker: ChatWorker,

    mode_choice: ModeChoice,
    engage_url: String,
    engage_cwd: String,
    /// Resolved DB path handed to the worker for all SQLite reads/writes (E21).
    db_path: PathBuf,

    engagement_id: Option<String>,
    engage_status: Option<bugfound_engagement::EngagementStatus>,
    engage_report: String,
    last_status_poll: Option<Instant>,

    chat: Vec<ChatLine>,
    stream_line: Option<usize>,
    chat_input: String,
    busy: bool,
    pending: Vec<(String, bugfound_store::Approval)>,
    show_settings: bool,
    /// Startup config/store problems, surfaced in the UI instead of being
    /// swallowed by a silent fallback.
    warnings: Vec<String>,
    /// A store-open failure is reported once, not on every approval refresh.
    db_warning_shown: bool,

    status: String,
    cfg_default_model: String,
    cfg_proxy_url: String,
    /// Non-secret description of the API key (env:VAR or "set in config").
    /// The value itself is never rendered.
    api_key_source: String,
    scope_in_text: String,

    logo_texture: Option<egui::TextureHandle>,
}

impl DesktopApp {
    fn new() -> Self {
        // Backwards compatibility: prefer an existing cwd config, otherwise
        // use the per-user config dir (no new dependency required).
        let cwd_config = PathBuf::from("bugfound.toml");
        let config_path = if cwd_config.exists() {
            cwd_config
        } else {
            let base = config::config_dir();
            if base.as_os_str().is_empty() {
                cwd_config
            } else {
                base.join("bugfound.toml")
            }
        };
        let (config, config_warning) = match AppConfig::load(&config_path) {
            Ok(config) => (config, None),
            Err(e) => (
                AppConfig::default(),
                Some(format!(
                    "could not read {} ({e}). Using default settings; the file was left untouched.",
                    config_path.display()
                )),
            ),
        };
        // All DB access (including the startup probe) happens in the worker:
        // the UI thread never opens or queries the store (E21). A failure is
        // surfaced by the Refresh snapshot event instead.
        let db_path = config::resolve_db_path(&config.storage.path);
        let mut warnings = Vec::new();
        if let Some(warning) = config_warning {
            warnings.push(warning);
        }
        let mut app = Self {
            config_path,
            config,
            worker: ChatWorker::spawn(),
            mode_choice: ModeChoice::FullAuto,
            engage_url: String::new(),
            engage_cwd: ".".into(),
            db_path,
            engagement_id: None,
            engage_status: None,
            engage_report: String::new(),
            last_status_poll: None,
            chat: Vec::new(),
            stream_line: None,
            chat_input: String::new(),
            busy: false,
            pending: Vec::new(),
            show_settings: false,
            warnings,
            db_warning_shown: false,
            status: "ready".into(),
            cfg_default_model: String::new(),
            cfg_proxy_url: String::new(),
            api_key_source: String::new(),
            scope_in_text: String::new(),
            logo_texture: None,
        };
        app.load_config_fields();
        for warning in app.warnings.clone() {
            app.say(ChatRole::Notice, format!("warning: {warning}"));
        }
        app.refresh();
        app
    }

    /// Never include the secret value: only its source is displayable.
    fn api_key_source(raw: &str) -> String {
        let raw = raw.trim();
        if let Some(var) = raw.strip_prefix("env:") {
            let var = var.trim();
            if var.is_empty() {
                "env: (missing variable name)".into()
            } else {
                format!("env:{var}")
            }
        } else if raw.is_empty() {
            "not set".into()
        } else {
            "set in config (hidden)".into()
        }
    }

    fn load_config_fields(&mut self) {
        self.cfg_default_model = self.config.llm.default_model.clone().unwrap_or_default();
        self.cfg_proxy_url = self.config.network.proxy_url.clone().unwrap_or_default();
        self.scope_in_text = self.config.scope.in_scope.join("\n");
        self.api_key_source = Self::api_key_source(&self.config.llm.api_key);
        self.mode_choice = match config::parse_mode(&self.config.agent.mode) {
            Ok(Mode::Ask) => ModeChoice::Ask,
            Ok(Mode::FullAuto) => ModeChoice::FullAuto,
            // Invalid config is reported by validate(); default the toggle to
            // the safe mode rather than silently granting FullAuto.
            Err(_) => ModeChoice::Ask,
        };
        if self.engage_cwd == "." {
            self.engage_cwd = self.config.workspace().to_string();
        }
    }

    fn apply_config_fields(&mut self) {
        self.config.llm.default_model =
            Some(self.cfg_default_model.trim().to_string()).filter(|s| !s.is_empty());
        self.config.network.proxy_url =
            Some(self.cfg_proxy_url.trim().to_string()).filter(|s| !s.is_empty());
        self.config.scope.in_scope = lines(&self.scope_in_text);
        let workspace = self.engage_cwd.trim().to_string();
        self.config.workspace = if workspace.is_empty() {
            ".".into()
        } else {
            workspace.clone()
        };
        self.config.agent.workspace = self.config.workspace.clone();
        self.config.agent.mode = match self.mode_choice {
            ModeChoice::Ask => "ask".into(),
            ModeChoice::FullAuto => "full_auto".into(),
        };
    }

    fn say(&mut self, role: ChatRole, text: impl Into<String>) {
        self.chat.push(ChatLine {
            role,
            text: text.into(),
        });
    }

    /// Request an approval snapshot from the worker; no store I/O on the UI
    /// thread (E21). The snapshot arrives as `ChatWorkerEvent::Approvals`.
    fn refresh(&mut self) {
        self.pending.clear();
        self.worker.send(ChatCommand::Refresh {
            db_path: self.db_path.clone(),
        });
    }

    fn push_delta(&mut self, text: &str) {
        if self.stream_line.is_none() {
            self.chat.push(ChatLine {
                role: ChatRole::Agent,
                text: String::new(),
            });
            self.stream_line = Some(self.chat.len() - 1);
        }
        if let Some(index) = self.stream_line {
            self.chat[index].text.push_str(text);
        }
    }

    /// Consume worker results. Every result here was computed off the UI
    /// thread, so this loop never opens a store or reads a file (E21).
    fn poll_worker(&mut self) {
        if self.busy && self.worker.is_finished() {
            self.busy = false;
            self.status = "ready".into();
        }
        while let Ok(event) = self.worker.try_recv() {
            match event {
                ChatWorkerEvent::Started { label } => {
                    self.busy = true;
                    self.status = format!("running: {label}");
                }
                ChatWorkerEvent::Delta { text } => self.push_delta(&text),
                ChatWorkerEvent::Finished { text } => {
                    if let Some(index) = self.stream_line {
                        if self.chat[index].text.is_empty() {
                            self.chat[index].text = redact(&text);
                        }
                        self.stream_line = None;
                    }
                    self.busy = false;
                    self.status = "ready".into();
                    self.refresh();
                }
                ChatWorkerEvent::Error { text } => {
                    if self.stream_line.is_some() {
                        self.stream_line = None;
                    }
                    self.busy = false;
                    self.status = "ready".into();
                    self.say(ChatRole::Agent, format!("error: {}", redact(&text)));
                    self.refresh();
                }
                ChatWorkerEvent::Engagement(event) => match event {
                    EngagementEvent::Started { engagement_id } => {
                        self.engagement_id = Some(engagement_id);
                    }
                    EngagementEvent::ReportReady { path } => {
                        self.worker.send(ChatCommand::ReadReport { path });
                    }
                    EngagementEvent::Finished { summary } => {
                        self.say(ChatRole::Agent, redact(&summary));
                    }
                    EngagementEvent::Error { message } => {
                        self.say(ChatRole::Agent, format!("error: {}", redact(&message)));
                    }
                    other => self.say(ChatRole::Activity, event_line(&other)),
                },
                ChatWorkerEvent::Approvals { pending, error } => {
                    self.pending = pending;
                    if let Some(error) = error {
                        if !self.db_warning_shown {
                            self.db_warning_shown = true;
                            let warning = format!(
                                "could not open {} ({error}). Running without approval refresh; the file was left untouched.",
                                self.db_path.display()
                            );
                            self.warnings.push(warning.clone());
                            self.say(ChatRole::Notice, format!("warning: {warning}"));
                        }
                    }
                }
                ChatWorkerEvent::EngageActionResult { action, result } => match result {
                    Ok(()) => self.say(ChatRole::Notice, format!("{action:?} sent")),
                    Err(e) => self.say(ChatRole::Agent, format!("{action:?} error: {e}")),
                },
                ChatWorkerEvent::EngagementStatus { result } => match result {
                    Ok(status) => self.engage_status = Some(status),
                    Err(e) => self.say(ChatRole::Agent, format!("status error: {e}")),
                },
                ChatWorkerEvent::Report { path, result } => match result {
                    Ok(text) => {
                        self.engage_report = redact(&text);
                        self.say(
                            ChatRole::Agent,
                            format!("Report ready: {}", redact(&path.display().to_string())),
                        );
                    }
                    Err(e) => self.say(ChatRole::Agent, format!("report read error: {e}")),
                },
            }
        }
    }

    fn send(&mut self) {
        if self.busy {
            return;
        }
        let text = self.chat_input.trim().to_string();
        if text.is_empty() {
            return;
        }
        self.say(ChatRole::User, text.clone());
        self.chat_input.clear();
        if let Err(e) = self.config.validate() {
            self.say(ChatRole::Agent, format!("config error: {e:#}"));
            return;
        }
        self.apply_config_fields();
        self.worker.send(ChatCommand::Chat {
            config: self.config.clone(),
            text,
            cwd: self.engage_cwd.clone(),
            mode: self.mode_choice.into(),
        });
    }

    fn decide(&mut self, session: String, decision: &str) {
        self.worker.send(ChatCommand::Approval {
            config: self.config.clone(),
            session,
            decision: decision.into(),
            cwd: self.engage_cwd.clone(),
            mode: self.mode_choice.into(),
        });
    }

    fn start_engagement(&mut self) {
        if self.busy {
            return;
        }
        let url = self.engage_url.trim().to_string();
        if url.is_empty() {
            self.say(ChatRole::Agent, "enter a program URL first");
            return;
        }
        if let Err(e) = self.config.validate() {
            self.say(ChatRole::Agent, format!("config error: {e:#}"));
            return;
        }
        self.apply_config_fields();
        self.engagement_id = None;
        self.engage_status = None;
        self.engage_report.clear();
        self.last_status_poll = None;
        self.say(
            ChatRole::Agent,
            "Reading the brief and planning the engagement…",
        );
        let budgets = self.config.effective_budgets();
        let options = bugfound_engagement::EngagementOptions {
            mode: self.mode_choice.into(),
            max_steps: budgets.max_steps,
            max_tool_calls: budgets.max_tool_calls,
            max_network_calls: budgets.max_network_calls,
            requests_per_minute: budgets.requests_per_minute,
            max_estimated_tokens: budgets.max_tokens,
            allow_network_write: self.config.network.allow_network_write,
            allow_intrusive: self.config.network.allow_intrusive,
            auto_approve_all: self.config.agent.auto_approve_all,
            oob_endpoint: self.config.oob.endpoint.clone(),
            oob_admin_token: self.config.oob.admin_token(),
            resume_from_checkpoint: self.config.agent.resume_from_checkpoint,
            trusted_local_targets: self.config.network.trusted_local_targets.clone(),
            external_commands: self.config.external_tools.commands.clone(),
        };
        self.worker.send(ChatCommand::Engagement {
            config: self.config.clone(),
            url,
            cwd: self.engage_cwd.clone(),
            options,
            roe: config::roe_options(&self.config),
            loop_options: config::loop_options(&self.config),
        });
    }

    /// Send the control signal to the worker; the UI never writes the DB (E21).
    fn engage_action(&mut self, action: EngageAction) {
        let Some(id) = self.engagement_id.clone() else {
            self.say(ChatRole::Notice, "start an engagement first");
            return;
        };
        self.worker.send(ChatCommand::EngageAction {
            db_path: self.db_path.clone(),
            id,
            action,
        });
    }

    /// One step of the 700 ms poll cadence: the read itself runs in the worker,
    /// and the result arrives as `ChatWorkerEvent::EngagementStatus` (E21).
    fn poll_engagement_status(&mut self) {
        let Some(id) = self.engagement_id.clone() else {
            return;
        };
        self.worker.send(ChatCommand::PollStatus {
            db_path: self.db_path.clone(),
            id,
        });
    }
}

fn lines(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect()
}

fn event_line(event: &EngagementEvent) -> String {
    match event {
        EngagementEvent::Started { engagement_id } => format!("started {}", redact(engagement_id)),
        EngagementEvent::BriefIngested { profile } => format!(
            "brief: {} in-scope, {} out-of-scope",
            profile.scope.in_scope.len(),
            profile.scope.out_of_scope.len()
        ),
        EngagementEvent::PlanUpdated { tasks } => format!("plan: {} tasks", tasks.len()),
        EngagementEvent::Action {
            tool, ok, detail, ..
        } => format!(
            "{} {}: {}",
            if *ok { "ok" } else { "no" },
            redact(tool),
            redact(detail)
        ),
        EngagementEvent::Finding {
            title, severity, ..
        } => format!("finding [{}] {}", redact(severity), redact(title)),
        EngagementEvent::ReportReady { path } => {
            format!("report: {}", redact(&path.display().to_string()))
        }
        EngagementEvent::Error { message } => format!("error: {}", redact(message)),
        EngagementEvent::Finished { summary } => format!("done: {}", redact(summary)),
    }
}

impl eframe::App for DesktopApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_worker();
        if self.busy {
            ctx.request_repaint();
        }
        let poll_due = self.engagement_id.is_some()
            && self
                .last_status_poll
                .map(|at| at.elapsed() >= Duration::from_millis(700))
                .unwrap_or(true);
        if poll_due {
            self.poll_engagement_status();
            self.last_status_poll = Some(Instant::now());
        }

        if self.logo_texture.is_none() {
            let image =
                egui::ColorImage::from_rgba_unmultiplied([LOGO_WIDTH, LOGO_HEIGHT], LOGO_RGBA);
            self.logo_texture =
                Some(ctx.load_texture("bugfound_logo", image, egui::TextureOptions::LINEAR));
        }

        egui::TopBottomPanel::top("top").show(ctx, |ui| {
            ui.horizontal(|ui| {
                if let Some(texture) = &self.logo_texture {
                    ui.add(egui::Image::from_texture(texture).max_size([24.0, 32.0].into()));
                }
                ui.heading("BugFound");
                ui.separator();
                let state = if self.busy {
                    "working…"
                } else {
                    match &self.engage_status {
                        Some(status) => &redact(&status.state),
                        None => "idle",
                    }
                };
                ui.label(state);
                if let Some(status) = &self.engage_status {
                    ui.label(format!(
                        "· {}/{} tasks · {} findings · {} coverage",
                        status.tasks_done, status.tasks_total, status.findings, status.coverage
                    ));
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if self.engagement_id.is_some() {
                        if ui.small_button("Pause").clicked() {
                            self.engage_action(EngageAction::Pause);
                        }
                        if ui.small_button("Resume").clicked() {
                            self.engage_action(EngageAction::Resume);
                        }
                        if ui.small_button("Abort").clicked() {
                            self.engage_action(EngageAction::Abort);
                        }
                    }
                    let label = if self.show_settings {
                        "Back"
                    } else {
                        "Settings"
                    };
                    if ui.button(label).clicked() {
                        self.show_settings = !self.show_settings;
                    }
                });
            });
        });

        egui::TopBottomPanel::bottom("composer").show(ctx, |ui| {
            ui.horizontal(|ui| {
                let enabled = !self.busy && !self.show_settings;
                let response = ui.add_enabled(
                    enabled,
                    egui::TextEdit::singleline(&mut self.chat_input)
                        .hint_text("Program URL, lalu follow-up…"),
                );
                let enter = ui.input(|i| i.key_pressed(egui::Key::Enter));
                if enabled && (ui.button("Send").clicked() || (enter && response.has_focus())) {
                    self.send();
                }
                if self.busy {
                    ui.spinner();
                }
            });
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            if self.show_settings {
                self.ui_settings(ui);
            } else {
                self.ui_chat(ui);
            }
        });
    }
}

impl DesktopApp {
    fn ui_chat(&mut self, ui: &mut egui::Ui) {
        egui::ScrollArea::vertical()
            .stick_to_bottom(true)
            .show(ui, |ui| {
                if self.chat.is_empty() {
                    ui.add_space(40.0);
                    ui.vertical_centered(|ui| {
                        ui.heading("BugFound");
                        ui.label("Ketik URL program bug bounty untuk memulai.");
                        ui.label("Agent bekerja di belakang layar; kamu melihat percakapan dan hasilnya.");
                        ui.horizontal(|ui| {
                            if ui.button("Start engagement with URL").clicked() {
                                self.start_engagement();
                            }
                        });
                    });
                }

                for line in &self.chat {
                    match line.role {
                        ChatRole::User => {
                            ui.horizontal(|ui| {
                                ui.strong("You:");
                                ui.label(redact(&line.text));
                            });
                        }
                        ChatRole::Agent => {
                            ui.horizontal(|ui| {
                                ui.strong("BugFound:");
                                ui.label(redact(&line.text));
                            });
                        }
                        ChatRole::Activity => {
                            ui.horizontal(|ui| {
                                ui.label("  ·");
                                ui.label(egui::RichText::new(redact(&line.text)).small().weak());
                            });
                        }
                        ChatRole::Notice => {
                            ui.label(egui::RichText::new(redact(&line.text)).italics().weak());
                        }
                    }
                }

                if !self.pending.is_empty() {
                    ui.heading("Needs your decision");
                    let pending = self.pending.clone();
                    for (session, approval) in pending {
                        ui.group(|ui| {
                            ui.label(format!(
                                "{} | {} | {}",
                                &session[..session.len().min(8)],
                                redact(&approval.tool_name),
                                redact(&approval.risk)
                            ));
                            ui.label(redact(&approval.args_json));
                            ui.horizontal(|ui| {
                                if ui.button("Approve").clicked() {
                                    self.decide(session.clone(), "approve");
                                }
                                if ui.button("Deny").clicked() {
                                    self.decide(session.clone(), "deny");
                                }
                            });
                        });
                    }
                }

                if !self.engage_report.is_empty() {
                    ui.collapsing("Report", |ui| {
                        ui.text_edit_multiline(&mut self.engage_report);
                    });
                }
            });
    }

    fn ui_settings(&mut self, ui: &mut egui::Ui) {
        egui::ScrollArea::vertical().show(ui, |ui| {
            ui.heading("Settings");
            for warning in &self.warnings {
                ui.label(
                    egui::RichText::new(format!("warning: {warning}"))
                        .color(egui::Color32::from_rgb(255, 190, 90)),
                );
            }
            ui.horizontal(|ui| {
                ui.radio_value(
                    &mut self.mode_choice,
                    ModeChoice::FullAuto,
                    "Autonomous (policy-bounded)",
                );
                ui.radio_value(&mut self.mode_choice, ModeChoice::Ask, "Guided (ask first)");
            });
            ui.horizontal(|ui| {
                ui.label("base_url");
                ui.text_edit_singleline(&mut self.config.llm.base_url);
            });
            ui.horizontal(|ui| {
                ui.label("api_key ");
                // Password mode masks the value; only its source is shown.
                ui.add(
                    egui::TextEdit::singleline(&mut self.config.llm.api_key)
                        .password(true)
                        .hint_text("literal key or env:VAR"),
                );
                ui.label(format!("source: {}", self.api_key_source));
            });
            ui.horizontal(|ui| {
                ui.label("model   ");
                ui.text_edit_singleline(&mut self.cfg_default_model);
            });
            ui.horizontal(|ui| {
                ui.label("workspace");
                ui.text_edit_singleline(&mut self.engage_cwd);
            });
            ui.horizontal(|ui| {
                ui.label("steps");
                ui.add(egui::DragValue::new(&mut self.config.agent.max_steps));
                ui.label("tools");
                ui.add(egui::DragValue::new(&mut self.config.agent.max_tool_calls));
                ui.label("net");
                ui.add(egui::DragValue::new(
                    &mut self.config.agent.max_network_calls,
                ));
            });
            ui.label("In-scope patterns (one per line)");
            ui.text_edit_multiline(&mut self.scope_in_text);
            ui.checkbox(
                &mut self.config.network.allow_network_write,
                "Allow network-write tools",
            );
            ui.checkbox(
                &mut self.config.network.allow_intrusive,
                "Allow intrusive tools",
            );
            if ui.button("Save").clicked() {
                self.apply_config_fields();
                match self
                    .config
                    .validate()
                    .and_then(|_| self.config.save(&self.config_path))
                {
                    Ok(()) => {
                        self.say(ChatRole::Notice, "settings saved");
                        self.load_config_fields();
                    }
                    Err(e) => self.say(ChatRole::Agent, format!("config error: {e:#}")),
                }
            }
        });
    }
}

fn main() -> eframe::Result<()> {
    let icon = egui::IconData {
        rgba: LOGO_RGBA.to_vec(),
        width: LOGO_WIDTH as u32,
        height: LOGO_HEIGHT as u32,
    };
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("BugFound")
            .with_icon(Arc::new(icon))
            .with_inner_size([1040.0, 720.0]),
        ..Default::default()
    };
    eframe::run_native(
        "BugFound",
        options,
        Box::new(|_cc| Ok(Box::new(DesktopApp::new()) as Box<dyn eframe::App>)),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn engagement_options_carry_policy_budgets() {
        let config: AppConfig = toml::from_str(crate::config::POLICY_CONFIG).expect("parse config");
        let budgets = config.effective_budgets();
        assert_eq!(budgets.max_steps, 11);
        assert_eq!(budgets.max_tool_calls, 22);
        assert_eq!(budgets.max_network_calls, 33);
        assert_eq!(budgets.requests_per_minute, 44);
        assert_eq!(budgets.max_tokens, 55);
        assert_eq!(config::loop_options(&config).max_rounds, 1);
    }

    #[test]
    fn engagement_roe_comes_from_config_not_default() {
        let mut config = AppConfig::default();
        config.authorization.roe_policy_mode = "permissive_audited".into();
        assert!(matches!(
            config::roe_options(&config).mode,
            bugfound_engagement::RoePolicyMode::PermissiveAudited
        ));
        config.agent.max_rounds = 3;
        config.agent.llm_planning = true;
        let loop_options = config::loop_options(&config);
        assert_eq!(loop_options.max_rounds, 3);
        assert!(loop_options.llm_planning);
        assert!(loop_options.adaptive_planning);
    }

    #[test]
    fn api_key_hint_never_contains_the_value() {
        assert_eq!(
            DesktopApp::api_key_source("env:OPENAI_API_KEY"),
            "env:OPENAI_API_KEY"
        );
        assert_eq!(
            DesktopApp::api_key_source("sk-super-secret"),
            "set in config (hidden)"
        );
        assert!(!DesktopApp::api_key_source("sk-super-secret").contains("sk-super"));
    }
}
