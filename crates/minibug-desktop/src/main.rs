mod config;
mod worker;

use config::AppConfig;
use eframe::egui;
use minibug_policy::Mode;
use minibug_store::{redact, Store};
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread::JoinHandle;
use worker::{Job, JobEvent};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tab {
    Sessions,
    Run,
    Approvals,
    Config,
    Tools,
    Logs,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum DetailTab {
    Messages,
    Events,
    Findings,
    Assets,
    Artifacts,
    Coverage,
    Report,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ModeChoice {
    Ask,
    FullAuto,
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
    store: Store,
    tab: Tab,
    detail_tab: DetailTab,
    mode_choice: ModeChoice,
    run_mode_choice: ModeChoice,
    goal: String,
    cwd: String,
    status: String,
    last_output: String,
    selected: Option<String>,
    sessions: Vec<minibug_store::Session>,
    messages: Vec<minibug_store::Message>,
    events: Vec<minibug_store::Event>,
    findings: Vec<minibug_store::Finding>,
    assets: Vec<minibug_store::Asset>,
    artifacts: Vec<minibug_store::Artifact>,
    coverage: Vec<String>,
    hypotheses: Vec<minibug_store::Hypothesis>,
    report: String,
    pending: Vec<(String, minibug_store::Approval)>,
    cfg_default_model: String,
    cfg_system_prompt: String,
    cfg_proxy_url: String,
    scope_engagement: String,
    scope_notes: String,
    scope_in_text: String,
    scope_out_text: String,
    tool_list: Vec<(String, String)>,
    tx: Sender<JobEvent>,
    rx: Receiver<JobEvent>,
    worker: Option<JoinHandle<()>>,
}

impl DesktopApp {
    fn new() -> Self {
        let config_path = PathBuf::from("minibug.toml");
        let config = AppConfig::load(&config_path).unwrap_or_else(|_| AppConfig::default());
        let store =
            Store::open(&config.storage.path).unwrap_or_else(|_| Store::open(":memory:").unwrap());
        let (tx, rx) = mpsc::channel();
        let mut app = Self {
            config_path,
            config,
            store,
            tab: Tab::Sessions,
            detail_tab: DetailTab::Messages,
            mode_choice: ModeChoice::Ask,
            run_mode_choice: ModeChoice::Ask,
            goal: String::new(),
            cwd: ".".into(),
            status: "ready".into(),
            last_output: String::new(),
            selected: None,
            sessions: Vec::new(),
            messages: Vec::new(),
            events: Vec::new(),
            findings: Vec::new(),
            assets: Vec::new(),
            artifacts: Vec::new(),
            coverage: Vec::new(),
            hypotheses: Vec::new(),
            report: String::new(),
            pending: Vec::new(),
            cfg_default_model: String::new(),
            cfg_system_prompt: String::new(),
            cfg_proxy_url: String::new(),
            scope_engagement: String::new(),
            scope_notes: String::new(),
            scope_in_text: String::new(),
            scope_out_text: String::new(),
            tool_list: Vec::new(),
            tx,
            rx,
            worker: None,
        };
        app.load_config_fields();
        app.refresh();
        app.refresh_tools();
        app
    }

    fn load_config_fields(&mut self) {
        self.cfg_default_model = self.config.llm.default_model.clone().unwrap_or_default();
        self.cfg_system_prompt = self.config.agent.system_prompt.clone().unwrap_or_default();
        self.cfg_proxy_url = self.config.network.proxy_url.clone().unwrap_or_default();
        self.scope_engagement = self.config.scope.engagement.clone().unwrap_or_default();
        self.scope_notes = self.config.scope.notes.clone().unwrap_or_default();
        self.scope_in_text = self.config.scope.in_scope.join("\n");
        self.scope_out_text = self.config.scope.out_of_scope.join("\n");
        self.mode_choice = if self.config.agent.mode == "full_auto" {
            ModeChoice::FullAuto
        } else {
            ModeChoice::Ask
        };
        self.run_mode_choice = self.mode_choice;
    }

    fn apply_config_fields(&mut self) {
        self.config.llm.default_model =
            Some(self.cfg_default_model.trim().to_string()).filter(|s| !s.is_empty());
        self.config.agent.system_prompt =
            Some(self.cfg_system_prompt.trim().to_string()).filter(|s| !s.is_empty());
        self.config.network.proxy_url =
            Some(self.cfg_proxy_url.trim().to_string()).filter(|s| !s.is_empty());
        self.config.scope.engagement =
            Some(self.scope_engagement.trim().to_string()).filter(|s| !s.is_empty());
        self.config.scope.notes =
            Some(self.scope_notes.trim().to_string()).filter(|s| !s.is_empty());
        self.config.scope.in_scope = lines(&self.scope_in_text);
        self.config.scope.out_of_scope = lines(&self.scope_out_text);
        self.config.agent.mode = match self.mode_choice {
            ModeChoice::Ask => "ask".into(),
            ModeChoice::FullAuto => "full_auto".into(),
        };
    }

    fn refresh(&mut self) {
        self.sessions = self.store.list_sessions(200).unwrap_or_default();
        self.pending = self
            .sessions
            .iter()
            .filter_map(|session| {
                self.store
                    .get_pending_approval(&session.id)
                    .ok()
                    .flatten()
                    .map(|approval| (session.id.clone(), approval))
            })
            .collect();
        let selected = self.selected.clone();
        if let Some(id) = selected {
            self.messages = self.store.list_messages(&id).unwrap_or_default();
            self.events = self.store.list_events(&id, 300).unwrap_or_default();
            self.findings = self.store.list_findings(&id).unwrap_or_default();
            self.assets = self.store.list_assets(&id).unwrap_or_default();
            self.artifacts = self.store.list_artifacts(&id).unwrap_or_default();
            self.coverage = self.store.coverage_targets(&id).unwrap_or_default();
            self.hypotheses = self.store.list_hypotheses(&id).unwrap_or_default();
            self.report = self.store.export_report(&id).unwrap_or_default();
        }
    }

    fn refresh_tools(&mut self) {
        self.tool_list = minibug_tools::external_tool_availability()
            .into_iter()
            .map(|(name, path)| {
                (
                    name,
                    path.map(|p| p.display().to_string())
                        .unwrap_or_else(|| "not installed".into()),
                )
            })
            .collect();
    }

    fn spawn(&mut self, job: Job, label: &str) {
        if self.worker.is_some() {
            self.status = "a job is already running".into();
            return;
        }
        if let Err(e) = self.config.validate() {
            self.status = format!("config error: {e:#}");
            return;
        }
        self.apply_config_fields();
        let config = self.config.clone();
        let tx = self.tx.clone();
        self.last_output.clear();
        self.status = format!("running: {label}");
        self.worker = Some(worker::spawn_job(config, job, tx));
    }

    fn poll_worker(&mut self) {
        let mut finished = false;
        while let Ok(event) = self.rx.try_recv() {
            match event {
                JobEvent::Started { label } => self.status = format!("running: {label}"),
                JobEvent::Finished { text } => {
                    self.last_output = text;
                    self.status = "finished".into();
                    finished = true;
                }
                JobEvent::Error { text } => {
                    self.last_output = text.clone();
                    self.status = format!("error: {text}");
                    finished = true;
                }
            }
        }
        if finished {
            self.worker = None;
            self.refresh();
        }
        if self.worker.is_some() {
            self.ctx_request_repaint();
        }
    }

    fn ctx_request_repaint(&self) {
        // Called from update via a context reference; no-op placeholder kept
        // so poll_worker stays simple. update() requests repaint below.
    }
}

fn lines(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect()
}

impl eframe::App for DesktopApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_worker();
        if self.worker.is_some() {
            ctx.request_repaint();
        }

        egui::TopBottomPanel::top("top").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.heading("MiniBug Desktop");
                ui.separator();
                for (tab, label) in [
                    (Tab::Sessions, "Sessions"),
                    (Tab::Run, "New Run"),
                    (Tab::Approvals, "Approvals"),
                    (Tab::Config, "Config"),
                    (Tab::Tools, "Tools"),
                    (Tab::Logs, "Logs"),
                ] {
                    if ui.selectable_label(self.tab == tab, label).clicked() {
                        self.tab = tab;
                        self.refresh();
                    }
                }
                ui.separator();
                ui.label(redact(&self.status));
                if ui.button("Refresh").clicked() {
                    self.refresh();
                }
            });
        });

        egui::CentralPanel::default().show(ctx, |ui| match self.tab {
            Tab::Sessions => self.ui_sessions(ui),
            Tab::Run => self.ui_run(ui),
            Tab::Approvals => self.ui_approvals(ui),
            Tab::Config => self.ui_config(ui),
            Tab::Tools => self.ui_tools(ui),
            Tab::Logs => self.ui_logs(ui),
        });
    }
}

impl DesktopApp {
    fn ui_sessions(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.heading("Sessions");
            ui.label(format!("{} total", self.sessions.len()));
        });
        ui.separator();
        egui::SidePanel::left("session_list")
            .resizable(true)
            .default_width(280.0)
            .show_inside(ui, |ui| {
                egui::ScrollArea::vertical().show(ui, |ui| {
                    for session in self.sessions.clone() {
                        let label = format!(
                            "{}\n{} | {}",
                            &session.id[..session.id.len().min(8)],
                            session.state,
                            redact(&session.goal).chars().take(60).collect::<String>()
                        );
                        if ui
                            .selectable_label(
                                self.selected.as_deref() == Some(session.id.as_str()),
                                label,
                            )
                            .clicked()
                        {
                            self.selected = Some(session.id.clone());
                            self.refresh();
                        }
                    }
                });
            });
        egui::CentralPanel::default().show_inside(ui, |ui| {
            let Some(id) = self.selected.clone() else {
                ui.label("select a session");
                return;
            };
            ui.horizontal(|ui| {
                for (tab, label) in [
                    (DetailTab::Messages, "Messages"),
                    (DetailTab::Events, "Events"),
                    (DetailTab::Findings, "Findings"),
                    (DetailTab::Assets, "Assets"),
                    (DetailTab::Artifacts, "Artifacts"),
                    (DetailTab::Coverage, "Coverage"),
                    (DetailTab::Report, "Report"),
                ] {
                    if ui.selectable_label(self.detail_tab == tab, label).clicked() {
                        self.detail_tab = tab;
                    }
                }
            });
            ui.separator();
            egui::ScrollArea::vertical().show(ui, |ui| match self.detail_tab {
                DetailTab::Messages => {
                    for message in &self.messages {
                        ui.label(format!("[{}] {}", message.role, redact(&message.content)));
                        ui.separator();
                    }
                }
                DetailTab::Events => {
                    for event in &self.events {
                        ui.label(format!(
                            "{} [{}] {}",
                            event.created_at,
                            event.kind,
                            redact(&event.message)
                        ));
                    }
                }
                DetailTab::Findings => {
                    for finding in &self.findings {
                        ui.label(format!(
                            "[{}] {} | {} | status={}",
                            finding.severity,
                            redact(&finding.title),
                            redact(finding.asset.as_deref().unwrap_or("-")),
                            finding.status
                        ));
                        ui.label(redact(&finding.description));
                        if let Some(request) = &finding.request {
                            ui.label(format!("request: {}", redact(request)));
                        }
                        if let Some(response) = &finding.response {
                            ui.label(format!("response: {}", redact(response)));
                        }
                        ui.separator();
                    }
                }
                DetailTab::Assets => {
                    for asset in &self.assets {
                        ui.label(format!("{} = {}", asset.kind, redact(&asset.value)));
                    }
                }
                DetailTab::Artifacts => {
                    for artifact in &self.artifacts {
                        ui.label(format!(
                            "{} {}",
                            artifact.kind,
                            redact(artifact.path.as_deref().unwrap_or("-"))
                        ));
                    }
                }
                DetailTab::Coverage => {
                    for target in &self.coverage {
                        ui.label(redact(target));
                    }
                    ui.separator();
                    ui.label("Hypotheses:");
                    for hypothesis in &self.hypotheses {
                        ui.label(format!(
                            "[{}] {}",
                            hypothesis.status,
                            redact(&hypothesis.statement)
                        ));
                    }
                }
                DetailTab::Report => {
                    ui.text_edit_multiline(&mut self.report);
                    if ui.button("Save report to file").clicked() {
                        let path = format!("report-{}.md", &id[..id.len().min(8)]);
                        match std::fs::write(&path, &self.report) {
                            Ok(()) => self.status = format!("report written: {path}"),
                            Err(e) => self.status = format!("report error: {e}"),
                        }
                    }
                }
            });
        });
    }

    fn ui_run(&mut self, ui: &mut egui::Ui) {
        ui.heading("New engagement run");
        ui.label("Goal:");
        ui.text_edit_multiline(&mut self.goal);
        ui.horizontal(|ui| {
            ui.label("Workspace:");
            ui.text_edit_singleline(&mut self.cwd);
        });
        ui.horizontal(|ui| {
            ui.radio_value(
                &mut self.run_mode_choice,
                ModeChoice::Ask,
                "ask (require approval)",
            );
            ui.radio_value(
                &mut self.run_mode_choice,
                ModeChoice::FullAuto,
                "full_auto (policy bounded)",
            );
        });
        if ui.button("Start run").clicked() {
            let job = Job::Run {
                goal: self.goal.trim().to_string(),
                cwd: self.cwd.clone(),
                mode: self.run_mode_choice.into(),
            };
            self.spawn(job, "run");
        }
        ui.separator();
        ui.label("Last output:");
        ui.text_edit_multiline(&mut self.last_output);
    }

    fn ui_approvals(&mut self, ui: &mut egui::Ui) {
        ui.heading("Pending approvals");
        if self.pending.is_empty() {
            ui.label("(none)");
            return;
        }
        egui::ScrollArea::vertical().show(ui, |ui| {
            let pending = self.pending.clone();
            for (session, approval) in pending {
                ui.group(|ui| {
                    ui.label(format!(
                        "session {} | tool {} | risk {}",
                        &session[..session.len().min(8)],
                        redact(&approval.tool_name),
                        redact(&approval.risk)
                    ));
                    ui.label(format!(
                        "expires: {}",
                        approval.expires_at.as_deref().unwrap_or("-")
                    ));
                    ui.label(format!("args: {}", redact(&approval.args_json)));
                    ui.horizontal(|ui| {
                        if ui.button("Approve").clicked() {
                            let job = Job::Approve {
                                session: session.clone(),
                                decision: "approve".into(),
                                cwd: self.cwd.clone(),
                                mode: self.run_mode_choice.into(),
                            };
                            self.spawn(job, "approve");
                        }
                        if ui.button("Deny").clicked() {
                            let job = Job::Approve {
                                session: session.clone(),
                                decision: "deny".into(),
                                cwd: self.cwd.clone(),
                                mode: self.run_mode_choice.into(),
                            };
                            self.spawn(job, "deny");
                        }
                    });
                });
            }
        });
    }

    fn ui_config(&mut self, ui: &mut egui::Ui) {
        ui.heading("Configuration");
        ui.separator();
        ui.label("LLM");
        ui.horizontal(|ui| {
            ui.label("base_url");
            ui.text_edit_singleline(&mut self.config.llm.base_url);
        });
        ui.horizontal(|ui| {
            ui.label("api_key");
            ui.text_edit_singleline(&mut self.config.llm.api_key);
        });
        ui.horizontal(|ui| {
            ui.label("model");
            ui.text_edit_singleline(&mut self.cfg_default_model);
        });
        ui.horizontal(|ui| {
            ui.label("timeout_ms");
            ui.add(egui::DragValue::new(&mut self.config.llm.timeout_ms).speed(100));
        });
        ui.horizontal(|ui| {
            ui.label("cost /1K in");
            ui.add(egui::DragValue::new(&mut self.config.llm.cost_per_1k_input).speed(0.0001));
            ui.label("out");
            ui.add(egui::DragValue::new(&mut self.config.llm.cost_per_1k_output).speed(0.0001));
        });
        ui.separator();
        ui.label("Agent");
        ui.horizontal(|ui| {
            ui.radio_value(&mut self.mode_choice, ModeChoice::Ask, "ask");
            ui.radio_value(&mut self.mode_choice, ModeChoice::FullAuto, "full_auto");
        });
        ui.horizontal(|ui| {
            ui.label("max_steps");
            ui.add(egui::DragValue::new(&mut self.config.agent.max_steps));
            ui.label("max_tools");
            ui.add(egui::DragValue::new(&mut self.config.agent.max_tool_calls));
            ui.label("max_net");
            ui.add(egui::DragValue::new(
                &mut self.config.agent.max_network_calls,
            ));
        });
        ui.horizontal(|ui| {
            ui.label("rpm");
            ui.add(egui::DragValue::new(
                &mut self.config.agent.requests_per_minute,
            ));
            ui.label("max_tokens");
            ui.add(egui::DragValue::new(
                &mut self.config.agent.max_estimated_tokens,
            ));
        });
        ui.label("system prompt");
        ui.text_edit_multiline(&mut self.cfg_system_prompt);
        ui.label(format!(
            "auto approve: {}",
            self.config.agent.auto_approve_tools.join(", ")
        ));
        ui.separator();
        ui.label("Scope (one pattern per line)");
        ui.horizontal(|ui| {
            ui.label("engagement");
            ui.text_edit_singleline(&mut self.scope_engagement);
        });
        ui.horizontal(|ui| {
            ui.label("in scope");
            ui.text_edit_multiline(&mut self.scope_in_text);
            ui.label("out of scope");
            ui.text_edit_multiline(&mut self.scope_out_text);
        });
        ui.label("notes");
        ui.text_edit_multiline(&mut self.scope_notes);
        ui.separator();
        ui.label("Network / adapters");
        ui.checkbox(
            &mut self.config.network.allow_proxy,
            "allow proxy (loopback only)",
        );
        ui.horizontal(|ui| {
            ui.label("proxy_url");
            ui.text_edit_singleline(&mut self.cfg_proxy_url);
        });
        ui.label(format!(
            "trusted local: {}",
            self.config.network.trusted_local_targets.join(", ")
        ));
        ui.checkbox(
            &mut self.config.external_tools.enabled,
            "enable external adapters",
        );
        ui.checkbox(
            &mut self.config.external_tools.auto_detect,
            "auto-detect binaries",
        );
        ui.separator();
        if ui.button("Save config").clicked() {
            self.apply_config_fields();
            match self
                .config
                .validate()
                .and_then(|_| self.config.save(&self.config_path))
            {
                Ok(()) => {
                    self.status = format!("config saved: {}", self.config_path.display());
                    self.load_config_fields();
                }
                Err(e) => self.status = format!("config error: {e:#}"),
            }
        }
    }

    fn ui_tools(&mut self, ui: &mut egui::Ui) {
        ui.heading("External tool availability");
        if ui.button("Rescan PATH").clicked() {
            self.refresh_tools();
        }
        ui.separator();
        for (name, availability) in &self.tool_list {
            ui.label(format!("{name}: {availability}"));
        }
    }

    fn ui_logs(&mut self, ui: &mut egui::Ui) {
        ui.heading("Event log");
        egui::ScrollArea::vertical().show(ui, |ui| {
            for event in &self.events {
                ui.label(format!(
                    "{} [{}] {} {}",
                    event.created_at,
                    event.level,
                    event.kind,
                    redact(&event.message)
                ));
            }
            if self.events.is_empty() {
                ui.label("(no events; select a session)");
            }
        });
    }
}

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("MiniBug Desktop")
            .with_inner_size([1280.0, 800.0]),
        ..Default::default()
    };
    eframe::run_native(
        "MiniBug Desktop",
        options,
        Box::new(|_cc| Ok(Box::new(DesktopApp::new()) as Box<dyn eframe::App>)),
    )
}
