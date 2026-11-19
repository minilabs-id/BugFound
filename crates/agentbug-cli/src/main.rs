use agentbug_core::{prioritize_targets, AgentConfig, Runner};
use agentbug_llm::{Llm, LlmConfig};
use agentbug_policy::{parse_scope_brief, Mode};
use agentbug_store::{redact, Store};
use agentbug_tools::{try_default_registry_with_options, ToolOptions};
use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(
    name = "agentbug",
    version,
    about = "AgentBug universal agent core (hardened MVP)"
)]
struct Cli {
    /// Path to config TOML
    #[arg(long, default_value = "agentbug.toml", global = true)]
    config: PathBuf,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a sample config in the current directory
    Init {
        /// Overwrite if exists
        #[arg(long)]
        force: bool,
    },
    /// Run a new goal/session
    Run {
        /// Goal/prompt for the agent
        #[arg(long)]
        goal: String,
        /// Execution mode
        #[arg(long, value_enum)]
        mode: Option<ModeArg>,
        /// Workspace/cwd for tools (confined)
        #[arg(long, default_value = ".")]
        cwd: String,
    },
    /// Resume a session waiting for approval
    Resume {
        /// Session id
        #[arg(long)]
        session: String,
        /// Approve the pending tool call
        #[arg(long, conflicts_with = "deny")]
        approve: bool,
        /// Deny the pending tool call
        #[arg(long, conflicts_with = "approve")]
        deny: bool,
        /// Workspace/cwd for tools (must be the intended workspace)
        #[arg(long, default_value = ".")]
        cwd: String,
        /// Execution mode (policy for continued run)
        #[arg(long, value_enum)]
        mode: Option<ModeArg>,
    },
    /// Approve a pending tool call (alias for resume --approve)
    Approve {
        /// Session id
        #[arg(long)]
        session: String,
        /// Workspace/cwd for tools (must be the intended workspace)
        #[arg(long, default_value = ".")]
        cwd: String,
        /// Execution mode (policy for continued run)
        #[arg(long, value_enum)]
        mode: Option<ModeArg>,
    },
    /// Deny a pending tool call (alias for resume --deny)
    Deny {
        /// Session id
        #[arg(long)]
        session: String,
        /// Workspace/cwd for tools (must be the intended workspace)
        #[arg(long, default_value = ".")]
        cwd: String,
        /// Execution mode (policy for continued run)
        #[arg(long, value_enum)]
        mode: Option<ModeArg>,
    },
    /// List recent sessions
    Sessions {
        /// Max sessions to show
        #[arg(long, default_value_t = 20)]
        limit: usize,
    },
    /// Show audit log events for a session (or all if no session)
    Logs {
        /// Session id (optional; shows all if omitted)
        #[arg(long)]
        session: Option<String>,
        /// Max events to show
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
    /// List findings for a session
    Findings {
        #[arg(long)]
        session: String,
    },
    /// List assets for a session
    Assets {
        #[arg(long)]
        session: String,
    },
    /// List artifacts for a session
    Artifacts {
        #[arg(long)]
        session: String,
    },
    /// Export a report for a session
    Report {
        #[arg(long)]
        session: String,
        #[arg(long)]
        output: Option<String>,
    },
    /// Show live session state, budgets, approvals and coverage
    Status {
        #[arg(long)]
        session: String,
    },
    /// Validate configuration and local environment
    Doctor,
    /// List pending approvals with full details
    Approvals {
        #[arg(long)]
        session: String,
    },
    /// Import an engagement brief into [scope]
    ScopeImport {
        #[arg(long)]
        file: PathBuf,
        #[arg(long)]
        program: Option<String>,
    },
    /// Track testing hypotheses for a session
    Hypothesis {
        #[arg(long)]
        session: String,
        #[arg(long)]
        add: Option<String>,
        #[arg(long)]
        list: bool,
    },
    /// Prioritize in-scope targets that have not been covered yet
    Plan {
        #[arg(long)]
        session: String,
    },
    /// Show external adapter availability
    Tools,
    /// Show estimated token usage and cost
    Tokens {
        #[arg(long)]
        session: String,
    },
    /// Verify the tamper-evident event hash chain
    VerifyLog {
        #[arg(long)]
        session: String,
    },
    /// Run a full autonomous bug-bounty engagement from a program URL
    Engage {
        #[arg(long)]
        url: String,
        #[arg(long, default_value = ".")]
        cwd: String,
        #[arg(long)]
        db: Option<String>,
        /// Only ingest the public brief and plan; never execute tools against the target
        #[arg(long)]
        brief_only: bool,
    },
    /// Inspect/control a running engagement
    Engagement {
        #[arg(long)]
        id: String,
        #[arg(long)]
        db: Option<String>,
        #[arg(long)]
        status: bool,
        #[arg(long)]
        pause: bool,
        #[arg(long)]
        resume: bool,
        #[arg(long)]
        abort: bool,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum ModeArg {
    Ask,
    FullAuto,
}
impl From<ModeArg> for Mode {
    fn from(m: ModeArg) -> Self {
        match m {
            ModeArg::Ask => Mode::Ask,
            ModeArg::FullAuto => Mode::FullAuto,
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Default, Clone)]
struct FileConfig {
    #[serde(default)]
    llm: LlmFile,
    #[serde(default)]
    agent: AgentFile,
    #[serde(default)]
    storage: StorageFile,
    #[serde(default)]
    scope: agentbug_policy::ScopeConfig,
    #[serde(default)]
    network: NetworkFile,
    #[serde(default)]
    external_tools: ExternalFile,
}

impl FileConfig {
    fn validate(&self) -> Result<()> {
        agentbug_llm::validate_base_url(&self.llm.base_url)
            .with_context(|| format!("invalid llm.base_url '{}'", self.llm.base_url))?;
        if let Some(mode) = self.agent.mode.as_deref() {
            if !matches!(mode, "ask" | "full_auto" | "full-auto") {
                return Err(anyhow!(
                    "invalid agent.mode '{mode}' (expected 'ask' or 'full_auto')"
                ));
            }
        }
        if let Some(max_steps) = self.agent.max_steps {
            if max_steps == 0 {
                return Err(anyhow!("agent.max_steps must be greater than zero"));
            }
            if max_steps > 200 {
                return Err(anyhow!(
                    "agent.max_steps must be at most 200 (got {max_steps}); values above the 200-step clamp are rejected"
                ));
            }
        }
        // Absurd budget values are almost always a misconfiguration; reject them
        // rather than letting a run consume unbounded time or resources.
        let budgets = [
            ("agent.max_steps", self.agent.max_steps.map(|v| v as u64)),
            (
                "agent.max_tool_calls",
                self.agent.max_tool_calls.map(|v| v as u64),
            ),
            (
                "agent.max_network_calls",
                self.agent.max_network_calls.map(|v| v as u64),
            ),
            ("agent.requests_per_minute", self.agent.requests_per_minute),
        ];
        for (name, value) in budgets {
            if let Some(v) = value {
                if v > 1_000_000 {
                    return Err(anyhow!("{name} must be at most 1000000 (got {v})"));
                }
            }
        }
        if self.llm.timeout_ms < 1000 {
            return Err(anyhow!("llm.timeout_ms must be at least 1000"));
        }
        for pattern in self
            .scope
            .in_scope
            .iter()
            .chain(self.scope.out_of_scope.iter())
        {
            if pattern.trim().is_empty() {
                return Err(anyhow!("scope patterns must not be empty"));
            }
        }
        Ok(())
    }
}
#[derive(Debug, Deserialize, Serialize, Clone)]
struct LlmFile {
    #[serde(default = "d_base")]
    base_url: String,
    #[serde(default)]
    api_key: String,
    #[serde(default)]
    default_model: Option<String>,
    #[serde(default = "d_timeout")]
    timeout_ms: u64,
    #[serde(default)]
    cost_per_1k_input: f64,
    #[serde(default)]
    cost_per_1k_output: f64,
}
impl Default for LlmFile {
    fn default() -> Self {
        Self {
            base_url: d_base(),
            api_key: String::new(),
            default_model: None,
            timeout_ms: d_timeout(),
            cost_per_1k_input: 0.0,
            cost_per_1k_output: 0.0,
        }
    }
}
fn d_base() -> String {
    "https://api.openai.com".into()
}
fn d_timeout() -> u64 {
    60000
}
#[derive(Debug, Deserialize, Serialize, Default, Clone)]
struct AgentFile {
    #[serde(default)]
    mode: Option<String>,
    #[serde(default)]
    max_steps: Option<usize>,
    #[serde(default)]
    system_prompt: Option<String>,
    #[serde(default)]
    system: Option<String>,
    #[serde(default)]
    max_tool_calls: Option<usize>,
    #[serde(default)]
    max_network_calls: Option<usize>,
    #[serde(default)]
    requests_per_minute: Option<u64>,
    #[serde(default)]
    auto_approve_tools: Vec<String>,
    #[serde(default)]
    max_estimated_tokens: Option<u64>,
}
#[derive(Debug, Deserialize, Serialize, Clone, Default)]
struct NetworkFile {
    #[serde(default)]
    allow_proxy: bool,
    #[serde(default)]
    proxy_url: Option<String>,
    #[serde(default)]
    trusted_local_targets: Vec<String>,
}
#[derive(Debug, Deserialize, Serialize, Clone, Default)]
struct ExternalFile {
    #[serde(default)]
    enabled: bool,
    #[serde(default)]
    auto_detect: bool,
    #[serde(default)]
    commands: std::collections::BTreeMap<String, String>,
}
#[derive(Debug, Deserialize, Serialize, Clone)]
struct StorageFile {
    #[serde(default = "d_db")]
    path: String,
}
impl Default for StorageFile {
    fn default() -> Self {
        Self { path: d_db() }
    }
}
fn d_db() -> String {
    ".agentbug/agentbug.db".into()
}

fn load_config(path: &Path) -> Result<FileConfig> {
    if path.exists() {
        let s = std::fs::read_to_string(path)
            .with_context(|| format!("read config {}", path.display()))?;
        let cfg: FileConfig =
            toml::from_str(&s).with_context(|| format!("parse config {}", path.display()))?;
        Ok(cfg)
    } else {
        Ok(FileConfig::default())
    }
}

fn resolve_api_key(raw: &str) -> Result<String> {
    let raw = raw.trim();
    if let Some(var) = raw.strip_prefix("env:") {
        let var = var.trim();
        if var.is_empty() {
            return Err(anyhow!("llm.api_key uses env: but variable name is empty"));
        }
        let val = std::env::var(var).with_context(|| {
            format!("environment variable '{var}' is not set (required by llm.api_key=env:{var})")
        })?;
        if val.trim().is_empty() {
            return Err(anyhow!("environment variable '{var}' is empty"));
        }
        Ok(val)
    } else {
        if raw.is_empty() {
            return Err(anyhow!(
                "llm.api_key is not set. Set it in config or use api_key = \"env:VAR\""
            ));
        }
        Ok(raw.to_string())
    }
}

fn resolve_mode(arg: Option<ModeArg>, cfg_mode: Option<&str>) -> Mode {
    if let Some(m) = arg {
        return m.into();
    }
    match cfg_mode {
        Some("full_auto") | Some("full-auto") => Mode::FullAuto,
        Some("ask") => Mode::Ask,
        _ => Mode::Ask,
    }
}

type RunnerParts = (
    Option<Store>,
    Arc<dyn Llm>,
    agentbug_tools::ToolRegistry,
    agentbug_policy::PolicyEngine,
    AgentConfig,
);

fn build_runner(cfg: &FileConfig, cwd: &str, mode: Mode, open_store: bool) -> Result<RunnerParts> {
    let api_key = resolve_api_key(&cfg.llm.api_key)?;
    let llm_cfg = LlmConfig {
        base_url: cfg.llm.base_url.clone(),
        api_key,
        default_model: cfg
            .llm
            .default_model
            .as_ref()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty()),
        timeout_ms: cfg.llm.timeout_ms,
    };
    let client = agentbug_llm::LlmClient::new(llm_cfg)?;
    // default_registry() unwraps tool construction on an invalid cwd; verify the
    // workspace up front so callers get a clean error instead of a panic.
    std::fs::canonicalize(cwd)
        .with_context(|| format!("invalid or inaccessible workspace cwd '{cwd}'"))?;
    let options = ToolOptions {
        allow_proxy: cfg.network.allow_proxy,
        proxy_url: cfg.network.proxy_url.clone(),
        trusted_local_targets: cfg.network.trusted_local_targets.clone(),
        enable_external_tools: cfg.external_tools.enabled,
        external_commands: cfg.external_tools.commands.clone(),
        auto_detect_external: cfg.external_tools.auto_detect,
        scope_in: cfg.scope.in_scope.clone(),
        scope_out: cfg.scope.out_of_scope.clone(),
        ..Default::default()
    };
    let tools = try_default_registry_with_options(cwd, options)?;
    let policy = agentbug_core::build_policy_config(agentbug_policy::PolicyConfig {
        mode,
        scope: cfg.scope.clone(),
        ..Default::default()
    });
    let agent = AgentConfig {
        mode,
        max_steps: cfg.agent.max_steps.unwrap_or(20),
        system_prompt: cfg
            .agent
            .system_prompt
            .clone()
            .or_else(|| cfg.agent.system.clone()),
        system: cfg.agent.system.clone(),
        max_tool_calls: cfg.agent.max_tool_calls.unwrap_or(0),
        max_network_calls: cfg.agent.max_network_calls.unwrap_or(0),
        requests_per_minute: cfg.agent.requests_per_minute.unwrap_or(0),
        auto_approve_tools: cfg.agent.auto_approve_tools.clone(),
        max_estimated_tokens: cfg.agent.max_estimated_tokens.unwrap_or(0),
        cost_per_1k_input: cfg.llm.cost_per_1k_input,
        cost_per_1k_output: cfg.llm.cost_per_1k_output,
        ..Default::default()
    };
    let store = if open_store {
        Some(Store::open(&cfg.storage.path)?)
    } else {
        None
    };
    Ok((store, Arc::new(client), tools, policy, agent))
}

fn print_approval_summary(store: &Store, session: &str) {
    match store.list_pending_approvals(session) {
        Ok(approvals) => {
            for approval in approvals {
                println!(
                    "pending approval: tool={} risk={} reason={} expires={} args={}",
                    redact(&approval.tool_name),
                    redact(&approval.risk),
                    redact(approval.reason.as_deref().unwrap_or("-")),
                    approval.expires_at.as_deref().unwrap_or("-"),
                    redact(&approval.args_json)
                );
            }
        }
        Err(e) => eprintln!("warning: cannot list approvals: {e}"),
    }
}

fn print_engagement_status(db: &std::path::Path, id: &str) -> Result<()> {
    let status = agentbug_engagement::status_at(db, id).context("query engagement status")?;
    println!("engagement={} state={}", redact(id), redact(&status.state));
    println!(
        "tasks_total={} tasks_done={} findings={} coverage={}",
        status.tasks_total, status.tasks_done, status.findings, status.coverage
    );
    println!(
        "report_path={}",
        redact(
            &status
                .report_path
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "-".into())
        )
    );
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("info".parse().unwrap()))
        .with_target(false)
        .init();
    let cli = Cli::parse();
    let config_path = cli.config.clone();
    let cfg = load_config(&cli.config)?;
    cfg.validate()?;
    match cli.command {
        Commands::Init { force } => {
            let path = Path::new("agentbug.toml");
            if path.exists() && !force {
                println!("agentbug.toml already exists (use --force to overwrite)");
            } else {
                let sample = r#"# AgentBug core config (hardened MVP)
[llm]
base_url = "https://api.openai.com"
# api_key = "env:OPENAI_API_KEY"  # recommended: read from environment
# api_key = "sk-..."
# default_model = "gpt-4o-mini"
timeout_ms = 60000

[agent]
mode = "ask"          # ask | full_auto
max_steps = 20

[storage]
path = ".agentbug/agentbug.db"
"#;
                std::fs::write(path, sample).context("write agentbug.toml")?;
                println!("wrote agentbug.toml");
            }
        }
        Commands::Run { goal, mode, cwd } => {
            let mode = resolve_mode(mode, cfg.agent.mode.as_deref());
            let (store, client, tools, policy, agent) = build_runner(&cfg, &cwd, mode, true)?;
            let store = store.expect("store");
            let runner = Runner::new(store, client, tools, policy, agent);
            match runner.run_goal(&goal).await {
                Ok(out) => println!("{}", out),
                Err(e) => {
                    eprintln!("error: {e:#}");
                    std::process::exit(1);
                }
            }
        }
        Commands::Resume {
            session,
            approve,
            deny,
            cwd,
            mode,
        } => {
            if approve == deny {
                return Err(anyhow!("specify exactly one of --approve or --deny"));
            }
            let mode = resolve_mode(mode, cfg.agent.mode.as_deref());
            let (store, client, tools, policy, agent) = build_runner(&cfg, &cwd, mode, true)?;
            let store = store.expect("store");
            print_approval_summary(&store, &session);
            let runner = Runner::new(store, client, tools, policy, agent);
            let decision = if approve { "approve" } else { "deny" };
            match runner.resume_session(&session, decision).await {
                Ok(out) => println!("{}", out),
                Err(e) => {
                    eprintln!("error: {e:#}");
                    std::process::exit(1);
                }
            }
        }
        Commands::Approve { session, cwd, mode } => {
            let mode = resolve_mode(mode, cfg.agent.mode.as_deref());
            let (store, client, tools, policy, agent) = build_runner(&cfg, &cwd, mode, true)?;
            let store = store.expect("store");
            print_approval_summary(&store, &session);
            let runner = Runner::new(store, client, tools, policy, agent);
            match runner.resume_session(&session, "approve").await {
                Ok(out) => println!("{}", out),
                Err(e) => {
                    eprintln!("error: {e:#}");
                    std::process::exit(1);
                }
            }
        }
        Commands::Deny { session, cwd, mode } => {
            let mode = resolve_mode(mode, cfg.agent.mode.as_deref());
            let (store, client, tools, policy, agent) = build_runner(&cfg, &cwd, mode, true)?;
            let store = store.expect("store");
            print_approval_summary(&store, &session);
            let runner = Runner::new(store, client, tools, policy, agent);
            match runner.resume_session(&session, "deny").await {
                Ok(out) => println!("{}", out),
                Err(e) => {
                    eprintln!("error: {e:#}");
                    std::process::exit(1);
                }
            }
        }
        Commands::Sessions { limit } => {
            let store = Store::open(&cfg.storage.path)?;
            let sessions = store.list_sessions(limit)?;
            if sessions.is_empty() {
                println!("(no sessions)");
            } else {
                for s in sessions {
                    let pending = store
                        .get_pending_approval(&s.id)
                        .ok()
                        .flatten()
                        .map(|a| format!(" pending_tool={}", a.tool_name))
                        .unwrap_or_default();
                    println!(
                        "{}\tstate={}\tmodel={}\tcreated={}\tgoal={}{}",
                        redact(&s.id),
                        redact(&s.state),
                        redact(&s.model.unwrap_or_else(|| "-".into())),
                        redact(&s.created_at),
                        redact(&s.goal).replace('\n', " "),
                        redact(&pending)
                    );
                }
            }
        }
        Commands::Logs { session, limit } => {
            let store = Store::open(&cfg.storage.path)?;
            let events = match session.as_deref() {
                Some(sid) => store.list_events(sid, limit)?,
                None => store.list_all_events(limit)?,
            };
            if events.is_empty() {
                println!("(no events)");
            } else {
                for e in events {
                    let short_sid = if e.session_id.len() > 8 {
                        &e.session_id[..8]
                    } else {
                        &e.session_id
                    };
                    println!(
                        "{}\t{}\t{}\t{}\t{}\t{}",
                        redact(&e.created_at),
                        redact(short_sid),
                        redact(&e.level),
                        redact(&e.kind),
                        redact(&e.session_id),
                        redact(&e.message)
                    );
                }
            }
        }
        Commands::Findings { session } => {
            let store = Store::open(&cfg.storage.path)?;
            let items = store.list_findings(&session)?;
            if items.is_empty() {
                println!("(no findings)");
            }
            for f in items {
                println!(
                    "[{}] {} (asset: {})",
                    redact(&f.severity),
                    redact(&f.title),
                    redact(f.asset.as_deref().unwrap_or_default())
                );
                if !f.description.is_empty() {
                    println!("  {}", redact(&f.description));
                }
            }
        }
        Commands::Assets { session } => {
            let store = Store::open(&cfg.storage.path)?;
            let items = store.list_assets(&session)?;
            if items.is_empty() {
                println!("(no assets)");
            }
            for a in items {
                println!("{} = {}", redact(&a.kind), redact(&a.value));
            }
        }
        Commands::Artifacts { session } => {
            let store = Store::open(&cfg.storage.path)?;
            let items = store.list_artifacts(&session)?;
            if items.is_empty() {
                println!("(no artifacts)");
            }
            for a in items {
                println!(
                    "{} {}",
                    redact(&a.kind),
                    redact(a.path.as_deref().unwrap_or_default())
                );
            }
        }
        Commands::Report { session, output } => {
            let store = Store::open(&cfg.storage.path)?;
            let report = store.export_report(&session)?;
            if let Some(path) = output {
                std::fs::write(path, report)?;
                println!("report written");
            } else {
                println!("{}", redact(&report));
            }
        }
        Commands::Status { session } => {
            let store = Store::open(&cfg.storage.path)?;
            let session_row = store
                .get_session(&session)?
                .ok_or_else(|| anyhow!("session not found: {session}"))?;
            let budget = store.budget_usage(&session)?;
            let approvals = store.list_pending_approvals(&session)?;
            let findings = store.list_findings(&session)?;
            let coverage = store.coverage_count(&session)?;
            let hypotheses = store.list_hypotheses(&session)?;
            println!(
                "session={} state={} model={}",
                session_row.id,
                session_row.state,
                session_row.model.unwrap_or_else(|| "-".into())
            );
            println!(
                "budget steps={}/{} tools={} network={} rpm_window={}",
                budget.steps_used,
                cfg.agent.max_steps.unwrap_or(20),
                budget.tool_calls_used,
                budget.network_calls_used,
                budget.calls_in_window
            );
            println!(
                "pending_approvals={} findings={} coverage={} hypotheses={}",
                approvals.len(),
                findings.len(),
                coverage,
                hypotheses.len()
            );
            for approval in approvals {
                println!(
                    "  pending: tool={} expires={}",
                    redact(&approval.tool_name),
                    approval.expires_at.as_deref().unwrap_or("-")
                );
            }
            for hypothesis in hypotheses.iter().take(10) {
                println!(
                    "  hypothesis [{}] {}",
                    redact(&hypothesis.status),
                    redact(&hypothesis.statement)
                );
            }
        }
        Commands::Doctor => {
            cfg.validate()?;
            let store = Store::open(&cfg.storage.path)?;
            println!("config: ok");
            println!("database: ok ({})", cfg.storage.path);
            match resolve_api_key(&cfg.llm.api_key) {
                Ok(_) => println!("api_key: ok"),
                Err(e) => println!("api_key: unavailable ({e})"),
            }
            println!(
                "scope: in_scope={} out_of_scope={}",
                cfg.scope.in_scope.len(),
                cfg.scope.out_of_scope.len()
            );
            println!(
                "proxy={} external_tools={}",
                cfg.network.allow_proxy, cfg.external_tools.enabled
            );
            drop(store);
        }
        Commands::Approvals { session } => {
            let store = Store::open(&cfg.storage.path)?;
            let approvals = store.list_pending_approvals(&session)?;
            if approvals.is_empty() {
                println!("(no pending approvals)");
            } else {
                print_approval_summary(&store, &session);
            }
        }
        Commands::ScopeImport { file, program } => {
            let text = std::fs::read_to_string(&file)
                .with_context(|| format!("read scope brief {}", file.display()))?;
            let mut scope = parse_scope_brief(&text);
            if let Some(name) = program {
                scope.engagement = Some(name);
            }
            let mut updated = cfg.clone();
            updated.scope = scope;
            let serialized = toml::to_string_pretty(&updated).context("serialize config")?;
            std::fs::write(&config_path, serialized)
                .with_context(|| format!("write config {}", config_path.display()))?;
            println!(
                "scope imported: in_scope={} out_of_scope={}",
                updated.scope.in_scope.len(),
                updated.scope.out_of_scope.len()
            );
        }
        Commands::Hypothesis { session, add, list } => {
            let store = Store::open(&cfg.storage.path)?;
            if let Some(ref statement) = add {
                let hypothesis = store.add_hypothesis(&session, statement)?;
                println!("added hypothesis {}", hypothesis.id);
            }
            if list || add.is_none() {
                for hypothesis in store.list_hypotheses(&session)? {
                    println!(
                        "[{}] {} {}",
                        hypothesis.id,
                        hypothesis.status,
                        redact(&hypothesis.statement)
                    );
                }
            }
        }
        Commands::Plan { session } => {
            let store = Store::open(&cfg.storage.path)?;
            let covered = store.coverage_targets(&session)?;
            let hypotheses = store.list_hypotheses(&session)?;
            let targets = prioritize_targets(&cfg.scope.in_scope, &covered, &hypotheses);
            if targets.is_empty() {
                println!("(no uncovered targets; refine scope or add hypotheses)");
            }
            for (index, target) in targets.iter().enumerate() {
                println!("{}. {}", index + 1, redact(target));
            }
        }
        Commands::Tools => {
            for (name, path) in agentbug_tools::external_tool_availability() {
                println!(
                    "{}\t{}",
                    name,
                    path.map(|p| p.display().to_string())
                        .unwrap_or_else(|| "not installed".into())
                );
            }
        }
        Commands::Tokens { session } => {
            let store = Store::open(&cfg.storage.path)?;
            let usage = store.token_usage(&session)?;
            println!(
                "prompt_tokens={} completion_tokens={} total={} cost_usd={:.6}",
                usage.prompt_tokens,
                usage.completion_tokens,
                usage.prompt_tokens + usage.completion_tokens,
                usage.cost_usd
            );
        }
        Commands::VerifyLog { session } => {
            let store = Store::open(&cfg.storage.path)?;
            let valid = store.verify_event_chain(&session)?;
            println!("event_chain={}", if valid { "valid" } else { "TAMPERED" });
            if !valid {
                std::process::exit(1);
            }
        }
        Commands::Engage {
            url,
            cwd,
            db,
            brief_only,
        } => {
            let db_path = db.unwrap_or_else(|| cfg.storage.path.clone());
            let (tx, rx) = std::sync::mpsc::channel::<agentbug_engagement::EngagementEvent>();

            // Keep the id emitted by the Started event so Ctrl+C can abort the
            // running engagement from an independent signal-watching thread.
            let engagement_id = Arc::new(std::sync::Mutex::new(None::<String>));
            let id_for_signal = Arc::clone(&engagement_id);
            std::thread::spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("build signal runtime");
                runtime.block_on(async move {
                    if tokio::signal::ctrl_c().await.is_ok() {
                        let guard = id_for_signal.lock().unwrap();
                        if let Some(id) = guard.as_ref() {
                            match agentbug_engagement::abort(id) {
                                Ok(()) => {}
                                Err(e) => eprintln!("warning: failed to abort engagement: {e}"),
                            }
                        }
                    }
                });
            });

            let worker_url = url.clone();
            let worker_cwd = cwd.clone();
            let worker_db = db_path.clone();
            let worker = std::thread::spawn(move || {
                if brief_only {
                    agentbug_engagement::engage_brief_only(
                        &worker_url,
                        Path::new(&worker_cwd),
                        Path::new(&worker_db),
                        tx,
                    )
                } else {
                    agentbug_engagement::engage(
                        &worker_url,
                        Path::new(&worker_cwd),
                        Path::new(&worker_db),
                        tx,
                    )
                }
            });

            let mut exit_code = loop {
                match rx.recv() {
                    Ok(agentbug_engagement::EngagementEvent::Started { engagement_id: id }) => {
                        println!("engagement started: id={}", redact(&id));
                        *engagement_id.lock().unwrap() = Some(id);
                    }
                    Ok(agentbug_engagement::EngagementEvent::BriefIngested { .. }) => {
                        println!("brief ingested");
                    }
                    Ok(agentbug_engagement::EngagementEvent::PlanUpdated { tasks }) => {
                        println!("plan updated: {} tasks", tasks.len());
                        for task in tasks {
                            println!("  - {}", redact(&task));
                        }
                    }
                    Ok(agentbug_engagement::EngagementEvent::Action {
                        tool,
                        target,
                        ok,
                        detail,
                    }) => println!(
                        "action: tool={} target={} ok={} detail={}",
                        redact(&tool),
                        redact(target.as_deref().unwrap_or("-")),
                        ok,
                        redact(&detail).replace('\n', " ")
                    ),
                    Ok(agentbug_engagement::EngagementEvent::Finding {
                        id,
                        title,
                        severity,
                    }) => println!(
                        "finding: [{}] {} id={}",
                        redact(&severity),
                        redact(&title),
                        redact(&id)
                    ),
                    Ok(agentbug_engagement::EngagementEvent::ReportReady { path }) => {
                        println!("report ready: {}", redact(&path.display().to_string()));
                    }
                    Ok(agentbug_engagement::EngagementEvent::Error { message }) => {
                        eprintln!("engagement error: {}", redact(&message));
                        break 1;
                    }
                    Ok(agentbug_engagement::EngagementEvent::Finished { summary }) => {
                        println!("engagement finished: {}", redact(&summary));
                        break 0;
                    }
                    Err(e) => {
                        eprintln!("engagement event channel closed: {e}");
                        break 1;
                    }
                }
            };

            match worker.join() {
                Ok(Ok(_)) => {}
                Ok(Err(e)) => {
                    eprintln!("engagement error: {e:#}");
                    if exit_code == 0 {
                        exit_code = 1;
                    }
                }
                Err(_) => {
                    eprintln!("engagement worker panicked");
                    exit_code = 1;
                }
            }
            if exit_code != 0 {
                std::process::exit(exit_code);
            }
        }
        Commands::Engagement {
            id,
            db,
            status,
            pause,
            resume,
            abort,
        } => {
            let db_path = std::path::PathBuf::from(db.unwrap_or_else(|| cfg.storage.path.clone()));
            if pause {
                agentbug_engagement::pause_at(&db_path, &id).context("pause engagement")?;
                println!("engagement {} paused", redact(&id));
            }
            if resume {
                agentbug_engagement::resume_at(&db_path, &id).context("resume engagement")?;
                println!("engagement {} resumed", redact(&id));
            }
            if abort {
                agentbug_engagement::abort_at(&db_path, &id).context("abort engagement")?;
                println!("engagement {} aborted", redact(&id));
            }
            if status || !(pause || resume || abort) {
                print_engagement_status(&db_path, &id)?;
            }
        }
    }
    Ok(())
}
