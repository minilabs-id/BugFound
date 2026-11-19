use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use minibug_core::{AgentConfig, Runner};
use minibug_llm::{Llm, LlmConfig};
use minibug_policy::Mode;
use minibug_store::{redact, Store};
use minibug_tools::default_registry;
use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(
    name = "minibug",
    version,
    about = "MiniBug universal agent core (hardened MVP)"
)]
struct Cli {
    /// Path to config TOML
    #[arg(long, default_value = "minibug.toml", global = true)]
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

#[derive(Debug, Deserialize, Default)]
struct FileConfig {
    #[serde(default)]
    llm: LlmFile,
    #[serde(default)]
    agent: AgentFile,
    #[serde(default)]
    storage: StorageFile,
    #[serde(default)]
    scope: minibug_policy::ScopeConfig,
}

impl FileConfig {
    fn validate(&self) -> Result<()> {
        minibug_llm::validate_base_url(&self.llm.base_url)
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
#[derive(Debug, Deserialize, Clone)]
struct LlmFile {
    #[serde(default = "d_base")]
    base_url: String,
    #[serde(default)]
    api_key: String,
    #[serde(default)]
    default_model: Option<String>,
    #[serde(default = "d_timeout")]
    timeout_ms: u64,
}
impl Default for LlmFile {
    fn default() -> Self {
        Self {
            base_url: d_base(),
            api_key: String::new(),
            default_model: None,
            timeout_ms: d_timeout(),
        }
    }
}
fn d_base() -> String {
    "https://api.openai.com".into()
}
fn d_timeout() -> u64 {
    60000
}
#[derive(Debug, Deserialize, Default, Clone)]
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
}
#[derive(Debug, Deserialize, Clone)]
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
    ".minibug/minibug.db".into()
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
    minibug_tools::ToolRegistry,
    minibug_policy::PolicyEngine,
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
    let client = minibug_llm::LlmClient::new(llm_cfg)?;
    // default_registry() unwraps tool construction on an invalid cwd; verify the
    // workspace up front so callers get a clean error instead of a panic.
    std::fs::canonicalize(cwd)
        .with_context(|| format!("invalid or inaccessible workspace cwd '{cwd}'"))?;
    let tools = default_registry(cwd);
    let policy = minibug_core::build_policy_config(minibug_policy::PolicyConfig {
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
        ..Default::default()
    };
    let store = if open_store {
        Some(Store::open(&cfg.storage.path)?)
    } else {
        None
    };
    Ok((store, Arc::new(client), tools, policy, agent))
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("info".parse().unwrap()))
        .with_target(false)
        .init();
    let cli = Cli::parse();
    let cfg = load_config(&cli.config)?;
    cfg.validate()?;
    match cli.command {
        Commands::Init { force } => {
            let path = Path::new("minibug.toml");
            if path.exists() && !force {
                println!("minibug.toml already exists (use --force to overwrite)");
            } else {
                let sample = r#"# MiniBug core config (hardened MVP)
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
path = ".minibug/minibug.db"
"#;
                std::fs::write(path, sample).context("write minibug.toml")?;
                println!("wrote minibug.toml");
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
            let runner = Runner::new(store.expect("store"), client, tools, policy, agent);
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
            let runner = Runner::new(store.expect("store"), client, tools, policy, agent);
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
    }
    Ok(())
}
