use anyhow::{anyhow, Context, Result};
use bugfound_core::{AgentConfig, Runner};
use bugfound_engagement::platform::Platform;
use bugfound_engagement::prioritize_targets;
use bugfound_llm::{Llm, LlmConfig};
use bugfound_policy::{parse_scope_brief, Mode};
use bugfound_store::{redact, SafeHarborReceipt, Store};
use bugfound_tools::{try_default_registry_with_options, ToolOptions};
use chrono::{Duration, Utc};
use clap::{Parser, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "bugfound", version, about = "BugFound agent core")]
struct Cli {
    /// Path to config TOML. If omitted, the default location is used; if
    /// supplied explicitly it must exist (a typo must never become defaults).
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Record or list offline safe-harbor receipts (advisory only; never authorizes action)
    Receipt {
        #[command(subcommand)]
        action: ReceiptCommands,
        /// Database path (defaults to configured storage path)
        #[arg(long, global = true)]
        db: Option<String>,
    },
    /// Record an out-of-band operator acknowledgement for an unparsed ROE rule (offline)
    Authorize {
        /// Exact program URL passed to engage --url
        #[arg(long)]
        url: String,
        /// sha256 hex of the extracted brief text
        #[arg(long)]
        content_hash: String,
        /// Verbatim unparsed ROE line
        #[arg(long, required_unless_present = "version", conflicts_with = "version")]
        rule: Option<String>,
        /// Acknowledge a whole brief version by its content hash
        #[arg(long, required_unless_present = "rule", conflicts_with = "rule")]
        version: Option<String>,
        /// Operator identity recorded in the audit trail
        #[arg(long)]
        operator: String,
        /// Reason for the acknowledgement
        #[arg(long, default_value = "")]
        note: String,
        /// Database path (defaults to configured storage path)
        #[arg(long)]
        db: Option<String>,
    },
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
    /// Prune audit/trace events older than a retention window (chain-guarded)
    Prune {
        /// Session id; omit to prune every session in the store
        #[arg(long)]
        session: Option<String>,
        /// Lookback in days; defaults to storage.retention_days in the config
        #[arg(long)]
        days: Option<usize>,
        /// Report what would be deleted without writing anything
        #[arg(long)]
        dry_run: bool,
    },
    /// Run a full autonomous bug-bounty engagement from a program URL
    Engage {
        /// Public program URL used to fetch the brief (unless --brief-file is given)
        #[arg(long, required_unless_present = "brief_file")]
        url: Option<String>,
        /// Read an already-extracted brief from a local file for an authorized
        /// offline target. No public-brief fetch is performed in this mode.
        #[arg(long)]
        brief_file: Option<String>,
        #[arg(long, default_value = ".")]
        cwd: String,
        #[arg(long)]
        db: Option<String>,
        /// Only ingest the public brief and plan; never execute tools against the target
        #[arg(long)]
        brief_only: bool,
        /// Read-only brief source (generic uses the existing public-page fetch)
        #[arg(long, value_enum, default_value_t = PlatformArg::Generic)]
        platform: PlatformArg,
        /// NAME of the environment variable holding the platform API token.
        /// The token value is never read by the CLI, written to config, or logged.
        #[arg(long)]
        api_key_env: Option<String>,
    },
    /// Inspect/control a running engagement
    #[command(group(
        clap::ArgGroup::new("engagement_action")
            .args(["pause", "resume", "abort"])
            .multiple(false)
    ))]
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
        /// Re-fetch the program brief on resume and verify its content hash
        #[arg(long, requires = "resume")]
        revalidate_brief: bool,
    },
}

#[derive(Subcommand)]
enum ReceiptCommands {
    /// Record a safe-harbor receipt. Decision is always "acknowledged"; there
    /// is no flag to bypass ROE or approve a tool.
    Add {
        /// Exact program URL passed to engage --url
        #[arg(long)]
        program_url: String,
        /// sha256 hex of the extracted brief text (64 hex characters)
        #[arg(long)]
        brief_content_hash: String,
        /// Scope version the receipt covers
        #[arg(long)]
        scope_version: String,
        /// sha256 hex of the acknowledged terms (64 hex characters)
        #[arg(long)]
        terms_hash: String,
        /// Operator identity recorded in the audit trail
        #[arg(long)]
        operator: String,
        /// Expiry as ISO-8601, e.g. 2027-01-01T00:00:00Z
        #[arg(long)]
        expires_at: String,
        /// Optional operator note
        #[arg(long, default_value = "")]
        note: String,
    },
    /// List safe-harbor receipts recorded for a program
    List {
        #[arg(long)]
        program_url: String,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum PlatformArg {
    Generic,
    HackerOne,
    Bugcrowd,
    Intigriti,
}

impl From<PlatformArg> for Platform {
    fn from(value: PlatformArg) -> Self {
        match value {
            PlatformArg::Generic => Platform::Generic,
            PlatformArg::HackerOne => Platform::HackerOne,
            PlatformArg::Bugcrowd => Platform::Bugcrowd,
            PlatformArg::Intigriti => Platform::Intigriti,
        }
    }
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

#[derive(Debug, Deserialize, Serialize, Clone)]
struct FileConfig {
    #[serde(default)]
    llm: LlmFile,
    #[serde(default)]
    agent: AgentFile,
    #[serde(default)]
    policy: PolicyFile,
    #[serde(default)]
    storage: StorageFile,
    #[serde(default)]
    scope: bugfound_policy::ScopeConfig,
    #[serde(default)]
    network: NetworkFile,
    #[serde(default)]
    external_tools: ExternalFile,
    #[serde(default)]
    oob: OobFile,
    /// Operator-only rules-of-engagement controls. The universal ROE mode is
    /// read exclusively from here — never from CLI flags, `auto_approve_all`,
    /// the run `mode`, or any LLM/tool value.
    #[serde(default)]
    authorization: AuthorizationFile,
    /// Workspace for the runtime owner. Default "." keeps old configs working.
    #[serde(default = "default_workspace")]
    workspace: String,
}

fn default_workspace() -> String {
    ".".to_string()
}

impl Default for FileConfig {
    fn default() -> Self {
        Self {
            llm: LlmFile::default(),
            agent: AgentFile::default(),
            policy: PolicyFile::default(),
            storage: StorageFile::default(),
            scope: bugfound_policy::ScopeConfig::default(),
            network: NetworkFile::default(),
            external_tools: ExternalFile::default(),
            oob: OobFile::default(),
            authorization: AuthorizationFile::default(),
            workspace: default_workspace(),
        }
    }
}

/// Config-only universal ROE mode. Kept as the raw string so `validate` can
/// reject unknown values with a clear operator-facing message; the typed
/// `RoePolicyMode` is produced by `roe_options` after validation.
#[derive(Debug, Deserialize, Serialize, Clone)]
struct AuthorizationFile {
    #[serde(default = "default_roe_policy_mode")]
    roe_policy_mode: String,
}

fn default_roe_policy_mode() -> String {
    "strict".to_string()
}

impl Default for AuthorizationFile {
    fn default() -> Self {
        Self {
            roe_policy_mode: default_roe_policy_mode(),
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Default, Clone)]
struct OobFile {
    /// Loopback admin endpoint of `bugfound-collaborator`.
    endpoint: Option<String>,
    /// Name of the environment variable holding the admin bearer secret.
    /// Preferred over a literal so the credential never lands in config files.
    admin_token_env: Option<String>,
    /// Optional operator-pinned admin bearer secret (discouraged; prefer env).
    token: Option<String>,
}

impl OobFile {
    /// Resolve the admin credential from the pinned value or the named env var.
    /// Empty/missing credentials stay empty so the OOB path fails closed.
    fn admin_token(&self) -> String {
        if let Some(pinned) = self.token.as_deref() {
            let pinned = pinned.trim();
            if !pinned.is_empty() {
                return pinned.to_string();
            }
        }
        self.admin_token_env
            .as_deref()
            .and_then(|name| std::env::var(name.trim()).ok())
            .map(|value| value.trim().to_string())
            .unwrap_or_default()
    }
}

impl FileConfig {
    fn validate(&self) -> Result<()> {
        bugfound_llm::validate_base_url(&self.llm.base_url)
            .with_context(|| format!("invalid llm.base_url '{}'", self.llm.base_url))?;
        if let Some(mode) = self.agent.mode.as_deref() {
            parse_mode(mode)?;
        }
        if let Some(max_steps) = self.agent.max_steps {
            // 0 means "unset" so `[policy] budgets.max_steps` can win.
            if max_steps > 200 {
                return Err(anyhow!(
                    "agent.max_steps must be at most 200 (got {max_steps}); values above the 200-step clamp are rejected"
                ));
            }
        }
        // Bounded search rounds: at least one pass, at most ten. This is an
        // operator-only cap on revisiting unfinished playbooks, not a permission.
        if let Some(max_rounds) = self.agent.max_rounds {
            if max_rounds == 0 {
                return Err(anyhow!("agent.max_rounds must be at least 1"));
            }
            if max_rounds > 10 {
                return Err(anyhow!(
                    "agent.max_rounds must be at most 10 (got {max_rounds})"
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
        // 0 = disabled; a larger window must still be a plausible number of
        // days, never an accidental mass deletion of the audit log.
        if self.storage.retention_days > 36_500 {
            return Err(anyhow!(
                "storage.retention_days must be at most 36500 (got {}); 0 disables retention",
                self.storage.retention_days
            ));
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
        match self.authorization.roe_policy_mode.as_str() {
            "strict" | "permissive_audited" => {}
            other => {
                return Err(anyhow!(
                    "invalid authorization.roe_policy_mode '{other}' (expected 'strict' or 'permissive_audited')"
                ));
            }
        }
        Ok(())
    }

    /// Effective budgets: a non-zero `[policy]` value wins, otherwise the
    /// legacy `[agent]` scalar (or the caller's default) is used.
    fn effective_budgets(&self, default_max_steps: usize) -> bugfound_policy::BudgetConfig {
        let budgets = self.policy.budgets();
        bugfound_policy::BudgetConfig {
            max_steps: if budgets.max_steps > 0 {
                budgets.max_steps
            } else {
                self.agent.max_steps.unwrap_or(default_max_steps)
            },
            max_tool_calls: if budgets.max_tool_calls > 0 {
                budgets.max_tool_calls
            } else {
                self.agent.max_tool_calls.unwrap_or(0)
            },
            max_network_calls: if budgets.max_network_calls > 0 {
                budgets.max_network_calls
            } else {
                self.agent.max_network_calls.unwrap_or(0)
            },
            requests_per_minute: if budgets.requests_per_minute > 0 {
                budgets.requests_per_minute
            } else {
                self.agent.requests_per_minute.unwrap_or(0)
            },
            max_tokens: if budgets.max_tokens > 0 {
                budgets.max_tokens
            } else {
                self.agent.max_estimated_tokens.unwrap_or(0)
            },
        }
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
    /// Extra models to try when the primary reports ModelNotFound.
    #[serde(default)]
    fallback_models: Vec<String>,
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
            fallback_models: Vec::new(),
        }
    }
}
fn d_base() -> String {
    "https://api.openai.com".into()
}
fn d_timeout() -> u64 {
    60000
}
#[derive(Debug, Deserialize, Serialize, Clone)]
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
    /// Bounded number of search rounds. Config-only: never derived from
    /// `auto_approve_all`, `mode`, CLI flags or LLM/tool output.
    #[serde(default)]
    max_rounds: Option<usize>,
    /// Use the LLM planner for adaptive step selection. Config-only; requires
    /// `adaptive_planning` to be enabled in the deployment wiring.
    #[serde(default)]
    llm_planning: Option<bool>,
    /// Resume a version-checked investigation checkpoint at engagement start.
    /// Config-only; requires `BUGFOUND_CHECKPOINT_KEY` for durable restarts.
    #[serde(default)]
    resume_from_checkpoint: Option<bool>,
    #[serde(default)]
    requests_per_minute: Option<u64>,
    #[serde(default)]
    auto_approve_tools: Vec<String>,
    #[serde(default)]
    max_estimated_tokens: Option<u64>,
    /// Explicit escape hatch: skip every approval prompt. Default off.
    #[serde(default)]
    auto_approve_all: bool,
    /// Legacy/UI workspace alias; mirrors the top-level `workspace` key.
    #[serde(default = "default_workspace")]
    workspace: String,
}

impl Default for AgentFile {
    fn default() -> Self {
        Self {
            mode: None,
            max_steps: None,
            system_prompt: None,
            system: None,
            max_tool_calls: None,
            max_network_calls: None,
            max_rounds: None,
            llm_planning: None,
            resume_from_checkpoint: None,
            requests_per_minute: None,
            auto_approve_tools: Vec::new(),
            max_estimated_tokens: None,
            auto_approve_all: false,
            workspace: default_workspace(),
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Default, Clone)]
struct PolicyFile {
    #[serde(default)]
    allowed_tools: Vec<String>,
    #[serde(default)]
    denied_tools: Vec<String>,
    #[serde(default)]
    allowed_targets: Vec<String>,
    #[serde(default)]
    denied_targets: Vec<String>,
    #[serde(default)]
    max_steps_budget: usize,
    #[serde(default)]
    max_tool_calls_budget: usize,
    #[serde(default)]
    max_network_calls_budget: usize,
    #[serde(default)]
    requests_per_minute_budget: u64,
    #[serde(default)]
    max_tokens_budget: u64,
}

impl PolicyFile {
    fn budgets(&self) -> bugfound_policy::BudgetConfig {
        bugfound_policy::BudgetConfig {
            max_tool_calls: self.max_tool_calls_budget,
            max_network_calls: self.max_network_calls_budget,
            requests_per_minute: self.requests_per_minute_budget,
            max_steps: self.max_steps_budget,
            max_tokens: self.max_tokens_budget,
        }
    }
}
#[derive(Debug, Deserialize, Serialize, Clone, Default)]
struct NetworkFile {
    #[serde(default)]
    allow_proxy: bool,
    #[serde(default)]
    proxy_url: Option<String>,
    #[serde(default)]
    trusted_local_targets: Vec<String>,
    /// Opt in to network-write tools during an engagement. Default off.
    #[serde(default)]
    allow_network_write: bool,
    /// Opt in to intrusive/fuzzing tools during an engagement. Default off.
    #[serde(default)]
    allow_intrusive: bool,
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
    /// Retention window in days for audit/trace events. 0 = disabled.
    #[serde(default)]
    retention_days: usize,
}
impl Default for StorageFile {
    fn default() -> Self {
        Self {
            path: d_db(),
            retention_days: 0,
        }
    }
}
fn d_db() -> String {
    ".bugfound/bugfound.db".into()
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

/// One canonical mode parser for all three surfaces. `full-auto` is an alias
/// of `full_auto`; an unknown value is an error, never a silent FullAuto.
fn parse_mode(raw: &str) -> Result<Mode> {
    match raw.trim() {
        "ask" => Ok(Mode::Ask),
        "full_auto" | "full-auto" => Ok(Mode::FullAuto),
        other => Err(anyhow!(
            "invalid agent.mode '{other}' (expected 'ask' or 'full_auto')"
        )),
    }
}

/// Doctor treats a missing/unresolvable API key as a hard failure so CI and
/// operators get a non-zero exit instead of a green "unavailable" line.
fn doctor_api_key(cfg: &FileConfig) -> Result<String> {
    resolve_api_key(&cfg.llm.api_key).context("api_key: unavailable")
}

/// Fail closed: a missing mode means Ask, an unknown configured mode is an
/// error. FullAuto is only ever an explicit operator choice.
fn resolve_mode(arg: Option<ModeArg>, cfg_mode: Option<&str>) -> Result<Mode> {
    if let Some(m) = arg {
        return Ok(m.into());
    }
    match cfg_mode {
        Some(raw) => parse_mode(raw),
        None => Ok(Mode::Ask),
    }
}

/// dirs-style config dir without a new dependency; empty means cwd fallback.
fn config_dir() -> PathBuf {
    #[cfg(windows)]
    {
        std::env::var_os("APPDATA")
            .map(|value| PathBuf::from(value).join("BugFound"))
            .unwrap_or_default()
    }
    #[cfg(target_os = "macos")]
    {
        std::env::var_os("HOME")
            .map(|value| {
                PathBuf::from(value)
                    .join("Library")
                    .join("Application Support")
                    .join("BugFound")
            })
            .unwrap_or_default()
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))
            .map(|base| base.join("bugfound"))
            .unwrap_or_default()
    }
}

fn data_dir() -> PathBuf {
    #[cfg(windows)]
    {
        std::env::var_os("LOCALAPPDATA")
            .map(|value| PathBuf::from(value).join("BugFound"))
            .unwrap_or_default()
    }
    #[cfg(target_os = "macos")]
    {
        std::env::var_os("HOME")
            .map(|value| {
                PathBuf::from(value)
                    .join("Library")
                    .join("Application Support")
                    .join("BugFound")
            })
            .unwrap_or_default()
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        std::env::var_os("XDG_DATA_HOME")
            .map(PathBuf::from)
            .or_else(|| {
                std::env::var_os("HOME")
                    .map(|home| PathBuf::from(home).join(".local").join("share"))
            })
            .map(|base| base.join("bugfound"))
            .unwrap_or_default()
    }
}

/// Explicit `--config` must point at a real file; only the implicit path may
/// fall back to the default location (and then to built-in defaults).
fn resolve_config_path(explicit: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(path) = explicit {
        if !path.exists() {
            return Err(anyhow!(
                "config file not found: {} (explicit --config path)",
                path.display()
            ));
        }
        return Ok(path);
    }
    let cwd = PathBuf::from("bugfound.toml");
    if cwd.exists() {
        return Ok(cwd);
    }
    let base = config_dir();
    if base.as_os_str().is_empty() {
        Ok(cwd)
    } else {
        Ok(base.join("bugfound.toml"))
    }
}

/// Prefer an existing/relative DB path (backwards compatible), otherwise use
/// the per-user data directory.
fn resolve_db_path(raw: &str) -> PathBuf {
    let path = PathBuf::from(raw);
    if path.is_absolute() || path.exists() || path.parent().is_some_and(|p| p.exists()) {
        return path;
    }
    let base = data_dir();
    if base.as_os_str().is_empty() {
        path
    } else {
        base.join(path.file_name().unwrap_or_default())
    }
}

type RunnerParts = (
    Option<Store>,
    Arc<dyn Llm>,
    bugfound_tools::ToolRegistry,
    bugfound_policy::PolicyEngine,
    AgentConfig,
);

fn policy_config(cfg: &FileConfig, mode: Mode) -> bugfound_policy::PolicyConfig {
    // A12: feed the same effective budgets into both PolicyConfig layers.
    let budgets = cfg.effective_budgets(20);
    bugfound_policy::PolicyConfig {
        mode,
        scope: cfg.scope.clone(),
        allowed_tools: cfg.policy.allowed_tools.clone(),
        denied_tools: cfg.policy.denied_tools.clone(),
        allowed_targets: cfg.policy.allowed_targets.clone(),
        denied_targets: cfg.policy.denied_targets.clone(),
        budgets: budgets.clone(),
        rate_limits: budgets,
        ..Default::default()
    }
}

fn agent_config(cfg: &FileConfig, mode: Mode) -> AgentConfig {
    let budgets = cfg.effective_budgets(20);
    AgentConfig {
        mode,
        max_steps: budgets.max_steps,
        system_prompt: cfg
            .agent
            .system_prompt
            .clone()
            .or_else(|| cfg.agent.system.clone()),
        system: cfg.agent.system.clone(),
        // Legacy scalars mirror the resolved budgets so no layer can reintroduce
        // the unaliased values (A12).
        max_tool_calls: budgets.max_tool_calls,
        max_network_calls: budgets.max_network_calls,
        requests_per_minute: budgets.requests_per_minute,
        auto_approve_tools: cfg.agent.auto_approve_tools.clone(),
        auto_approve_all: cfg.agent.auto_approve_all,
        max_estimated_tokens: budgets.max_tokens,
        cost_per_1k_input: cfg.llm.cost_per_1k_input,
        cost_per_1k_output: cfg.llm.cost_per_1k_output,
        budgets: budgets.clone(),
        budget: budgets.clone(),
        rate_limits: budgets.clone(),
        rate_limit: budgets,
        ..Default::default()
    }
}

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
        fallback_models: cfg.llm.fallback_models.clone(),
        timeout_ms: cfg.llm.timeout_ms,
    };
    let client = bugfound_llm::LlmClient::new(llm_cfg)?;
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
    let policy = bugfound_core::build_policy_config(policy_config(cfg, mode));
    let agent = agent_config(cfg, mode);
    let store = if open_store {
        let store = Store::open(resolve_db_path(&cfg.storage.path))?;
        bugfound_core::settle_on_boot(&store)?;
        Some(store)
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

/// H-01: build engagement limits from the operator's config instead of using
/// the permissive compatibility defaults.
fn engagement_options(cfg: &FileConfig) -> bugfound_engagement::EngagementOptions {
    let budgets = cfg.effective_budgets(60);
    bugfound_engagement::EngagementOptions {
        mode: resolve_mode(None, cfg.agent.mode.as_deref()).unwrap_or(Mode::Ask),
        max_steps: budgets.max_steps,
        max_tool_calls: budgets.max_tool_calls,
        max_network_calls: budgets.max_network_calls,
        requests_per_minute: budgets.requests_per_minute,
        max_estimated_tokens: budgets.max_tokens,
        allow_network_write: cfg.network.allow_network_write,
        allow_intrusive: cfg.network.allow_intrusive,
        auto_approve_all: cfg.agent.auto_approve_all,
        oob_endpoint: cfg.oob.endpoint.clone(),
        oob_admin_token: cfg.oob.admin_token(),
        resume_from_checkpoint: cfg.agent.resume_from_checkpoint.unwrap_or(false),
        trusted_local_targets: cfg.network.trusted_local_targets.clone(),
        external_commands: cfg.external_tools.commands.clone(),
    }
}

/// Translate the operator's config-only ROE mode into the engagement option.
/// `validate` restricts the string to one of the two accepted values.
fn roe_options(cfg: &FileConfig) -> bugfound_engagement::EngagementRoeOptions {
    let mode = match cfg.authorization.roe_policy_mode.as_str() {
        "permissive_audited" => bugfound_engagement::RoePolicyMode::PermissiveAudited,
        // Anything else is rejected by `FileConfig::validate`; strict is also
        // the fail-closed default.
        _ => bugfound_engagement::RoePolicyMode::Strict,
    };
    bugfound_engagement::EngagementRoeOptions { mode }
}

/// Translate the operator's config-only search-round cap into the engagement
/// loop option. `validate` restricts the value to 1..=10; absent means one
/// round, which preserves the original single-pass behavior.
fn engagement_loop_options(cfg: &FileConfig) -> bugfound_engagement::EngagementLoopOptions {
    bugfound_engagement::EngagementLoopOptions {
        max_rounds: cfg.agent.max_rounds.unwrap_or(1),
        adaptive_planning: cfg.agent.llm_planning.unwrap_or(false),
        llm_planning: cfg.agent.llm_planning.unwrap_or(false),
    }
}

/// Emit a loud operator notice so the permissive mode is never a silent downgrade.
fn warn_if_permissive_roe(cfg: &FileConfig) {
    if cfg.authorization.roe_policy_mode == "permissive_audited" {
        eprintln!(
            "warning: authorization.roe_policy_mode = \"permissive_audited\" is active: \
             every unmappable ROE line is auto-acknowledged for its exact brief hash, \
             the engagement outcome is forced to `incomplete`, and every auto-acknowledgement \
             is fully audited. This does NOT relax denied finding classes, scope, or tool gates."
        );
    }
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

fn print_engagement_status(db: &std::path::Path, id: &str) -> Result<()> {
    let status = bugfound_engagement::status_at(db, id).context("query engagement status")?;
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
    // Additive advisory line only. It cannot change state, ROE or outcome.
    let store = Store::open(db)?;
    if let Some(line) = bugfound_engagement::valid_safe_harbor_receipt_line(&store, id)? {
        println!("{line}");
    }
    Ok(())
}

/// Sample config written by `bugfound init`. Kept as a constant so tests can
/// assert that the operator-only ROE controls are documented.
const INIT_SAMPLE: &str = r#"# BugFound core config
[llm]
base_url = "https://api.openai.com"
# api_key = "env:OPENAI_API_KEY"  # recommended: read from environment
# api_key = "sk-..."
# default_model = "gpt-4o-mini"
timeout_ms = 60000

[agent]
mode = "full_auto"    # ask | full_auto (ask keeps human approval prompts)
max_steps = 20
# Bounded search rounds (config-only, 1..=10). Later rounds retry unfinished
# playbooks from a different angle; 1 keeps the original single pass.
max_rounds = 1
# Escape hatch: skip every approval prompt (off by default).
auto_approve_all = false

# Universal ROE policy mode (config-only; never derived from flags or LLM output):
#   strict             - unmappable ROE lines abort until an operator acknowledges them.
#   permissive_audited - auto-acknowledge every unmappable line for the exact brief hash,
#                        force outcome `incomplete`, and fully audit every acknowledgement.
# See docs/engagement.md ("Universal ROE policy mode").
# [authorization]
# roe_policy_mode = "strict"

# Policy allow/deny lists and budgets. Budgets are aliases: 0 = unlimited.
[policy]
allowed_tools = []
denied_tools = []
allowed_targets = []
denied_targets = []
max_steps_budget = 0
max_tool_calls_budget = 0
max_network_calls_budget = 0
requests_per_minute_budget = 0
max_tokens_budget = 0

[network]
# Explicit opt-ins needed for state-changing / intrusive engagements.
allow_network_write = false
allow_intrusive = false

[storage]
path = ".bugfound/bugfound.db"
# Retention window in days for audit/trace events, applied on startup.
# 0 = disabled (default); max 36500. Use `bugfound prune --dry-run` to preview.
# retention_days = 30

# Browser adapters (config-only). Commands are opt-in by being present; keep
# them scoped by ROE/scope gates. Install deps before first use.
[external_tools]
enabled = true
auto_detect = true

[external_tools.commands]
# Google Chrome DevTools MCP (CDP-based, recommended):
#   npm install eval/fixtures/chrome-mcp
chrome_mcp = "node eval/fixtures/chrome-mcp/chrome-mcp-wrapper.js {action} {url} {selector}"
# Playwright fallback:
#   npm install eval/fixtures/browser && npx playwright install chromium
playwright = "node eval/fixtures/browser/playwright-wrapper.js {action} {url} {selector}"
"#;

/// CLI twin of the desktop startup retention pass. A zero window is an error
/// here (the operator asked for a prune explicitly); a broken chain is fatal.
fn prune_retention(
    store: &Store,
    session: Option<String>,
    days: usize,
    dry_run: bool,
) -> Result<()> {
    if days == 0 {
        return Err(anyhow!(
            "retention window is 0 (disabled); pass --days or set storage.retention_days"
        ));
    }
    if days > 36_500 {
        return Err(anyhow!("--days must be at most 36500 (got {days})"));
    }
    let cutoff_at = Utc::now() - Duration::days(days as i64);
    let cutoff = cutoff_at.to_rfc3339();
    let ids: Vec<String> = match session {
        Some(id) => vec![id],
        None => store
            .list_sessions(usize::MAX)
            .context("list sessions for retention")?
            .into_iter()
            .map(|s| s.id)
            .collect(),
    };
    for id in ids {
        if dry_run {
            let old = store
                .list_events(&id, usize::MAX)
                .with_context(|| format!("list events for session {id}"))?
                .into_iter()
                .filter(|event| {
                    chrono::DateTime::parse_from_rfc3339(&event.created_at)
                        .map(|stamp| stamp.with_timezone(&Utc) < cutoff_at)
                        .unwrap_or(false)
                })
                .count();
            println!("{id}: would prune up to {old} audit event(s) before {cutoff}");
            if !store.verify_event_chain(&id)? {
                eprintln!("event_chain=TAMPERED for session {id}");
                std::process::exit(1);
            }
            continue;
        }
        match store.prune_events_before(&id, &cutoff) {
            Ok(pruned) => println!("{id}: pruned {pruned} audit event(s)"),
            Err(error) => {
                eprintln!(
                    "retention: could not prune audit events for session {id} ({error}); nothing was deleted for that session"
                );
                continue;
            }
        }
        match store.verify_event_chain(&id) {
            Ok(true) => {}
            Ok(false) => {
                eprintln!("event_chain=TAMPERED for session {id}; trace events were not pruned");
                std::process::exit(1);
            }
            Err(error) => {
                eprintln!("retention: could not verify event chain for session {id} ({error})");
                std::process::exit(1);
            }
        }
        // Trace rows are keyed by `trace_events.engagement_id`; the audit
        // session id is that same scope, so pass it deliberately.
        match store.prune_trace_events_before(&id, &cutoff) {
            Ok(pruned) => println!("{id}: pruned {pruned} trace event(s)"),
            Err(error) => {
                eprintln!("retention: could not prune trace events for session {id} ({error})");
            }
        }
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("info".parse().unwrap()))
        .with_target(false)
        .init();
    let cli = Cli::parse();
    let config_path = resolve_config_path(cli.config.clone())?;
    let cfg = load_config(&config_path)?;
    let db_path = resolve_db_path(&cfg.storage.path);
    cfg.validate()?;
    warn_if_permissive_roe(&cfg);
    match cli.command {
        Commands::Init { force } => {
            let path = Path::new("bugfound.toml");
            if path.exists() && !force {
                println!("bugfound.toml already exists (use --force to overwrite)");
            } else {
                std::fs::write(path, INIT_SAMPLE).context("write bugfound.toml")?;
                println!("wrote bugfound.toml");
            }
        }
        Commands::Run { goal, mode, cwd } => {
            let mode = resolve_mode(mode, cfg.agent.mode.as_deref())?;
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
            let mode = resolve_mode(mode, cfg.agent.mode.as_deref())?;
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
            let mode = resolve_mode(mode, cfg.agent.mode.as_deref())?;
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
            let mode = resolve_mode(mode, cfg.agent.mode.as_deref())?;
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
            let store = Store::open(&db_path)?;
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
            let store = Store::open(&db_path)?;
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
            let store = Store::open(&db_path)?;
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
            let store = Store::open(&db_path)?;
            let items = store.list_assets(&session)?;
            if items.is_empty() {
                println!("(no assets)");
            }
            for a in items {
                println!("{} = {}", redact(&a.kind), redact(&a.value));
            }
        }
        Commands::Artifacts { session } => {
            let store = Store::open(&db_path)?;
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
            let store = Store::open(&db_path)?;
            let report = store.export_report(&session)?;
            if let Some(path) = output {
                std::fs::write(path, report)?;
                println!("report written");
            } else {
                println!("{}", redact(&report));
            }
        }
        Commands::Status { session } => {
            let store = Store::open(&db_path)?;
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
                cfg.effective_budgets(20).max_steps,
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
            let store = Store::open(&db_path)?;
            println!("config: ok");
            println!("database: ok ({})", db_path.display());
            doctor_api_key(&cfg)?;
            println!("api_key: ok");
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
            let store = Store::open(&db_path)?;
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
            let store = Store::open(&db_path)?;
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
            let store = Store::open(&db_path)?;
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
            for (name, path) in bugfound_tools::external_tool_availability() {
                println!(
                    "{}\t{}",
                    name,
                    path.map(|p| p.display().to_string())
                        .unwrap_or_else(|| "not installed".into())
                );
            }
        }
        Commands::Tokens { session } => {
            let store = Store::open(&db_path)?;
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
            let store = Store::open(&db_path)?;
            let valid = store.verify_event_chain(&session)?;
            println!("event_chain={}", if valid { "valid" } else { "TAMPERED" });
            if !valid {
                std::process::exit(1);
            }
        }
        Commands::Prune {
            session,
            days,
            dry_run,
        } => {
            let days = days.unwrap_or(cfg.storage.retention_days);
            let store = Store::open(&db_path)?;
            prune_retention(&store, session, days, dry_run)?;
        }
        Commands::Receipt { action, db } => {
            let db_path = db
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|| db_path.clone());
            let store = Store::open(&db_path)?;
            match action {
                ReceiptCommands::Add {
                    program_url,
                    brief_content_hash,
                    scope_version,
                    terms_hash,
                    operator,
                    expires_at,
                    note,
                } => {
                    if !is_sha256_hex(&brief_content_hash) {
                        eprintln!("brief_content_hash must be 64 hex characters");
                        std::process::exit(1);
                    }
                    if !is_sha256_hex(&terms_hash) {
                        eprintln!("terms_hash must be 64 hex characters");
                        std::process::exit(1);
                    }
                    if program_url.trim().is_empty()
                        || scope_version.trim().is_empty()
                        || operator.trim().is_empty()
                    {
                        eprintln!("program_url, scope_version and operator are required");
                        std::process::exit(1);
                    }
                    if chrono::DateTime::parse_from_rfc3339(&expires_at).is_err() {
                        eprintln!("expires_at must be ISO-8601, e.g. 2027-01-01T00:00:00Z");
                        std::process::exit(1);
                    }
                    // Deterministic id makes re-running the same add idempotent.
                    let id = format!(
                        "{:x}",
                        <sha2::Sha256 as sha2::Digest>::digest(
                            format!(
                                "{}|{}|{}|{}|{}|{}|{}",
                                program_url,
                                brief_content_hash,
                                scope_version,
                                terms_hash,
                                operator,
                                expires_at,
                                note
                            )
                            .as_bytes()
                        )
                    );
                    let receipt = SafeHarborReceipt {
                        id,
                        program_url,
                        brief_content_hash,
                        scope_version,
                        terms_hash,
                        operator,
                        acquired_at: chrono::Utc::now().to_rfc3339(),
                        expires_at,
                        // Hardcoded: no flag may create a bypass or different decision.
                        decision: "acknowledged".to_string(),
                        note,
                    };
                    let inserted = store.save_safe_harbor_receipt(&receipt)?;
                    println!(
                        "{} receipt_id={}",
                        if inserted {
                            "safe-harbor receipt recorded"
                        } else {
                            "safe-harbor receipt already present (idempotent)"
                        },
                        receipt.id
                    );
                }
                ReceiptCommands::List { program_url } => {
                    let receipts = store.list_safe_harbor_receipts(&program_url)?;
                    if receipts.is_empty() {
                        println!("(no safe-harbor receipts)");
                    }
                    for receipt in receipts {
                        println!(
                            "{} scope={} operator={} acquired={} expires={} decision={} note={}",
                            receipt.id,
                            redact(&receipt.scope_version),
                            redact(&receipt.operator),
                            receipt.acquired_at,
                            receipt.expires_at,
                            receipt.decision,
                            redact(&receipt.note)
                        );
                    }
                }
            }
        }
        Commands::Authorize {
            url,
            content_hash,
            rule,
            version,
            operator,
            note,
            db,
        } => {
            if !is_sha256_hex(&content_hash) {
                eprintln!("content_hash must be 64 lowercase hex characters");
                std::process::exit(1);
            }
            if operator.trim().is_empty() {
                eprintln!("operator is required");
                std::process::exit(1);
            }
            let db_path = db
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|| db_path.clone());
            let store = Store::open(&db_path)?;
            let (subject_kind, subject_hash, subject_text) = if let Some(rule) = rule {
                let trimmed = rule.trim();
                let digest = format!(
                    "{:x}",
                    <sha2::Sha256 as sha2::Digest>::digest(trimmed.as_bytes())
                );
                ("unparsed_roe", digest, trimmed.to_string())
            } else {
                ("brief_version", version.unwrap(), content_hash.clone())
            };
            let ack = bugfound_store::AuthorizationAck {
                program_url: url,
                content_hash,
                subject_kind: subject_kind.to_string(),
                subject_hash,
                subject_text,
                decision: "acknowledged".to_string(),
                // A CLI "acknowledge" is a raw text ack; it carries no typed
                // restriction and therefore cannot clear a fail-closed ROE line.
                restriction_json: None,
                operator,
                note,
                created_at: String::new(),
            };
            let inserted = store.save_authorization_ack(&ack)?;
            println!(
                "{}",
                if inserted {
                    "acknowledgement recorded"
                } else {
                    "acknowledgement already present (idempotent)"
                }
            );
        }
        Commands::Engage {
            url,
            brief_file,
            cwd,
            db,
            brief_only,
            platform,
            api_key_env,
        } => {
            // A local brief is already-extracted text. Read the bytes and use a
            // lossy UTF-8 fallback; the contents are never printed or logged.
            let local_brief_text = match &brief_file {
                Some(path) => {
                    let bytes =
                        std::fs::read(path).with_context(|| format!("read brief file {path}"))?;
                    Some(String::from_utf8_lossy(&bytes).into_owned())
                }
                None => None,
            };
            if brief_file.is_some() {
                println!("brief source: local brief file (offline; public brief fetch disabled)");
            }
            // Only the environment-variable NAME is passed down. The CLI never
            // reads, prints or stores the token value.
            let platform_options = bugfound_engagement::EngagementPlatformOptions {
                platform: platform.into(),
                api_key_env,
            };
            let db_path = db
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|| db_path.clone());
            let monitor = Arc::new(bugfound_core::Monitor::new(
                Store::open(&db_path)?,
                bugfound_core::EventBus::global().clone(),
                bugfound_core::MonitorConfig {
                    journal_dir: std::path::Path::new(&cwd).join("eval/work/monitor"),
                    ..Default::default()
                },
            ));
            monitor.start()?;
            let options = engagement_options(&cfg);
            let roe = roe_options(&cfg);
            let loop_options = engagement_loop_options(&cfg);
            let (tx, rx) = std::sync::mpsc::channel::<bugfound_engagement::EngagementEvent>();

            // Keep the id emitted by the Started event so Ctrl+C can abort the
            // running engagement from an independent signal-watching thread.
            let engagement_id = Arc::new(std::sync::Mutex::new(None::<String>));
            let id_for_signal = Arc::clone(&engagement_id);
            let signal_db = std::path::PathBuf::from(&db_path);
            std::thread::spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("build signal runtime");
                runtime.block_on(async move {
                    if tokio::signal::ctrl_c().await.is_ok() {
                        let guard = id_for_signal.lock().unwrap_or_else(|e| e.into_inner());
                        if let Some(id) = guard.as_ref() {
                            match bugfound_engagement::abort_at(&signal_db, id) {
                                Ok(()) => {}
                                Err(e) => eprintln!("warning: failed to abort engagement: {e}"),
                            }
                        }
                    }
                });
            });

            let (worker_url, worker_brief) = match local_brief_text {
                Some(text) => (String::new(), Some(text)),
                None => (url.unwrap_or_default(), None),
            };
            let worker_cwd = cwd.clone();
            let worker_db = db_path.clone();
            let worker = std::thread::spawn(move || -> Result<()> {
                if let Some(brief_text) = worker_brief {
                    bugfound_engagement::engage_with_local_brief_tx_and_roe_and_loop(
                        Path::new(&worker_db),
                        Path::new(&worker_cwd),
                        &brief_text,
                        options,
                        roe,
                        loop_options,
                        tx,
                    )
                    .map(|_| ())
                } else if brief_only {
                    bugfound_engagement::engage_brief_only_with_platform_and_roe(
                        &worker_url,
                        Path::new(&worker_cwd),
                        Path::new(&worker_db),
                        options,
                        platform_options,
                        roe,
                        loop_options,
                        tx,
                    )
                    .map(|_| ())
                } else if matches!(platform, PlatformArg::Generic) {
                    // The generic platform uses the plain public-page fetch, so
                    // this is the URL engagement path that honours the operator's
                    // config-only universal ROE mode.
                    bugfound_engagement::engage_with_options_and_loop(
                        &worker_url,
                        Path::new(&worker_cwd),
                        Path::new(&worker_db),
                        options,
                        roe,
                        loop_options,
                        tx,
                    )
                    .map(|_| ())
                } else {
                    bugfound_engagement::engage_with_platform_and_roe(
                        &worker_url,
                        Path::new(&worker_cwd),
                        Path::new(&worker_db),
                        options,
                        platform_options,
                        roe,
                        loop_options,
                        tx,
                    )
                    .map(|_| ())
                }
            });

            let mut exit_code = loop {
                match rx.recv() {
                    Ok(bugfound_engagement::EngagementEvent::Started { engagement_id: id }) => {
                        println!("engagement started: id={}", redact(&id));
                        monitor.track(&id);
                        *engagement_id.lock().unwrap_or_else(|e| e.into_inner()) = Some(id);
                    }
                    Ok(bugfound_engagement::EngagementEvent::BriefIngested { .. }) => {
                        println!("brief ingested");
                    }
                    Ok(bugfound_engagement::EngagementEvent::PlanUpdated { tasks }) => {
                        println!("plan updated: {} tasks", tasks.len());
                        for task in tasks {
                            println!("  - {}", redact(&task));
                        }
                    }
                    Ok(bugfound_engagement::EngagementEvent::Action {
                        tool,
                        target,
                        ok,
                        detail,
                    }) => {
                        if let Some(id) = engagement_id
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .as_ref()
                        {
                            monitor.observe(
                                id,
                                if ok { "action.ok" } else { "action.denied" },
                                if ok { "info" } else { "warn" },
                                &format!("tool={tool} detail={detail}"),
                            );
                        }
                        println!(
                            "action: tool={} target={} ok={} detail={}",
                            redact(&tool),
                            redact(target.as_deref().unwrap_or("-")),
                            ok,
                            redact(&detail).replace('\n', " ")
                        )
                    }
                    Ok(bugfound_engagement::EngagementEvent::Finding {
                        id,
                        title,
                        severity,
                    }) => {
                        if let Some(id) = engagement_id
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .as_ref()
                        {
                            monitor.observe(id, "result.saved", "info", &title);
                        }
                        println!(
                            "finding: [{}] {} id={}",
                            redact(&severity),
                            redact(&title),
                            redact(&id)
                        )
                    }
                    Ok(bugfound_engagement::EngagementEvent::ReportReady { path }) => {
                        println!("report ready: {}", redact(&path.display().to_string()));
                    }
                    Ok(bugfound_engagement::EngagementEvent::Error { message }) => {
                        eprintln!("engagement error: {}", redact(&message));
                        break 1;
                    }
                    Ok(bugfound_engagement::EngagementEvent::Finished { summary }) => {
                        println!("engagement finished: {}", redact(&summary));
                        break 0;
                    }
                    Err(e) => {
                        eprintln!("engagement event channel closed: {e}");
                        break 1;
                    }
                }
            };

            let _ = monitor.stop();
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
            revalidate_brief,
        } => {
            let db_path = db
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|| db_path.clone());
            if pause {
                bugfound_engagement::pause_at(&db_path, &id).context("pause engagement")?;
                println!("engagement {} paused", redact(&id));
            }
            if resume {
                if revalidate_brief {
                    println!(
                        "engagement {} revalidation requested; the brief will be re-fetched at the next safe boundary",
                        redact(&id)
                    );
                }
                bugfound_engagement::resume_at_with_revalidation(&db_path, &id, revalidate_brief)
                    .context("resume engagement")?;
                println!("engagement {} resumed", redact(&id));
            }
            if abort {
                bugfound_engagement::abort_at(&db_path, &id).context("abort engagement")?;
                println!("engagement {} aborted", redact(&id));
            }
            if status || !(pause || resume || abort) {
                print_engagement_status(&db_path, &id)?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const OPT_IN_CONFIG: &str = r#"
[llm]
base_url = "https://api.openai.com"
api_key = "test-key"

[agent]
mode = "full_auto"
auto_approve_all = true

[network]
allow_network_write = true
allow_intrusive = true
"#;

    // Kept byte-for-byte identical to the desktop config parity test.
    const POLICY_CONFIG: &str = r#"
[llm]
api_key = "test-key"

[agent]
mode = "full_auto"
max_steps = 7

[policy]
allowed_tools = ["http_request", "dns_lookup"]
denied_tools = ["shell"]
allowed_targets = ["example.com"]
denied_targets = ["evil.example.com"]
max_steps_budget = 11
max_tool_calls_budget = 22
max_network_calls_budget = 33
requests_per_minute_budget = 44
max_tokens_budget = 55
"#;

    #[test]
    fn engagement_opt_ins_are_parsed_and_forwarded() {
        let cfg: FileConfig = toml::from_str(OPT_IN_CONFIG).expect("parse config");
        cfg.validate().expect("validate config");
        assert!(cfg.network.allow_network_write);
        assert!(cfg.network.allow_intrusive);
        assert!(cfg.agent.auto_approve_all);
        let options = engagement_options(&cfg);
        assert!(options.allow_network_write);
        assert!(options.allow_intrusive);
        assert!(options.auto_approve_all);
    }

    #[test]
    fn config_defaults_are_fail_closed() {
        let cfg = FileConfig::default();
        assert!(!cfg.network.allow_network_write);
        assert!(!cfg.network.allow_intrusive);
        assert!(!cfg.agent.auto_approve_all);
        assert_eq!(cfg.authorization.roe_policy_mode, "strict");
        assert_eq!(cfg.storage.retention_days, 0);
        assert_eq!(cfg.workspace, ".");
        assert_eq!(cfg.agent.workspace, ".");
        // Missing mode means Ask, never FullAuto.
        assert_eq!(resolve_mode(None, None).unwrap(), Mode::Ask);
        assert_eq!(
            resolve_mode(None, cfg.agent.mode.as_deref()).unwrap(),
            Mode::Ask
        );
        let options = engagement_options(&cfg);
        assert!(!options.allow_network_write);
        assert!(!options.allow_intrusive);
        assert!(!options.auto_approve_all);
    }

    #[test]
    fn max_rounds_defaults_to_one_and_is_config_only() {
        let cfg = FileConfig::default();
        assert_eq!(cfg.agent.max_rounds, None);
        assert_eq!(engagement_loop_options(&cfg).max_rounds, 1);

        let cfg: FileConfig = toml::from_str("").expect("parse empty config");
        cfg.validate().expect("validate empty config");
        assert_eq!(engagement_loop_options(&cfg).max_rounds, 1);

        // auto_approve_all and mode are unrelated gates; neither may change the
        // bounded search-round cap.
        let cfg: FileConfig = toml::from_str(OPT_IN_CONFIG).expect("parse opt-in config");
        cfg.validate().expect("validate opt-in config");
        assert_eq!(engagement_loop_options(&cfg).max_rounds, 1);
    }

    #[test]
    fn max_rounds_is_validated_and_forwarded() {
        for (value, message) in [(0, "at least 1"), (11, "at most 10")] {
            let text = format!("[agent]\nmax_rounds = {value}\n");
            let cfg: FileConfig = toml::from_str(&text).expect("parse config");
            let error = cfg
                .validate()
                .expect_err("out-of-range max_rounds must be rejected");
            assert!(
                error.to_string().contains("agent.max_rounds"),
                "unexpected error: {error}"
            );
            assert!(
                error.to_string().contains(message),
                "unexpected error: {error}"
            );
        }

        for value in [1, 10] {
            let text = format!("[agent]\nmax_rounds = {value}\n");
            let cfg: FileConfig = toml::from_str(&text).expect("parse config");
            cfg.validate()
                .expect("in-range max_rounds must be accepted");
            assert_eq!(engagement_loop_options(&cfg).max_rounds, value);
        }
    }

    #[test]
    fn init_sample_documents_max_rounds() {
        assert!(
            INIT_SAMPLE.contains("max_rounds = 1"),
            "init sample must document the single-round default"
        );
        assert!(
            INIT_SAMPLE.contains("1..=10"),
            "init sample must document the validated range"
        );
    }

    #[test]
    fn retention_days_defaults_off_and_is_capped() {
        let cfg: FileConfig = toml::from_str("").expect("parse empty config");
        cfg.validate().expect("validate empty config");
        assert_eq!(cfg.storage.retention_days, 0);

        let cfg: FileConfig =
            toml::from_str("[storage]\nretention_days = 30\n").expect("parse retention config");
        cfg.validate().expect("validate retention config");
        assert_eq!(cfg.storage.retention_days, 30);

        let cfg: FileConfig = toml::from_str("[storage]\nretention_days = 36501\n")
            .expect("parse oversized retention config");
        let error = cfg.validate().expect_err("oversized retention must fail");
        assert!(
            error.to_string().contains("storage.retention_days"),
            "unexpected error: {error}"
        );
        assert!(
            INIT_SAMPLE.contains("retention_days"),
            "init sample must document the retention key"
        );
        assert!(
            INIT_SAMPLE.contains("0 = disabled"),
            "init sample must document the fail-closed default"
        );
    }

    #[test]
    fn policy_fields_are_forwarded_into_policy_config() {
        let cfg: FileConfig = toml::from_str(POLICY_CONFIG).expect("parse config");
        cfg.validate().expect("validate config");
        let policy = policy_config(&cfg, Mode::FullAuto);
        assert_eq!(policy.allowed_tools, ["http_request", "dns_lookup"]);
        assert_eq!(policy.denied_tools, ["shell"]);
        assert_eq!(policy.allowed_targets, ["example.com"]);
        assert_eq!(policy.denied_targets, ["evil.example.com"]);
        let effective = bugfound_core::build_policy_config(policy.clone()).effective_budgets();
        assert_eq!(effective.max_steps, 11);
        assert_eq!(effective.max_tool_calls, 22);
        assert_eq!(effective.max_network_calls, 33);
        assert_eq!(effective.requests_per_minute, 44);
        assert_eq!(effective.max_tokens, 55);
        assert_eq!(policy.budgets.max_steps, 11);
        assert_eq!(policy.rate_limits.max_tokens, 55);
    }

    #[test]
    fn budget_aliases_are_wired_into_agent_config() {
        let cfg: FileConfig = toml::from_str(POLICY_CONFIG).expect("parse config");
        let agent = agent_config(&cfg, Mode::FullAuto);
        assert_eq!(agent.max_steps, cfg.effective_budgets(20).max_steps);
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
    fn policy_budgets_are_forwarded_into_engagement_options() {
        let cfg: FileConfig = toml::from_str(POLICY_CONFIG).expect("parse config");
        let options = engagement_options(&cfg);
        assert_eq!(options.max_steps, 11);
        assert_eq!(options.max_tool_calls, 22);
        assert_eq!(options.max_network_calls, 33);
        assert_eq!(options.requests_per_minute, 44);
        assert_eq!(options.max_estimated_tokens, 55);
    }

    #[test]
    fn oob_admin_token_is_threaded_into_engagement_options() {
        let var = format!("BUGFOUND_CLI_TEST_OOB_{}", std::process::id());
        std::env::remove_var(&var);
        let text =
            format!("[oob]\nendpoint = \"http://127.0.0.1:8082\"\nadmin_token_env = \"{var}\"\n");
        let cfg: FileConfig = toml::from_str(&text).expect("parse oob config");
        // Missing env stays empty so the OOB path fails closed.
        assert!(engagement_options(&cfg).oob_admin_token.is_empty());

        std::env::set_var(&var, "admin-secret");
        let options = engagement_options(&cfg);
        assert_eq!(options.oob_admin_token, "admin-secret");
        assert!(
            bugfound_engagement::verification::HttpOobOracle::new(
                options.oob_endpoint.as_deref().unwrap(),
                &options.oob_admin_token,
            )
            .is_some(),
            "a configured endpoint must receive a usable non-empty token"
        );
        std::env::remove_var(&var);
    }

    #[test]
    fn engage_accepts_brief_file_without_url() {
        let cli = Cli::try_parse_from([
            "bugfound",
            "engage",
            "--brief-file",
            "brief.txt",
            "--cwd",
            "workspace",
        ])
        .expect("parse engage with --brief-file and no --url");
        match cli.command {
            Commands::Engage {
                url,
                brief_file,
                cwd,
                ..
            } => {
                assert!(url.is_none());
                assert_eq!(brief_file.as_deref(), Some("brief.txt"));
                assert_eq!(cwd, "workspace");
            }
            _ => panic!("expected engage command"),
        }
    }

    #[test]
    fn engage_rejects_missing_url_and_brief_file() {
        let error = Cli::try_parse_from(["bugfound", "engage"])
            .err()
            .expect("engage must require either --url or --brief-file");
        assert!(
            error.to_string().contains("--url"),
            "unexpected clap error: {error}"
        );
    }

    #[test]
    fn engage_still_accepts_url_without_brief_file() {
        let cli = Cli::try_parse_from(["bugfound", "engage", "--url", "https://example.com"])
            .expect("parse engage with --url");
        match cli.command {
            Commands::Engage {
                url, brief_file, ..
            } => {
                assert_eq!(url.as_deref(), Some("https://example.com"));
                assert!(brief_file.is_none());
            }
            _ => panic!("expected engage command"),
        }
    }

    #[test]
    fn policy_section_round_trips() {
        let cfg: FileConfig = toml::from_str(POLICY_CONFIG).expect("parse config");
        let text = toml::to_string_pretty(&cfg).expect("serialize config");
        let reloaded: FileConfig = toml::from_str(&text).expect("reparse config");
        assert_eq!(reloaded.policy.allowed_tools, cfg.policy.allowed_tools);
        assert_eq!(reloaded.policy.denied_targets, cfg.policy.denied_targets);
        assert_eq!(reloaded.policy.max_tokens_budget, 55);
    }

    const STRICT_ROE_CONFIG: &str = r#"
[authorization]
roe_policy_mode = "strict"
"#;

    const PERMISSIVE_ROE_CONFIG: &str = r#"
[authorization]
roe_policy_mode = "permissive_audited"
"#;

    const UNKNOWN_ROE_CONFIG: &str = r#"
[authorization]
roe_policy_mode = "permissive"
"#;

    #[test]
    fn roe_policy_mode_defaults_to_strict() {
        let cfg = FileConfig::default();
        assert_eq!(cfg.authorization.roe_policy_mode, "strict");
        assert!(matches!(
            roe_options(&cfg).mode,
            bugfound_engagement::RoePolicyMode::Strict
        ));

        let cfg: FileConfig = toml::from_str("").expect("parse empty config");
        cfg.validate().expect("validate empty config");
        assert_eq!(cfg.authorization.roe_policy_mode, "strict");
        assert!(matches!(
            roe_options(&cfg).mode,
            bugfound_engagement::RoePolicyMode::Strict
        ));

        let cfg: FileConfig = toml::from_str("[authorization]\n").expect("parse empty section");
        cfg.validate().expect("validate empty section");
        assert_eq!(cfg.authorization.roe_policy_mode, "strict");
        assert!(matches!(
            roe_options(&cfg).mode,
            bugfound_engagement::RoePolicyMode::Strict
        ));
    }

    #[test]
    fn validate_accepts_strict_and_permissive_audited() {
        let cfg: FileConfig = toml::from_str(STRICT_ROE_CONFIG).expect("parse strict config");
        cfg.validate().expect("validate strict config");
        assert!(matches!(
            roe_options(&cfg).mode,
            bugfound_engagement::RoePolicyMode::Strict
        ));

        let cfg: FileConfig =
            toml::from_str(PERMISSIVE_ROE_CONFIG).expect("parse permissive config");
        cfg.validate().expect("validate permissive config");
        assert!(matches!(
            roe_options(&cfg).mode,
            bugfound_engagement::RoePolicyMode::PermissiveAudited
        ));
    }

    #[test]
    fn validate_rejects_unknown_roe_policy_mode() {
        let cfg: FileConfig = toml::from_str(UNKNOWN_ROE_CONFIG).expect("parse unknown config");
        let error = cfg
            .validate()
            .expect_err("unknown ROE policy mode must be rejected");
        let message = error.to_string();
        assert!(
            message.contains("authorization.roe_policy_mode"),
            "unexpected error: {message}"
        );
        assert!(
            message.contains("'strict' or 'permissive_audited'"),
            "unexpected error: {message}"
        );
    }

    #[test]
    fn roe_mode_is_config_only() {
        // auto_approve_all and mode are unrelated gates; neither may change the
        // universal ROE mode, and there is no CLI flag for it.
        let cfg: FileConfig = toml::from_str(OPT_IN_CONFIG).expect("parse opt-in config");
        cfg.validate().expect("validate opt-in config");
        assert!(cfg.agent.auto_approve_all);
        assert!(matches!(
            roe_options(&cfg).mode,
            bugfound_engagement::RoePolicyMode::Strict
        ));

        // There is deliberately no CLI flag for the universal ROE mode.
        assert!(
            Cli::try_parse_from([
                "bugfound",
                "engage",
                "--url",
                "https://example.com",
                "--roe-policy-mode",
                "permissive_audited",
            ])
            .is_err(),
            "ROE mode must be config-only, not a CLI flag"
        );
    }

    #[test]
    fn init_sample_documents_roe_policy_mode() {
        assert!(
            INIT_SAMPLE.contains("[authorization]"),
            "init sample must show the authorization section"
        );
        assert!(
            INIT_SAMPLE.contains("roe_policy_mode = \"strict\""),
            "init sample must document the strict default"
        );
        assert!(
            INIT_SAMPLE.contains("permissive_audited"),
            "init sample must document the permissive audited mode"
        );
    }

    #[test]
    fn parse_mode_accepts_full_auto_alias_in_both_surfaces() {
        assert_eq!(parse_mode("ask").unwrap(), Mode::Ask);
        assert_eq!(parse_mode("full_auto").unwrap(), Mode::FullAuto);
        assert_eq!(parse_mode(" full-auto ").unwrap(), Mode::FullAuto);
        assert!(parse_mode("full auto").is_err());
        assert!(parse_mode("yolo").is_err());
        assert!(parse_mode("").is_err());
        // Config validation must reject the same unknown values.
        let cfg: FileConfig =
            toml::from_str("[agent]\nmode = \"full-auto\"\n").expect("parse config with alias");
        cfg.validate().expect("alias must validate in CLI");
        let cfg: FileConfig = toml::from_str("[agent]\nmode = \"yolo\"\n").expect("parse config");
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn resolve_mode_never_defaults_to_full_auto() {
        assert_eq!(resolve_mode(None, None).unwrap(), Mode::Ask);
        assert!(resolve_mode(None, Some("yolo")).is_err());
        assert_eq!(
            resolve_mode(None, Some("full-auto")).unwrap(),
            Mode::FullAuto
        );
        assert_eq!(
            resolve_mode(Some(ModeArg::FullAuto), Some("yolo")).unwrap(),
            Mode::FullAuto
        );
    }

    #[test]
    fn explicit_missing_config_errors() {
        let missing =
            std::env::temp_dir().join(format!("bugfound-cli-missing-{}.toml", std::process::id()));
        let _ = std::fs::remove_file(&missing);
        let err = resolve_config_path(Some(missing.clone()))
            .expect_err("an explicit missing config must be an error");
        assert!(err.to_string().contains("config file not found"));

        // An implicit path is allowed to fall back to the default location.
        let implicit = resolve_config_path(None).expect("implicit config path");
        assert!(implicit.ends_with("bugfound.toml"));
    }

    #[test]
    fn pause_resume_abort_are_mutually_exclusive() {
        assert!(Cli::try_parse_from([
            "bugfound",
            "engagement",
            "--id",
            "eng-1",
            "--pause",
            "--abort"
        ])
        .is_err());
        assert!(Cli::try_parse_from([
            "bugfound",
            "engagement",
            "--id",
            "eng-1",
            "--resume",
            "--pause"
        ])
        .is_err());
        assert!(Cli::try_parse_from([
            "bugfound",
            "engagement",
            "--id",
            "eng-1",
            "--pause",
            "--resume",
            "--abort"
        ])
        .is_err());
        assert!(
            Cli::try_parse_from(["bugfound", "engagement", "--id", "eng-1", "--pause"]).is_ok()
        );
    }

    #[test]
    fn doctor_fails_without_api_key() {
        let mut cfg = FileConfig::default();
        cfg.llm.api_key = String::new();
        let err = doctor_api_key(&cfg).expect_err("doctor must fail without an API key");
        assert!(err.to_string().contains("api_key"));
        cfg.llm.api_key = "env:BUGFOUND_DOCTOR_MISSING_VAR".into();
        std::env::remove_var("BUGFOUND_DOCTOR_MISSING_VAR");
        assert!(doctor_api_key(&cfg).is_err());
        cfg.llm.api_key = "literal-key".into();
        assert_eq!(doctor_api_key(&cfg).unwrap(), "literal-key");
    }
}
