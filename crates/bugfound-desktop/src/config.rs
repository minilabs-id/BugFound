use anyhow::{anyhow, Context, Result};
use bugfound_policy::Mode;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AppConfig {
    pub llm: LlmCfg,
    pub agent: AgentCfg,
    pub policy: PolicyCfg,
    pub storage: StorageCfg,
    pub scope: bugfound_policy::ScopeConfig,
    pub network: NetworkCfg,
    pub external_tools: ExternalCfg,
    pub oob: OobCfg,
    /// Operator-only universal ROE mode, never a UI toggle or a default in
    /// the engagement builder.
    pub authorization: AuthorizationCfg,
    /// Workspace for the runtime owner ("." keeps old configs working).
    #[serde(default = "default_workspace")]
    pub workspace: String,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            llm: LlmCfg::default(),
            agent: AgentCfg::default(),
            policy: PolicyCfg::default(),
            storage: StorageCfg::default(),
            scope: bugfound_policy::ScopeConfig::default(),
            network: NetworkCfg::default(),
            external_tools: ExternalCfg::default(),
            oob: OobCfg::default(),
            authorization: AuthorizationCfg::default(),
            workspace: default_workspace(),
        }
    }
}

/// Config-only universal ROE mode. A string so `validate` rejects typos.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AuthorizationCfg {
    pub roe_policy_mode: String,
}

impl Default for AuthorizationCfg {
    fn default() -> Self {
        Self {
            roe_policy_mode: "strict".to_string(),
        }
    }
}

/// Optional external Collaborator admin endpoint and its bearer credential.
/// Keep the secret in an env var (by name) rather than the settings file; an
/// empty resolved token fails the OOB promotion path closed.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct OobCfg {
    pub endpoint: Option<String>,
    pub admin_token_env: Option<String>,
    pub token: Option<String>,
}

impl OobCfg {
    /// Resolve the pinned token or the named env var into the admin bearer
    /// secret. Missing/empty values stay empty (fail closed).
    pub fn admin_token(&self) -> String {
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LlmCfg {
    pub base_url: String,
    pub api_key: String,
    pub default_model: Option<String>,
    pub timeout_ms: u64,
    pub cost_per_1k_input: f64,
    pub cost_per_1k_output: f64,
    /// Extra models to try when the primary reports ModelNotFound.
    pub fallback_models: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AgentCfg {
    pub mode: String,
    pub max_steps: usize,
    pub system_prompt: Option<String>,
    /// Legacy alias accepted by the CLI; preserved on save.
    #[serde(default)]
    pub system: Option<String>,
    pub max_tool_calls: usize,
    pub max_network_calls: usize,
    pub requests_per_minute: u64,
    pub auto_approve_tools: Vec<String>,
    pub max_estimated_tokens: u64,
    /// Bounded search rounds (1..=10). Config-only.
    #[serde(default = "default_max_rounds")]
    pub max_rounds: usize,
    /// V3: LLM planner / adaptive engagement planning. Config-only.
    #[serde(default)]
    pub llm_planning: bool,
    /// Resume a version-checked checkpoint at engagement start. Config-only.
    #[serde(default)]
    pub resume_from_checkpoint: bool,
    /// Escape hatch: skip every approval prompt. Default off.
    pub auto_approve_all: bool,
    /// Legacy/UI workspace. Default "." for backwards compatibility.
    #[serde(default = "default_workspace")]
    pub workspace: String,
}

fn default_max_rounds() -> usize {
    1
}

fn default_workspace() -> String {
    ".".to_string()
}

/// One canonical mode parser shared in behaviour with the CLI and
/// desktop-core surfaces: `full-auto` is an alias of `full_auto`, and an
/// unknown value is an error (never a silent FullAuto).
pub fn parse_mode(raw: &str) -> Result<Mode> {
    match raw.trim() {
        "ask" => Ok(Mode::Ask),
        "full_auto" | "full-auto" => Ok(Mode::FullAuto),
        other => Err(anyhow!(
            "invalid agent.mode '{other}' (expected 'ask' or 'full_auto')"
        )),
    }
}

/// `[policy]` allow/deny lists and budget aliases. Layout is identical to the
/// CLI `FileConfig` `[policy]` section.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct PolicyCfg {
    #[serde(default)]
    pub allowed_tools: Vec<String>,
    #[serde(default)]
    pub denied_tools: Vec<String>,
    #[serde(default)]
    pub allowed_targets: Vec<String>,
    #[serde(default)]
    pub denied_targets: Vec<String>,
    #[serde(default)]
    pub max_steps_budget: usize,
    #[serde(default)]
    pub max_tool_calls_budget: usize,
    #[serde(default)]
    pub max_network_calls_budget: usize,
    #[serde(default)]
    pub requests_per_minute_budget: u64,
    #[serde(default)]
    pub max_tokens_budget: u64,
}

impl PolicyCfg {
    pub fn budgets(&self) -> bugfound_policy::BudgetConfig {
        bugfound_policy::BudgetConfig {
            max_tool_calls: self.max_tool_calls_budget,
            max_network_calls: self.max_network_calls_budget,
            requests_per_minute: self.requests_per_minute_budget,
            max_steps: self.max_steps_budget,
            max_tokens: self.max_tokens_budget,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct StorageCfg {
    pub path: String,
    /// Retention window in days for audit/trace events, applied at startup.
    /// `0` disables retention entirely (fail closed: no automatic deletion).
    #[serde(default)]
    pub retention_days: usize,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct NetworkCfg {
    pub allow_proxy: bool,
    pub proxy_url: Option<String>,
    pub trusted_local_targets: Vec<String>,
    /// Opt in to network-write tools during an engagement. Default off.
    pub allow_network_write: bool,
    /// Opt in to intrusive/fuzzing tools during an engagement. Default off.
    pub allow_intrusive: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ExternalCfg {
    pub enabled: bool,
    pub auto_detect: bool,
    pub commands: BTreeMap<String, String>,
}

impl Default for LlmCfg {
    fn default() -> Self {
        Self {
            base_url: "https://api.openai.com".into(),
            api_key: String::new(),
            default_model: None,
            timeout_ms: 60_000,
            cost_per_1k_input: 0.0,
            cost_per_1k_output: 0.0,
            fallback_models: Vec::new(),
        }
    }
}

impl Default for AgentCfg {
    fn default() -> Self {
        Self {
            mode: "full_auto".into(),
            // 0 = unset; `[policy] budgets.max_steps` wins, hard cap 20.
            max_steps: 0,
            system_prompt: None,
            system: None,
            max_tool_calls: 100,
            max_network_calls: 50,
            requests_per_minute: 60,
            auto_approve_tools: vec!["echo".into()],
            max_estimated_tokens: 0,
            max_rounds: default_max_rounds(),
            llm_planning: false,
            resume_from_checkpoint: false,
            auto_approve_all: false,
            workspace: default_workspace(),
        }
    }
}

impl Default for StorageCfg {
    fn default() -> Self {
        Self {
            path: ".bugfound/bugfound.db".into(),
            retention_days: 0,
        }
    }
}

impl Default for ExternalCfg {
    fn default() -> Self {
        let mut commands = BTreeMap::new();
        commands.insert(
            "chrome_mcp".into(),
            "node eval/fixtures/chrome-mcp/chrome-mcp-wrapper.js {action} {url} {selector}".into(),
        );
        commands.insert(
            "playwright".into(),
            "node eval/fixtures/browser/playwright-wrapper.js {action} {url} {selector}".into(),
        );
        Self {
            enabled: true,
            auto_detect: true,
            commands,
        }
    }
}

/// Recursive table merge: known keys are updated, unknown keys (at any depth)
/// survive a settings save.
fn merge_toml_tables(
    dst: &mut toml::map::Map<String, toml::Value>,
    src: &toml::map::Map<String, toml::Value>,
) {
    for (key, value) in src {
        if let (Some(toml::Value::Table(existing)), toml::Value::Table(incoming)) =
            (dst.get_mut(key), value)
        {
            merge_toml_tables(existing, incoming);
        } else {
            dst.insert(key.clone(), value.clone());
        }
    }
}

/// Platform-aware config directory (dirs-style, no new dependency). An empty
/// path means "use the current directory" for backwards compatibility.
pub fn config_dir() -> PathBuf {
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

/// Per-user data directory for the DB, with cwd fallback.
pub fn data_dir() -> PathBuf {
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

/// Keep an existing/relative path when present; otherwise use the data dir.
pub fn resolve_db_path(raw: &str) -> PathBuf {
    let path = PathBuf::from(raw);
    if path.is_absolute() || path.exists() || path.parent().is_some_and(|p| p.exists()) {
        return path;
    }
    let base = data_dir();
    if base.as_os_str().is_empty() {
        return path;
    }
    base.join(path.file_name().unwrap_or_default())
}

impl AppConfig {
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("read config {}", path.display()))?;
        toml::from_str(&text).with_context(|| format!("parse config {}", path.display()))
    }

    /// Merge into the existing document so a settings save never drops keys
    /// this build does not model (all CLI sections are modelled, but operators
    /// may keep their own extras).
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("create config dir {}", parent.display()))?;
            }
        }
        let ours = toml::Value::try_from(self).context("serialize config")?;
        let mut merged = if path.exists() {
            let text = std::fs::read_to_string(path)
                .with_context(|| format!("read config {}", path.display()))?;
            toml::from_str::<toml::Value>(&text).unwrap_or(ours.clone())
        } else {
            toml::Value::Table(Default::default())
        };
        if let (toml::Value::Table(dst), toml::Value::Table(src)) = (&mut merged, &ours) {
            merge_toml_tables(dst, src);
        }
        let text = toml::to_string_pretty(&merged).context("serialize config")?;
        std::fs::write(path, text).with_context(|| format!("write config {}", path.display()))
    }

    /// Effective budgets: a non-zero `[policy]` value wins, otherwise the
    /// legacy `[agent]` scalar is used.
    pub fn effective_budgets(&self) -> bugfound_policy::BudgetConfig {
        let budgets = self.policy.budgets();
        bugfound_policy::BudgetConfig {
            max_steps: if budgets.max_steps > 0 {
                budgets.max_steps
            } else if self.agent.max_steps > 0 {
                self.agent.max_steps
            } else {
                20
            },
            max_tool_calls: if budgets.max_tool_calls > 0 {
                budgets.max_tool_calls
            } else {
                self.agent.max_tool_calls
            },
            max_network_calls: if budgets.max_network_calls > 0 {
                budgets.max_network_calls
            } else {
                self.agent.max_network_calls
            },
            requests_per_minute: if budgets.requests_per_minute > 0 {
                budgets.requests_per_minute
            } else {
                self.agent.requests_per_minute
            },
            max_tokens: if budgets.max_tokens > 0 {
                budgets.max_tokens
            } else {
                self.agent.max_estimated_tokens
            },
        }
    }

    pub fn validate(&self) -> Result<()> {
        let url = self.llm.base_url.trim();
        let (scheme, authority) = url
            .split_once("://")
            .ok_or_else(|| anyhow!("llm.base_url must start with http:// or https://"))?;
        if !matches!(scheme, "http" | "https") {
            return Err(anyhow!("llm.base_url must use the http or https scheme"));
        }
        let host = authority
            .split(['/', '?', '#'])
            .next()
            .unwrap_or_default()
            .trim();
        if host.is_empty() {
            return Err(anyhow!("llm.base_url must include a host"));
        }
        parse_mode(&self.agent.mode)?;
        // 0 is "unset" and lets `[policy] budgets.max_steps` win.
        if self.agent.max_steps > 200 {
            return Err(anyhow!(
                "agent.max_steps must be at most 200 (got {})",
                self.agent.max_steps
            ));
        }
        if !(1..=10).contains(&self.agent.max_rounds) {
            return Err(anyhow!(
                "agent.max_rounds must be in 1..=10 (got {})",
                self.agent.max_rounds
            ));
        }
        // 0 = disabled; an absurd window is almost certainly a typo and must
        // never silently erase years of audit log.
        if self.storage.retention_days > 36_500 {
            return Err(anyhow!(
                "storage.retention_days must be at most 36500 (got {}); 0 disables retention",
                self.storage.retention_days
            ));
        }
        match self.authorization.roe_policy_mode.as_str() {
            "strict" | "permissive_audited" => {}
            other => {
                return Err(anyhow!(
                    "invalid authorization.roe_policy_mode '{other}' (expected 'strict' or 'permissive_audited')"
                ))
            }
        }
        if self.workspace.trim().is_empty() || self.agent.workspace.trim().is_empty() {
            return Err(anyhow!("workspace must not be empty"));
        }
        resolve_api_key(&self.llm.api_key)?;
        Ok(())
    }

    pub fn workspace(&self) -> &str {
        let top = self.workspace.trim();
        let legacy = self.agent.workspace.trim();
        if top.is_empty() || (top == "." && legacy != ".") {
            legacy
        } else {
            top
        }
    }
}

/// The engagement builder must use the operator's ROE mode, not
/// `EngagementRoeOptions::default()`.
pub fn roe_options(config: &AppConfig) -> bugfound_engagement::EngagementRoeOptions {
    let mode = match config.authorization.roe_policy_mode.as_str() {
        "permissive_audited" => bugfound_engagement::RoePolicyMode::PermissiveAudited,
        _ => bugfound_engagement::RoePolicyMode::Strict,
    };
    bugfound_engagement::EngagementRoeOptions { mode }
}

pub fn loop_options(config: &AppConfig) -> bugfound_engagement::EngagementLoopOptions {
    bugfound_engagement::EngagementLoopOptions {
        max_rounds: config.agent.max_rounds,
        adaptive_planning: config.agent.llm_planning,
        llm_planning: config.agent.llm_planning,
    }
}

/// Resolve a literal API key or an `env:VAR` reference into the actual secret.
pub fn resolve_api_key(raw: &str) -> Result<String> {
    let raw = raw.trim();
    if let Some(var) = raw.strip_prefix("env:") {
        let var = var.trim();
        if var.is_empty() {
            return Err(anyhow!("llm.api_key uses env: but variable name is empty"));
        }
        let value = std::env::var(var)
            .with_context(|| format!("environment variable '{var}' is not set"))?;
        if value.trim().is_empty() {
            return Err(anyhow!("environment variable '{var}' is empty"));
        }
        return Ok(value);
    }
    if raw.is_empty() {
        return Err(anyhow!(
            "llm.api_key is not set (use a literal key or api_key = \"env:VAR\")"
        ));
    }
    Ok(raw.to_string())
}

// Kept byte-for-byte identical to the CLI config parity test.
#[cfg(test)]
pub(crate) const POLICY_CONFIG: &str = r#"
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_example_config() {
        let cfg = AppConfig::default();
        assert_eq!(cfg.agent.mode, "full_auto");
        assert_eq!(cfg.agent.max_steps, 0);
        assert_eq!(cfg.effective_budgets().max_steps, 20);
        assert_eq!(cfg.llm.base_url, "https://api.openai.com");
        assert_eq!(cfg.llm.timeout_ms, 60_000);
        assert_eq!(cfg.storage.path, ".bugfound/bugfound.db");
        assert_eq!(cfg.storage.retention_days, 0);
        assert!(!cfg.network.allow_proxy);
        assert!(!cfg.network.allow_network_write);
        assert!(!cfg.network.allow_intrusive);
        assert!(!cfg.agent.auto_approve_all);
        assert!(cfg.external_tools.enabled);
        assert!(cfg.external_tools.auto_detect);
        assert!(cfg.external_tools.commands.contains_key("chrome_mcp"));
        assert!(cfg.external_tools.commands.contains_key("playwright"));
        assert!(cfg.oob.endpoint.is_none());
        assert!(cfg.oob.admin_token().is_empty());
        assert_eq!(cfg.authorization.roe_policy_mode, "strict");
        assert_eq!(cfg.agent.max_rounds, 1);
        assert!(!cfg.agent.llm_planning);
        assert_eq!(cfg.workspace, ".");
        assert_eq!(cfg.agent.workspace, ".");
    }

    #[test]
    fn engagement_opt_ins_share_the_cli_config_layout() {
        // Same `[network]` / `[agent]` keys the CLI FileConfig accepts.
        const TEXT: &str = r#"
[llm]
api_key = "test-key"

[agent]
mode = "full_auto"
auto_approve_all = true

[network]
allow_network_write = true
allow_intrusive = true
"#;
        let cfg: AppConfig = toml::from_str(TEXT).expect("parse config");
        cfg.validate().expect("validate config");
        assert!(cfg.network.allow_network_write);
        assert!(cfg.network.allow_intrusive);
        assert!(cfg.agent.auto_approve_all);
        let saved = toml::to_string_pretty(&cfg).expect("serialize config");
        let reloaded: AppConfig = toml::from_str(&saved).expect("reparse config");
        assert!(reloaded.network.allow_network_write);
        assert!(reloaded.network.allow_intrusive);
        assert!(reloaded.agent.auto_approve_all);
    }

    #[test]
    fn policy_section_matches_cli_layout() {
        let cfg: AppConfig = toml::from_str(POLICY_CONFIG).expect("parse config");
        cfg.validate().expect("validate config");
        assert_eq!(cfg.policy.allowed_tools, ["http_request", "dns_lookup"]);
        assert_eq!(cfg.policy.denied_tools, ["shell"]);
        assert_eq!(cfg.policy.allowed_targets, ["example.com"]);
        assert_eq!(cfg.policy.denied_targets, ["evil.example.com"]);
        let budgets = cfg.policy.budgets();
        assert_eq!(budgets.max_steps, 11);
        assert_eq!(budgets.max_tool_calls, 22);
        assert_eq!(budgets.max_network_calls, 33);
        assert_eq!(budgets.requests_per_minute, 44);
        assert_eq!(budgets.max_tokens, 55);

        let saved = toml::to_string_pretty(&cfg).expect("serialize config");
        let reloaded: AppConfig = toml::from_str(&saved).expect("reparse config");
        assert_eq!(reloaded.policy.allowed_tools, cfg.policy.allowed_tools);
        assert_eq!(reloaded.policy.denied_targets, cfg.policy.denied_targets);
        assert_eq!(reloaded.policy.max_tokens_budget, 55);
    }

    #[test]
    fn effective_budgets_prefer_policy_over_agent_scalars() {
        let cfg: AppConfig = toml::from_str(POLICY_CONFIG).expect("parse config");
        let effective = cfg.effective_budgets();
        assert_eq!(effective.max_steps, 11);
        assert_eq!(effective.max_tool_calls, 22);
        assert_eq!(effective.max_network_calls, 33);
        assert_eq!(effective.requests_per_minute, 44);
        assert_eq!(effective.max_tokens, 55);

        let fallback = AppConfig::default();
        let effective = fallback.effective_budgets();
        // Both layers unset -> hard cap 20, not the raw `0` sentinel.
        assert_eq!(effective.max_steps, 20);
        assert_eq!(effective.max_tool_calls, fallback.agent.max_tool_calls);
        assert_eq!(
            effective.max_network_calls,
            fallback.agent.max_network_calls
        );
        assert_eq!(
            effective.requests_per_minute,
            fallback.agent.requests_per_minute
        );
        assert_eq!(effective.max_tokens, fallback.agent.max_estimated_tokens);
    }

    #[test]
    fn missing_file_loads_default() {
        let path = std::env::temp_dir().join(format!(
            "bugfound-desktop-missing-{}.toml",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let cfg = AppConfig::load(&path).unwrap();
        assert_eq!(cfg.agent.mode, "full_auto");
        assert!(cfg.external_tools.commands.contains_key("chrome_mcp"));
        assert!(cfg.external_tools.commands.contains_key("playwright"));
    }

    #[test]
    fn save_then_load_round_trip() {
        let path = std::env::temp_dir().join(format!(
            "bugfound-desktop-config-{}.toml",
            std::process::id()
        ));
        let mut cfg = AppConfig::default();
        cfg.llm.api_key = "literal-key".into();
        cfg.agent.mode = "full_auto".into();
        cfg.authorization.roe_policy_mode = "permissive_audited".into();
        cfg.oob.endpoint = Some("http://127.0.0.1:8082".into());
        cfg.oob.admin_token_env = Some("BUGFOUND_TEST_OOB".into());
        cfg.agent.llm_planning = true;
        cfg.agent.max_rounds = 4;
        cfg.storage.retention_days = 30;
        cfg.workspace = "/tmp/workspace".into();
        cfg.save(&path).unwrap();
        let loaded = AppConfig::load(&path).unwrap();
        assert_eq!(loaded.llm.api_key, "literal-key");
        assert_eq!(loaded.agent.mode, "full_auto");
        assert_eq!(loaded.authorization.roe_policy_mode, "permissive_audited");
        assert_eq!(
            loaded.oob.endpoint.as_deref(),
            Some("http://127.0.0.1:8082")
        );
        assert!(loaded.agent.llm_planning);
        assert_eq!(loaded.agent.max_rounds, 4);
        assert_eq!(loaded.storage.retention_days, 30);
        assert_eq!(loaded.workspace, "/tmp/workspace");
        loaded.validate().unwrap();
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn egui_save_preserves_authorization_oob_and_llm_planning() {
        const TEXT: &str = r#"
[llm]
api_key = "test-key"
[agent]
mode = "full-auto"
llm_planning = true
max_rounds = 2
[authorization]
roe_policy_mode = "permissive_audited"
[oob]
endpoint = "http://127.0.0.1:8082"
admin_token_env = "BUGFOUND_OOB_TEST"
[custom_section]
kept = "unknown key"
"#;
        let cfg: AppConfig = toml::from_str(TEXT).expect("parse config");
        assert!(matches!(
            parse_mode(&cfg.agent.mode).unwrap(),
            Mode::FullAuto
        ));
        assert!(matches!(
            roe_options(&cfg).mode,
            bugfound_engagement::RoePolicyMode::PermissiveAudited
        ));
        assert_eq!(loop_options(&cfg).max_rounds, 2);
        let path = std::env::temp_dir().join(format!(
            "bugfound-egui-roundtrip-{}.toml",
            std::process::id()
        ));
        // The merge-on-save contract preserves keys in an EXISTING document.
        std::fs::write(&path, TEXT).expect("seed original config");
        cfg.save(&path).expect("save config");
        let text = std::fs::read_to_string(&path).expect("read saved config");
        assert!(text.contains("[authorization]"), "section lost: {text}");
        assert!(text.contains("roe_policy_mode"), "ROE key lost: {text}");
        assert!(text.contains("[oob]"), "OOB section lost: {text}");
        assert!(text.contains("llm_planning"), "llm_planning lost: {text}");
        assert!(text.contains("kept"), "unknown key lost: {text}");
        let loaded = AppConfig::load(&path).expect("load config");
        assert_eq!(loaded.authorization.roe_policy_mode, "permissive_audited");
        assert_eq!(
            loaded.oob.endpoint.as_deref(),
            Some("http://127.0.0.1:8082")
        );
        assert!(loaded.agent.llm_planning);
        assert_eq!(loaded.agent.max_rounds, 2);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn parse_mode_accepts_full_auto_alias_in_both_surfaces() {
        assert_eq!(parse_mode("ask").unwrap(), Mode::Ask);
        assert_eq!(parse_mode("full_auto").unwrap(), Mode::FullAuto);
        assert_eq!(parse_mode(" full-auto ").unwrap(), Mode::FullAuto);
        assert!(parse_mode("yolo").is_err());
        assert!(parse_mode("").is_err());
    }

    #[test]
    fn validate_rejects_bad_values() {
        let mut cfg = AppConfig::default();
        cfg.llm.api_key = "key".into();
        cfg.validate().unwrap();

        cfg.llm.base_url = "ftp://example.com".into();
        assert!(cfg.validate().is_err());
        cfg.llm.base_url = "https://".into();
        assert!(cfg.validate().is_err());

        cfg.llm.base_url = "https://api.openai.com".into();
        cfg.agent.mode = "yolo".into();
        assert!(cfg.validate().is_err());
        cfg.agent.mode = "full-auto".into(); // accepted alias
        assert!(cfg.validate().is_ok());

        cfg.agent.mode = "ask".into();
        cfg.agent.max_steps = 0; // unset: valid, policy budget wins
        assert!(cfg.validate().is_ok());
        cfg.agent.max_steps = 201;
        assert!(cfg.validate().is_err());
        cfg.agent.max_steps = 0;

        cfg.authorization.roe_policy_mode = "permissive".into();
        assert!(cfg.validate().is_err());
        cfg.authorization.roe_policy_mode = "strict".into();
        cfg.agent.max_rounds = 0;
        assert!(cfg.validate().is_err());
        cfg.agent.max_rounds = 1;
        cfg.storage.retention_days = 36_501;
        assert!(cfg.validate().is_err());
        cfg.storage.retention_days = 36_500;
        assert!(cfg.validate().is_ok());
        cfg.storage.retention_days = 0;
        cfg.workspace = String::new();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn resolve_api_key_literal_and_env() {
        assert_eq!(resolve_api_key(" sk-secret ").unwrap(), "sk-secret");
        assert!(resolve_api_key("").is_err());
        assert!(resolve_api_key("env:").is_err());

        let var = format!("BUGFOUND_DESKTOP_TEST_KEY_{}", std::process::id());
        std::env::set_var(&var, "env-secret");
        assert_eq!(
            resolve_api_key(&format!("env:{var}")).unwrap(),
            "env-secret"
        );
        std::env::set_var(&var, "   ");
        assert!(resolve_api_key(&format!("env:{var}")).is_err());
        std::env::remove_var(&var);
        assert!(resolve_api_key(&format!("env:{var}")).is_err());
    }

    #[test]
    fn oob_admin_token_prefers_pinned_then_env() {
        let cfg = OobCfg::default();
        assert!(cfg.admin_token().is_empty());

        let var = format!("BUGFOUND_DESKTOP_TEST_OOB_{}", std::process::id());
        std::env::set_var(&var, "env-admin-secret");
        let cfg = OobCfg {
            endpoint: None,
            admin_token_env: Some(var.clone()),
            token: None,
        };
        assert_eq!(cfg.admin_token(), "env-admin-secret");
        let pinned = OobCfg {
            token: Some("pinned-secret".into()),
            ..cfg
        };
        assert_eq!(pinned.admin_token(), "pinned-secret");
        std::env::remove_var(&var);
    }
}
