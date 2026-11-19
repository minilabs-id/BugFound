use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct AppConfig {
    pub llm: LlmCfg,
    pub agent: AgentCfg,
    pub policy: PolicyCfg,
    pub storage: StorageCfg,
    pub scope: agentbug_policy::ScopeConfig,
    pub network: NetworkCfg,
    pub external_tools: ExternalCfg,
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AgentCfg {
    pub mode: String,
    pub max_steps: usize,
    pub system_prompt: Option<String>,
    pub max_tool_calls: usize,
    pub max_network_calls: usize,
    pub requests_per_minute: u64,
    pub auto_approve_tools: Vec<String>,
    pub max_estimated_tokens: u64,
    /// Escape hatch: skip every approval prompt. Default off.
    pub auto_approve_all: bool,
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
    pub fn budgets(&self) -> agentbug_policy::BudgetConfig {
        agentbug_policy::BudgetConfig {
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
        }
    }
}

impl Default for AgentCfg {
    fn default() -> Self {
        Self {
            mode: "ask".into(),
            max_steps: 20,
            system_prompt: None,
            max_tool_calls: 100,
            max_network_calls: 50,
            requests_per_minute: 60,
            auto_approve_tools: vec!["echo".into()],
            max_estimated_tokens: 0,
            auto_approve_all: false,
        }
    }
}

impl Default for StorageCfg {
    fn default() -> Self {
        Self {
            path: ".agentbug/agentbug.db".into(),
        }
    }
}

impl Default for ExternalCfg {
    fn default() -> Self {
        Self {
            enabled: false,
            auto_detect: true,
            commands: BTreeMap::new(),
        }
    }
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

    pub fn save(&self, path: &Path) -> Result<()> {
        let text = toml::to_string_pretty(self).context("serialize config")?;
        std::fs::write(path, text).with_context(|| format!("write config {}", path.display()))
    }

    /// Effective budgets: a non-zero `[policy]` value wins, otherwise the
    /// legacy `[agent]` scalar is used.
    pub fn effective_budgets(&self) -> agentbug_policy::BudgetConfig {
        let budgets = self.policy.budgets();
        agentbug_policy::BudgetConfig {
            max_steps: if budgets.max_steps > 0 {
                budgets.max_steps
            } else {
                self.agent.max_steps
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
        match self.agent.mode.as_str() {
            "ask" | "full_auto" => {}
            other => {
                return Err(anyhow!(
                    "invalid agent.mode '{other}' (expected 'ask' or 'full_auto')"
                ))
            }
        }
        if !(1..=200).contains(&self.agent.max_steps) {
            return Err(anyhow!(
                "agent.max_steps must be between 1 and 200 (got {})",
                self.agent.max_steps
            ));
        }
        resolve_api_key(&self.llm.api_key)?;
        Ok(())
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
        assert_eq!(cfg.agent.mode, "ask");
        assert_eq!(cfg.agent.max_steps, 20);
        assert_eq!(cfg.llm.base_url, "https://api.openai.com");
        assert_eq!(cfg.llm.timeout_ms, 60_000);
        assert_eq!(cfg.storage.path, ".agentbug/agentbug.db");
        assert!(!cfg.network.allow_proxy);
        assert!(!cfg.network.allow_network_write);
        assert!(!cfg.network.allow_intrusive);
        assert!(!cfg.agent.auto_approve_all);
        assert!(cfg.external_tools.auto_detect);
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
        assert_eq!(effective.max_steps, fallback.agent.max_steps);
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
            "agentbug-desktop-missing-{}.toml",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let cfg = AppConfig::load(&path).unwrap();
        assert_eq!(cfg.agent.mode, "ask");
    }

    #[test]
    fn save_then_load_round_trip() {
        let path = std::env::temp_dir().join(format!(
            "agentbug-desktop-config-{}.toml",
            std::process::id()
        ));
        let mut cfg = AppConfig::default();
        cfg.llm.api_key = "literal-key".into();
        cfg.agent.mode = "full_auto".into();
        cfg.save(&path).unwrap();
        let loaded = AppConfig::load(&path).unwrap();
        assert_eq!(loaded.llm.api_key, "literal-key");
        assert_eq!(loaded.agent.mode, "full_auto");
        loaded.validate().unwrap();
        let _ = std::fs::remove_file(&path);
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

        cfg.agent.mode = "ask".into();
        cfg.agent.max_steps = 0;
        assert!(cfg.validate().is_err());
        cfg.agent.max_steps = 201;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn resolve_api_key_literal_and_env() {
        assert_eq!(resolve_api_key(" sk-secret ").unwrap(), "sk-secret");
        assert!(resolve_api_key("").is_err());
        assert!(resolve_api_key("env:").is_err());

        let var = format!("AGENTBUG_DESKTOP_TEST_KEY_{}", std::process::id());
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
}
