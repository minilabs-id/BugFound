use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct AppConfig {
    pub llm: LlmCfg,
    pub agent: AgentCfg,
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
        assert!(cfg.external_tools.auto_detect);
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
