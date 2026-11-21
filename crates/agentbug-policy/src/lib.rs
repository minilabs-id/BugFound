use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::net::IpAddr;

/// Execution permission mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    #[default]
    Ask,
    FullAuto,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Allow,
    Ask,
    Deny,
}

/// Budget/rate-limit configuration for agent runs.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BudgetConfig {
    #[serde(default)]
    pub max_tool_calls: usize,
    #[serde(default)]
    pub max_network_calls: usize,
    #[serde(default)]
    pub requests_per_minute: u64,
    #[serde(default)]
    pub max_steps: usize,
    /// Hard cap on estimated prompt+completion tokens for a session (0 = unlimited).
    #[serde(default)]
    pub max_tokens: u64,
}

/// Engagement/scope policy for bug bounty operations.
/// Targets can be hostnames, wildcard domains (*.example.com), URLs, or CIDR-like prefixes (best-effort string match).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ScopeConfig {
    /// If non-empty, any network target must match at least one entry.
    #[serde(default)]
    pub in_scope: Vec<String>,
    /// Targets matching any entry are always denied.
    #[serde(default)]
    pub out_of_scope: Vec<String>,
    /// Optional program/engagement name for prompts and reports.
    #[serde(default)]
    pub engagement: Option<String>,
    /// Optional notes/constraints shown to the agent.
    #[serde(default)]
    pub notes: Option<String>,
}

impl ScopeConfig {
    pub fn is_configured(&self) -> bool {
        !self.in_scope.is_empty() || !self.out_of_scope.is_empty() || self.engagement.is_some()
    }

    fn norm_host(target: &str) -> String {
        let t = target.trim();
        let without_scheme = t
            .strip_prefix("https://")
            .or_else(|| t.strip_prefix("http://"))
            .unwrap_or(t);
        let authority = without_scheme.split('/').next().unwrap_or(without_scheme);
        let authority = authority.rsplit('@').next().unwrap_or(authority);
        let host = if authority.starts_with('[') {
            authority
                .split(']')
                .next()
                .unwrap_or(authority)
                .trim_start_matches('[')
                .to_string()
        } else {
            authority.split(':').next().unwrap_or(authority).to_string()
        };
        host.trim_end_matches('.').to_ascii_lowercase()
    }

    fn cidr_matches(pattern: &str, target: &str) -> bool {
        let Some((network, bits)) = pattern.split_once('/') else {
            return false;
        };
        let Ok(bits) = bits.parse::<u32>() else {
            return false;
        };
        let (Ok(net), Ok(addr)) = (
            network.trim().parse::<IpAddr>(),
            Self::norm_host(target).parse::<IpAddr>(),
        ) else {
            return false;
        };
        match (net, addr) {
            (IpAddr::V4(n), IpAddr::V4(a)) if bits <= 32 => {
                let mask = if bits == 0 {
                    0
                } else {
                    u32::MAX << (32 - bits)
                };
                u32::from(n) & mask == u32::from(a) & mask
            }
            (IpAddr::V6(n), IpAddr::V6(a)) if bits <= 128 => {
                let mask = if bits == 0 {
                    0
                } else {
                    u128::MAX << (128 - bits)
                };
                u128::from(n) & mask == u128::from(a) & mask
            }
            _ => false,
        }
    }

    fn matches(pattern: &str, target: &str) -> bool {
        let p = pattern.trim().to_ascii_lowercase();
        if p.is_empty() {
            return false;
        }
        if p == "*" {
            return true;
        }
        if p.contains('/') {
            let network = p.split('/').next().unwrap_or_default();
            if network.parse::<IpAddr>().is_ok() {
                return Self::cidr_matches(&p, target);
            }
            // Host-oriented pattern with a path: match the host component only.
            let host = network.trim_end_matches('.');
            let t_host = Self::norm_host(target);
            if let Some(suffix) = host.strip_prefix("*.") {
                return t_host == suffix || t_host.ends_with(&format!(".{suffix}"));
            }
            return t_host == host || t_host.ends_with(&format!(".{host}"));
        }
        let t_raw = target.trim().to_ascii_lowercase();
        let t_host = Self::norm_host(target);
        if let Some(suffix) = p.strip_prefix("*.") {
            return t_host == suffix || t_host.ends_with(&format!(".{suffix}"));
        }
        t_host == p
            || t_raw == p
            || t_host.ends_with(&format!(".{p}"))
            || t_raw.starts_with(&format!("{p}/"))
    }

    /// Number of host labels in a scope rule, ignoring any path. Used to
    /// compare how specific two matching rules are.
    fn specificity(rule: &str) -> usize {
        let host = rule
            .split("://")
            .last()
            .unwrap_or(rule)
            .split('/')
            .next()
            .unwrap_or(rule);
        host.trim_start_matches("*.")
            .trim_matches('.')
            .split('.')
            .filter(|part| !part.is_empty())
            .count()
    }

    /// A path-scoped exclusion (e.g. `clockify.me/help/*`) must not exclude a
    /// bare host target: that is broader than the rule intends.
    fn is_path_scoped_exclusion(rule: &str) -> bool {
        rule.contains('/')
            && rule
                .split('/')
                .next()
                .unwrap_or_default()
                .parse::<std::net::IpAddr>()
                .is_err()
    }

    pub fn check_target(&self, target: &str) -> (bool, String) {
        if target.trim().is_empty() {
            return (false, "empty target".to_string());
        }
        let out_matches: Vec<&String> = self
            .out_of_scope
            .iter()
            .filter(|rule| !Self::is_path_scoped_exclusion(rule))
            .filter(|rule| Self::matches(rule, target))
            .collect();
        if self.in_scope.is_empty() {
            if let Some(rule) = out_matches.first() {
                return (
                    false,
                    format!("target '{target}' matches out-of-scope rule '{rule}'"),
                );
            }
            return (true, "no in-scope restrictions configured".to_string());
        }
        let in_matches: Vec<&String> = self
            .in_scope
            .iter()
            .filter(|rule| Self::matches(rule, target))
            .collect();
        // A program may list a concrete asset as in-scope while also excluding
        // a broad wildcard subdomain. The more specific, explicitly named asset
        // wins; an out-of-scope wildcard alone never overrides it.
        let winning_in = in_matches.iter().find(|in_rule| {
            let in_labels = Self::specificity(in_rule);
            let in_exact = !in_rule.contains('*');
            !out_matches.is_empty()
                && out_matches.iter().all(|out_rule| {
                    out_rule.contains('*') && (in_exact || in_labels > Self::specificity(out_rule))
                })
        });
        if let Some(winner) = winning_in {
            return (
                true,
                format!(
                    "target '{target}' allowed by more specific in-scope asset '{winner}' despite broader out-of-scope wildcard"
                ),
            );
        }
        if let Some(rule) = out_matches.first() {
            return (
                false,
                format!("target '{target}' matches out-of-scope rule '{rule}'"),
            );
        }
        if let Some(rule) = in_matches.first() {
            return (
                true,
                format!("target '{target}' allowed by scope rule '{rule}'"),
            );
        }
        (
            false,
            format!("target '{target}' is not in engagement scope"),
        )
    }
}

/// Advisory trace for one brief-derived scope rule. Never consulted by
/// `PolicyEngine`; it exists only so the domain can record where a rule came
/// from. `kind` is `scope_in` or `scope_out`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopeRuleTrace {
    pub kind: &'static str,
    pub value: String,
    pub quote: String,
    pub section: String,
}

/// Parse with provenance. The legacy [`parse_scope_brief`] delegates here and
/// discards the traces, giving one implementation of matching semantics.
pub fn parse_scope_brief_traced(text: &str) -> (ScopeConfig, Vec<ScopeRuleTrace>) {
    let mut scope = ScopeConfig::default();
    let mut traces = Vec::new();
    let mut out_section = false;
    let mut notes = Vec::new();
    let mut prose_in_scope: Vec<String> = Vec::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        let lower = line.to_ascii_lowercase();
        if lower.contains("out of scope") || lower.contains("out-of-scope") {
            out_section = true;
            continue;
        }
        if lower.contains("in scope") || lower.contains("in-scope") {
            out_section = false;
            continue;
        }
        if let Some(value) = line
            .strip_prefix("Program:")
            .or_else(|| line.strip_prefix("Engagement:"))
        {
            scope.engagement = Some(value.trim().to_string());
            continue;
        }
        let candidate = line
            .strip_prefix("- ")
            .or_else(|| line.strip_prefix('-'))
            .unwrap_or(line)
            .trim();
        let looks_like_pattern = !candidate.is_empty()
            && !candidate.contains(char::is_whitespace)
            && (candidate.starts_with("*.")
                || candidate.contains('.')
                || candidate.contains('/')
                || candidate.contains(':'));
        if looks_like_pattern {
            let kind = if out_section { "scope_out" } else { "scope_in" };
            if out_section {
                scope.out_of_scope.push(candidate.to_string());
            } else {
                scope.in_scope.push(candidate.to_string());
            }
            traces.push(ScopeRuleTrace {
                kind,
                value: candidate.to_string(),
                quote: line.to_string(),
                section: if out_section {
                    "Out of scope"
                } else {
                    "In scope"
                }
                .to_string(),
            });
            continue;
        }
        if !out_section {
            prose_in_scope.push(line.to_string());
        }
        notes.push(line.to_string());
    }
    // Some disclosure policies state scope inside prose instead of a list,
    // e.g. "Any website served from the *.ada.com, *.ada.health domains".
    // Only use this fallback when no explicit in-scope entry was found, and
    // never draw it from the out-of-scope part of the brief.
    if scope.in_scope.is_empty() {
        for line in &prose_in_scope {
            for token in line.split(|c: char| c.is_whitespace() || c == ',' || c == ';') {
                let candidate = token.trim_matches(['`', '"', '\'', '(', ')', '.']);
                if candidate.starts_with("*.")
                    && candidate.len() > 3
                    && candidate[2..].contains('.')
                    && !scope.in_scope.iter().any(|value| value == candidate)
                {
                    scope.in_scope.push(candidate.to_string());
                    traces.push(ScopeRuleTrace {
                        kind: "scope_in",
                        value: candidate.to_string(),
                        quote: line.clone(),
                        section: "In scope (prose)".to_string(),
                    });
                }
            }
        }
    }
    if !notes.is_empty() {
        scope.notes = Some(notes.join(" | "));
    }
    (scope, traces)
}

/// Parse a human-authored program brief into a ScopeConfig.
pub fn parse_scope_brief(text: &str) -> ScopeConfig {
    parse_scope_brief_traced(text).0
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfig {
    #[serde(default)]
    pub mode: Mode,
    #[serde(default)]
    pub allowed_targets: Vec<String>,
    #[serde(default)]
    pub denied_targets: Vec<String>,
    #[serde(default = "default_true")]
    pub deny_destructive: bool,
    /// Scope enforcement for bug bounty engagements.
    #[serde(default)]
    pub scope: ScopeConfig,
    /// Tools explicitly denied regardless of mode/risk.
    #[serde(default)]
    pub denied_tools: Vec<String>,
    /// If non-empty, only these tools are allowed.
    #[serde(default)]
    pub allowed_tools: Vec<String>,
    /// Budget/rate-limit configuration.
    #[serde(default)]
    pub budgets: BudgetConfig,
    #[serde(default)]
    pub budget: BudgetConfig,
    #[serde(default)]
    pub rate_limits: BudgetConfig,
    #[serde(default)]
    pub rate_limit: BudgetConfig,
}

fn default_true() -> bool {
    true
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            mode: Mode::Ask,
            allowed_targets: vec![],
            denied_targets: vec![],
            deny_destructive: true,
            scope: ScopeConfig::default(),
            denied_tools: vec![],
            allowed_tools: vec![],
            budgets: BudgetConfig::default(),
            budget: BudgetConfig::default(),
            rate_limits: BudgetConfig::default(),
            rate_limit: BudgetConfig::default(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ActionRequest {
    pub tool: String,
    pub risk: String,
    pub target: Option<String>,
}

#[derive(Debug, Clone)]
pub struct PolicyEngine {
    cfg: PolicyConfig,
}

impl PolicyEngine {
    pub fn new(cfg: PolicyConfig) -> Self {
        Self { cfg }
    }

    pub fn config(&self) -> &PolicyConfig {
        &self.cfg
    }

    pub fn evaluate(&self, req: &ActionRequest) -> (Decision, String) {
        let risk = req.risk.as_str();
        let tool = req.tool.as_str();

        // 0) explicit tool denies/allows
        if self.cfg.denied_tools.iter().any(|t| t == tool) {
            return (Decision::Deny, format!("tool '{tool}' denied by policy"));
        }
        if !self.cfg.allowed_tools.is_empty() && !self.cfg.allowed_tools.iter().any(|t| t == tool) {
            return (
                Decision::Deny,
                format!("tool '{tool}' not in allowed tool list"),
            );
        }

        // 1) destructive always denied by default
        if self.cfg.deny_destructive && risk == "destructive" {
            return (
                Decision::Deny,
                "destructive action denied by policy".to_string(),
            );
        }

        // 2) explicit target denies/allows (legacy list)
        if let Some(t) = req.target.as_deref() {
            if self
                .cfg
                .denied_targets
                .iter()
                .any(|d| ScopeConfig::matches(d, t))
            {
                return (Decision::Deny, "target denied by policy".to_string());
            }
            if !self.cfg.allowed_targets.is_empty()
                && !self
                    .cfg
                    .allowed_targets
                    .iter()
                    .any(|a| ScopeConfig::matches(a, t))
            {
                return (Decision::Deny, "target not in allowlist".to_string());
            }

            // 2b) engagement scope enforcement for network-capable actions
            if matches!(risk, "network" | "intrusive" | "exec")
                || tool.contains("http")
                || tool.contains("dns")
                || tool.contains("scan")
                || tool.contains("probe")
            {
                let (ok, reason) = self.cfg.scope.check_target(t);
                if !ok {
                    return (Decision::Deny, reason);
                }
            }
        } else if self.cfg.scope.is_configured()
            && (matches!(risk, "network" | "intrusive" | "exec")
                || tool.contains("http")
                || tool.contains("dns")
                || tool.contains("scan")
                || tool.contains("probe"))
        {
            return (
                Decision::Deny,
                "network action requires an explicit in-scope target when engagement scope is configured".to_string(),
            );
        }

        // 3) exec/network/intrusive require elevated trust
        let elevated = matches!(risk, "exec" | "network" | "intrusive");

        match self.cfg.mode {
            Mode::Ask => {
                if elevated || tool == "shell_exec" {
                    (
                        Decision::Ask,
                        "risky action requires approval (ask mode)".to_string(),
                    )
                } else {
                    (Decision::Allow, "allowed in ask mode".to_string())
                }
            }
            Mode::FullAuto => {
                if risk == "destructive" {
                    (
                        Decision::Deny,
                        "destructive denied in full_auto".to_string(),
                    )
                } else {
                    (
                        Decision::Allow,
                        "allowed in full_auto within policy".to_string(),
                    )
                }
            }
        }
    }

    pub fn scope_summary(&self) -> Option<String> {
        if !self.cfg.scope.is_configured() {
            return None;
        }
        let mut parts = vec![];
        if let Some(e) = &self.cfg.scope.engagement {
            parts.push(format!("engagement={e}"));
        }
        if !self.cfg.scope.in_scope.is_empty() {
            parts.push(format!("in_scope={}", self.cfg.scope.in_scope.join(",")));
        }
        if !self.cfg.scope.out_of_scope.is_empty() {
            parts.push(format!(
                "out_of_scope={}",
                self.cfg.scope.out_of_scope.join(",")
            ));
        }
        if let Some(n) = &self.cfg.scope.notes {
            parts.push(format!("notes={n}"));
        }
        Some(parts.join(" | "))
    }

    pub fn allowed_network_targets_hint(&self) -> BTreeSet<String> {
        self.cfg.scope.in_scope.iter().cloned().collect()
    }

    /// Merge the equivalent budget aliases into one effective budget.
    /// A non-zero value in a more specific alias wins.
    pub fn effective_budgets(&self) -> BudgetConfig {
        let pick = |get: fn(&BudgetConfig) -> usize| {
            [
                &self.cfg.budgets,
                &self.cfg.budget,
                &self.cfg.rate_limits,
                &self.cfg.rate_limit,
            ]
            .into_iter()
            .map(get)
            .find(|v| *v > 0)
            .unwrap_or(0)
        };
        let pick_u64 = |get: fn(&BudgetConfig) -> u64| {
            [
                &self.cfg.budgets,
                &self.cfg.budget,
                &self.cfg.rate_limits,
                &self.cfg.rate_limit,
            ]
            .into_iter()
            .map(get)
            .find(|v| *v > 0)
            .unwrap_or(0)
        };
        BudgetConfig {
            max_tool_calls: pick(|b| b.max_tool_calls),
            max_network_calls: pick(|b| b.max_network_calls),
            requests_per_minute: pick_u64(|b| b.requests_per_minute),
            max_steps: pick(|b| b.max_steps),
            max_tokens: pick_u64(|b| b.max_tokens),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ask_mode_safe_allows_risky_asks() {
        let p = PolicyEngine::new(PolicyConfig::default());
        let (d, _) = p.evaluate(&ActionRequest {
            tool: "echo".into(),
            risk: "safe".into(),
            target: None,
        });
        assert_eq!(d, Decision::Allow);
        let (d, _) = p.evaluate(&ActionRequest {
            tool: "shell_exec".into(),
            risk: "exec".into(),
            target: None,
        });
        assert_eq!(d, Decision::Ask);
    }

    #[test]
    fn full_auto_allows_non_destructive_but_denies_destructive() {
        let p = PolicyEngine::new(PolicyConfig {
            mode: Mode::FullAuto,
            ..Default::default()
        });
        let (d, _) = p.evaluate(&ActionRequest {
            tool: "shell_exec".into(),
            risk: "exec".into(),
            target: None,
        });
        assert_eq!(d, Decision::Allow);
        let (d, _) = p.evaluate(&ActionRequest {
            tool: "x".into(),
            risk: "destructive".into(),
            target: None,
        });
        assert_eq!(d, Decision::Deny);
    }

    #[test]
    fn scope_denies_out_of_scope_and_allows_in_scope() {
        let p = PolicyEngine::new(PolicyConfig {
            mode: Mode::FullAuto,
            scope: ScopeConfig {
                in_scope: vec!["*.example.com".into(), "api.test".into()],
                out_of_scope: vec!["admin.example.com".into()],
                engagement: Some("test".into()),
                notes: None,
            },
            ..Default::default()
        });
        let (d, _) = p.evaluate(&ActionRequest {
            tool: "http_probe".into(),
            risk: "network".into(),
            target: Some("https://www.example.com/path".into()),
        });
        assert_eq!(d, Decision::Allow);
        let (d, _) = p.evaluate(&ActionRequest {
            tool: "http_probe".into(),
            risk: "network".into(),
            target: Some("https://admin.example.com".into()),
        });
        assert_eq!(d, Decision::Deny);
        let (d, _) = p.evaluate(&ActionRequest {
            tool: "http_probe".into(),
            risk: "network".into(),
            target: Some("https://evil.com".into()),
        });
        assert_eq!(d, Decision::Deny);
    }

    #[test]
    fn scope_pattern_does_not_match_lookalike_hosts() {
        let p = PolicyEngine::new(PolicyConfig {
            mode: Mode::FullAuto,
            scope: ScopeConfig {
                in_scope: vec!["example.com".into()],
                ..Default::default()
            },
            ..Default::default()
        });
        let (d, _) = p.evaluate(&ActionRequest {
            tool: "http_request".into(),
            risk: "network".into(),
            target: Some("https://notexample.com/path".into()),
        });
        assert_eq!(d, Decision::Deny);
        let (d, _) = p.evaluate(&ActionRequest {
            tool: "http_request".into(),
            risk: "network".into(),
            target: Some("https://evil.com/redirect?to=example.com".into()),
        });
        assert_eq!(d, Decision::Deny);
        let (d, _) = p.evaluate(&ActionRequest {
            tool: "http_request".into(),
            risk: "network".into(),
            target: Some("https://api.example.com/v1".into()),
        });
        assert_eq!(d, Decision::Allow);
    }

    #[test]
    fn scope_brief_parser_handles_sections() {
        let brief = "Program: Acme Corp\nIn scope:\n- *.acme.com\n- 10.0.0.0/8\nOut of scope:\n- admin.acme.com\nContact: security@acme.com";
        let scope = parse_scope_brief(brief);
        assert_eq!(scope.engagement.as_deref(), Some("Acme Corp"));
        assert_eq!(scope.in_scope, vec!["*.acme.com", "10.0.0.0/8"]);
        assert_eq!(scope.out_of_scope, vec!["admin.acme.com"]);
        assert!(scope.notes.unwrap().contains("security@acme.com"));
    }

    #[test]
    fn exec_requires_in_scope_target_when_scope_configured() {
        let p = PolicyEngine::new(PolicyConfig {
            mode: Mode::FullAuto,
            scope: ScopeConfig {
                in_scope: vec!["example.com".into()],
                ..Default::default()
            },
            ..Default::default()
        });
        let (d, reason) = p.evaluate(&ActionRequest {
            tool: "shell_exec".into(),
            risk: "exec".into(),
            target: None,
        });
        assert_eq!(d, Decision::Deny, "{reason}");
        let (d, _) = p.evaluate(&ActionRequest {
            tool: "shell_exec".into(),
            risk: "exec".into(),
            target: Some("https://example.com".into()),
        });
        assert_eq!(d, Decision::Allow);
    }

    #[test]
    fn cidr_scope_rules_match_real_address_ranges() {
        let p = PolicyEngine::new(PolicyConfig {
            mode: Mode::FullAuto,
            scope: ScopeConfig {
                in_scope: vec!["10.0.0.0/8".into(), "2001:db8::/32".into()],
                ..Default::default()
            },
            ..Default::default()
        });
        let (d, _) = p.evaluate(&ActionRequest {
            tool: "http_request".into(),
            risk: "network".into(),
            target: Some("http://10.1.2.3/".into()),
        });
        assert_eq!(d, Decision::Allow);
        let (d, _) = p.evaluate(&ActionRequest {
            tool: "http_request".into(),
            risk: "network".into(),
            target: Some("http://11.1.2.3/".into()),
        });
        assert_eq!(d, Decision::Deny);
    }

    #[test]
    fn legacy_allowlist_rejects_lookalike_hosts() {
        let p = PolicyEngine::new(PolicyConfig {
            mode: Mode::FullAuto,
            allowed_targets: vec!["example.com".into()],
            ..Default::default()
        });
        let (d, _) = p.evaluate(&ActionRequest {
            tool: "http_request".into(),
            risk: "network".into(),
            target: Some("https://notexample.com/".into()),
        });
        assert_eq!(d, Decision::Deny);
    }

    #[test]
    fn effective_budgets_prefer_non_zero_alias() {
        let p = PolicyEngine::new(PolicyConfig {
            budgets: BudgetConfig {
                max_tool_calls: 7,
                max_network_calls: 3,
                ..Default::default()
            },
            rate_limit: BudgetConfig {
                requests_per_minute: 10,
                ..Default::default()
            },
            ..Default::default()
        });
        let b = p.effective_budgets();
        assert_eq!(b.max_tool_calls, 7);
        assert_eq!(b.max_network_calls, 3);
        assert_eq!(b.requests_per_minute, 10);
    }
}

#[cfg(test)]
mod provenance_tests {
    use super::*;

    #[test]
    fn traced_parser_matches_legacy_decision() {
        let brief = "Program: Acme\nIn scope\n- example.com\n- *.example.org\nOut of scope\n- admin.example.com\nSome note here";
        let legacy = parse_scope_brief(brief);
        let (traced, traces) = parse_scope_brief_traced(brief);
        assert_eq!(legacy.in_scope, traced.in_scope);
        assert_eq!(legacy.out_of_scope, traced.out_of_scope);
        assert_eq!(legacy.engagement, traced.engagement);
        assert_eq!(legacy.notes, traced.notes);
        assert_eq!(traces.len(), 3);
        assert_eq!(traces[0].kind, "scope_in");
        assert_eq!(traces[0].value, "example.com");
        assert_eq!(traces[2].kind, "scope_out");
        assert!(traces[0].quote.contains("example.com"));
    }

    #[test]
    fn prose_wildcard_scope_is_detected() {
        let brief = "Security Policy\nAny website or service served from the *.ada.com, *.ada.health domains.\nOut of scope: third-party applications only.\n";
        let (scope, traces) = parse_scope_brief_traced(brief);
        assert!(scope.in_scope.iter().any(|v| v == "*.ada.com"));
        assert!(scope.in_scope.iter().any(|v| v == "*.ada.health"));
        assert!(traces
            .iter()
            .any(|t| t.section == "In scope (prose)" && t.value == "*.ada.com"));
    }

    #[test]
    fn scope_matches_host_of_path_bearing_pattern() {
        // Wildcard host pattern with a path matches the bare host and subdomains.
        assert!(ScopeConfig::matches(
            "*.api.clockify.me/api/",
            "api.clockify.me"
        ));
        assert!(ScopeConfig::matches(
            "*.api.clockify.me/api/",
            "sub.api.clockify.me"
        ));
        // Exact host pattern with a path matches the bare host.
        assert!(ScopeConfig::matches(
            "account.cake.com/api/",
            "account.cake.com"
        ));
        // A real CIDR still behaves as a CIDR.
        assert!(ScopeConfig::matches("10.1.2.0/24", "10.1.2.3"));
        assert!(!ScopeConfig::matches("10.1.2.0/24", "11.0.0.1"));
    }

    #[test]
    fn path_scoped_exclusion_does_not_block_specific_host() {
        let scope = ScopeConfig {
            in_scope: vec!["*.api.clockify.me/api/".to_string()],
            out_of_scope: vec![
                "clockify.me/help/*".to_string(),
                "*.clockify.me".to_string(),
            ],
            engagement: None,
            notes: None,
        };
        let (ok, reason) = scope.check_target("api.clockify.me");
        assert!(ok, "{reason}");
        // A genuinely excluded subdomain stays excluded.
        let (ok, _) = scope.check_target("nope.clockify.me");
        assert!(!ok);
        // An exact out-of-scope host still wins over a wildcard in-scope rule.
        let strict = ScopeConfig {
            in_scope: vec!["*.example.com".to_string()],
            out_of_scope: vec!["admin.example.com".to_string()],
            engagement: None,
            notes: None,
        };
        assert!(!strict.check_target("admin.example.com").0);
    }
}
