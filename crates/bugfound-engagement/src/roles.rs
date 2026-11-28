//! Domain-owned role profiles. The kernel sees only opaque prompt strings and
//! a filtered `ToolRegistry`; role ids never leak into `bugfound-core`.

use bugfound_tools::{ToolRegistry, SESSION_FINISH_TOOL};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RoleId {
    General,
    ProgramIntel,
    Recon,
    Research,
    Testing,
    Verification,
    Report,
}

impl RoleId {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::General => "general",
            Self::ProgramIntel => "program_intel",
            Self::Recon => "recon",
            Self::Research => "research",
            Self::Testing => "testing",
            Self::Verification => "verification",
            Self::Report => "report",
        }
    }
}

pub struct RoleProfile {
    pub id: RoleId,
    pub system_addendum: &'static str,
    pub allow_tools: &'static [&'static str],
    pub max_steps: usize,
    pub max_tool_calls: usize,
    pub max_tools: usize,
}

/// Deterministic role selection for a WSTG playbook. No LLM choice.
pub fn role_for_playbook(playbook_id: &str) -> RoleId {
    match playbook_id {
        "wstg-info" => RoleId::Recon,
        "wstg-config" => RoleId::Research,
        _ => RoleId::Testing,
    }
}

pub fn role_profile(id: RoleId) -> RoleProfile {
    match id {
        RoleId::General => RoleProfile {
            id,
            system_addendum: "Work through the assigned task carefully and report evidence.",
            allow_tools: &[], // empty means: inherit the whole ROE-filtered base
            max_steps: 20,
            max_tool_calls: 0,
            max_tools: 5,
        },
        RoleId::ProgramIntel => RoleProfile {
            id,
            system_addendum:
                "Extract authoritative facts from the program brief. Do not probe targets.",
            allow_tools: &[
                "read_file",
                "read",
                "http_probe",
                "dns",
                "dns_lookup",
                "dns_resolve",
                "knowledge_lookup",
                "task_put",
                "clue_put",
                SESSION_FINISH_TOOL,
            ],
            max_steps: 8,
            max_tool_calls: 8,
            max_tools: 5,
        },
        RoleId::Recon => RoleProfile {
            id,
            system_addendum: "Map in-scope assets. No intrusive or state-changing actions.",
            allow_tools: &[
                "dns",
                "dns_lookup",
                "dns_resolve",
                "http_probe",
                "echo",
                "subdomain_enum",
                "content_discovery",
                "clue_put",
                "task_put",
                SESSION_FINISH_TOOL,
            ],
            max_steps: 12,
            max_tool_calls: 16,
            max_tools: 5,
        },
        RoleId::Research => RoleProfile {
            id,
            system_addendum: "Consult known methodology and record concise, sourced notes.",
            allow_tools: &[
                "knowledge_lookup",
                "read_file",
                "http_probe",
                "clue_put",
                SESSION_FINISH_TOOL,
            ],
            max_steps: 8,
            max_tool_calls: 8,
            max_tools: 5,
        },
        RoleId::Testing => RoleProfile {
            id,
            system_addendum:
                "Test hypotheses within ROE. Findings are advisory until independently verified.",
            allow_tools: &[], // inherit the ROE-filtered base; no new privilege
            max_steps: 24,
            max_tool_calls: 0,
            max_tools: 5,
        },
        RoleId::Verification => RoleProfile {
            id,
            system_addendum:
                "Try to disprove the candidate. You cannot create findings; report counterevidence.",
            allow_tools: &[
                "read_file",
                "http_probe",
                "knowledge_lookup",
                "echo",
                "clue_put",
                "role_result",
                SESSION_FINISH_TOOL,
            ],
            max_steps: 10,
            max_tool_calls: 10,
            max_tools: 5,
        },
        RoleId::Report => RoleProfile {
            id,
            system_addendum:
                "Draft a factual report from verified evidence only. No target access.",
            allow_tools: &[SESSION_FINISH_TOOL],
            max_steps: 4,
            max_tool_calls: 0,
            max_tools: 5,
        },
    }
}

/// Build a role-scoped registry from an already ROE-filtered base. Role
/// filtering is a second independent layer; it never widens the base registry.
pub fn build_role_tools(base: &ToolRegistry, role: RoleId) -> ToolRegistry {
    let profile = role_profile(role);
    // An empty allow-list means "inherit the whole ROE-filtered base". The
    // numeric cap bounds explicit allow-lists only: applying it to an inherited
    // base would alphabetically truncate the registry before evidence tools
    // such as `http_probe`, `http_request` and `save_finding` are ever seen.
    let inherit_base = profile.allow_tools.is_empty();
    let mut scoped = ToolRegistry::new();
    let mut non_terminal = 0usize;
    for spec in base.specs() {
        if !inherit_base && !profile.allow_tools.iter().any(|name| *name == spec.name) {
            continue;
        }
        if !inherit_base && spec.name != SESSION_FINISH_TOOL {
            if non_terminal >= profile.max_tools {
                continue;
            }
            non_terminal += 1;
        }
        let Some(tool) = base.get(&spec.name) else {
            continue;
        };
        scoped.register_with_host_risk(tool, base.host_risk(&spec.name).to_string());
    }
    if scoped.get(SESSION_FINISH_TOOL).is_none() {
        if let Some(tool) = base.get(SESSION_FINISH_TOOL) {
            scoped.register_with_host_risk(tool, "safe");
        }
    }
    scoped
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A side-effect-free named tool so registry filtering can be exercised
    /// against a fully controlled base surface.
    struct NamedTool(&'static str);

    #[async_trait::async_trait]
    impl bugfound_tools::Tool for NamedTool {
        fn spec(&self) -> bugfound_tools::ToolSpec {
            bugfound_tools::ToolSpec::new(self.0, "", serde_json::json!({"type":"object"}))
        }

        async fn run(
            &self,
            _input: serde_json::Value,
        ) -> anyhow::Result<bugfound_tools::ToolResult> {
            Ok(bugfound_tools::ToolResult {
                ok: true,
                output: String::new(),
                structured: None,
            })
        }
    }

    fn base_with(names: &[&'static str]) -> ToolRegistry {
        let mut base = ToolRegistry::new();
        for name in names {
            base.register_with_host_risk(std::sync::Arc::new(NamedTool(name)), "safe");
        }
        base
    }

    fn has(scoped: &ToolRegistry, name: &str) -> bool {
        scoped.get(name).is_some()
    }

    /// Base with enough alphabetically-earlier tools that the old `max_tools: 5`
    /// cap would hide the evidence tools under test.
    fn evidence_base() -> ToolRegistry {
        base_with(&[
            "clue_put",
            "content_discovery",
            "decode",
            "dns_lookup",
            "echo",
            "http_probe",
            "http_request",
            "save_finding",
            "validate_poc",
            SESSION_FINISH_TOOL,
        ])
    }

    #[test]
    fn verification_role_cannot_save_findings_or_validate_poc() {
        let scoped = build_role_tools(&evidence_base(), RoleId::Verification);
        assert!(!has(&scoped, "save_finding"));
        assert!(!has(&scoped, "validate_poc"));
    }

    #[test]
    fn report_role_is_tool_free_except_terminal() {
        let scoped = build_role_tools(&evidence_base(), RoleId::Report);
        let names: Vec<String> = scoped.specs().into_iter().map(|s| s.name).collect();
        assert_eq!(names, vec![SESSION_FINISH_TOOL.to_string()]);
    }

    #[test]
    fn testing_role_exposes_save_finding_http_request_and_http_probe() {
        let scoped = build_role_tools(&evidence_base(), RoleId::Testing);
        for name in ["save_finding", "http_request", "http_probe", "validate_poc"] {
            assert!(has(&scoped, name), "testing role should expose {name}");
        }
    }

    #[test]
    fn general_role_exposes_save_finding() {
        let scoped = build_role_tools(&evidence_base(), RoleId::General);
        assert!(has(&scoped, "save_finding"));
    }

    #[test]
    fn empty_allow_tools_inherits_full_base_registry() {
        let names = [
            "aaa",
            "bbb",
            "ccc",
            "ddd",
            "eee",
            "fff",
            "ggg",
            "http_probe",
            "http_request",
            "save_finding",
            SESSION_FINISH_TOOL,
            "validate_poc",
        ];
        assert!(role_profile(RoleId::General).allow_tools.is_empty());
        assert!(role_profile(RoleId::Testing).allow_tools.is_empty());
        let base = base_with(&names);
        let mut expected: Vec<String> = names.iter().map(|name| name.to_string()).collect();
        expected.sort();
        for role in [RoleId::General, RoleId::Testing] {
            let scoped = build_role_tools(&base, role);
            let actual: Vec<String> = scoped.specs().into_iter().map(|s| s.name).collect();
            assert_eq!(actual, expected, "{role:?} should inherit the whole base");
        }
    }
}

#[test]
fn playbook_role_mapping_is_total_and_deterministic() {
    assert_eq!(role_for_playbook("wstg-info"), RoleId::Recon);
    assert_eq!(role_for_playbook("wstg-config"), RoleId::Research);
    assert_eq!(role_for_playbook("wstg-authz"), RoleId::Testing);
    assert_eq!(role_for_playbook("custom"), RoleId::Testing);
    assert!(role_profile(RoleId::Verification)
        .allow_tools
        .contains(&"role_result"));
}

#[test]
fn role_tool_cap_excludes_terminal_tool() {
    let base = ToolRegistry::new();
    for role in [
        RoleId::General,
        RoleId::Recon,
        RoleId::Research,
        RoleId::Testing,
        RoleId::Verification,
    ] {
        let scoped = build_role_tools(&base, role);
        let non_terminal = scoped
            .specs()
            .into_iter()
            .filter(|spec| spec.name != SESSION_FINISH_TOOL)
            .count();
        assert!(non_terminal <= role_profile(role).max_tools);
    }
}
