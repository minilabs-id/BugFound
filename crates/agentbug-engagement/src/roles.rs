//! Domain-owned role profiles. The kernel sees only opaque prompt strings and
//! a filtered `ToolRegistry`; role ids never leak into `agentbug-core`.

use agentbug_tools::{ToolRegistry, SESSION_FINISH_TOOL};
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
        },
        RoleId::Testing => RoleProfile {
            id,
            system_addendum:
                "Test hypotheses within ROE. Findings are advisory until independently verified.",
            allow_tools: &[], // inherit the ROE-filtered base; no new privilege
            max_steps: 24,
            max_tool_calls: 0,
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
        },
        RoleId::Report => RoleProfile {
            id,
            system_addendum:
                "Draft a factual report from verified evidence only. No target access.",
            allow_tools: &[SESSION_FINISH_TOOL],
            max_steps: 4,
            max_tool_calls: 0,
        },
    }
}

/// Build a role-scoped registry from an already ROE-filtered base. Role
/// filtering is a second independent layer; it never widens the base registry.
pub fn build_role_tools(base: &ToolRegistry, role: RoleId) -> ToolRegistry {
    let profile = role_profile(role);
    let mut scoped = ToolRegistry::new();
    for spec in base.specs() {
        if !profile.allow_tools.is_empty()
            && !profile.allow_tools.iter().any(|name| *name == spec.name)
        {
            continue;
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

    #[test]
    fn verification_role_cannot_save_findings_or_validate_poc() {
        let base = ToolRegistry::new();
        let scoped = build_role_tools(&base, RoleId::Verification);
        assert!(!scoped.specs().iter().any(|s| s.name == "save_finding"));
        assert!(!scoped.specs().iter().any(|s| s.name == "validate_poc"));
    }

    #[test]
    fn report_role_is_tool_free_except_terminal() {
        let mut base = ToolRegistry::new();
        base.register_with_host_risk(
            std::sync::Arc::new(agentbug_tools::SessionFinishTool),
            "safe",
        );
        let scoped = build_role_tools(&base, RoleId::Report);
        let names: Vec<String> = scoped.specs().into_iter().map(|s| s.name).collect();
        assert_eq!(names, vec![SESSION_FINISH_TOOL.to_string()]);
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
