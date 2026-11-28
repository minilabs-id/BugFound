//! Deterministic intent-gate preflight (ADR-V3-003).
//!
//! Planner/tool output is untrusted. These ordered rules run before the legacy
//! policy table and fail closed. The full gate (schema, ROE class, budgets,
//! approval identity, idempotency) is completed as the orchestrator is rewired
//! in V3 Phase P2; this preflight is the part that can be enforced today without
//! leaking domain vocabulary into the kernel.

use crate::{ActionRequest, Decision, PolicyConfig, ScopeConfig};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GateResult {
    pub decision: Decision,
    pub reason: String,
}

/// Ordered preflight rules. `deny` always wins over `ask`/`allow`.
pub struct IntentGate<'a> {
    cfg: &'a PolicyConfig,
}

impl<'a> IntentGate<'a> {
    pub fn new(cfg: &'a PolicyConfig) -> Self {
        Self { cfg }
    }

    pub fn preflight(&self, req: &ActionRequest) -> Option<GateResult> {
        // 0) An action with no host classification is not executable.
        let risk = req.risk.trim();
        if risk.is_empty() || risk.eq_ignore_ascii_case("unknown") {
            return Some(GateResult {
                decision: Decision::Deny,
                reason: "unclassified tool risk denied by intent gate".into(),
            });
        }

        // 1) Explicit tool deny is absolute — it cannot be overridden by an
        //    allow list, an "always" approval, or auto-approve settings.
        if self.cfg.denied_tools.iter().any(|t| t == &req.tool) {
            return Some(GateResult {
                decision: Decision::Deny,
                reason: format!("tool '{}' denied by policy", req.tool),
            });
        }

        // 2) Any matching target deny wins, even if another rule allows it.
        if let Some(target) = req.target.as_deref() {
            if self
                .cfg
                .denied_targets
                .iter()
                .any(|denied| ScopeConfig::matches(denied, target))
            {
                return Some(GateResult {
                    decision: Decision::Deny,
                    reason: "target denied by policy".into(),
                });
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unclassified_risk_is_denied() {
        let cfg = PolicyConfig::default();
        let gate = IntentGate::new(&cfg);
        let result = gate.preflight(&ActionRequest {
            tool: "echo".into(),
            risk: "unknown".into(),
            target: None,
        });
        assert_eq!(result.expect("denied").decision, Decision::Deny);
    }

    #[test]
    fn deny_wins_over_allow_list() {
        let cfg = PolicyConfig {
            allowed_tools: vec!["echo".into()],
            denied_tools: vec!["echo".into()],
            ..Default::default()
        };
        let gate = IntentGate::new(&cfg);
        let result = gate.preflight(&ActionRequest {
            tool: "echo".into(),
            risk: "safe".into(),
            target: None,
        });
        assert_eq!(result.expect("denied").decision, Decision::Deny);
    }

    #[test]
    fn classified_safe_action_passes_preflight() {
        let cfg = PolicyConfig::default();
        let gate = IntentGate::new(&cfg);
        let result = gate.preflight(&ActionRequest {
            tool: "echo".into(),
            risk: "safe".into(),
            target: None,
        });
        assert!(result.is_none());
    }
}
