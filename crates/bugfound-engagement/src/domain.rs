//! Bug-bounty implementation of the universal kernel's domain ports.
//!
//! The kernel sees only trait objects. All finding/scope/WSTG vocabulary lives
//! here, on the domain side of ADR-001.

use bugfound_kernel_traits::{
    digest_goal_and_context, GoalLock, ProgressObserver, PromptContributor, ToolResultSink,
};
use bugfound_store::{domain_progress_count, persist_tool_result, Hypothesis, MemoryWrite, Store};
use bugfound_tools::ToolResult;
use serde_json::Value;
use std::collections::HashSet;

use crate::roles::{role_profile, RoleId};

/// Domain adapter supplied to the kernel Runner by engagement orchestration.
#[derive(Debug, Clone)]
pub struct BountyDomain {
    pub scope_summary: Option<String>,
    pub role: RoleId,
    pub scope_key: String,
    pub parent_session_id: Option<String>,
    pub task_id: Option<String>,
}

impl GoalLock for BountyDomain {
    fn digest(&self, goal: &str) -> String {
        digest_goal_and_context(goal, self.scope_summary.as_deref())
    }

    fn digest_with_context(&self, goal: &str, context: Option<&str>) -> String {
        // The kernel supplies the canonical scope JSON. Use it exclusively so
        // the domain-captured summary is never double-counted; fall back to the
        // legacy summary only when no context is supplied.
        digest_goal_and_context(goal, context.or(self.scope_summary.as_deref()))
    }
}

impl PromptContributor for BountyDomain {
    fn additional_system_prompt(&self) -> Option<String> {
        let scope = match &self.scope_summary {
            Some(summary) => {
                format!("Engagement scope: {summary}. Never probe out-of-scope targets.")
            }
            None => "Never probe out-of-scope targets.".to_string(),
        };
        Some(format!(
            "{scope} {}",
            role_profile(self.role).system_addendum
        ))
    }
}

impl ToolResultSink for BountyDomain {
    fn on_tool_result(
        &self,
        store: &Store,
        session_id: &str,
        tool_name: &str,
        args: &Value,
        result: &ToolResult,
    ) {
        persist_tool_result(store, session_id, tool_name, args, result);
        if !result.ok || tool_name.starts_with("memory.") || tool_name.starts_with("role.") {
            return;
        }
        let raw = format!("tool={tool_name} args={} result={}", args, result.output);
        let content = bugfound_store::redact(&raw)
            .chars()
            .take(4096)
            .collect::<String>();
        let anchor = store
            .list_events(session_id, 1)
            .ok()
            .and_then(|events| events.first().map(|event| event.hash.clone()));
        let _ = store.add_memory(MemoryWrite {
            session_id,
            parent_session_id: self.parent_session_id.as_deref(),
            source_kind: "tool_result",
            source_id: tool_name,
            source_event_hash: anchor.as_deref(),
            role: Some(self.role.as_str()),
            task_id: self.task_id.as_deref(),
            scope_key: &self.scope_key,
            tier: "episodic",
            content: &content,
        });
    }
}

impl ProgressObserver for BountyDomain {
    fn progress_count(&self, store: &Store, session_id: &str) -> usize {
        domain_progress_count(store, session_id)
    }
}

/// Coverage-driven target suggestions: expand wildcard scope entries, remove
/// already covered targets, and rank candidates mentioned by hypotheses.
pub fn prioritize_targets(
    scope_in: &[String],
    covered: &[String],
    hypotheses: &[Hypothesis],
) -> Vec<String> {
    let mut candidates = Vec::new();
    for pattern in scope_in {
        let pattern = pattern.trim().to_ascii_lowercase();
        if let Some(suffix) = pattern.strip_prefix("*.") {
            candidates.push(suffix.to_string());
            for sub in ["www", "api", "dev", "staging", "mail", "admin"] {
                candidates.push(format!("{sub}.{suffix}"));
            }
        } else if !pattern.is_empty() && !pattern.contains('/') {
            candidates.push(pattern);
        }
    }
    let covered: HashSet<String> = covered.iter().map(|c| c.to_ascii_lowercase()).collect();
    let mut ranked: Vec<(usize, String)> = candidates
        .into_iter()
        .filter(|candidate| !covered.contains(candidate))
        .map(|candidate| {
            let score = hypotheses
                .iter()
                .filter(|hypothesis| {
                    hypothesis
                        .statement
                        .to_ascii_lowercase()
                        .contains(&candidate)
                })
                .count();
            (score, candidate)
        })
        .collect();
    ranked.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
    ranked.into_iter().map(|(_, candidate)| candidate).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_with_context_uses_context_exclusively() {
        let domain = BountyDomain {
            scope_summary: Some("legacy summary".into()),
            role: RoleId::General,
            scope_key: "example.com".into(),
            parent_session_id: None,
            task_id: None,
        };
        let json = r#"{"in_scope":["example.com"],"out_of_scope":[]}"#;
        assert_eq!(
            domain.digest_with_context("goal", Some(json)),
            digest_goal_and_context("goal", Some(json))
        );
        assert_ne!(
            domain.digest_with_context("goal", Some(json)),
            domain.digest("goal")
        );
    }

    #[test]
    fn planner_expands_scope_and_removes_covered_targets() {
        let scope = vec!["*.example.com".to_string(), "api.internal".to_string()];
        let covered = vec!["www.example.com".to_string()];
        let targets = prioritize_targets(&scope, &covered, &[]);
        assert!(targets.contains(&"example.com".to_string()));
        assert!(targets.contains(&"api.example.com".to_string()));
        assert!(targets.contains(&"api.internal".to_string()));
        assert!(!targets.contains(&"www.example.com".to_string()));
    }

    #[test]
    fn tool_reported_validation_never_promotes_finding() {
        let store = bugfound_store::Store::open(":memory:").unwrap();
        let finding = store
            .add_finding(
                "session",
                "Candidate",
                "high",
                Some("https://example.com"),
                None,
                "description",
                None,
                None,
                None,
                None,
            )
            .unwrap();
        let result = bugfound_tools::ToolResult {
            ok: true,
            output: "valid".into(),
            structured: Some(serde_json::json!({ "valid": true })),
        };
        let args = serde_json::json!({ "finding_id": finding.id });
        bugfound_store::persist_tool_result(&store, "session", "validate_poc", &args, &result);
        let findings = store.list_findings("session").unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].status, "open");
    }

    #[test]
    fn raw_capture_bytes_are_attached_to_finding() {
        let store = bugfound_store::Store::open(":memory:").unwrap();
        let args = serde_json::json!({
            "title": "Reflected XSS",
            "severity": "medium",
            "asset": "https://example.com/q",
            "request": "LLM supplied - must not be used",
            "response": "LLM supplied - must not be used",
        });
        let raw_request = b"GET /q?x=<script> HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let raw_response = b"HTTP/1.1 200 OK\r\nX-Canary: CANARY-42\r\n\r\nreflected";
        // B5: authoritative bytes come from a server-owned HTTP capture, not
        // from the model-controlled `save_finding` structured payload.
        store
            .put_session_capture("s", raw_request, raw_response, "CANARY-42")
            .unwrap();
        let result = bugfound_tools::ToolResult {
            ok: true,
            output: "captured".into(),
            structured: None,
        };
        bugfound_store::persist_tool_result(&store, "s", "save_finding", &args, &result);
        let findings = store.list_findings("s").unwrap();
        assert_eq!(findings.len(), 1);
        let capture = store
            .get_capture(&findings[0].id)
            .unwrap()
            .expect("capture must be persisted");
        assert_eq!(capture.request_bytes.as_slice(), raw_request);
        assert_eq!(capture.response_bytes.as_slice(), raw_response);
        assert_eq!(capture.canary, "CANARY-42");
    }

    #[test]
    fn task_put_and_clue_put_are_persisted() {
        let store = bugfound_store::Store::open(":memory:").unwrap();
        let ok = || bugfound_tools::ToolResult {
            ok: true,
            output: "ok".into(),
            structured: None,
        };
        let task_args = serde_json::json!({
            "statement": "check login",
            "playbook_id": "pb-1",
            "target": "example.com",
            "priority": "high",
        });
        bugfound_store::persist_tool_result(&store, "sess", "task_put", &task_args, &ok());
        let tasks = store.list_tasks("sess").unwrap();
        assert_eq!(tasks.len(), 1);
        assert_eq!(tasks[0].statement, "check login");
        assert_eq!(tasks[0].playbook_id, "pb-1");
        assert_eq!(tasks[0].priority, 3);

        let clue_args = serde_json::json!({
            "key": "header",
            "value": "X-Debug: 1",
            "source_tool": "http_request",
            "task_id": tasks[0].id,
        });
        bugfound_store::persist_tool_result(&store, "sess", "clue_put", &clue_args, &ok());
        let clues = store.list_clues("sess").unwrap();
        assert_eq!(clues.len(), 1);
        assert_eq!(clues[0].key, "header");
        assert_eq!(clues[0].source_tool, "http_request");
        assert_eq!(clues[0].task_id.as_deref(), Some(tasks[0].id.as_str()));
    }
}
