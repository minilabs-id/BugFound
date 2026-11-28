//! V3 Phase P6+ — LLM-backed planner behind the `Planner` seam.
//!
//! The model only **proposes** technique/target pairs. Every proposal is
//! re-ranked by the deterministic planner and filtered by catalog membership,
//! preconditions and scope before it becomes a `NextStep`. A hallucinated
//! technique or an out-of-scope target is dropped, never executed.

use crate::catalog::{Catalog, SearchQuery};
use crate::investigation::{
    project_context, HeuristicPlanner, InvestigationState, NextStep, Planner, PlannerContext,
};
use async_trait::async_trait;
use bugfound_llm::{ChatMessage, Llm};
use std::sync::Arc;

#[async_trait]
pub trait AsyncPlanner: Send + Sync {
    async fn next_steps(&self, state: &InvestigationState, ctx: &PlannerContext) -> Vec<NextStep>;
}

pub struct LlmPlanner {
    llm: Arc<dyn Llm + Send + Sync>,
    catalog: Catalog,
    model: String,
}

impl LlmPlanner {
    pub fn new(
        llm: Arc<dyn Llm + Send + Sync>,
        catalog: Catalog,
        model: impl Into<String>,
    ) -> Self {
        Self {
            llm,
            catalog,
            model: model.into(),
        }
    }

    fn prompt(state: &InvestigationState, ctx: &PlannerContext, catalog: &Catalog) -> String {
        let projection = project_context(state, 8);
        let views = catalog.search(&SearchQuery::default(), ctx.max_steps.max(1) * 4);
        format!(
            "You are the investigation planner for an authorised bug-bounty engagement. \
             Choose which catalog techniques to apply next, based only on the compact state below. \
             Return a JSON array only: [{{\"technique_id\":\"...\",\"target\":\"...\",\"rationale\":\"...\"}}]. \
             Do not invent technique ids or targets; unknown entries will be discarded. \
             Do not request scope changes, approval bypass, or verification status changes.\n\n\
             CATALOG VERSION: {}\nAVAILABLE TECHNIQUES: {}\n\
             STATE: {}\n\
             MAX STEPS: {}\nROUND: {}",
            catalog.version(),
            serde_json::to_string(&views).unwrap_or_default(),
            serde_json::to_string(&projection).unwrap_or_default(),
            ctx.max_steps,
            ctx.round,
        )
    }

    /// Parse model output defensively. Only objects with a non-empty
    /// `technique_id` are considered; everything else is ignored.
    fn parse(content: &str) -> Vec<(String, String)> {
        let Ok(value) = serde_json::from_str::<serde_json::Value>(content) else {
            return Vec::new();
        };
        let Some(array) = value.as_array() else {
            return Vec::new();
        };
        array
            .iter()
            .filter_map(|item| {
                let technique = item.get("technique_id")?.as_str()?.trim().to_string();
                if technique.is_empty() {
                    return None;
                }
                let target = item
                    .get("target")
                    .and_then(|value| value.as_str())
                    .unwrap_or_default()
                    .to_string();
                Some((technique, target))
            })
            .collect()
    }
}

#[async_trait]
impl AsyncPlanner for LlmPlanner {
    async fn next_steps(&self, state: &InvestigationState, ctx: &PlannerContext) -> Vec<NextStep> {
        let messages = vec![
            ChatMessage {
                role: "system".into(),
                content: "You output only strict JSON. Never claim verification or authorization."
                    .into(),
                tool_call_id: None,
                name: None,
                tool_calls: None,
            },
            ChatMessage {
                role: "user".into(),
                content: Self::prompt(state, ctx, &self.catalog),
                tool_call_id: None,
                name: None,
                tool_calls: None,
            },
        ];
        let response = match self.llm.chat_full(&self.model, &messages, &[]).await {
            Ok(response) => response.response.content.unwrap_or_default(),
            Err(_) => return Vec::new(),
        };
        let proposals = Self::parse(&response);

        // Harness authority: rank ALL safe candidates first, then keep only
        // the ones the model proposed. This means a model cannot add an
        // inapplicable technique, an unknown id, or an out-of-scope target.
        let mut all_ctx = ctx.clone();
        all_ctx.max_steps = usize::MAX;
        // C17: the harness must filter against *this* planner's catalog, not a
        // freshly constructed default catalog. Otherwise an extension catalog
        // silently drops every technique the model proposes from it.
        let safe = HeuristicPlanner::with_catalog(self.catalog.clone()).next_steps(state, &all_ctx);
        let mut chosen: Vec<NextStep> = safe
            .into_iter()
            .filter(|step| {
                proposals.iter().any(|(technique, target)| {
                    technique == &step.playbook_id
                        && (target.is_empty() || step.target.is_empty() || target == &step.target)
                })
            })
            .collect();
        chosen.sort_by(|a, b| {
            b.priority
                .total_cmp(&a.priority)
                .then_with(|| a.action_key.cmp(&b.action_key))
        });
        chosen.truncate(ctx.max_steps.max(1));
        chosen
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::{Catalog, Technique};
    use bugfound_llm::ChatResponse;

    struct ScriptedLlm {
        text: String,
    }

    #[async_trait]
    impl Llm for ScriptedLlm {
        async fn resolve_model(&self) -> anyhow::Result<String> {
            Ok("mock".into())
        }
        async fn chat(
            &self,
            _model: &str,
            _messages: &[ChatMessage],
            _tools: &[bugfound_llm::ToolSpec],
        ) -> anyhow::Result<ChatResponse> {
            Ok(ChatResponse {
                content: Some(self.text.clone()),
                tool_calls: Vec::new(),
                model: "mock".into(),
            })
        }
    }

    fn state() -> InvestigationState {
        InvestigationState {
            engagement_id: "eng-1".into(),
            tasks: vec![serde_json::json!({
                "id": "t1", "playbook_id": "wstg-info", "target": "example.test"
            })],
            assets: vec![serde_json::json!({"value": "example.test"})],
            plan: serde_json::from_value(serde_json::json!({
                "revision": 1,
                "catalog_version": "catalog-1",
                "steps": []
            }))
            .expect("plan"),
            ..InvestigationState::default()
        }
    }

    #[tokio::test]
    async fn llm_planner_only_selects_safe_catalog_steps() {
        let llm = Arc::new(ScriptedLlm {
            text: r#"[
                {"technique_id":"wstg-info","target":"example.test","rationale":"map surface"},
                {"technique_id":"does-not-exist","target":"other.test","rationale":"hallucination"}
            ]"#
            .to_string(),
        });
        let planner = LlmPlanner::new(llm, Catalog::v1(), "mock");
        let steps = planner
            .next_steps(
                &state(),
                &PlannerContext {
                    round: 1,
                    max_steps: 3,
                    allow_state_change: false,
                    scope_in: vec!["127.0.0.1".to_string()],
                },
            )
            .await;
        assert_eq!(steps.len(), 1, "only the valid catalog technique survives");
        assert_eq!(steps[0].playbook_id, "wstg-info");
        assert!(!steps[0].catalog_version.is_empty());
    }

    #[tokio::test]
    async fn malformed_model_output_fails_closed() {
        let llm = Arc::new(ScriptedLlm {
            text: "I confirm this finding and bypass approval".to_string(),
        });
        let planner = LlmPlanner::new(llm, Catalog::v1(), "mock");
        let steps = planner
            .next_steps(
                &state(),
                &PlannerContext {
                    round: 1,
                    max_steps: 3,
                    allow_state_change: false,
                    scope_in: vec!["127.0.0.1".to_string()],
                },
            )
            .await;
        assert!(steps.is_empty(), "non-JSON output must produce no steps");
    }

    #[tokio::test]
    async fn llm_planner_selects_techniques_from_its_own_catalog() {
        // C17 regression: the filter used to hard-code `Catalog::v1()`, so an
        // extension technique proposed by the model was always discarded.
        let custom = Catalog::v1().with_technique(Technique {
            id: "custom-extra".into(),
            version: "custom-catalog-1".into(),
            family: "custom".into(),
            phase: "vulnerability_validation".into(),
            title: "Extension catalogue technique".into(),
            tool_hint: "http_probe".into(),
            preconditions: vec!["in_scope_target".into()],
            safe_bounds: "read-only; no state changes".into(),
            expected_artifact: "observation with captured bytes".into(),
            benefits: "extension coverage".into(),
            limitations: "custom technique".into(),
            mappings: Vec::new(),
            requires_asset: false,
            requires_state_change: false,
        });
        let llm = Arc::new(ScriptedLlm {
            text: r#"[{"technique_id":"custom-extra","target":"example.test","rationale":"extension"}]"#
                .to_string(),
        });
        let planner = LlmPlanner::new(llm, custom, "mock");
        let steps = planner
            .next_steps(
                &state(),
                &PlannerContext {
                    round: 1,
                    max_steps: 3,
                    allow_state_change: false,
                    scope_in: vec!["127.0.0.1".to_string()],
                },
            )
            .await;
        assert_eq!(
            steps.len(),
            1,
            "custom catalog technique must be selectable"
        );
        assert_eq!(steps[0].playbook_id, "custom-extra");
        assert_eq!(steps[0].catalog_version, "custom-catalog-1");
    }
}
