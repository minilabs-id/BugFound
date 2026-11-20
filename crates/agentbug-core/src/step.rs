//! Helpers for building one agent step. These are additive; `Runner` keeps its
//! own inline implementation so existing behaviour is unchanged.

use agentbug_llm::ChatMessage;
use agentbug_store::Store;
use agentbug_tools::ToolRegistry;
use anyhow::Result;

/// Outcome of a single logical step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StepResult {
    Continue,
    Final { text: String },
    NeedApproval { id: String },
    Failed { err: String },
}

impl StepResult {
    pub fn is_continue(&self) -> bool {
        matches!(self, Self::Continue)
    }

    pub fn is_final(&self) -> bool {
        matches!(self, Self::Final { .. })
    }

    pub fn final_text(&self) -> Option<&str> {
        match self {
            Self::Final { text } => Some(text),
            _ => None,
        }
    }
}

/// Reload the durable history for a session as chat messages.
pub fn reload_history(store: &Store, session_id: &str) -> Result<Vec<ChatMessage>> {
    let history = store.list_messages(session_id)?;
    Ok(history
        .into_iter()
        .map(|message| ChatMessage {
            role: message.role,
            content: message.content,
            tool_call_id: message.tool_call_id,
            name: message.name,
            tool_calls: message
                .tool_calls_json
                .as_deref()
                .and_then(|raw| serde_json::from_str(raw).ok()),
        })
        .collect())
}

/// Tool specs are now one canonical type shared by registries and providers.
pub fn build_tool_specs(registry: &ToolRegistry) -> Vec<agentbug_tools::ToolSpec> {
    registry.specs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn step_result_helpers() {
        assert!(StepResult::Continue.is_continue());
        let final_step = StepResult::Final {
            text: "done".into(),
        };
        assert!(final_step.is_final());
        assert_eq!(final_step.final_text(), Some("done"));
        assert!(!StepResult::NeedApproval { id: "a".into() }.is_final());
    }

    #[test]
    fn reload_history_and_build_tool_specs() {
        let store = Store::open(":memory:").unwrap();
        let session = store.create_session("goal").unwrap();
        store
            .add_message_full(
                &session.id,
                "assistant",
                "calling",
                None,
                Some(r#"[{"id":"c1","name":"echo","arguments":{"text":"hi"}}]"#),
                None,
            )
            .unwrap();
        let history = reload_history(&store, &session.id).unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].tool_calls.as_ref().unwrap()[0].id, "c1");

        let mut registry = ToolRegistry::new();
        registry.register(Arc::new(agentbug_tools::EchoTool));
        let specs = build_tool_specs(&registry);
        assert_eq!(specs.len(), 1);
        assert_eq!(specs[0].name, "echo");
    }
}
