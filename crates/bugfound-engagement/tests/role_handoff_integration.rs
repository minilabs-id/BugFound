use anyhow::Result;
use async_trait::async_trait;
use bugfound_core::{build_policy_config, AgentConfig, Runner};
use bugfound_engagement::{BountyDomain, HandoffTool, RoleId};
use bugfound_llm::{ChatMessage, ChatResponse, Llm, ToolCall, ToolSpec};
use bugfound_policy::{Mode, PolicyConfig};
use bugfound_store::Store;
use bugfound_tools::ToolRegistry;
use serde_json::{json, Value};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

struct ScriptedLlm {
    model: String,
    responses: Mutex<VecDeque<ChatResponse>>,
}

#[async_trait]
impl Llm for ScriptedLlm {
    async fn resolve_model(&self) -> Result<String> {
        Ok(self.model.clone())
    }

    async fn chat(
        &self,
        _model: &str,
        _messages: &[ChatMessage],
        _tools: &[ToolSpec],
    ) -> Result<ChatResponse> {
        self.responses
            .lock()
            .unwrap()
            .pop_front()
            .ok_or_else(|| anyhow::anyhow!("script exhausted"))
    }
}

fn tool_call(id: &str, name: &str, arguments: Value) -> ToolCall {
    ToolCall {
        id: id.to_string(),
        name: name.to_string(),
        arguments,
    }
}

#[tokio::test]
async fn one_goal_is_delegated_to_two_distinct_roles() {
    let store = Store::open(":memory:").unwrap();
    let engagement_id = "eng-handoff-test";
    let marker = format!("engagement_id={engagement_id}");
    let scope_key = format!("engagement={engagement_id}");

    let responses = vec![
        // root: delegate recon
        ChatResponse {
            content: None,
            tool_calls: vec![tool_call(
                "h1",
                "role_handoff",
                json!({"role": "recon", "goal": "map assets"}),
            )],
            model: "m".to_string(),
        },
        // child recon: one recorded tool call, then finish
        ChatResponse {
            content: None,
            tool_calls: vec![tool_call("e1", "echo", json!({"text": "recon evidence"}))],
            model: "m".to_string(),
        },
        ChatResponse {
            content: None,
            tool_calls: vec![tool_call(
                "f1",
                "session_finish",
                json!({"reason": "recon complete"}),
            )],
            model: "m".to_string(),
        },
        // root: delegate verification
        ChatResponse {
            content: None,
            tool_calls: vec![tool_call(
                "h2",
                "role_handoff",
                json!({"role": "verification", "goal": "disprove candidate"}),
            )],
            model: "m".to_string(),
        },
        ChatResponse {
            content: None,
            tool_calls: vec![tool_call("e2", "echo", json!({"text": "counterevidence"}))],
            model: "m".to_string(),
        },
        ChatResponse {
            content: None,
            tool_calls: vec![tool_call(
                "f2",
                "session_finish",
                json!({"reason": "verification complete"}),
            )],
            model: "m".to_string(),
        },
        ChatResponse {
            content: Some("done".to_string()),
            tool_calls: vec![],
            model: "m".to_string(),
        },
    ];
    let llm: Arc<dyn Llm + Send + Sync> = Arc::new(ScriptedLlm {
        model: "m".to_string(),
        responses: Mutex::new(VecDeque::from(responses)),
    });

    let mut base = ToolRegistry::new();
    base.register_with_host_risk(Arc::new(bugfound_tools::EchoTool), "safe");
    base.register_with_host_risk(Arc::new(bugfound_tools::SessionFinishTool), "safe");
    let policy_config = PolicyConfig {
        mode: Mode::FullAuto,
        ..Default::default()
    };
    let mut root_tools = base.clone();
    root_tools.register_with_host_risk(
        Arc::new(HandoffTool {
            store: store.clone(),
            llm: llm.clone(),
            base_tools: base,
            policy_config,
            agent: AgentConfig::default(),
            scope_summary: None,
            engagement_marker: marker.clone(),
            memory_scope_key: scope_key.clone(),
        }),
        "network",
    );
    root_tools.register_with_host_risk(
        Arc::new(bugfound_engagement::MemoryRecallTool {
            store: store.clone(),
            engagement_marker: marker.clone(),
            memory_scope_key: scope_key.clone(),
        }),
        "read",
    );

    let runner = Runner::new(
        store.clone(),
        llm,
        root_tools,
        build_policy_config(PolicyConfig {
            mode: Mode::FullAuto,
            ..Default::default()
        }),
        AgentConfig {
            mode: Mode::FullAuto,
            max_steps: 12,
            ..Default::default()
        },
    )
    .with_domain(Arc::new(BountyDomain {
        scope_summary: None,
        role: RoleId::General,
        scope_key,
        parent_session_id: None,
        task_id: None,
    }));

    runner
        .run_goal(&format!("{marker}\nroot goal"))
        .await
        .unwrap();

    let sessions: Vec<_> = store
        .list_sessions(500)
        .unwrap()
        .into_iter()
        .filter(|session| session.goal.contains(&marker))
        .collect();
    assert_eq!(sessions.len(), 3, "root plus two child sessions");

    let mut roles = Vec::new();
    for session in &sessions {
        if let Some((role, status, _payload)) = store.get_session_result(&session.id).unwrap() {
            assert_eq!(status, "ok");
            roles.push(role);
            let memory = store
                .list_memory(
                    &session.id,
                    &format!("engagement={engagement_id}"),
                    "episodic",
                    None,
                    8,
                )
                .unwrap();
            assert!(!memory.is_empty(), "child should record episodic memory");
            assert!(memory.iter().any(|item| item.source_event_hash.is_some()));
            assert!(store.verify_memory_hashes(&session.id).unwrap());
            assert!(store.verify_event_chain(&session.id).unwrap());
        }
    }
    roles.sort();
    assert_eq!(roles, vec!["recon".to_string(), "verification".to_string()]);
}
