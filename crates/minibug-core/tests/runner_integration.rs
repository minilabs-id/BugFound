use anyhow::Result;
use async_trait::async_trait;
use minibug_core::{build_policy, build_policy_config, AgentConfig, Runner};
use minibug_llm::{ChatMessage, ChatResponse, Llm, ToolCall, ToolSpec as LlmToolSpec};
use minibug_policy::Mode;
use minibug_store::Store;
use minibug_tools::{Tool, ToolRegistry, ToolResult, ToolSpec};
use serde_json::{json, Value};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

struct MockLlm {
    responses: Mutex<VecDeque<ChatResponse>>,
    model: String,
}

impl MockLlm {
    fn new(model: &str, responses: Vec<ChatResponse>) -> Self {
        Self {
            responses: Mutex::new(VecDeque::from(responses)),
            model: model.to_string(),
        }
    }
}

#[async_trait]
impl Llm for MockLlm {
    async fn resolve_model(&self) -> Result<String> {
        Ok(self.model.clone())
    }

    async fn chat(
        &self,
        _model: &str,
        _messages: &[ChatMessage],
        _tools: &[LlmToolSpec],
    ) -> Result<ChatResponse> {
        let mut q = self.responses.lock().unwrap();
        Ok(q.pop_front().unwrap_or(ChatResponse {
            content: Some("(no scripted response)".into()),
            tool_calls: vec![],
            model: self.model.clone(),
        }))
    }
}

struct MockExecTool;

#[async_trait]
impl Tool for MockExecTool {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "mock_exec".into(),
            description: "Deterministic mock exec tool".into(),
            input_schema: json!({"type":"object","properties":{"cmd":{"type":"string"}},"required":["cmd"]}),
            risk: "exec".into(),
        }
    }

    async fn run(&self, args: Value) -> Result<ToolResult> {
        let cmd = args.get("cmd").and_then(|v| v.as_str()).unwrap_or("");
        Ok(ToolResult {
            ok: true,
            output: format!("ran:{cmd}"),
            structured: None,
        })
    }
}

fn base_tools_with_mock_exec() -> ToolRegistry {
    let mut r = ToolRegistry::new();
    r.register(Arc::new(MockExecTool));
    r
}

#[tokio::test]
async fn completes_with_tool_call_and_final_answer() {
    let store = Store::open(":memory:").unwrap();
    let llm = Arc::new(MockLlm::new(
        "mock-model",
        vec![
            ChatResponse {
                content: None,
                tool_calls: vec![ToolCall {
                    id: "c1".into(),
                    name: "echo".into(),
                    arguments: json!({"text":"hello"}),
                }],
                model: "mock-model".into(),
            },
            ChatResponse {
                content: Some("done: hello".into()),
                tool_calls: vec![],
                model: "mock-model".into(),
            },
        ],
    ));
    let mut tools = ToolRegistry::new();
    tools.register(Arc::new(minibug_tools::EchoTool));

    let runner = Runner::new(
        store.clone(),
        llm,
        tools,
        build_policy(Mode::Ask),
        AgentConfig {
            mode: Mode::Ask,
            max_steps: 5,
            ..Default::default()
        },
    );

    let out = runner.run_goal("say hello via tool").await.unwrap();
    assert_eq!(out, "done: hello");

    let sessions = store.list_sessions(10).unwrap();
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].state, "completed");
    let msgs = store.list_messages(&sessions[0].id).unwrap();
    assert!(msgs
        .iter()
        .any(|m| m.role == "tool" && m.content.contains("ok=true") && m.content.contains("hello")));
    assert!(msgs
        .iter()
        .any(|m| m.role == "assistant" && m.content == "done: hello"));
}

#[tokio::test]
async fn ask_mode_pauses_for_approval_and_resumes_on_approve() {
    let store = Store::open(":memory:").unwrap();
    let llm = Arc::new(MockLlm::new(
        "mock-model",
        vec![
            ChatResponse {
                content: None,
                tool_calls: vec![ToolCall {
                    id: "c1".into(),
                    name: "mock_exec".into(),
                    arguments: json!({"cmd":"echo hi"}),
                }],
                model: "mock-model".into(),
            },
            ChatResponse {
                content: Some("finished after approval".into()),
                tool_calls: vec![],
                model: "mock-model".into(),
            },
        ],
    ));

    let runner = Runner::new(
        store.clone(),
        llm,
        base_tools_with_mock_exec(),
        build_policy(Mode::Ask),
        AgentConfig {
            mode: Mode::Ask,
            max_steps: 5,
            ..Default::default()
        },
    );

    let out = runner.run_goal("run a command").await.unwrap();
    assert!(out.contains("waiting approval"));
    let session = store.list_sessions(10).unwrap().remove(0);
    assert_eq!(session.state, "waiting_approval");
    let pending = store.get_pending_approval(&session.id).unwrap().unwrap();
    assert_eq!(pending.tool_name, "mock_exec");

    let resumed = runner.resume_session(&session.id, "approve").await.unwrap();
    assert_eq!(resumed, "finished after approval");
    let session2 = store.get_session(&session.id).unwrap().unwrap();
    assert_eq!(session2.state, "completed");
    let msgs = store.list_messages(&session.id).unwrap();
    assert!(msgs.iter().any(|m| m.role == "tool"
        && m.content.contains("ok=true")
        && m.content.contains("ran:echo hi")));
    let events = store.list_events(&session.id, 100).unwrap();
    assert!(events.iter().any(|e| e.kind == "approval.required"));
    assert!(events
        .iter()
        .any(|e| e.kind == "approval.resolved" && e.message.contains("approved")));
    assert!(events.iter().any(|e| e.kind == "session.completed"));
}

#[tokio::test]
async fn ask_mode_deny_continues_without_executing() {
    let store = Store::open(":memory:").unwrap();
    let llm = Arc::new(MockLlm::new(
        "mock-model",
        vec![
            ChatResponse {
                content: None,
                tool_calls: vec![ToolCall {
                    id: "c1".into(),
                    name: "mock_exec".into(),
                    arguments: json!({"cmd":"danger"}),
                }],
                model: "mock-model".into(),
            },
            ChatResponse {
                content: Some("ok, I will not run it".into()),
                tool_calls: vec![],
                model: "mock-model".into(),
            },
        ],
    ));

    let runner = Runner::new(
        store.clone(),
        llm,
        base_tools_with_mock_exec(),
        build_policy(Mode::Ask),
        AgentConfig {
            mode: Mode::Ask,
            max_steps: 5,
            ..Default::default()
        },
    );

    let out = runner.run_goal("run a command").await.unwrap();
    assert!(out.contains("waiting approval"));
    let session = store.list_sessions(10).unwrap().remove(0);
    let resumed = runner.resume_session(&session.id, "deny").await.unwrap();
    assert_eq!(resumed, "ok, I will not run it");
    let session2 = store.get_session(&session.id).unwrap().unwrap();
    assert_eq!(session2.state, "completed");
    let msgs = store.list_messages(&session.id).unwrap();
    assert!(msgs.iter().any(|m| m.role == "tool"
        && m.content.contains("DENIED")
        && m.content.contains("user denied approval")));
    assert!(!msgs.iter().any(|m| m.content.contains("ran:danger")));
    let events = store.list_events(&session.id, 100).unwrap();
    assert!(events
        .iter()
        .any(|e| e.kind == "approval.resolved" && e.message.contains("denied")));
    assert!(events.iter().any(|e| e.kind == "session.completed"));
}

#[tokio::test]
async fn stale_running_session_is_marked_interrupted() {
    let store = Store::open(":memory:").unwrap();
    let session = store.create_session("interrupted goal").unwrap();
    store.set_session_state(&session.id, "running").unwrap();
    store.set_session_model(&session.id, "mock-model").unwrap();

    let llm = Arc::new(MockLlm::new("mock-model", vec![]));
    let runner = Runner::new(
        store.clone(),
        llm,
        ToolRegistry::new(),
        build_policy(Mode::Ask),
        AgentConfig {
            mode: Mode::Ask,
            max_steps: 5,
            ..Default::default()
        },
    );

    let err = runner
        .resume_session(&session.id, "approve")
        .await
        .unwrap_err();
    assert!(err.to_string().contains("interrupted"));
    let s = store.get_session(&session.id).unwrap().unwrap();
    assert_eq!(s.state, "interrupted");
    // no active owner/lease after recovery
    assert!(s.owner_id.is_none());
    assert!(s.lease_expires_at.is_none());
    let events = store.list_events(&session.id, 50).unwrap();
    assert!(events.iter().any(|e| e.kind == "session.recovered_stale"));
}

#[tokio::test]
async fn cannot_resume_completed_session() {
    let store = Store::open(":memory:").unwrap();
    let session = store.create_session("done").unwrap();
    store.set_session_state(&session.id, "completed").unwrap();
    store.set_session_model(&session.id, "mock-model").unwrap();

    let runner = Runner::new(
        store.clone(),
        Arc::new(MockLlm::new("mock-model", vec![])),
        ToolRegistry::new(),
        build_policy(Mode::Ask),
        AgentConfig::default(),
    );
    let err = runner
        .resume_session(&session.id, "approve")
        .await
        .unwrap_err();
    assert!(err.to_string().contains("already completed"));
}

#[tokio::test]
async fn llm_error_fails_session_and_logs_event() {
    struct FailingLlm;
    #[async_trait]
    impl Llm for FailingLlm {
        async fn resolve_model(&self) -> Result<String> {
            Ok("mock-model".into())
        }
        async fn chat(
            &self,
            _model: &str,
            _messages: &[ChatMessage],
            _tools: &[LlmToolSpec],
        ) -> Result<ChatResponse> {
            Err(anyhow::anyhow!("simulated llm outage"))
        }
    }

    let store = Store::open(":memory:").unwrap();
    let runner = Runner::new(
        store.clone(),
        Arc::new(FailingLlm),
        ToolRegistry::new(),
        build_policy(Mode::Ask),
        AgentConfig {
            mode: Mode::Ask,
            max_steps: 5,
            ..Default::default()
        },
    );

    let err = runner.run_goal("boom").await.unwrap_err();
    assert!(err.to_string().contains("simulated llm outage"));
    let session = store.list_sessions(10).unwrap().remove(0);
    assert_eq!(session.state, "failed");
    let events = store.list_events(&session.id, 50).unwrap();
    assert!(events.iter().any(|e| e.kind == "llm.chat_failed"));
    assert!(events.iter().any(|e| e.kind == "session.failed"));
}

#[tokio::test]
async fn full_auto_executes_risky_tool_without_pause() {
    let store = Store::open(":memory:").unwrap();
    let llm = Arc::new(MockLlm::new(
        "mock-model",
        vec![
            ChatResponse {
                content: None,
                tool_calls: vec![ToolCall {
                    id: "c1".into(),
                    name: "mock_exec".into(),
                    arguments: json!({"cmd":"auto"}),
                }],
                model: "mock-model".into(),
            },
            ChatResponse {
                content: Some("auto done".into()),
                tool_calls: vec![],
                model: "mock-model".into(),
            },
        ],
    ));

    let runner = Runner::new(
        store.clone(),
        llm,
        base_tools_with_mock_exec(),
        build_policy(Mode::FullAuto),
        AgentConfig {
            mode: Mode::FullAuto,
            max_steps: 5,
            ..Default::default()
        },
    );

    let out = runner.run_goal("run auto").await.unwrap();
    assert_eq!(out, "auto done");
    let session = store.list_sessions(10).unwrap().remove(0);
    assert_eq!(session.state, "completed");
    let msgs = store.list_messages(&session.id).unwrap();
    assert!(msgs.iter().any(|m| m.content.contains("ran:auto")));
}

#[tokio::test]
async fn max_steps_fails_session() {
    let store = Store::open(":memory:").unwrap();
    // always returns a tool call -> never reaches final
    let responses = (0..5)
        .map(|i| ChatResponse {
            content: None,
            tool_calls: vec![ToolCall {
                id: format!("c{i}"),
                name: "echo".into(),
                arguments: json!({"text": format!("s{i}")}),
            }],
            model: "mock-model".into(),
        })
        .collect::<Vec<_>>();
    let llm = Arc::new(MockLlm::new("mock-model", responses));
    let mut tools = ToolRegistry::new();
    tools.register(Arc::new(minibug_tools::EchoTool));

    let runner = Runner::new(
        store.clone(),
        llm,
        tools,
        build_policy(Mode::FullAuto),
        AgentConfig {
            mode: Mode::FullAuto,
            max_steps: 3,
            ..Default::default()
        },
    );

    let err = runner.run_goal("loop forever").await.unwrap_err();
    assert!(err.to_string().contains("max steps"));
    let session = store.list_sessions(10).unwrap().remove(0);
    assert_eq!(session.state, "failed");
}

#[tokio::test]
async fn bounty_tool_results_are_persisted() {
    let store = Store::open(":memory:").unwrap();
    let llm = Arc::new(MockLlm::new(
        "mock-model",
        vec![
            ChatResponse {
                content: None,
                tool_calls: vec![
                    ToolCall {
                        id: "f1".into(),
                        name: "save_finding".into(),
                        arguments: json!({
                            "title": "SQLi in login",
                            "severity": "high",
                            "asset": "https://example.com/login",
                            "description": "Union-based injection",
                            "evidence": "token=supersecret"
                        }),
                    },
                    ToolCall {
                        id: "a1".into(),
                        name: "record_asset".into(),
                        arguments: json!({"kind": "url", "value": "https://example.com/login"}),
                    },
                    ToolCall {
                        id: "t1".into(),
                        name: "save_artifact".into(),
                        arguments: json!({"kind": "evidence", "content": "response body"}),
                    },
                ],
                model: "mock-model".into(),
            },
            ChatResponse {
                content: Some("report drafted".into()),
                tool_calls: vec![],
                model: "mock-model".into(),
            },
        ],
    ));
    let mut tools = ToolRegistry::new();
    tools.register(Arc::new(minibug_tools::SaveFindingTool));
    tools.register(Arc::new(minibug_tools::RecordAssetTool));
    tools.register(Arc::new(minibug_tools::SaveArtifactTool::new(".").unwrap()));

    let runner = Runner::new(
        store.clone(),
        llm,
        tools,
        build_policy(Mode::FullAuto),
        AgentConfig {
            mode: Mode::FullAuto,
            max_steps: 5,
            ..Default::default()
        },
    );
    assert_eq!(
        runner.run_goal("draft report").await.unwrap(),
        "report drafted"
    );

    let session = store.list_sessions(10).unwrap().remove(0);
    let findings = store.list_findings(&session.id).unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].title, "SQLi in login");
    assert_eq!(findings[0].severity, "high");
    let assets = store.list_assets(&session.id).unwrap();
    assert_eq!(assets.len(), 1);
    assert_eq!(assets[0].value, "https://example.com/login");
    let artifacts = store.list_artifacts(&session.id).unwrap();
    assert_eq!(artifacts.len(), 1);

    let report = store.export_report(&session.id).unwrap();
    assert!(report.contains("SQLi in login"));
    assert!(!report.contains("supersecret"));
}

#[tokio::test]
async fn tool_call_budget_blocks_excess_calls() {
    let store = Store::open(":memory:").unwrap();
    let responses = (0..2)
        .map(|i| ChatResponse {
            content: None,
            tool_calls: vec![ToolCall {
                id: format!("c{i}"),
                name: "echo".into(),
                arguments: json!({"text": format!("s{i}")}),
            }],
            model: "mock-model".into(),
        })
        .chain(std::iter::once(ChatResponse {
            content: Some("done within budget".into()),
            tool_calls: vec![],
            model: "mock-model".into(),
        }))
        .collect();
    let llm = Arc::new(MockLlm::new("mock-model", responses));
    let mut tools = ToolRegistry::new();
    tools.register(Arc::new(minibug_tools::EchoTool));

    let runner = Runner::new(
        store.clone(),
        llm,
        tools,
        build_policy(Mode::FullAuto),
        AgentConfig {
            mode: Mode::FullAuto,
            max_steps: 5,
            max_tool_calls: 1,
            ..Default::default()
        },
    );
    assert_eq!(
        runner.run_goal("budget check").await.unwrap(),
        "done within budget"
    );
    let session = store.list_sessions(10).unwrap().remove(0);
    let msgs = store.list_messages(&session.id).unwrap();
    assert!(msgs
        .iter()
        .any(|m| m.content.contains("ok=true") && m.content.contains("s0")));
    assert!(!msgs
        .iter()
        .any(|m| m.content.contains("ok=true") && m.content.contains("s1")));
    assert!(msgs.iter().any(|m| m.content.contains("BUDGET_EXCEEDED")));
    let events = store.list_events(&session.id, 100).unwrap();
    assert!(events.iter().any(|e| e.kind == "budget.exceeded"));
}

#[tokio::test]
async fn network_call_budget_blocks_excess_calls() {
    struct MockNetTool;
    #[async_trait]
    impl Tool for MockNetTool {
        fn spec(&self) -> ToolSpec {
            ToolSpec {
                name: "mock_net".into(),
                description: "mock network tool".into(),
                input_schema: json!({"type":"object"}),
                risk: "network".into(),
            }
        }
        async fn run(&self, _args: Value) -> Result<ToolResult> {
            Ok(ToolResult {
                ok: true,
                output: "probed".into(),
                structured: None,
            })
        }
    }

    let store = Store::open(":memory:").unwrap();
    let responses = (0..2)
        .map(|i| ChatResponse {
            content: None,
            tool_calls: vec![ToolCall {
                id: format!("n{i}"),
                name: "mock_net".into(),
                arguments: json!({"target": "example.com"}),
            }],
            model: "mock-model".into(),
        })
        .chain(std::iter::once(ChatResponse {
            content: Some("network done".into()),
            tool_calls: vec![],
            model: "mock-model".into(),
        }))
        .collect();
    let mut tools = ToolRegistry::new();
    tools.register(Arc::new(MockNetTool));

    let runner = Runner::new(
        store.clone(),
        Arc::new(MockLlm::new("mock-model", responses)),
        tools,
        build_policy(Mode::FullAuto),
        AgentConfig {
            mode: Mode::FullAuto,
            max_steps: 5,
            max_network_calls: 1,
            ..Default::default()
        },
    );
    assert_eq!(
        runner.run_goal("network budget").await.unwrap(),
        "network done"
    );
    let session = store.list_sessions(10).unwrap().remove(0);
    let msgs = store.list_messages(&session.id).unwrap();
    assert_eq!(
        msgs.iter().filter(|m| m.content.contains("probed")).count(),
        1
    );
    assert!(msgs
        .iter()
        .any(|m| m.content.contains("max_network_calls=1")));
}

#[tokio::test]
async fn budget_survives_resume_with_a_new_runner() {
    let store = Store::open(":memory:").unwrap();
    let responses = vec![
        ChatResponse {
            content: None,
            tool_calls: vec![ToolCall {
                id: "safe".into(),
                name: "echo".into(),
                arguments: json!({"text": "first"}),
            }],
            model: "mock-model".into(),
        },
        ChatResponse {
            content: None,
            tool_calls: vec![ToolCall {
                id: "risky".into(),
                name: "mock_exec".into(),
                arguments: json!({"cmd": "echo hi"}),
            }],
            model: "mock-model".into(),
        },
        ChatResponse {
            content: Some("finished".into()),
            tool_calls: vec![],
            model: "mock-model".into(),
        },
    ];
    let mut tools = ToolRegistry::new();
    tools.register(Arc::new(minibug_tools::EchoTool));
    tools.register(Arc::new(MockExecTool));

    let runner = Runner::new(
        store.clone(),
        Arc::new(MockLlm::new("mock-model", responses)),
        tools.clone(),
        build_policy(Mode::Ask),
        AgentConfig {
            mode: Mode::Ask,
            max_steps: 5,
            max_tool_calls: 1,
            ..Default::default()
        },
    );
    runner.run_goal("budget across resume").await.unwrap();
    let session = store.list_sessions(10).unwrap().remove(0);
    assert_eq!(session.state, "waiting_approval");

    // Simulate the CLI: a brand-new Runner must see the durable counter.
    let fresh = Runner::new(
        store.clone(),
        Arc::new(MockLlm::new(
            "mock-model",
            vec![ChatResponse {
                content: Some("finished".into()),
                tool_calls: vec![],
                model: "mock-model".into(),
            }],
        )),
        tools,
        build_policy(Mode::Ask),
        AgentConfig {
            mode: Mode::Ask,
            max_steps: 5,
            max_tool_calls: 1,
            ..Default::default()
        },
    );
    assert_eq!(
        fresh.resume_session(&session.id, "approve").await.unwrap(),
        "finished"
    );
    let msgs = store.list_messages(&session.id).unwrap();
    assert!(msgs.iter().any(|m| m.content.contains("BUDGET_EXCEEDED")));
    assert!(!msgs.iter().any(|m| m.content.contains("ran:echo hi")));
}

#[tokio::test]
async fn deferred_tool_calls_execute_after_approval() {
    let store = Store::open(":memory:").unwrap();
    let responses = vec![
        ChatResponse {
            content: None,
            tool_calls: vec![
                ToolCall {
                    id: "ask1".into(),
                    name: "mock_exec".into(),
                    arguments: json!({"cmd": "echo risky"}),
                },
                ToolCall {
                    id: "tail1".into(),
                    name: "echo".into(),
                    arguments: json!({"text": "tail-output"}),
                },
            ],
            model: "mock-model".into(),
        },
        ChatResponse {
            content: Some("all done".into()),
            tool_calls: vec![],
            model: "mock-model".into(),
        },
    ];
    let mut tools = ToolRegistry::new();
    tools.register(Arc::new(MockExecTool));
    tools.register(Arc::new(minibug_tools::EchoTool));
    let runner = Runner::new(
        store.clone(),
        Arc::new(MockLlm::new("mock-model", responses)),
        tools,
        build_policy(Mode::Ask),
        AgentConfig {
            mode: Mode::Ask,
            max_steps: 5,
            ..Default::default()
        },
    );
    runner.run_goal("batch").await.unwrap();
    let session = store.list_sessions(10).unwrap().remove(0);
    assert_eq!(session.state, "waiting_approval");
    assert_eq!(
        runner.resume_session(&session.id, "approve").await.unwrap(),
        "all done"
    );
    let msgs = store.list_messages(&session.id).unwrap();
    assert!(msgs.iter().any(|m| m.content.contains("ran:echo risky")));
    assert!(msgs.iter().any(|m| m.content.contains("tail-output")));
    assert!(msgs
        .iter()
        .any(|m| m.content.contains("<untrusted_tool_output>")));
}

#[tokio::test]
async fn policy_deny_after_parking_blocks_approved_execution() {
    let store = Store::open(":memory:").unwrap();
    let responses = vec![
        ChatResponse {
            content: None,
            tool_calls: vec![ToolCall {
                id: "c1".into(),
                name: "mock_exec".into(),
                arguments: json!({"cmd": "echo hi"}),
            }],
            model: "mock-model".into(),
        },
        ChatResponse {
            content: Some("done".into()),
            tool_calls: vec![],
            model: "mock-model".into(),
        },
    ];
    let mut runner = Runner::new(
        store.clone(),
        Arc::new(MockLlm::new("mock-model", responses)),
        base_tools_with_mock_exec(),
        build_policy(Mode::Ask),
        AgentConfig {
            mode: Mode::Ask,
            max_steps: 5,
            ..Default::default()
        },
    );
    runner.run_goal("scope changed").await.unwrap();
    let session = store.list_sessions(10).unwrap().remove(0);
    runner.policy = build_policy_config(minibug_policy::PolicyConfig {
        mode: Mode::Ask,
        denied_tools: vec!["mock_exec".into()],
        ..Default::default()
    });
    assert_eq!(
        runner.resume_session(&session.id, "approve").await.unwrap(),
        "done"
    );
    let msgs = store.list_messages(&session.id).unwrap();
    assert!(msgs.iter().any(|m| m.content.contains("policy changed")));
    assert!(!msgs.iter().any(|m| m.content.contains("ran:echo hi")));
}
