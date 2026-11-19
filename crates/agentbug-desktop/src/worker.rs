use crate::config::{resolve_api_key, AppConfig};
use agentbug_core::{AgentConfig, Runner};
use agentbug_llm::LlmConfig;
use agentbug_policy::{Mode, PolicyConfig};
use agentbug_store::Store;
use agentbug_tools::{try_default_registry_with_options, ToolOptions};
use anyhow::{Context, Result};
use std::sync::mpsc::Sender;
use std::sync::Arc;

pub enum Job {
    Run {
        goal: String,
        cwd: String,
        mode: Mode,
    },
    Approve {
        session: String,
        decision: String,
        cwd: String,
        mode: Mode,
    },
}

pub enum JobEvent {
    Started { label: String },
    Finished { text: String },
    Error { text: String },
}

fn job_label(job: &Job) -> String {
    match job {
        Job::Run { goal, .. } => {
            let preview: String = goal.trim().chars().take(60).collect();
            format!("run: {preview}")
        }
        Job::Approve {
            session, decision, ..
        } => {
            let short: String = session.chars().take(8).collect();
            format!("{decision}: {short}")
        }
    }
}

fn policy_config(config: &AppConfig, mode: Mode) -> PolicyConfig {
    let budgets = config.policy.budgets();
    PolicyConfig {
        mode,
        scope: config.scope.clone(),
        allowed_tools: config.policy.allowed_tools.clone(),
        denied_tools: config.policy.denied_tools.clone(),
        allowed_targets: config.policy.allowed_targets.clone(),
        denied_targets: config.policy.denied_targets.clone(),
        budgets: budgets.clone(),
        rate_limits: budgets,
        ..Default::default()
    }
}

fn agent_config(config: &AppConfig, mode: Mode) -> AgentConfig {
    let budgets = config.effective_budgets();
    AgentConfig {
        mode,
        max_steps: config.agent.max_steps,
        system_prompt: config.agent.system_prompt.clone(),
        budgets: budgets.clone(),
        budget: budgets.clone(),
        rate_limits: budgets.clone(),
        rate_limit: budgets,
        max_tool_calls: config.agent.max_tool_calls,
        max_network_calls: config.agent.max_network_calls,
        requests_per_minute: config.agent.requests_per_minute,
        auto_approve_tools: config.agent.auto_approve_tools.clone(),
        auto_approve_all: config.agent.auto_approve_all,
        max_estimated_tokens: config.agent.max_estimated_tokens,
        cost_per_1k_input: config.llm.cost_per_1k_input,
        cost_per_1k_output: config.llm.cost_per_1k_output,
        ..Default::default()
    }
}

fn build_runner(config: &AppConfig, cwd: &str, mode: Mode) -> Result<Runner> {
    let api_key = resolve_api_key(&config.llm.api_key)?;
    let llm_config = LlmConfig {
        base_url: config.llm.base_url.clone(),
        api_key,
        default_model: config
            .llm
            .default_model
            .clone()
            .filter(|value| !value.trim().is_empty()),
        timeout_ms: config.llm.timeout_ms,
    };
    let client = agentbug_llm::LlmClient::new(llm_config)?;

    std::fs::canonicalize(cwd)
        .with_context(|| format!("invalid or inaccessible workspace cwd '{cwd}'"))?;
    let options = ToolOptions {
        allow_proxy: config.network.allow_proxy,
        proxy_url: config.network.proxy_url.clone(),
        trusted_local_targets: config.network.trusted_local_targets.clone(),
        enable_external_tools: config.external_tools.enabled,
        external_commands: config.external_tools.commands.clone(),
        auto_detect_external: config.external_tools.auto_detect,
        scope_in: config.scope.in_scope.clone(),
        scope_out: config.scope.out_of_scope.clone(),
        ..Default::default()
    };
    let tools = try_default_registry_with_options(cwd, options)?;

    let policy = agentbug_core::build_policy_config(policy_config(config, mode));
    let agent = agent_config(config, mode);

    let store = Store::open(&config.storage.path)?;
    Ok(Runner::new(store, Arc::new(client), tools, policy, agent))
}

pub fn spawn_job(config: AppConfig, job: Job, tx: Sender<JobEvent>) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let label = job_label(&job);
        let runtime = match tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
        {
            Ok(runtime) => runtime,
            Err(e) => {
                let _ = tx.send(JobEvent::Error {
                    text: format!("{e:#}"),
                });
                return;
            }
        };

        let (cwd, mode) = match &job {
            Job::Run { cwd, mode, .. } | Job::Approve { cwd, mode, .. } => (cwd.clone(), *mode),
        };
        let runner = match build_runner(&config, &cwd, mode) {
            Ok(runner) => runner,
            Err(e) => {
                let _ = tx.send(JobEvent::Error {
                    text: format!("{e:#}"),
                });
                return;
            }
        };

        let _ = tx.send(JobEvent::Started { label });
        let outcome = runtime.block_on(async {
            match &job {
                Job::Run { goal, .. } => runner.run_goal(goal).await,
                Job::Approve {
                    session, decision, ..
                } => runner.resume_session(session, decision).await,
            }
        });
        match outcome {
            Ok(text) => {
                let _ = tx.send(JobEvent::Finished { text });
            }
            Err(e) => {
                let _ = tx.send(JobEvent::Error {
                    text: format!("{e:#}"),
                });
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_fields_and_budget_aliases_are_forwarded() {
        let config: AppConfig = toml::from_str(crate::config::POLICY_CONFIG).expect("parse config");
        let policy = policy_config(&config, Mode::FullAuto);
        assert_eq!(policy.allowed_tools, ["http_request", "dns_lookup"]);
        assert_eq!(policy.denied_tools, ["shell"]);
        assert_eq!(policy.allowed_targets, ["example.com"]);
        assert_eq!(policy.denied_targets, ["evil.example.com"]);
        assert_eq!(policy.budgets.max_steps, 11);
        assert_eq!(policy.rate_limits.max_tokens, 55);
        let agent = agent_config(&config, Mode::FullAuto);
        for alias in [
            &agent.budgets,
            &agent.budget,
            &agent.rate_limits,
            &agent.rate_limit,
        ] {
            assert_eq!(alias.max_steps, 11);
            assert_eq!(alias.max_tool_calls, 22);
            assert_eq!(alias.max_network_calls, 33);
            assert_eq!(alias.requests_per_minute, 44);
            assert_eq!(alias.max_tokens, 55);
        }
    }

    #[test]
    fn labels_describe_the_job() {
        let run = Job::Run {
            goal: "probe example.com".into(),
            cwd: ".".into(),
            mode: Mode::Ask,
        };
        assert_eq!(job_label(&run), "run: probe example.com");

        let approve = Job::Approve {
            session: "0123456789abcdef".into(),
            decision: "approve".into(),
            cwd: ".".into(),
            mode: Mode::Ask,
        };
        assert_eq!(job_label(&approve), "approve: 01234567");
    }
}
