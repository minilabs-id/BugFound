use crate::config::{resolve_api_key, AppConfig};
use anyhow::{Context, Result};
use minibug_core::{AgentConfig, Runner};
use minibug_llm::LlmConfig;
use minibug_policy::{BudgetConfig, Mode, PolicyConfig};
use minibug_store::Store;
use minibug_tools::{try_default_registry_with_options, ToolOptions};
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
    let client = minibug_llm::LlmClient::new(llm_config)?;

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

    let policy = minibug_core::build_policy_config(PolicyConfig {
        mode,
        scope: config.scope.clone(),
        ..Default::default()
    });

    let budget = BudgetConfig {
        max_tool_calls: config.agent.max_tool_calls,
        max_network_calls: config.agent.max_network_calls,
        requests_per_minute: config.agent.requests_per_minute,
        max_steps: config.agent.max_steps,
        max_tokens: config.agent.max_estimated_tokens,
    };
    let agent = AgentConfig {
        mode,
        max_steps: config.agent.max_steps,
        system_prompt: config.agent.system_prompt.clone(),
        budgets: budget.clone(),
        budget: budget.clone(),
        rate_limits: budget.clone(),
        rate_limit: budget,
        max_tool_calls: config.agent.max_tool_calls,
        max_network_calls: config.agent.max_network_calls,
        requests_per_minute: config.agent.requests_per_minute,
        auto_approve_tools: config.agent.auto_approve_tools.clone(),
        max_estimated_tokens: config.agent.max_estimated_tokens,
        cost_per_1k_input: config.llm.cost_per_1k_input,
        cost_per_1k_output: config.llm.cost_per_1k_output,
        ..Default::default()
    };

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
