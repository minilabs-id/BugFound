//! Bounded parallel subagent jobs built from std threads and mpsc only.

use anyhow::{anyhow, Result};
use minibug_tools::ToolRegistry;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};

#[derive(Debug, Clone)]
pub struct SubagentResult {
    pub name: String,
    pub output: String,
    pub ok: bool,
}

#[derive(Default)]
struct Gate {
    active: usize,
    cancelled: bool,
}

struct Shared {
    gate: Mutex<Gate>,
    cv: Condvar,
    records: Mutex<Vec<(usize, SubagentResult)>>,
    joins: Mutex<Vec<JoinHandle<()>>>,
}

/// Runs submitted jobs with at most `max_parallel` executing at once.
#[derive(Clone)]
pub struct SubagentJobs {
    max_parallel: usize,
    cancelled: Arc<AtomicBool>,
    submitted: Arc<AtomicUsize>,
    completed: Arc<AtomicUsize>,
    shared: Arc<Shared>,
}

impl Default for SubagentJobs {
    fn default() -> Self {
        Self::new(4)
    }
}

impl SubagentJobs {
    pub fn new(max_parallel: usize) -> Self {
        Self {
            max_parallel: max_parallel.max(1),
            cancelled: Arc::new(AtomicBool::new(false)),
            submitted: Arc::new(AtomicUsize::new(0)),
            completed: Arc::new(AtomicUsize::new(0)),
            shared: Arc::new(Shared {
                gate: Mutex::new(Gate::default()),
                cv: Condvar::new(),
                records: Mutex::new(Vec::new()),
                joins: Mutex::new(Vec::new()),
            }),
        }
    }

    /// Queue a job. Each job sends its structured result to `tx` and also
    /// records it internally so `join_all` can return all results.
    pub fn submit(
        &self,
        name: impl Into<String>,
        goal: impl Into<String>,
        tools: ToolRegistry,
        tx: Sender<SubagentResult>,
    ) -> Result<()> {
        if self.cancelled.load(Ordering::Relaxed) {
            return Err(anyhow!("subagent jobs are cancelled"));
        }
        let index = self.submitted.fetch_add(1, Ordering::Relaxed);
        let name = name.into();
        let goal = goal.into();
        let shared = Arc::clone(&self.shared);
        let cancelled = Arc::clone(&self.cancelled);
        let completed = Arc::clone(&self.completed);
        let max_parallel = self.max_parallel;
        let thread_name = format!("subagent-{name}");

        let handle = thread::Builder::new()
            .name(thread_name)
            .spawn(move || {
                let mut gate = shared.gate.lock().unwrap();
                while gate.active >= max_parallel && !gate.cancelled {
                    gate = shared.cv.wait(gate).unwrap();
                }
                if gate.cancelled {
                    drop(gate);
                    let result = SubagentResult {
                        name,
                        output: "cancelled".into(),
                        ok: false,
                    };
                    shared.records.lock().unwrap().push((index, result.clone()));
                    completed.fetch_add(1, Ordering::Relaxed);
                    let _ = tx.send(result);
                    return;
                }
                gate.active += 1;
                drop(gate);

                let result = run_job(&name, &goal, &tools, &cancelled);
                shared.records.lock().unwrap().push((index, result.clone()));
                completed.fetch_add(1, Ordering::Relaxed);
                let _ = tx.send(result);

                let mut gate = shared.gate.lock().unwrap();
                gate.active -= 1;
                drop(gate);
                shared.cv.notify_all();
            })
            .map_err(|error| anyhow!("spawn subagent job: {error}"))?;

        self.shared.joins.lock().unwrap().push(handle);
        Ok(())
    }

    /// Wait for every submitted job and return results in submission order.
    pub fn join_all(&self) -> Vec<SubagentResult> {
        let handles: Vec<JoinHandle<()>> = std::mem::take(&mut *self.shared.joins.lock().unwrap());
        for handle in handles {
            let _ = handle.join();
        }
        let mut records = std::mem::take(&mut *self.shared.records.lock().unwrap());
        records.sort_by_key(|(index, _)| *index);
        records.into_iter().map(|(_, result)| result).collect()
    }

    /// Cancel queued and running jobs. Running tool calls are checked at their
    /// boundary; results for cancelled jobs report `ok = false`.
    pub fn cancel_all(&self) {
        self.cancelled.store(true, Ordering::Relaxed);
        let mut gate = self.shared.gate.lock().unwrap();
        gate.cancelled = true;
        drop(gate);
        self.shared.cv.notify_all();
    }

    /// Allow a new batch of jobs after a cancellation.
    pub fn reset(&self) {
        self.cancelled.store(false, Ordering::Relaxed);
        let mut gate = self.shared.gate.lock().unwrap();
        gate.cancelled = false;
    }

    /// Number of submitted jobs that have not produced a result yet.
    pub fn pending(&self) -> usize {
        let submitted = self.submitted.load(Ordering::Relaxed);
        let completed = self.completed.load(Ordering::Relaxed);
        submitted.saturating_sub(completed)
    }
}

fn run_job(name: &str, goal: &str, tools: &ToolRegistry, cancelled: &AtomicBool) -> SubagentResult {
    if cancelled.load(Ordering::Relaxed) {
        return SubagentResult {
            name: name.to_string(),
            output: "cancelled".into(),
            ok: false,
        };
    }
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            return SubagentResult {
                name: name.to_string(),
                output: format!("runtime error: {error}"),
                ok: false,
            };
        }
    };

    let (output, ok) = match tools.get("echo") {
        Some(tool) => match runtime.block_on(tool.run(serde_json::json!({"text": goal}))) {
            Ok(result) => (result.output, result.ok),
            Err(error) => (format!("tool error: {error}"), false),
        },
        None => (format!("{name}: {goal}"), true),
    };

    SubagentResult {
        name: name.to_string(),
        output,
        ok,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use std::sync::Arc;

    fn registry() -> ToolRegistry {
        let mut tools = ToolRegistry::new();
        tools.register(Arc::new(minibug_tools::EchoTool));
        tools
    }

    #[test]
    fn jobs_return_structured_results_in_order() {
        let jobs = SubagentJobs::new(2);
        let (tx, rx) = mpsc::channel();
        for i in 0..4 {
            jobs.submit(
                format!("job{i}"),
                format!("goal {i}"),
                registry(),
                tx.clone(),
            )
            .unwrap();
        }
        let results = jobs.join_all();
        assert_eq!(results.len(), 4);
        for (i, result) in results.iter().enumerate() {
            assert_eq!(result.name, format!("job{i}"));
            assert!(result.ok);
            assert!(result.output.contains(&format!("goal {i}")));
        }
        assert_eq!(rx.try_iter().count(), 4);
        assert_eq!(jobs.pending(), 0);
    }

    #[test]
    fn cancel_all_marks_results_failed() {
        let jobs = SubagentJobs::default();
        jobs.cancel_all();
        let (tx, _rx) = mpsc::channel();
        assert!(jobs.submit("late", "goal", registry(), tx).is_err());
        jobs.reset();
        let (tx, _rx) = mpsc::channel();
        jobs.submit("fresh", "goal", ToolRegistry::new(), tx)
            .unwrap();
        let results = jobs.join_all();
        assert_eq!(results.len(), 1);
        assert!(results[0].ok);
    }
}
