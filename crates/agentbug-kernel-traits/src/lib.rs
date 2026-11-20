//! Generic ports through which a domain adapts the universal kernel.
//!
//! These traits contain no bug-bounty vocabulary. Implementations live in the
//! domain layer (`agentbug-engagement`), while [`KernelDomain`] preserves the
//! storage-backed defaults used by plain kernel runners.

use agentbug_store::Store;
use agentbug_tools::ToolResult;
use serde_json::Value;
use sha2::{Digest, Sha256};

/// Domain-separated goal binding. The kernel persists and compares the digest
/// verbatim; only the domain decides which context bytes are bound into it.
pub trait GoalLock: Send + Sync {
    fn digest(&self, goal: &str) -> String;
}

/// Additional system text supplied by the domain. `None` means no extra
/// system message; the kernel's generic base prompt is always present.
pub trait PromptContributor: Send + Sync {
    fn additional_system_prompt(&self) -> Option<String>;
}

/// Sink for successful tool results. The kernel never inspects domain payloads;
/// it forwards the authoritative structured result to the domain adapter.
pub trait ToolResultSink: Send + Sync {
    fn on_tool_result(
        &self,
        store: &Store,
        session_id: &str,
        tool_name: &str,
        args: &Value,
        result: &ToolResult,
    );
}

/// Monotonic domain progress counter consumed by the kernel's stall detector.
pub trait ProgressObserver: Send + Sync {
    fn progress_count(&self, store: &Store, session_id: &str) -> usize;
}

/// Bundle of ports injected into `Runner`.
pub trait Domain: GoalLock + PromptContributor + ToolResultSink + ProgressObserver {}
impl<T: GoalLock + PromptContributor + ToolResultSink + ProgressObserver> Domain for T {}

/// SHA-256 over `goal || 0x00 || context`. Kept as a pure helper so the kernel
/// and domain produce byte-identical digests for the same inputs.
pub fn digest_goal_and_context(goal: &str, context: Option<&str>) -> String {
    let mut hasher = Sha256::new();
    hasher.update(goal.as_bytes());
    hasher.update([0u8]);
    hasher.update(context.unwrap_or("").as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Default adapter: no domain prompt, no extra digest context, and the
/// storage-backed persistence/progress behavior the kernel shipped with.
pub struct KernelDomain;

impl GoalLock for KernelDomain {
    fn digest(&self, goal: &str) -> String {
        digest_goal_and_context(goal, None)
    }
}

impl PromptContributor for KernelDomain {
    fn additional_system_prompt(&self) -> Option<String> {
        None
    }
}

impl ToolResultSink for KernelDomain {
    fn on_tool_result(
        &self,
        store: &Store,
        session_id: &str,
        tool_name: &str,
        args: &Value,
        result: &ToolResult,
    ) {
        agentbug_store::persist_tool_result(store, session_id, tool_name, args, result);
    }
}

impl ProgressObserver for KernelDomain {
    fn progress_count(&self, store: &Store, session_id: &str) -> usize {
        agentbug_store::domain_progress_count(store, session_id)
    }
}
