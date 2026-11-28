//! Serializable view models. Nothing in here may contain a secret or an
//! unreviewed tool payload: redaction happens in `projection.rs` before a DTO
//! is built.

use serde::Serialize;

/// Serializable error for Tauri commands. `kind` is typed for future frontend
/// branching; Phase 0 flattens it to `message` in the UI.
#[derive(Debug, Serialize)]
#[serde(tag = "kind", content = "message", rename_all = "camelCase")]
pub enum AppError {
    Config(String),
    Storage(String),
    InvalidInput(String),
    Internal(String),
}

impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Config(m) => write!(f, "config error: {m}"),
            Self::Storage(m) => write!(f, "storage error: {m}"),
            Self::InvalidInput(m) => write!(f, "invalid input: {m}"),
            Self::Internal(m) => write!(f, "internal error: {m}"),
        }
    }
}

impl std::error::Error for AppError {}

impl From<anyhow::Error> for AppError {
    fn from(error: anyhow::Error) -> Self {
        Self::Internal(error.to_string())
    }
}

pub type AppResult<T> = Result<T, AppError>;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppSnapshot {
    pub product: String,
    pub version: String,
    pub status: String,
    /// Non-empty when config or DB startup degraded to a safe fallback.
    pub startup_warnings: Vec<String>,
    pub sessions: Vec<SessionSummary>,
    pub settings: SettingsSnapshot,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionSummary {
    pub id: String,
    pub title: String,
    pub state: String,
    pub model: Option<String>,
    pub created_at: String,
    pub updated_at: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SettingsSnapshot {
    pub mode: String,
    pub workspace: String,
    pub base_url_configured: bool,
    /// `env`, `literal`, or `missing`. Never the value itself.
    pub api_key_source: String,
    pub default_model: Option<String>,
    pub storage_path: String,
    pub budgets: BudgetSnapshot,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BudgetSnapshot {
    pub max_steps: usize,
    pub max_tool_calls: usize,
    pub max_network_calls: usize,
    pub requests_per_minute: u64,
    pub max_tokens: u64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TimelineItem {
    pub id: String,
    pub role: String,
    pub text: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApprovalSummary {
    pub id: String,
    pub session_id: String,
    pub tool: String,
    pub risk: String,
    pub reason: Option<String>,
    pub args_redacted: String,
    pub expires_at: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FindingSummary {
    pub id: String,
    pub title: String,
    pub severity: String,
    pub status: String,
    pub verdict: String,
    pub confidence: String,
    pub catalog_version: String,
    pub tlp_label: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InvestigationView {
    pub engagement_id: String,
    pub revision: u64,
    pub phase: String,
    pub catalog_version: String,
    pub tlp_label: String,
    pub plan_steps: usize,
    pub open_hypotheses: usize,
    pub coverage_rows: usize,
    pub reflections: usize,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditEventView {
    pub kind: String,
    pub actor: String,
    pub step_id: String,
    pub payload_json: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReportView {
    pub path: String,
    pub text: String,
}
