//! Business handlers shared by the Tauri shell. These functions have no Tauri
//! attributes so they can be tested and reused by another surface.

use crate::dto::{
    AppResult, AppSnapshot, ApprovalSummary, AuditEventView, FindingSummary, InvestigationView,
    ReportView, SessionSummary, TimelineItem,
};
use crate::projection;
use crate::AppState;
use bugfound_store::redact;

/// Initial handshake: the frontend calls this once on mount and receives a
/// complete, redacted projection of the store and non-secret settings.
pub fn app_ready(state: &AppState) -> AppResult<AppSnapshot> {
    let config = state
        .config
        .lock()
        .map_err(|e| crate::dto::AppError::Config(format!("config lock poisoned: {e}")))?;
    let mut snapshot = projection::app_snapshot(&state.store, &config)
        .map_err(|e| crate::dto::AppError::Storage(e.to_string()))?;
    snapshot.startup_warnings = state.startup_warnings.clone();
    if !snapshot.startup_warnings.is_empty() {
        snapshot.status = "degraded".into();
    }
    Ok(snapshot)
}

fn storage<T>(value: anyhow::Result<T>) -> AppResult<T> {
    value.map_err(|error| crate::dto::AppError::Storage(error.to_string()))
}

/// Session list for the sidebar. Strings are redacted in the projection layer.
pub fn sessions_list(state: &AppState) -> AppResult<Vec<SessionSummary>> {
    let sessions = storage(state.store.list_sessions(200))?;
    Ok(sessions
        .into_iter()
        .map(|session| SessionSummary {
            id: session.id,
            title: redact(&session.goal),
            state: session.state,
            model: session.model.map(|model| redact(&model)),
            created_at: session.created_at,
            updated_at: session.updated_at,
        })
        .collect())
}

pub fn session_history(state: &AppState, session_id: &str) -> AppResult<Vec<TimelineItem>> {
    let messages = storage(state.store.list_messages(session_id))?;
    Ok(messages
        .into_iter()
        .map(|message| TimelineItem {
            id: message.id,
            role: message.role,
            text: redact(&message.content),
        })
        .collect())
}

pub fn approvals_list(state: &AppState, session_id: &str) -> AppResult<Vec<ApprovalSummary>> {
    let approvals = storage(state.store.list_pending_approvals(session_id))?;
    Ok(approvals
        .into_iter()
        .map(|approval| ApprovalSummary {
            id: approval.id,
            session_id: approval.session_id,
            tool: redact(&approval.tool_name),
            risk: redact(&approval.risk),
            reason: approval.reason.map(|reason| redact(&reason)),
            args_redacted: redact(&approval.args_json),
            expires_at: approval.expires_at,
        })
        .collect())
}

/// All pending approvals across recent sessions, for the operator queue.
pub fn pending_approvals(state: &AppState) -> AppResult<Vec<ApprovalSummary>> {
    let mut out = Vec::new();
    for session in storage(state.store.list_sessions(200))? {
        for approval in storage(state.store.list_pending_approvals(&session.id))? {
            out.push(ApprovalSummary {
                id: approval.id,
                session_id: approval.session_id,
                tool: redact(&approval.tool_name),
                risk: redact(&approval.risk),
                reason: approval.reason.map(|reason| redact(&reason)),
                args_redacted: redact(&approval.args_json),
                expires_at: approval.expires_at,
            });
        }
    }
    Ok(out)
}

pub fn findings_list(state: &AppState, session_id: &str) -> AppResult<Vec<FindingSummary>> {
    let findings = storage(state.store.list_findings(session_id))?;
    Ok(findings
        .into_iter()
        .map(|finding| {
            let (verdict, confidence, catalog_version, tlp_label) = state
                .store
                .finding_provenance(&finding.id)
                .ok()
                .flatten()
                .map(|provenance| {
                    (
                        provenance.verdict,
                        provenance.confidence,
                        provenance.catalog_version,
                        provenance.tlp_label,
                    )
                })
                .unwrap_or_else(|| {
                    (
                        finding.verdict.unwrap_or_else(|| "observed".into()),
                        "unknown".into(),
                        String::new(),
                        String::new(),
                    )
                });
            FindingSummary {
                id: redact(&finding.id),
                title: redact(&finding.title),
                severity: redact(&finding.severity),
                status: redact(&finding.status),
                verdict: redact(&verdict),
                confidence,
                catalog_version,
                tlp_label,
            }
        })
        .collect())
}

pub fn investigation_view(
    state: &AppState,
    engagement_id: &str,
) -> AppResult<Option<InvestigationView>> {
    let Some(row) = storage(state.store.get_investigation_state(engagement_id))? else {
        return Ok(None);
    };
    let value: serde_json::Value = serde_json::from_str(&row.state_json).map_err(|error| {
        crate::dto::AppError::Storage(format!("invalid investigation state: {error}"))
    })?;
    let count = |key: &str| -> usize {
        value
            .get(key)
            .and_then(serde_json::Value::as_array)
            .map(Vec::len)
            .unwrap_or(0)
    };
    let string = |key: &str| -> String {
        value
            .get(key)
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_string()
    };
    Ok(Some(InvestigationView {
        engagement_id: engagement_id.to_string(),
        revision: row.revision,
        phase: string("phase"),
        catalog_version: value
            .get("plan")
            .and_then(|plan| plan.get("catalog_version"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_string(),
        tlp_label: string("tlp_label"),
        plan_steps: value
            .get("plan")
            .and_then(|plan| plan.get("steps"))
            .and_then(serde_json::Value::as_array)
            .map(Vec::len)
            .unwrap_or(0),
        open_hypotheses: count("hypotheses"),
        coverage_rows: count("coverage"),
        reflections: count("reflections"),
    }))
}

pub fn audit_events(
    state: &AppState,
    engagement_id: &str,
    limit: usize,
) -> AppResult<Vec<AuditEventView>> {
    let events = storage(state.store.list_investigation_events(engagement_id, limit))?;
    Ok(events
        .into_iter()
        .map(|event| AuditEventView {
            kind: event.kind,
            actor: event.actor,
            step_id: event.step_id,
            payload_json: redact(&event.payload_json),
        })
        .collect())
}

pub fn report_read(state: &AppState, engagement_id: &str) -> AppResult<ReportView> {
    // E13: verify the exact on-disk bytes against the recorded digest *before*
    // any redaction or projection. `latest_report_path` remains a thin wrapper
    // over `latest_report` for callers that only need the location.
    let record = storage(state.store.latest_report(engagement_id))?.ok_or_else(|| {
        crate::dto::AppError::InvalidInput("no report for this engagement".into())
    })?;
    let path = std::path::PathBuf::from(record.path);
    let path = if path.is_absolute() {
        path
    } else {
        std::env::current_dir()
            .map_err(|error| crate::dto::AppError::Storage(error.to_string()))?
            .join(path)
    };
    let bytes = std::fs::read(&path)
        .map_err(|error| crate::dto::AppError::Storage(format!("read report: {error}")))?;
    if !bugfound_store::verify_report_hash(&record.sha256, &bytes) {
        return Err(crate::dto::AppError::Storage(
            "report integrity check failed".into(),
        ));
    }
    let text = String::from_utf8(bytes)
        .map_err(|error| crate::dto::AppError::Storage(format!("read report: {error}")))?;
    Ok(ReportView {
        path: redact(&path.display().to_string()),
        text: redact(&text),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AppConfig;
    use crate::runtime::RuntimeHandle;
    use bugfound_store::Store;
    use std::path::PathBuf;
    use std::sync::Mutex;

    // SHA-256 of the exact bytes "abc".
    const ABC_SHA256: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    fn test_state(store: Store) -> AppState {
        AppState {
            config_path: PathBuf::from("bugfound.toml"),
            config: Mutex::new(AppConfig::default()),
            store: store.clone(),
            startup_warnings: Vec::new(),
            runtime: RuntimeHandle::new(store),
        }
    }

    fn temp_report(name: &str, bytes: &[u8]) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("bf-report-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let file = dir.join("report.md");
        std::fs::write(&file, bytes).expect("write report");
        file
    }

    #[test]
    fn report_read_accepts_bytes_matching_recorded_hash() {
        let file = temp_report("valid", b"abc");
        let store = Store::open(":memory:").expect("store");
        store
            .save_report(
                "eng-valid",
                "markdown",
                file.to_str().expect("utf8 path"),
                ABC_SHA256,
            )
            .expect("save report");

        let view = report_read(&test_state(store), "eng-valid").expect("read report");

        assert_eq!(view.text, "abc");
        assert!(view.path.contains("report.md"));
        let _ = std::fs::remove_dir_all(file.parent().expect("temp dir"));
    }

    #[test]
    fn report_read_rejects_tampered_bytes() {
        let file = temp_report("tampered", b"abcd");
        let store = Store::open(":memory:").expect("store");
        store
            .save_report(
                "eng-tampered",
                "markdown",
                file.to_str().expect("utf8 path"),
                ABC_SHA256,
            )
            .expect("save report");

        match report_read(&test_state(store), "eng-tampered") {
            Err(crate::dto::AppError::Storage(message)) => {
                assert_eq!(message, "report integrity check failed")
            }
            Err(other) => panic!("unexpected error: {other}"),
            Ok(_) => panic!("tampered report must not be served"),
        }
        let _ = std::fs::remove_dir_all(file.parent().expect("temp dir"));
    }
}
