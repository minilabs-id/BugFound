use bugfound_desktop_core::dto::{
    AppError, AppResult, AppSnapshot, ApprovalSummary, AuditEventView, FindingSummary,
    InvestigationView, ReportView, SessionSummary, TimelineItem,
};
use bugfound_desktop_core::runtime::{RuntimeEvent, RuntimeStatus};
use bugfound_desktop_core::AppState;

/// Initial handshake. The webview calls this once on mount.
#[tauri::command]
fn app_ready(state: tauri::State<'_, AppState>) -> AppResult<AppSnapshot> {
    bugfound_desktop_core::commands::app_ready(&state)
}

#[tauri::command]
fn sessions_list(state: tauri::State<'_, AppState>) -> AppResult<Vec<SessionSummary>> {
    bugfound_desktop_core::commands::sessions_list(&state)
}

#[tauri::command]
fn session_history(
    state: tauri::State<'_, AppState>,
    session_id: String,
) -> AppResult<Vec<TimelineItem>> {
    bugfound_desktop_core::commands::session_history(&state, &session_id)
}

#[tauri::command]
fn approvals_list(
    state: tauri::State<'_, AppState>,
    session_id: String,
) -> AppResult<Vec<ApprovalSummary>> {
    bugfound_desktop_core::commands::approvals_list(&state, &session_id)
}

#[tauri::command]
fn findings_list(
    state: tauri::State<'_, AppState>,
    session_id: String,
) -> AppResult<Vec<FindingSummary>> {
    bugfound_desktop_core::commands::findings_list(&state, &session_id)
}

#[tauri::command]
fn investigation_view(
    state: tauri::State<'_, AppState>,
    engagement_id: String,
) -> AppResult<Option<InvestigationView>> {
    bugfound_desktop_core::commands::investigation_view(&state, &engagement_id)
}

#[tauri::command]
fn audit_events(
    state: tauri::State<'_, AppState>,
    engagement_id: String,
    limit: usize,
) -> AppResult<Vec<AuditEventView>> {
    bugfound_desktop_core::commands::audit_events(&state, &engagement_id, limit)
}

#[tauri::command]
fn report_read(state: tauri::State<'_, AppState>, engagement_id: String) -> AppResult<ReportView> {
    bugfound_desktop_core::commands::report_read(&state, &engagement_id)
}

fn event_bridge(
    channel: tauri::ipc::Channel<RuntimeEvent>,
) -> std::sync::mpsc::Sender<RuntimeEvent> {
    let (sender, receiver) = std::sync::mpsc::channel::<RuntimeEvent>();
    std::thread::spawn(move || {
        while let Ok(event) = receiver.recv() {
            let _ = channel.send(event);
        }
    });
    sender
}

#[tauri::command]
fn runtime_status(state: tauri::State<'_, AppState>) -> AppResult<RuntimeStatus> {
    Ok(state.runtime.status())
}

#[tauri::command]
fn runtime_chat(
    state: tauri::State<'_, AppState>,
    text: String,
    channel: tauri::ipc::Channel<RuntimeEvent>,
) -> AppResult<()> {
    let config = state
        .config
        .lock()
        .map_err(|error| AppError::Config(error.to_string()))?
        .clone();
    state.runtime.chat(config, text, event_bridge(channel));
    Ok(())
}

#[tauri::command]
fn runtime_chat_send(
    state: tauri::State<'_, AppState>,
    session: String,
    text: String,
    // Accepted for API compatibility with the webview, but deliberately NOT
    // used: the workspace is operator configuration and is confined by
    // `desktop-core::runtime::build_runner` via `AppConfig::workspace()`.
    cwd: Option<String>,
    channel: tauri::ipc::Channel<RuntimeEvent>,
) -> AppResult<()> {
    let _ = cwd;
    let config = state
        .config
        .lock()
        .map_err(|error| AppError::Config(error.to_string()))?
        .clone();
    state
        .runtime
        .chat_send(config, session, text, event_bridge(channel));
    Ok(())
}

#[tauri::command]
fn runtime_steer(
    state: tauri::State<'_, AppState>,
    session: String,
    text: String,
) -> AppResult<()> {
    state.runtime.steer(session, text);
    Ok(())
}

#[tauri::command]
fn runtime_stop(state: tauri::State<'_, AppState>, session: String) -> AppResult<()> {
    state.runtime.stop(session);
    Ok(())
}

#[tauri::command]
fn runtime_decide(
    state: tauri::State<'_, AppState>,
    session: String,
    decision: String,
    channel: tauri::ipc::Channel<RuntimeEvent>,
) -> AppResult<()> {
    let config = state
        .config
        .lock()
        .map_err(|error| AppError::Config(error.to_string()))?
        .clone();
    state
        .runtime
        .decide(config, session, decision, event_bridge(channel));
    Ok(())
}

#[tauri::command]
fn pending_approvals(state: tauri::State<'_, AppState>) -> AppResult<Vec<ApprovalSummary>> {
    bugfound_desktop_core::commands::pending_approvals(&state)
}

#[tauri::command]
fn engagement_start(
    state: tauri::State<'_, AppState>,
    url: String,
    cwd: String,
    channel: tauri::ipc::Channel<RuntimeEvent>,
) -> AppResult<()> {
    let config = state
        .config
        .lock()
        .map_err(|error| AppError::Config(error.to_string()))?
        .clone();
    state
        .runtime
        .engagement_start(config, url, cwd, event_bridge(channel));
    Ok(())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let state = AppState::load();
    tauri::Builder::default()
        .manage(state)
        .invoke_handler(tauri::generate_handler![
            app_ready,
            sessions_list,
            session_history,
            approvals_list,
            findings_list,
            investigation_view,
            audit_events,
            report_read,
            runtime_status,
            runtime_chat,
            runtime_chat_send,
            runtime_steer,
            runtime_stop,
            runtime_decide,
            pending_approvals,
            engagement_start
        ])
        .run(tauri::generate_context!())
        .expect("error while running BugFound");
}

/// Compile-time check that the error type crossing IPC stays serializable.
const _: fn() = || {
    fn assert_serialize<T: serde::Serialize>() {}
    assert_serialize::<AppError>();
};
