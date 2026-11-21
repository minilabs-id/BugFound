use anyhow::{Context, Result};
use chrono::{Duration, Utc};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::path::Path;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: String,
    pub goal: String,
    pub state: String,
    pub model: Option<String>,
    pub owner_id: Option<String>,
    pub lease_expires_at: Option<String>,
    pub created_at: String,
    pub updated_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub id: String,
    pub session_id: String,
    pub role: String,
    pub content: String,
    #[serde(default)]
    pub tool_call_id: Option<String>,
    #[serde(default)]
    pub tool_calls_json: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Approval {
    pub id: String,
    pub session_id: String,
    pub tool_name: String,
    pub args_json: String,
    pub risk: String,
    pub status: String,
    pub reason: Option<String>,
    pub created_at: String,
    #[serde(default)]
    pub tool_call_id: Option<String>,
    #[serde(default)]
    pub expires_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub id: String,
    pub session_id: String,
    pub level: String,
    pub kind: String,
    pub message: String,
    pub created_at: String,
    #[serde(default)]
    pub prev_hash: Option<String>,
    #[serde(default)]
    pub hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub session_id: String,
    pub title: String,
    pub severity: String,
    pub asset: Option<String>,
    pub vuln_type: Option<String>,
    pub description: String,
    pub reproduction: Option<String>,
    pub impact: Option<String>,
    pub remediation: Option<String>,
    pub evidence: Option<String>,
    pub status: String,
    pub created_at: String,
    pub updated_at: String,
    #[serde(default)]
    pub request: Option<String>,
    #[serde(default)]
    pub response: Option<String>,
    #[serde(default)]
    pub cvss: Option<String>,
    #[serde(default)]
    pub cwe: Option<String>,
    #[serde(default)]
    pub dedupe_key: Option<String>,
    #[serde(default)]
    pub evidence_hash: Option<String>,
    #[serde(default)]
    pub validated_at: Option<String>,
    #[serde(default)]
    pub validation_detail: Option<String>,
    #[serde(default)]
    pub verdict: Option<String>,
    #[serde(default)]
    pub gap_reason: Option<String>,
    #[serde(default)]
    pub counterevidence: Option<String>,
    #[serde(default)]
    pub confidence: Option<String>,
    #[serde(default)]
    pub confidence_rationale: Option<String>,
    #[serde(default)]
    pub severity_change_conditions: Option<String>,
    #[serde(default)]
    pub oracle_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Coverage {
    pub id: String,
    pub session_id: String,
    pub target: String,
    pub method: String,
    pub path: String,
    pub created_at: String,
    /// Stable requirement/test id this row accounts for (e.g. WSTG-ATHZ-04).
    pub requirement_id: String,
    /// covered | blocked | skipped | not-applicable
    pub status: String,
    /// Mandatory rationale for non-covered rows.
    pub rationale: String,
    /// Evidence artifact / capture hash reference.
    pub evidence_ref: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hypothesis {
    pub id: String,
    pub session_id: String,
    pub statement: String,
    pub status: String,
    pub created_at: String,
    #[serde(default)]
    pub requirement_id: String,
    #[serde(default)]
    pub claim: String,
    #[serde(default)]
    pub preconditions: String,
    #[serde(default)]
    pub oracle_type: String,
    #[serde(default)]
    pub rationale: String,
    #[serde(default)]
    pub evidence_ref: String,
    #[serde(default)]
    pub updated_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Asset {
    pub id: String,
    pub session_id: String,
    pub kind: String,
    pub value: String,
    pub metadata_json: Option<String>,
    pub first_seen: String,
    pub last_seen: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Artifact {
    pub id: String,
    pub session_id: String,
    pub kind: String,
    pub path: Option<String>,
    pub content: Option<String>,
    pub metadata_json: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone)]
pub struct Engagement {
    pub id: String,
    pub program_url: String,
    pub state: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone)]
pub struct Task {
    pub id: String,
    pub engagement_id: String,
    pub statement: String,
    pub playbook_id: String,
    pub target: Option<String>,
    pub priority: i64,
    pub status: String,
    pub created_at: String,
}

#[derive(Debug, Clone)]
pub struct Clue {
    pub id: String,
    pub engagement_id: String,
    pub task_id: Option<String>,
    pub source_tool: String,
    pub key: String,
    pub value_json: String,
    pub created_at: String,
}

/// Durable per-session execution accounting used by the runner.
#[derive(Debug, Clone, Copy, Default)]
pub struct BudgetUsage {
    pub steps_used: usize,
    pub tool_calls_used: usize,
    pub network_calls_used: usize,
    pub calls_in_window: usize,
}

/// Accumulated token counts and estimated spend for a session.
#[derive(Debug, Clone, Copy, Default)]
pub struct TokenUsage {
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
    pub cost_usd: f64,
}

#[derive(Debug, Clone)]
pub struct PendingCall {
    pub tool_call_id: Option<String>,
    pub name: String,
    pub args_json: String,
}

/// Authoritative, tool-captured request/response bytes for a finding. The
/// verifier reads this rather than trusting LLM-supplied evidence fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCapture {
    pub finding_id: String,
    pub request_bytes: Vec<u8>,
    pub response_bytes: Vec<u8>,
    pub canary: String,
    pub created_at: String,
}

/// Authoritative capture for a specific control role in a paired exchange.
/// The primary capture stays in `tool_captures`; only benign/payload controls
/// live here so existing `get_capture(finding_id)` callers are unchanged.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleCapture {
    pub finding_id: String,
    pub role: String,
    pub request_bytes: Vec<u8>,
    pub response_bytes: Vec<u8>,
    pub canary: String,
    pub marker: Option<String>,
    pub created_at: String,
}

/// Advisory provenance for one brief-derived rule. Never used to authorize
/// an action; it only records where a rule came from.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleProvenance {
    pub engagement_id: String,
    pub rule_kind: String,
    pub rule_value: String,
    pub source_url: String,
    pub section_pointer: String,
    pub verbatim_quote: String,
    pub verbatim_quote_hash: String,
    pub content_hash: String,
    pub extractor: String,
    pub observed_at: String,
}

#[derive(Clone)]
pub struct Store {
    conn: Arc<Mutex<Connection>>,
}

fn now() -> String {
    Utc::now().to_rfc3339()
}

fn parse_ts(s: &str) -> Option<chrono::DateTime<Utc>> {
    chrono::DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|d| d.with_timezone(&Utc))
}

fn sha256_hex(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Canonical evidence digest: `Sha256(request || response || artifact)`.
/// Raw bytes are concatenated without separators so the hash is reproducible
/// from the exact bytes that were captured, independent of text encoding.
fn sha256_evidence_bytes(request: &[u8], response: &[u8], artifact: Option<&[u8]>) -> String {
    let mut input =
        Vec::with_capacity(request.len() + response.len() + artifact.map_or(0, |a| a.len()));
    input.extend_from_slice(request);
    input.extend_from_slice(response);
    if let Some(artifact) = artifact {
        input.extend_from_slice(artifact);
    }
    format!("{:x}", Sha256::digest(input))
}

/// Requirement-keyed coverage decision input.
#[derive(Debug, Clone, Default)]
pub struct CoverageDecision<'a> {
    pub session_id: &'a str,
    pub target: &'a str,
    pub method: &'a str,
    pub path: &'a str,
    pub requirement_id: &'a str,
    pub status: &'a str,
    pub rationale: &'a str,
    pub evidence_ref: &'a str,
}

impl Store {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        if let Some(parent) = path.as_ref().parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("create db dir {}", parent.display()))?;
            }
        }
        let conn = Connection::open(path.as_ref()).context("open sqlite")?;
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             CREATE TABLE IF NOT EXISTS sessions(
               id TEXT PRIMARY KEY, goal TEXT NOT NULL, state TEXT NOT NULL, model TEXT,
               owner_id TEXT, lease_expires_at TEXT, created_at TEXT NOT NULL, updated_at TEXT
             );
             CREATE TABLE IF NOT EXISTS messages(
               id TEXT PRIMARY KEY, session_id TEXT NOT NULL, role TEXT NOT NULL, content TEXT NOT NULL,
               tool_call_id TEXT, tool_calls_json TEXT, name TEXT
             );
             CREATE TABLE IF NOT EXISTS approvals(
               id TEXT PRIMARY KEY, session_id TEXT NOT NULL, action TEXT NOT NULL, status TEXT NOT NULL, reason TEXT,
               tool_name TEXT, args_json TEXT, risk TEXT, created_at TEXT, tool_call_id TEXT, expires_at TEXT
             );
             CREATE TABLE IF NOT EXISTS events(
               id TEXT PRIMARY KEY, session_id TEXT NOT NULL, level TEXT NOT NULL, kind TEXT NOT NULL, message TEXT NOT NULL, created_at TEXT NOT NULL,
               prev_hash TEXT, hash TEXT
             );
             CREATE TABLE IF NOT EXISTS findings(
               id TEXT PRIMARY KEY, session_id TEXT NOT NULL, title TEXT NOT NULL, severity TEXT NOT NULL,
               asset TEXT, vuln_type TEXT, description TEXT NOT NULL, reproduction TEXT, impact TEXT,
               remediation TEXT, evidence TEXT, status TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
               request TEXT, response TEXT, cvss TEXT, cwe TEXT, dedupe_key TEXT, evidence_hash TEXT,
               validated_at TEXT, validation_detail TEXT, verdict TEXT, gap_reason TEXT,
               counterevidence TEXT, confidence TEXT, confidence_rationale TEXT,
               severity_change_conditions TEXT, oracle_type TEXT
             );
             CREATE TABLE IF NOT EXISTS assets(
               id TEXT PRIMARY KEY, session_id TEXT NOT NULL, kind TEXT NOT NULL, value TEXT NOT NULL,
               metadata_json TEXT, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
               UNIQUE(session_id, kind, value)
             );
             CREATE TABLE IF NOT EXISTS artifacts(
               id TEXT PRIMARY KEY, session_id TEXT NOT NULL, kind TEXT NOT NULL, path TEXT, content TEXT,
               metadata_json TEXT, created_at TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS coverage(
               id TEXT PRIMARY KEY, session_id TEXT NOT NULL, target TEXT NOT NULL, method TEXT NOT NULL DEFAULT '',
               path TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL,
               requirement_id TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT 'covered',
               rationale TEXT NOT NULL DEFAULT '', evidence_ref TEXT NOT NULL DEFAULT '',
               UNIQUE(session_id,target,method,path,requirement_id)
             );
             CREATE TABLE IF NOT EXISTS hypotheses(
               id TEXT PRIMARY KEY, session_id TEXT NOT NULL, statement TEXT NOT NULL,
               status TEXT NOT NULL DEFAULT 'open', created_at TEXT NOT NULL,
               requirement_id TEXT NOT NULL DEFAULT '', claim TEXT NOT NULL DEFAULT '',
               preconditions TEXT NOT NULL DEFAULT '', oracle_type TEXT NOT NULL DEFAULT '',
               rationale TEXT NOT NULL DEFAULT '', evidence_ref TEXT NOT NULL DEFAULT '',
               updated_at TEXT
             );
             CREATE TABLE IF NOT EXISTS approved_targets(
               session_id TEXT NOT NULL, target TEXT NOT NULL, created_at TEXT NOT NULL,
               PRIMARY KEY(session_id,target)
             );
             CREATE TABLE IF NOT EXISTS engagement_controls(
               engagement_id TEXT PRIMARY KEY, state TEXT NOT NULL, updated_at TEXT NOT NULL
             );
             CREATE INDEX IF NOT EXISTS idx_engagement_controls_id ON engagement_controls(engagement_id);
             CREATE TABLE IF NOT EXISTS authorization_revalidation(
               engagement_id TEXT PRIMARY KEY, state TEXT NOT NULL,
               observed_hash TEXT NOT NULL DEFAULT '', requested_at TEXT NOT NULL,
               updated_at TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS schema_version(
               version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS session_budgets(
               session_id TEXT PRIMARY KEY,
               steps_used INTEGER NOT NULL DEFAULT 0,
               tool_calls_used INTEGER NOT NULL DEFAULT 0,
               network_calls_used INTEGER NOT NULL DEFAULT 0,
               window_start_ms INTEGER NOT NULL DEFAULT 0,
               calls_in_window INTEGER NOT NULL DEFAULT 0,
               steps_offset INTEGER NOT NULL DEFAULT 0,
               tool_calls_offset INTEGER NOT NULL DEFAULT 0,
               network_calls_offset INTEGER NOT NULL DEFAULT 0,
               tokens_offset INTEGER NOT NULL DEFAULT 0
             );
             CREATE TABLE IF NOT EXISTS pending_tool_calls(
               id TEXT PRIMARY KEY, session_id TEXT NOT NULL, approval_id TEXT NOT NULL,
               tool_call_id TEXT, name TEXT NOT NULL, args_json TEXT NOT NULL, seq INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS token_usage(
               id TEXT PRIMARY KEY, session_id TEXT NOT NULL, prompt_tokens INTEGER NOT NULL,
               completion_tokens INTEGER NOT NULL, cost_usd REAL NOT NULL, created_at TEXT NOT NULL
             );
             CREATE INDEX IF NOT EXISTS idx_token_usage_session ON token_usage(session_id);
             CREATE TABLE IF NOT EXISTS goal_locks(
               session_id TEXT PRIMARY KEY, digest TEXT NOT NULL, created_at TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS session_flags(
               session_id TEXT NOT NULL, flag TEXT NOT NULL, created_at TEXT NOT NULL,
               PRIMARY KEY(session_id,flag)
             );
             CREATE TABLE IF NOT EXISTS tool_captures(
               finding_id TEXT PRIMARY KEY, request_bytes BLOB NOT NULL,
               response_bytes BLOB NOT NULL, canary TEXT NOT NULL, created_at TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS session_captures(
               session_id TEXT PRIMARY KEY, request_bytes BLOB NOT NULL,
               response_bytes BLOB NOT NULL, canary TEXT NOT NULL, created_at TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS finding_captures(
               id TEXT PRIMARY KEY, finding_id TEXT NOT NULL,
               role TEXT NOT NULL CHECK(role IN ('primary','paired_benign','paired_payload')),
               request_bytes BLOB NOT NULL, response_bytes BLOB NOT NULL,
               canary TEXT NOT NULL, marker TEXT, created_at TEXT NOT NULL,
               UNIQUE(finding_id, role)
             );
             CREATE INDEX IF NOT EXISTS idx_finding_captures_finding
               ON finding_captures(finding_id, role);
             CREATE TABLE IF NOT EXISTS session_inbox(
               id TEXT PRIMARY KEY, session_id TEXT NOT NULL, kind TEXT NOT NULL,
               delivery TEXT NOT NULL, payload_json TEXT NOT NULL,
               state TEXT NOT NULL, created_at TEXT NOT NULL, enqueued_seq INTEGER NOT NULL
             );
             CREATE INDEX IF NOT EXISTS idx_session_inbox_session
               ON session_inbox(session_id, state, enqueued_seq);
             CREATE TABLE IF NOT EXISTS tool_calls(
               id TEXT PRIMARY KEY, session_id TEXT NOT NULL, tool_call_id TEXT,
               name TEXT NOT NULL, args_json TEXT NOT NULL, args_sig TEXT NOT NULL,
               status TEXT NOT NULL, risk TEXT NOT NULL, ok INTEGER,
               result_text TEXT, created_at TEXT NOT NULL, settled_at TEXT
             );
             CREATE INDEX IF NOT EXISTS idx_tool_calls_session_sig
               ON tool_calls(session_id, name, args_sig, created_at);
             CREATE TABLE IF NOT EXISTS memory_items(
               id TEXT PRIMARY KEY, session_id TEXT NOT NULL, parent_session_id TEXT,
               source_kind TEXT NOT NULL, source_id TEXT NOT NULL, source_event_hash TEXT,
               role TEXT, task_id TEXT, scope_key TEXT NOT NULL, tier TEXT NOT NULL,
               content TEXT NOT NULL, sha256 TEXT NOT NULL, created_at TEXT NOT NULL
             );
             CREATE INDEX IF NOT EXISTS idx_memory_scope
               ON memory_items(session_id, scope_key, tier, created_at);
             CREATE TABLE IF NOT EXISTS session_results(
               session_id TEXT PRIMARY KEY, parent_session_id TEXT, parent_tool_call_id TEXT,
               role TEXT NOT NULL, status TEXT NOT NULL, payload_json TEXT NOT NULL,
               sha256 TEXT NOT NULL, created_at TEXT NOT NULL
             );
             CREATE INDEX IF NOT EXISTS idx_messages_session ON messages(session_id);
             CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id);
             CREATE INDEX IF NOT EXISTS idx_approvals_session ON approvals(session_id);
             CREATE INDEX IF NOT EXISTS idx_findings_session ON findings(session_id);
             CREATE INDEX IF NOT EXISTS idx_assets_session ON assets(session_id);
             CREATE INDEX IF NOT EXISTS idx_artifacts_session ON artifacts(session_id);
             CREATE INDEX IF NOT EXISTS idx_coverage_session ON coverage(session_id);
             CREATE INDEX IF NOT EXISTS idx_hypotheses_session ON hypotheses(session_id);
             CREATE INDEX IF NOT EXISTS idx_approved_targets_session ON approved_targets(session_id);
             CREATE INDEX IF NOT EXISTS idx_pending_calls_approval ON pending_tool_calls(approval_id);
             CREATE TABLE IF NOT EXISTS engagements(
               id TEXT PRIMARY KEY, program_url TEXT NOT NULL, state TEXT NOT NULL,
               created_at TEXT NOT NULL, updated_at TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS brief_snapshots(
               id TEXT PRIMARY KEY, engagement_id TEXT NOT NULL, raw_html TEXT,
               extracted_json TEXT, scope_json TEXT, roe_json TEXT, created_at TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS brief_rule_provenance(
               id TEXT PRIMARY KEY, engagement_id TEXT NOT NULL,
               rule_kind TEXT NOT NULL, rule_value TEXT NOT NULL,
               source_url TEXT NOT NULL, section_pointer TEXT,
               verbatim_quote TEXT NOT NULL, verbatim_quote_hash TEXT NOT NULL,
               content_hash TEXT NOT NULL, extractor TEXT NOT NULL,
               observed_at TEXT NOT NULL, created_at TEXT NOT NULL
             );
             CREATE INDEX IF NOT EXISTS idx_brief_rule_provenance_engagement
               ON brief_rule_provenance(engagement_id);
             CREATE TABLE IF NOT EXISTS authorization_snapshots(
               id TEXT PRIMARY KEY, engagement_id TEXT NOT NULL, version INTEGER NOT NULL,
               source_url TEXT NOT NULL, content_hash TEXT NOT NULL,
               scope_hash TEXT NOT NULL, roe_hash TEXT NOT NULL,
               observed_at TEXT NOT NULL, state TEXT NOT NULL, created_at TEXT NOT NULL,
               UNIQUE(engagement_id, content_hash)
             );
             CREATE INDEX IF NOT EXISTS idx_authorization_snapshots_engagement
               ON authorization_snapshots(engagement_id);
             CREATE TABLE IF NOT EXISTS authorization_acks(
               id TEXT PRIMARY KEY, program_url TEXT NOT NULL, content_hash TEXT NOT NULL,
               subject_kind TEXT NOT NULL, subject_hash TEXT NOT NULL,
               subject_text TEXT NOT NULL, decision TEXT NOT NULL,
               operator TEXT NOT NULL, note TEXT NOT NULL, created_at TEXT NOT NULL,
               UNIQUE(program_url, content_hash, subject_kind, subject_hash)
             );
             CREATE TABLE IF NOT EXISTS authorization_open_rules(
               id TEXT PRIMARY KEY, engagement_id TEXT NOT NULL, snapshot_hash TEXT NOT NULL,
               rule_hash TEXT NOT NULL, rule_text TEXT NOT NULL, state TEXT NOT NULL,
               created_at TEXT NOT NULL,
               UNIQUE(engagement_id, snapshot_hash, rule_hash)
             );
             CREATE TABLE IF NOT EXISTS safe_harbor_receipts(
               id TEXT PRIMARY KEY, program_url TEXT NOT NULL, brief_content_hash TEXT NOT NULL,
               scope_version TEXT NOT NULL, terms_hash TEXT NOT NULL, operator TEXT NOT NULL,
               acquired_at TEXT NOT NULL, expires_at TEXT NOT NULL, decision TEXT NOT NULL,
               note TEXT NOT NULL
             );
             CREATE INDEX IF NOT EXISTS idx_safe_harbor_receipts_program_hash
               ON safe_harbor_receipts(program_url, brief_content_hash);
             CREATE TABLE IF NOT EXISTS tasks(
               id TEXT PRIMARY KEY, engagement_id TEXT NOT NULL, statement TEXT NOT NULL,
               playbook_id TEXT NOT NULL DEFAULT '', target TEXT, priority INTEGER NOT NULL DEFAULT 0,
               status TEXT NOT NULL DEFAULT 'open', created_at TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS clues(
               id TEXT PRIMARY KEY, engagement_id TEXT NOT NULL, task_id TEXT,
               source_tool TEXT NOT NULL, \"key\" TEXT NOT NULL, value_json TEXT NOT NULL,
               created_at TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS evidence(
               id TEXT PRIMARY KEY, finding_id TEXT NOT NULL, kind TEXT NOT NULL, path TEXT,
               sha256 TEXT NOT NULL, request TEXT, response TEXT,
                request_bytes BLOB, response_bytes BLOB, artifact_bytes BLOB,
                created_at TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS reports(
               id TEXT PRIMARY KEY, engagement_id TEXT NOT NULL, format TEXT NOT NULL,
               path TEXT NOT NULL, sha256 TEXT NOT NULL, created_at TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS trace_events(
               id TEXT PRIMARY KEY, engagement_id TEXT NOT NULL, run_id TEXT NOT NULL,
               kind TEXT NOT NULL, payload_json TEXT NOT NULL, created_at TEXT NOT NULL
             );
             CREATE INDEX IF NOT EXISTS idx_brief_snapshots_engagement ON brief_snapshots(engagement_id);
             CREATE INDEX IF NOT EXISTS idx_tasks_engagement ON tasks(engagement_id);
             CREATE INDEX IF NOT EXISTS idx_clues_engagement ON clues(engagement_id);
             CREATE INDEX IF NOT EXISTS idx_evidence_finding ON evidence(finding_id);
             CREATE INDEX IF NOT EXISTS idx_reports_engagement ON reports(engagement_id);
             CREATE INDEX IF NOT EXISTS idx_trace_events_engagement ON trace_events(engagement_id);
             INSERT OR IGNORE INTO schema_version(version, applied_at)
               VALUES(1, strftime('%Y-%m-%dT%H:%M:%SZ','now'));
             INSERT OR IGNORE INTO schema_version(version, applied_at)
               VALUES(2, strftime('%Y-%m-%dT%H:%M:%SZ','now'));",
        )?;
        // best-effort migrations
        let _ = conn.execute("ALTER TABLE sessions ADD COLUMN updated_at TEXT", []);
        let _ = conn.execute("ALTER TABLE sessions ADD COLUMN owner_id TEXT", []);
        let _ = conn.execute("ALTER TABLE sessions ADD COLUMN lease_expires_at TEXT", []);
        let _ = conn.execute("ALTER TABLE approvals ADD COLUMN tool_name TEXT", []);
        let _ = conn.execute("ALTER TABLE approvals ADD COLUMN args_json TEXT", []);
        let _ = conn.execute("ALTER TABLE approvals ADD COLUMN risk TEXT", []);
        let _ = conn.execute("ALTER TABLE approvals ADD COLUMN created_at TEXT", []);
        let _ = conn.execute("ALTER TABLE approvals ADD COLUMN tool_call_id TEXT", []);
        let _ = conn.execute("ALTER TABLE approvals ADD COLUMN expires_at TEXT", []);
        let _ = conn.execute("ALTER TABLE findings ADD COLUMN request TEXT", []);
        let _ = conn.execute("ALTER TABLE findings ADD COLUMN response TEXT", []);
        let _ = conn.execute("ALTER TABLE findings ADD COLUMN cvss TEXT", []);
        let _ = conn.execute("ALTER TABLE findings ADD COLUMN cwe TEXT", []);
        let _ = conn.execute("ALTER TABLE findings ADD COLUMN dedupe_key TEXT", []);
        let _ = conn.execute("ALTER TABLE findings ADD COLUMN evidence_hash TEXT", []);
        let _ = conn.execute("ALTER TABLE findings ADD COLUMN validated_at TEXT", []);
        let _ = conn.execute("ALTER TABLE findings ADD COLUMN validation_detail TEXT", []);
        let _ = conn.execute("ALTER TABLE findings ADD COLUMN verdict TEXT", []);
        let _ = conn.execute("ALTER TABLE findings ADD COLUMN gap_reason TEXT", []);
        let _ = conn.execute("ALTER TABLE findings ADD COLUMN counterevidence TEXT", []);
        let _ = conn.execute("ALTER TABLE findings ADD COLUMN confidence TEXT", []);
        let _ = conn.execute(
            "ALTER TABLE findings ADD COLUMN confidence_rationale TEXT",
            [],
        );
        let _ = conn.execute(
            "ALTER TABLE findings ADD COLUMN severity_change_conditions TEXT",
            [],
        );
        let _ = conn.execute("ALTER TABLE findings ADD COLUMN oracle_type TEXT", []);
        let _ = conn.execute("ALTER TABLE events ADD COLUMN prev_hash TEXT", []);
        let _ = conn.execute("ALTER TABLE events ADD COLUMN hash TEXT", []);
        let _ = conn.execute("ALTER TABLE messages ADD COLUMN tool_call_id TEXT", []);
        let _ = conn.execute("ALTER TABLE messages ADD COLUMN tool_calls_json TEXT", []);
        let _ = conn.execute("ALTER TABLE messages ADD COLUMN name TEXT", []);
        let _ = conn.execute("ALTER TABLE evidence ADD COLUMN request_bytes BLOB", []);
        let _ = conn.execute("ALTER TABLE evidence ADD COLUMN response_bytes BLOB", []);
        let _ = conn.execute("ALTER TABLE evidence ADD COLUMN artifact_bytes BLOB", []);
        let _ = conn.execute(
            "ALTER TABLE sessions ADD COLUMN resume_attempts INTEGER NOT NULL DEFAULT 0",
            [],
        );
        // Parent->child budget inheritance: old databases gain zero-valued
        // offsets, so their existing usage snapshots are unchanged.
        for column in [
            "steps_offset INTEGER NOT NULL DEFAULT 0",
            "tool_calls_offset INTEGER NOT NULL DEFAULT 0",
            "network_calls_offset INTEGER NOT NULL DEFAULT 0",
            "tokens_offset INTEGER NOT NULL DEFAULT 0",
        ] {
            let _ = conn.execute(
                &format!("ALTER TABLE session_budgets ADD COLUMN {column}"),
                [],
            );
        }
        for column in [
            "requirement_id TEXT NOT NULL DEFAULT ''",
            "claim TEXT NOT NULL DEFAULT ''",
            "preconditions TEXT NOT NULL DEFAULT ''",
            "oracle_type TEXT NOT NULL DEFAULT ''",
            "rationale TEXT NOT NULL DEFAULT ''",
            "evidence_ref TEXT NOT NULL DEFAULT ''",
            "updated_at TEXT",
        ] {
            let _ = conn.execute(&format!("ALTER TABLE hypotheses ADD COLUMN {column}"), []);
        }
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    pub fn create_session(&self, goal: &str) -> Result<Session> {
        let ts = now();
        let s = Session {
            id: Uuid::new_v4().to_string(),
            goal: goal.to_string(),
            state: "idle".to_string(),
            model: None,
            owner_id: None,
            lease_expires_at: None,
            created_at: ts.clone(),
            updated_at: Some(ts.clone()),
        };
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO sessions(id,goal,state,model,owner_id,lease_expires_at,created_at,updated_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
            params![s.id, s.goal, s.state, s.model, s.owner_id, s.lease_expires_at, s.created_at, s.updated_at],
        )?;
        Ok(s)
    }

    pub fn get_session(&self, id: &str) -> Result<Option<Session>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id,goal,state,model,owner_id,lease_expires_at,created_at,updated_at FROM sessions WHERE id=?1",
        )?;
        let row = stmt
            .query_row(params![id], |r| {
                Ok(Session {
                    id: r.get(0)?,
                    goal: r.get(1)?,
                    state: r.get(2)?,
                    model: r.get(3)?,
                    owner_id: r.get(4)?,
                    lease_expires_at: r.get(5)?,
                    created_at: r.get(6)?,
                    updated_at: r.get(7)?,
                })
            })
            .optional()?;
        Ok(row)
    }

    pub fn list_sessions(&self, limit: usize) -> Result<Vec<Session>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id,goal,state,model,owner_id,lease_expires_at,created_at,updated_at FROM sessions ORDER BY rowid DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit as i64], |r| {
            Ok(Session {
                id: r.get(0)?,
                goal: r.get(1)?,
                state: r.get(2)?,
                model: r.get(3)?,
                owner_id: r.get(4)?,
                lease_expires_at: r.get(5)?,
                created_at: r.get(6)?,
                updated_at: r.get(7)?,
            })
        })?;
        let mut out = vec![];
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    pub fn set_session_model(&self, id: &str, model: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE sessions SET model=?2, updated_at=?3 WHERE id=?1",
            params![id, model, now()],
        )?;
        Ok(())
    }

    pub fn set_session_state(&self, id: &str, state: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE sessions SET state=?2, updated_at=?3 WHERE id=?1",
            params![id, state, now()],
        )?;
        Ok(())
    }

    /// Claim a session for exclusive execution. Returns Ok if claimed or lease expired (reclaim).
    /// Returns Err if another owner holds a valid lease.
    /// Atomically claim a session. A single conditional UPDATE prevents two
    /// processes from both winning the same lease (the old SELECT-then-UPDATE
    /// was only safe inside one process).
    pub fn claim_session(&self, session_id: &str, owner_id: &str, lease_secs: i64) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let now_ts = Utc::now();
        let now_s = now_ts.to_rfc3339();
        let new_lease = (now_ts + Duration::seconds(lease_secs)).to_rfc3339();
        let affected = conn.execute(
            "UPDATE sessions SET owner_id=?2, lease_expires_at=?3, updated_at=?4
             WHERE id=?1 AND (owner_id IS NULL OR owner_id=?2 OR lease_expires_at IS NULL OR lease_expires_at <= ?5)",
            params![session_id, owner_id, new_lease, now_s, now_s],
        )?;
        if affected > 0 {
            return Ok(());
        }
        let current: Option<Option<String>> = conn
            .query_row(
                "SELECT lease_expires_at FROM sessions WHERE id=?1",
                params![session_id],
                |r| r.get(0),
            )
            .optional()?;
        match current {
            None => Err(anyhow::anyhow!("session not found: {session_id}")),
            Some(lease) => Err(anyhow::anyhow!(
                "session {session_id} is claimed by another owner (lease until {})",
                lease.unwrap_or_else(|| "unknown".into())
            )),
        }
    }

    pub fn renew_lease(&self, session_id: &str, owner_id: &str, lease_secs: i64) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let affected = conn.execute(
            "UPDATE sessions SET lease_expires_at=?3, updated_at=?4 WHERE id=?1 AND owner_id=?2",
            params![
                session_id,
                owner_id,
                (Utc::now() + Duration::seconds(lease_secs)).to_rfc3339(),
                now()
            ],
        )?;
        if affected == 0 {
            return Err(anyhow::anyhow!(
                "cannot renew lease: session {session_id} not owned by {owner_id}"
            ));
        }
        Ok(())
    }

    pub fn release_claim(&self, session_id: &str, owner_id: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE sessions SET owner_id=NULL, lease_expires_at=NULL, updated_at=?3 WHERE id=?1 AND owner_id=?2",
            params![session_id, owner_id, now()],
        )?;
        Ok(())
    }

    pub fn is_lease_expired(&self, session_id: &str) -> Result<bool> {
        let s = self
            .get_session(session_id)?
            .ok_or_else(|| anyhow::anyhow!("session not found: {session_id}"))?;
        match s.lease_expires_at {
            Some(lease) => {
                if let Some(exp) = parse_ts(&lease) {
                    Ok(Utc::now() > exp)
                } else {
                    Ok(true)
                }
            }
            None => Ok(true),
        }
    }

    /// Mark stale running sessions (expired lease or no owner) as interrupted.
    /// Returns ids of sessions that were transitioned.
    pub fn mark_stale_running_interrupted(&self) -> Result<Vec<String>> {
        let conn = self.conn.lock().unwrap();
        let now_ts = Utc::now();
        let mut stmt = conn
            .prepare("SELECT id, lease_expires_at, owner_id FROM sessions WHERE state='running'")?;
        let rows: Vec<(String, Option<String>, Option<String>)> = stmt
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
            .filter_map(|r| r.ok())
            .collect();
        let mut ids = Vec::new();
        for (id, lease, owner) in rows {
            let expired = match lease {
                Some(l) => parse_ts(&l).map(|e| e < now_ts).unwrap_or(true),
                None => true,
            };
            if expired || owner.is_none() {
                let changed = conn.execute(
                    "UPDATE sessions SET state='interrupted', owner_id=NULL, lease_expires_at=NULL, updated_at=?2 WHERE id=?1 AND state='running'",
                    params![id, now()],
                )?;
                if changed > 0 {
                    ids.push(id);
                }
            }
        }
        Ok(ids)
    }

    /// Guarded state transition: only transitions if current state is in `from`.
    pub fn transition_state(&self, id: &str, from: &[&str], to: &str) -> Result<bool> {
        let conn = self.conn.lock().unwrap();
        let cur: Option<String> = conn
            .query_row("SELECT state FROM sessions WHERE id=?1", params![id], |r| {
                r.get(0)
            })
            .optional()?;
        let Some(cur) = cur else {
            return Err(anyhow::anyhow!("session not found: {id}"));
        };
        if !from.contains(&cur.as_str()) {
            return Ok(false);
        }
        conn.execute(
            "UPDATE sessions SET state=?2, updated_at=?3 WHERE id=?1",
            params![id, to, now()],
        )?;
        Ok(true)
    }

    /// Set state and clear ownership/lease (used for terminal/parked states).
    pub fn set_state_release(&self, id: &str, state: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE sessions SET state=?2, owner_id=NULL, lease_expires_at=NULL, updated_at=?3 WHERE id=?1",
            params![id, state, now()],
        )?;
        Ok(())
    }

    pub fn add_message(&self, session_id: &str, role: &str, content: &str) -> Result<()> {
        self.add_message_full(session_id, role, content, None, None, None)
    }

    pub fn add_message_full(
        &self,
        session_id: &str,
        role: &str,
        content: &str,
        tool_call_id: Option<&str>,
        tool_calls_json: Option<&str>,
        name: Option<&str>,
    ) -> Result<()> {
        let id = Uuid::new_v4().to_string();
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO messages(id,session_id,role,content,tool_call_id,tool_calls_json,name) VALUES(?1,?2,?3,?4,?5,?6,?7)",
            params![id, session_id, role, content, tool_call_id, tool_calls_json, name],
        )?;
        Ok(())
    }

    pub fn list_messages(&self, session_id: &str) -> Result<Vec<Message>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id,session_id,role,content,tool_call_id,tool_calls_json,name FROM messages WHERE session_id=?1 ORDER BY rowid ASC",
        )?;
        let rows = stmt.query_map(params![session_id], |r| {
            Ok(Message {
                id: r.get(0)?,
                session_id: r.get(1)?,
                role: r.get(2)?,
                content: r.get::<_, Option<String>>(3)?.unwrap_or_default(),
                tool_call_id: r.get(4)?,
                tool_calls_json: r.get(5)?,
                name: r.get(6)?,
            })
        })?;
        let mut out = vec![];
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    pub fn create_approval(
        &self,
        session_id: &str,
        tool_name: &str,
        args_json: &str,
        risk: &str,
        reason: &str,
        tool_call_id: Option<&str>,
    ) -> Result<Approval> {
        self.create_approval_with_ttl(
            session_id,
            tool_name,
            args_json,
            risk,
            reason,
            tool_call_id,
            900,
        )
    }

    #[allow(clippy::too_many_arguments)] // stable public persistence API with TTL
    pub fn create_approval_with_ttl(
        &self,
        session_id: &str,
        tool_name: &str,
        args_json: &str,
        risk: &str,
        reason: &str,
        tool_call_id: Option<&str>,
        ttl_secs: i64,
    ) -> Result<Approval> {
        let created_at = now();
        let expires_at = (Utc::now() + Duration::seconds(ttl_secs)).to_rfc3339();
        let a = Approval {
            id: Uuid::new_v4().to_string(),
            session_id: session_id.to_string(),
            tool_name: tool_name.to_string(),
            args_json: args_json.to_string(),
            risk: risk.to_string(),
            status: "pending".to_string(),
            reason: Some(reason.to_string()),
            created_at,
            tool_call_id: tool_call_id.map(|s| s.to_string()),
            expires_at: Some(expires_at),
        };
        let conn = self.conn.lock().unwrap();
        Self::insert_approval(&conn, &a)?;
        Ok(a)
    }

    /// Insert an approval row inside an existing transaction. Shared by the
    /// single-approval API and the atomic park path.
    fn insert_approval(conn: &Connection, approval: &Approval) -> Result<()> {
        conn.execute(
            "INSERT INTO approvals(id,session_id,action,status,reason,tool_name,args_json,risk,created_at,tool_call_id,expires_at)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
            params![
                approval.id,
                approval.session_id,
                approval.tool_name,
                approval.status,
                approval.reason,
                approval.tool_name,
                approval.args_json,
                approval.risk,
                approval.created_at,
                approval.tool_call_id,
                approval.expires_at,
            ],
        )?;
        Ok(())
    }

    pub fn get_pending_approval(&self, session_id: &str) -> Result<Option<Approval>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id,session_id,COALESCE(tool_name,action),COALESCE(args_json,'{}'),COALESCE(risk,''),status,reason,COALESCE(created_at,''),tool_call_id,expires_at
             FROM approvals WHERE session_id=?1 AND status='pending'
             AND (expires_at IS NULL OR expires_at > ?2)
             ORDER BY rowid DESC LIMIT 1",
        )?;
        let row = stmt
            .query_row(params![session_id, now()], |r| {
                Ok(Approval {
                    id: r.get(0)?,
                    session_id: r.get(1)?,
                    tool_name: r.get(2)?,
                    args_json: r.get(3)?,
                    risk: r.get(4)?,
                    status: r.get(5)?,
                    reason: r.get(6)?,
                    created_at: r.get(7)?,
                    tool_call_id: r.get(8)?,
                    expires_at: r.get(9)?,
                })
            })
            .optional()?;
        Ok(row)
    }

    pub fn list_pending_approvals(&self, session_id: &str) -> Result<Vec<Approval>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id,session_id,COALESCE(tool_name,action),COALESCE(args_json,'{}'),COALESCE(risk,''),status,reason,COALESCE(created_at,''),tool_call_id,expires_at
             FROM approvals WHERE session_id=?1 AND status='pending'
             AND (expires_at IS NULL OR expires_at > ?2)
             ORDER BY rowid ASC",
        )?;
        let rows = stmt.query_map(params![session_id, now()], |r| {
            Ok(Approval {
                id: r.get(0)?,
                session_id: r.get(1)?,
                tool_name: r.get(2)?,
                args_json: r.get(3)?,
                risk: r.get(4)?,
                status: r.get(5)?,
                reason: r.get(6)?,
                created_at: r.get(7)?,
                tool_call_id: r.get(8)?,
                expires_at: r.get(9)?,
            })
        })?;
        let mut out = vec![];
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    /// Mark pending approvals whose TTL has elapsed as expired.
    /// Returns the number of rows transitioned.
    pub fn expire_stale_approvals(&self) -> Result<usize> {
        let conn = self.conn.lock().unwrap();
        let affected = conn.execute(
            "UPDATE approvals SET status='expired'
             WHERE status='pending' AND expires_at IS NOT NULL AND expires_at <= ?1",
            params![now()],
        )?;
        Ok(affected)
    }

    /// Resolve an approval only if it is still pending and unexpired. Two
    /// concurrent resolvers cannot both approve the same action.
    pub fn resolve_approval(&self, id: &str, status: &str, reason: Option<&str>) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let affected = conn.execute(
            "UPDATE approvals SET status=?2, reason=COALESCE(?3, reason)
             WHERE id=?1 AND status='pending'
               AND (expires_at IS NULL OR expires_at > ?4)",
            params![id, status, reason, now()],
        )?;
        if affected == 0 {
            return Err(anyhow::anyhow!(
                "approval already resolved or not found: {id}"
            ));
        }
        Ok(())
    }

    pub fn add_event(
        &self,
        session_id: &str,
        level: &str,
        kind: &str,
        message: &str,
    ) -> Result<()> {
        let id = Uuid::new_v4().to_string();
        let created_at = now();
        let conn = self.conn.lock().unwrap();
        let prev_hash: Option<String> = conn
            .query_row(
                "SELECT hash FROM events WHERE session_id=?1 ORDER BY rowid DESC LIMIT 1",
                params![session_id],
                |r| r.get(0),
            )
            .optional()?;
        let prev = prev_hash.clone().unwrap_or_default();
        let hash = sha256_hex(&format!(
            "{prev}|{id}|{session_id}|{level}|{kind}|{message}|{created_at}"
        ));
        conn.execute(
            "INSERT INTO events(id,session_id,level,kind,message,created_at,prev_hash,hash)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
            params![id, session_id, level, kind, message, created_at, prev_hash, hash],
        )?;
        Ok(())
    }

    /// Recompute the SHA-256 chain for a session in insertion order and
    /// confirm every stored hash and link is intact.
    pub fn verify_event_chain(&self, session_id: &str) -> Result<bool> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id,session_id,level,kind,message,created_at,prev_hash,hash
             FROM events WHERE session_id=?1 ORDER BY rowid ASC",
        )?;
        let rows = stmt.query_map(params![session_id], |r| {
            Ok(Event {
                id: r.get(0)?,
                session_id: r.get(1)?,
                level: r.get(2)?,
                kind: r.get(3)?,
                message: r.get(4)?,
                created_at: r.get(5)?,
                prev_hash: r.get(6)?,
                hash: r.get::<_, Option<String>>(7)?.unwrap_or_default(),
            })
        })?;
        let mut expected_prev = String::new();
        for row in rows {
            let event = row?;
            if event.prev_hash.as_deref().unwrap_or_default() != expected_prev {
                return Ok(false);
            }
            let recomputed = sha256_hex(&format!(
                "{}|{}|{}|{}|{}|{}|{}",
                expected_prev,
                event.id,
                event.session_id,
                event.level,
                event.kind,
                event.message,
                event.created_at
            ));
            if event.hash != recomputed {
                return Ok(false);
            }
            expected_prev = recomputed;
        }
        Ok(true)
    }

    pub fn list_events(&self, session_id: &str, limit: usize) -> Result<Vec<Event>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id,session_id,level,kind,message,created_at,prev_hash,hash
             FROM events WHERE session_id=?1 ORDER BY rowid DESC LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![session_id, limit as i64], |r| {
            Ok(Event {
                id: r.get(0)?,
                session_id: r.get(1)?,
                level: r.get(2)?,
                kind: r.get(3)?,
                message: r.get(4)?,
                created_at: r.get(5)?,
                prev_hash: r.get(6)?,
                hash: r.get::<_, Option<String>>(7)?.unwrap_or_default(),
            })
        })?;
        let mut out = vec![];
        for r in rows {
            out.push(r?);
        }
        out.reverse();
        Ok(out)
    }

    pub fn list_all_events(&self, limit: usize) -> Result<Vec<Event>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id,session_id,level,kind,message,created_at,prev_hash,hash
             FROM events ORDER BY rowid DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit as i64], |r| {
            Ok(Event {
                id: r.get(0)?,
                session_id: r.get(1)?,
                level: r.get(2)?,
                kind: r.get(3)?,
                message: r.get(4)?,
                created_at: r.get(5)?,
                prev_hash: r.get(6)?,
                hash: r.get::<_, Option<String>>(7)?.unwrap_or_default(),
            })
        })?;
        let mut out = vec![];
        for r in rows {
            out.push(r?);
        }
        out.reverse();
        Ok(out)
    }

    #[allow(clippy::too_many_arguments)] // stable public persistence API
    pub fn add_finding(
        &self,
        session_id: &str,
        title: &str,
        severity: &str,
        asset: Option<&str>,
        vuln_type: Option<&str>,
        description: &str,
        reproduction: Option<&str>,
        impact: Option<&str>,
        remediation: Option<&str>,
        evidence: Option<&str>,
    ) -> Result<Finding> {
        let ts = now();
        let f = Finding {
            id: Uuid::new_v4().to_string(),
            session_id: session_id.to_string(),
            title: title.to_string(),
            severity: severity.to_string(),
            asset: asset.map(|s| s.to_string()),
            vuln_type: vuln_type.map(|s| s.to_string()),
            description: description.to_string(),
            reproduction: reproduction.map(|s| s.to_string()),
            impact: impact.map(|s| s.to_string()),
            remediation: remediation.map(|s| s.to_string()),
            evidence: evidence.map(|s| s.to_string()),
            status: "open".to_string(),
            created_at: ts.clone(),
            updated_at: ts,
            request: None,
            response: None,
            cvss: None,
            cwe: None,
            dedupe_key: None,
            evidence_hash: None,
            validated_at: None,
            validation_detail: None,
            verdict: None,
            gap_reason: None,
            counterevidence: None,
            confidence: None,
            confidence_rationale: None,
            severity_change_conditions: None,
            oracle_type: None,
        };
        let conn = self.conn.lock().unwrap();
        Self::insert_finding(&conn, &f)?;
        Ok(f)
    }

    #[allow(clippy::too_many_arguments)] // evidence-rich persistence API
    pub fn add_finding_with_evidence(
        &self,
        session_id: &str,
        title: &str,
        severity: &str,
        asset: Option<&str>,
        vuln_type: Option<&str>,
        description: &str,
        reproduction: Option<&str>,
        impact: Option<&str>,
        remediation: Option<&str>,
        evidence: Option<&str>,
        request: Option<&str>,
        response: Option<&str>,
        cvss: Option<&str>,
        cwe: Option<&str>,
    ) -> Result<Option<Finding>> {
        let dedupe_key = format!(
            "{}|{}|{}",
            title,
            asset.unwrap_or_default(),
            vuln_type.unwrap_or_default()
        )
        .to_lowercase();
        let conn = self.conn.lock().unwrap();
        let existing: Option<i64> = conn
            .query_row(
                "SELECT 1 FROM findings WHERE session_id=?1 AND dedupe_key=?2 LIMIT 1",
                params![session_id, dedupe_key],
                |r| r.get(0),
            )
            .optional()?;
        if existing.is_some() {
            return Ok(None);
        }
        let ts = now();
        let f = Finding {
            id: Uuid::new_v4().to_string(),
            session_id: session_id.to_string(),
            title: title.to_string(),
            severity: severity.to_string(),
            asset: asset.map(|s| s.to_string()),
            vuln_type: vuln_type.map(|s| s.to_string()),
            description: description.to_string(),
            reproduction: reproduction.map(|s| s.to_string()),
            impact: impact.map(|s| s.to_string()),
            remediation: remediation.map(|s| s.to_string()),
            evidence: evidence.map(|s| s.to_string()),
            status: "open".to_string(),
            created_at: ts.clone(),
            updated_at: ts,
            request: request.map(|s| s.to_string()),
            response: response.map(|s| s.to_string()),
            cvss: cvss.map(|s| s.to_string()),
            cwe: cwe.map(|s| s.to_string()),
            dedupe_key: Some(dedupe_key),
            evidence_hash: Some(Self::evidence_hash(evidence, request, response)),
            validated_at: None,
            validation_detail: None,
            verdict: None,
            gap_reason: None,
            counterevidence: None,
            confidence: None,
            confidence_rationale: None,
            severity_change_conditions: None,
            oracle_type: None,
        };
        Self::insert_finding(&conn, &f)?;
        Ok(Some(f))
    }

    fn insert_finding(conn: &Connection, f: &Finding) -> Result<()> {
        conn.execute(
            "INSERT INTO findings(id,session_id,title,severity,asset,vuln_type,description,reproduction,impact,remediation,evidence,status,created_at,updated_at,request,response,cvss,cwe,dedupe_key,evidence_hash,validated_at,validation_detail)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21,?22)",
            params![
                f.id, f.session_id, f.title, f.severity, f.asset, f.vuln_type, f.description,
                f.reproduction, f.impact, f.remediation, f.evidence, f.status, f.created_at, f.updated_at,
                f.request, f.response, f.cvss, f.cwe, f.dedupe_key, f.evidence_hash,
                f.validated_at, f.validation_detail
            ],
        )?;
        Ok(())
    }

    /// SHA-256 over `request || response || evidence(artifact)`, rendered as 64-hex.
    pub fn evidence_hash(
        evidence: Option<&str>,
        request: Option<&str>,
        response: Option<&str>,
    ) -> String {
        sha256_evidence_bytes(
            request.unwrap_or("").as_bytes(),
            response.unwrap_or("").as_bytes(),
            evidence.map(str::as_bytes),
        )
    }

    pub fn list_findings(&self, session_id: &str) -> Result<Vec<Finding>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id,session_id,title,severity,asset,vuln_type,description,reproduction,impact,remediation,evidence,status,created_at,updated_at,request,response,cvss,cwe,dedupe_key,evidence_hash,validated_at,validation_detail,verdict,gap_reason,
             counterevidence,confidence,confidence_rationale,severity_change_conditions,oracle_type
             FROM findings WHERE session_id=?1 ORDER BY rowid ASC",
        )?;
        let rows = stmt.query_map(params![session_id], |r| {
            Ok(Finding {
                id: r.get(0)?,
                session_id: r.get(1)?,
                title: r.get(2)?,
                severity: r.get(3)?,
                asset: r.get(4)?,
                vuln_type: r.get(5)?,
                description: r.get(6)?,
                reproduction: r.get(7)?,
                impact: r.get(8)?,
                remediation: r.get(9)?,
                evidence: r.get(10)?,
                status: r.get(11)?,
                created_at: r.get(12)?,
                updated_at: r.get(13)?,
                request: r.get(14)?,
                response: r.get(15)?,
                cvss: r.get(16)?,
                cwe: r.get(17)?,
                dedupe_key: r.get(18)?,
                evidence_hash: r.get(19)?,
                validated_at: r.get(20)?,
                validation_detail: r.get(21)?,
                verdict: r.get(22)?,
                gap_reason: r.get(23)?,
                counterevidence: r.get(24)?,
                confidence: r.get(25)?,
                confidence_rationale: r.get(26)?,
                severity_change_conditions: r.get(27)?,
                oracle_type: r.get(28)?,
            })
        })?;
        let mut out = vec![];
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// Attach authoritative raw tool bytes for a finding. Re-attaching replaces
    /// the prior capture so retrying a tool call cannot leave stale evidence.
    pub fn attach_capture(
        &self,
        finding_id: &str,
        request: &[u8],
        response: &[u8],
        canary: &str,
    ) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO tool_captures(finding_id,request_bytes,response_bytes,canary,created_at)
             VALUES(?1,?2,?3,?4,?5)
             ON CONFLICT(finding_id) DO UPDATE SET
               request_bytes=excluded.request_bytes, response_bytes=excluded.response_bytes,
               canary=excluded.canary, created_at=excluded.created_at",
            params![finding_id, request, response, canary, now()],
        )?;
        Ok(())
    }

    /// Read the authoritative bytes recorded for a finding, if any.
    pub fn get_capture(&self, finding_id: &str) -> Result<Option<ToolCapture>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT finding_id,request_bytes,response_bytes,canary,created_at
             FROM tool_captures WHERE finding_id=?1",
        )?;
        let row = stmt
            .query_row(params![finding_id], |r| {
                Ok(ToolCapture {
                    finding_id: r.get(0)?,
                    request_bytes: r.get(1)?,
                    response_bytes: r.get(2)?,
                    canary: r.get(3)?,
                    created_at: r.get(4)?,
                })
            })
            .optional()?;
        Ok(row)
    }

    /// Keep the most recent tool-generated capture for a session. Written by
    /// the sink for every tool result carrying `structured.capture`, so the
    /// bytes exist even when the tool name has no domain meaning.
    pub fn put_session_capture(
        &self,
        session_id: &str,
        request: &[u8],
        response: &[u8],
        canary: &str,
    ) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO session_captures(session_id, request_bytes, response_bytes, canary, created_at)
             VALUES (?1,?2,?3,?4,?5)
             ON CONFLICT(session_id) DO UPDATE SET
               request_bytes=excluded.request_bytes,
               response_bytes=excluded.response_bytes,
               canary=excluded.canary, created_at=excluded.created_at",
            params![session_id, request, response, canary, now()],
        )?;
        Ok(())
    }

    /// Consume the pending capture once, so a stale exchange cannot be attached
    /// to a later, unrelated finding.
    pub fn take_session_capture(&self, session_id: &str) -> Result<Option<ToolCapture>> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        let found: Option<ToolCapture> = tx
            .query_row(
                "SELECT session_id, request_bytes, response_bytes, canary, created_at
                 FROM session_captures WHERE session_id=?1",
                params![session_id],
                |r| {
                    Ok(ToolCapture {
                        finding_id: r.get(0)?,
                        request_bytes: r.get(1)?,
                        response_bytes: r.get(2)?,
                        canary: r.get(3)?,
                        created_at: r.get(4)?,
                    })
                },
            )
            .optional()?;
        if found.is_some() {
            tx.execute(
                "DELETE FROM session_captures WHERE session_id=?1",
                params![session_id],
            )?;
        }
        tx.commit()?;
        Ok(found)
    }

    /// Attach a control capture. Idempotent per `(finding_id, role)` and
    /// independent of the primary `tool_captures` row.
    pub fn attach_role_capture(
        &self,
        finding_id: &str,
        role: &str,
        request: &[u8],
        response: &[u8],
        canary: &str,
        marker: Option<&str>,
    ) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO finding_captures(id, finding_id, role, request_bytes,
             response_bytes, canary, marker, created_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8)
             ON CONFLICT(finding_id, role) DO UPDATE SET
               request_bytes=excluded.request_bytes,
               response_bytes=excluded.response_bytes,
               canary=excluded.canary, marker=excluded.marker,
               created_at=excluded.created_at",
            params![
                Uuid::new_v4().to_string(),
                finding_id,
                role,
                request,
                response,
                canary,
                marker,
                now()
            ],
        )?;
        Ok(())
    }

    pub fn get_role_capture(&self, finding_id: &str, role: &str) -> Result<Option<RoleCapture>> {
        let conn = self.conn.lock().unwrap();
        Ok(conn
            .query_row(
                "SELECT finding_id, role, request_bytes, response_bytes, canary, marker, created_at
             FROM finding_captures WHERE finding_id=?1 AND role=?2",
                params![finding_id, role],
                |r| {
                    Ok(RoleCapture {
                        finding_id: r.get(0)?,
                        role: r.get(1)?,
                        request_bytes: r.get(2)?,
                        response_bytes: r.get(3)?,
                        canary: r.get(4)?,
                        marker: r.get(5)?,
                        created_at: r.get(6)?,
                    })
                },
            )
            .optional()?)
    }

    /// Record a ternary closure verdict. Never stamps `validated_at`, so a
    /// ruled-out or unresolved finding can never satisfy `verified_findings`.
    pub fn set_finding_verdict(
        &self,
        finding_id: &str,
        verdict: &str,
        gap_reason: Option<&str>,
    ) -> Result<()> {
        anyhow::ensure!(
            matches!(verdict, "confirmed" | "ruled_out" | "open_proof_gap"),
            "unsupported verdict: {verdict}"
        );
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE findings SET verdict=?2, gap_reason=?3 WHERE id=?1",
            params![finding_id, verdict, gap_reason],
        )?;
        Ok(())
    }

    /// Findings with the given status for a session, oldest first.
    pub fn list_findings_by_status(&self, session_id: &str, status: &str) -> Result<Vec<Finding>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id,session_id,title,severity,asset,vuln_type,description,reproduction,impact,remediation,evidence,status,created_at,updated_at,request,response,cvss,cwe,dedupe_key,evidence_hash,validated_at,validation_detail,verdict,gap_reason,
             counterevidence,confidence,confidence_rationale,severity_change_conditions,oracle_type
             FROM findings WHERE session_id=?1 AND status=?2 ORDER BY rowid ASC",
        )?;
        let rows = stmt.query_map(params![session_id, status], |r| {
            Ok(Finding {
                id: r.get(0)?,
                session_id: r.get(1)?,
                title: r.get(2)?,
                severity: r.get(3)?,
                asset: r.get(4)?,
                vuln_type: r.get(5)?,
                description: r.get(6)?,
                reproduction: r.get(7)?,
                impact: r.get(8)?,
                remediation: r.get(9)?,
                evidence: r.get(10)?,
                status: r.get(11)?,
                created_at: r.get(12)?,
                updated_at: r.get(13)?,
                request: r.get(14)?,
                response: r.get(15)?,
                cvss: r.get(16)?,
                cwe: r.get(17)?,
                dedupe_key: r.get(18)?,
                evidence_hash: r.get(19)?,
                validated_at: r.get(20)?,
                validation_detail: r.get(21)?,
                verdict: r.get(22)?,
                gap_reason: r.get(23)?,
                counterevidence: r.get(24)?,
                confidence: r.get(25)?,
                confidence_rationale: r.get(26)?,
                severity_change_conditions: r.get(27)?,
                oracle_type: r.get(28)?,
            })
        })?;
        let mut out = vec![];
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    /// Record the validation outcome of a finding, stamping the time it was checked.
    pub fn set_finding_falsification(
        &self,
        id: &str,
        counterevidence: Option<&str>,
        confidence: Option<&str>,
        confidence_rationale: Option<&str>,
        severity_change_conditions: Option<&str>,
        oracle_type: Option<&str>,
    ) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE findings SET counterevidence=?2, confidence=?3,
             confidence_rationale=?4, severity_change_conditions=?5, oracle_type=?6
             WHERE id=?1",
            params![
                id,
                counterevidence,
                confidence,
                confidence_rationale,
                severity_change_conditions,
                oracle_type
            ],
        )?;
        Ok(())
    }

    pub fn set_finding_validation(
        &self,
        id: &str,
        status: &str,
        detail: Option<&str>,
    ) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE findings SET status=?2, validated_at=?3, validation_detail=?4 WHERE id=?1",
            params![id, status, now(), detail],
        )?;
        Ok(())
    }

    pub fn upsert_asset(
        &self,
        session_id: &str,
        kind: &str,
        value: &str,
        metadata_json: Option<&str>,
    ) -> Result<Asset> {
        let ts = now();
        let id = Uuid::new_v4().to_string();
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO assets(id,session_id,kind,value,metadata_json,first_seen,last_seen)
             VALUES(?1,?2,?3,?4,?5,?6,?6)
             ON CONFLICT(session_id,kind,value) DO UPDATE SET
               metadata_json=COALESCE(excluded.metadata_json, metadata_json),
               last_seen=excluded.last_seen",
            params![id, session_id, kind, value, metadata_json, ts],
        )?;
        let mut stmt = conn.prepare(
            "SELECT id,session_id,kind,value,metadata_json,first_seen,last_seen FROM assets WHERE session_id=?1 AND kind=?2 AND value=?3",
        )?;
        let a = stmt.query_row(params![session_id, kind, value], |r| {
            Ok(Asset {
                id: r.get(0)?,
                session_id: r.get(1)?,
                kind: r.get(2)?,
                value: r.get(3)?,
                metadata_json: r.get(4)?,
                first_seen: r.get(5)?,
                last_seen: r.get(6)?,
            })
        })?;
        Ok(a)
    }

    pub fn list_assets(&self, session_id: &str) -> Result<Vec<Asset>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id,session_id,kind,value,metadata_json,first_seen,last_seen FROM assets WHERE session_id=?1 ORDER BY kind, value",
        )?;
        let rows = stmt.query_map(params![session_id], |r| {
            Ok(Asset {
                id: r.get(0)?,
                session_id: r.get(1)?,
                kind: r.get(2)?,
                value: r.get(3)?,
                metadata_json: r.get(4)?,
                first_seen: r.get(5)?,
                last_seen: r.get(6)?,
            })
        })?;
        let mut out = vec![];
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    pub fn add_artifact(
        &self,
        session_id: &str,
        kind: &str,
        path: Option<&str>,
        content: Option<&str>,
        metadata_json: Option<&str>,
    ) -> Result<Artifact> {
        let a = Artifact {
            id: Uuid::new_v4().to_string(),
            session_id: session_id.to_string(),
            kind: kind.to_string(),
            path: path.map(|s| s.to_string()),
            content: content.map(|s| s.to_string()),
            metadata_json: metadata_json.map(|s| s.to_string()),
            created_at: now(),
        };
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO artifacts(id,session_id,kind,path,content,metadata_json,created_at) VALUES(?1,?2,?3,?4,?5,?6,?7)",
            params![a.id, a.session_id, a.kind, a.path, a.content, a.metadata_json, a.created_at],
        )?;
        Ok(a)
    }

    pub fn list_artifacts(&self, session_id: &str) -> Result<Vec<Artifact>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id,session_id,kind,path,content,metadata_json,created_at FROM artifacts WHERE session_id=?1 ORDER BY rowid ASC",
        )?;
        let rows = stmt.query_map(params![session_id], |r| {
            Ok(Artifact {
                id: r.get(0)?,
                session_id: r.get(1)?,
                kind: r.get(2)?,
                path: r.get(3)?,
                content: r.get(4)?,
                metadata_json: r.get(5)?,
                created_at: r.get(6)?,
            })
        })?;
        let mut out = vec![];
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    pub fn export_report(&self, session_id: &str) -> Result<String> {
        self.report(session_id)
    }
    pub fn export_session_report(&self, session_id: &str) -> Result<String> {
        self.report(session_id)
    }
    pub fn report(&self, session_id: &str) -> Result<String> {
        let session = self
            .get_session(session_id)?
            .ok_or_else(|| anyhow::anyhow!("session not found"))?;
        let findings = self.list_findings(session_id)?;
        let assets = self.list_assets(session_id)?;
        let artifacts = self.list_artifacts(session_id)?;
        let coverage = self.list_coverage(session_id)?;
        let hypotheses = self.list_hypotheses(session_id)?;
        let events = self.list_events(session_id, 1000)?;
        let mut out = String::new();
        out.push_str("# AgentBug Report\n\n");
        out.push_str(&format!("Session: {}\n", session.id));
        out.push_str(&format!("Goal: {}\n", redact(&session.goal)));
        out.push_str(&format!("State: {}\n\n", session.state));
        out.push_str("## Findings\n");
        if findings.is_empty() {
            out.push_str("(none)\n");
        }
        for f in findings {
            out.push_str(&format!("- [{}] {}", f.severity, redact(&f.title)));
            if let Some(a) = &f.asset {
                out.push_str(&format!(" (asset: {})", redact(a)));
            }
            out.push('\n');
            if !f.description.is_empty() {
                out.push_str(&format!("  {}\n", redact(&f.description)));
            }
            if let Some(r) = &f.reproduction {
                out.push_str(&format!("  Repro: {}\n", redact(r)));
            }
            if let Some(i) = &f.impact {
                out.push_str(&format!("  Impact: {}\n", redact(i)));
            }
            if let Some(rm) = &f.remediation {
                out.push_str(&format!("  Remediation: {}\n", redact(rm)));
            }
            if let Some(e) = &f.evidence {
                out.push_str(&format!("  Evidence: {}\n", redact(e)));
            }
            if let Some(rq) = &f.request {
                out.push_str(&format!("  Request: {}\n", redact(rq)));
            }
            if let Some(rs) = &f.response {
                out.push_str(&format!("  Response: {}\n", redact(rs)));
            }
            if let Some(c) = &f.cvss {
                out.push_str(&format!("  CVSS: {}\n", redact(c)));
            }
            if let Some(c) = &f.cwe {
                out.push_str(&format!("  CWE: {}\n", redact(c)));
            }
        }
        out.push_str("\n## Assets\n");
        if assets.is_empty() {
            out.push_str("(none)\n");
        }
        for a in assets {
            out.push_str(&format!("- {} = {}\n", a.kind, redact(&a.value)));
        }
        out.push_str("\n## Artifacts\n");
        if artifacts.is_empty() {
            out.push_str("(none)\n");
        }
        for a in artifacts {
            out.push_str(&format!(
                "- {} {}\n",
                a.kind,
                redact(&a.path.clone().unwrap_or_default())
            ));
            if let Some(c) = &a.content {
                out.push_str(&format!("  {}\n", redact(c)));
            }
            if let Some(m) = &a.metadata_json {
                out.push_str(&format!("  metadata: {}\n", redact(m)));
            }
        }
        out.push_str("\n## Coverage\n");
        if coverage.is_empty() {
            out.push_str("(none)\n");
        }
        for c in coverage {
            out.push_str(&format!(
                "- {} {} {}\n",
                redact(&c.method),
                redact(&c.target),
                redact(&c.path)
            ));
        }
        out.push_str("\n## Hypotheses\n");
        if hypotheses.is_empty() {
            out.push_str("(none)\n");
        }
        for h in hypotheses {
            out.push_str(&format!(
                "- [{}] {}\n",
                redact(&h.status),
                redact(&h.statement)
            ));
        }
        out.push_str("\n## Timeline\n");
        for e in events {
            out.push_str(&format!(
                "- {} [{}] {}\n",
                e.created_at,
                e.kind,
                redact(&e.message)
            ));
        }
        Ok(out)
    }

    pub fn ensure_budget(&self, session_id: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR IGNORE INTO session_budgets(session_id) VALUES(?1)",
            params![session_id],
        )?;
        Ok(())
    }

    /// Seed the inherited usage of a parent session into a child budget row.
    ///
    /// Idempotent: the offsets are written only once, when every offset is
    /// still zero. Later calls (including retries) are no-ops, so a resumed
    /// child cannot reset or double-apply its inherited usage. A row with all
    /// zero offsets is indistinguishable from a row created before inheritance
    /// existed.
    pub fn seed_budget_offsets(
        &self,
        session_id: &str,
        steps: usize,
        tool_calls: usize,
        network_calls: usize,
        tokens: usize,
    ) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR IGNORE INTO session_budgets(session_id) VALUES(?1)",
            params![session_id],
        )?;
        conn.execute(
            "UPDATE session_budgets SET
               steps_offset=?2, tool_calls_offset=?3,
               network_calls_offset=?4, tokens_offset=?5
             WHERE session_id=?1 AND steps_offset=0 AND tool_calls_offset=0
               AND network_calls_offset=0 AND tokens_offset=0",
            params![
                session_id,
                steps as i64,
                tool_calls as i64,
                network_calls as i64,
                tokens as i64
            ],
        )?;
        Ok(())
    }

    /// Durable usage snapshot. The requests-per-minute window rolls over after 60s.
    /// Inherited offsets are added to the raw counters so the existing budget
    /// gates see the parent's usage as if the child had spent it itself.
    pub fn budget_usage(&self, session_id: &str) -> Result<BudgetUsage> {
        let conn = self.conn.lock().unwrap();
        let row: Option<(i64, i64, i64, i64, i64)> = conn
            .query_row(
                "SELECT steps_used + steps_offset,
                        tool_calls_used + tool_calls_offset,
                        network_calls_used + network_calls_offset,
                        window_start_ms, calls_in_window
                 FROM session_budgets WHERE session_id=?1",
                params![session_id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .optional()?;
        let Some((steps, tools, network, start, window)) = row else {
            return Ok(BudgetUsage::default());
        };
        let now = Utc::now().timestamp_millis();
        let calls_in_window = if now.saturating_sub(start) >= 60_000 {
            0
        } else {
            window.max(0) as usize
        };
        Ok(BudgetUsage {
            steps_used: steps.max(0) as usize,
            tool_calls_used: tools.max(0) as usize,
            network_calls_used: network.max(0) as usize,
            calls_in_window,
        })
    }

    pub fn record_step(&self, session_id: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO session_budgets(session_id, steps_used) VALUES(?1, 1)
             ON CONFLICT(session_id) DO UPDATE SET steps_used = steps_used + 1",
            params![session_id],
        )?;
        Ok(())
    }

    /// Increment tool/network counters atomically, including the rolling rate window.
    pub fn record_tool_call(&self, session_id: &str, network: bool) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let now = Utc::now().timestamp_millis();
        let net = i64::from(network);
        conn.execute(
            "INSERT INTO session_budgets(session_id, tool_calls_used, network_calls_used, window_start_ms, calls_in_window)
             VALUES(?1, 1, ?2, ?3, 1)
             ON CONFLICT(session_id) DO UPDATE SET
               tool_calls_used = tool_calls_used + 1,
               network_calls_used = network_calls_used + ?2,
               window_start_ms = CASE WHEN ?3 - window_start_ms >= 60000 THEN ?3 ELSE window_start_ms END,
               calls_in_window = CASE WHEN ?3 - window_start_ms >= 60000 THEN 1 ELSE calls_in_window + 1 END",
            params![session_id, net, now],
        )?;
        Ok(())
    }

    /// Guarded transition that also verifies the caller still owns a live lease.
    pub fn transition_state_owned(
        &self,
        session_id: &str,
        owner_id: &str,
        from: &[&str],
        to: &str,
    ) -> Result<bool> {
        let conn = self.conn.lock().unwrap();
        let current: Option<(String, Option<String>, Option<String>)> = conn
            .query_row(
                "SELECT state, owner_id, lease_expires_at FROM sessions WHERE id=?1",
                params![session_id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        let Some((state, owner, lease)) = current else {
            return Err(anyhow::anyhow!("session not found: {session_id}"));
        };
        if owner.as_deref() != Some(owner_id) || !from.contains(&state.as_str()) {
            return Ok(false);
        }
        if let Some(lease) = lease {
            if parse_ts(&lease).map(|e| e <= Utc::now()).unwrap_or(true) {
                return Ok(false);
            }
        }
        conn.execute(
            "UPDATE sessions SET state=?4, updated_at=?5 WHERE id=?1 AND state=?2 AND owner_id=?3",
            params![session_id, state, owner_id, to, now()],
        )?;
        Ok(true)
    }

    /// Persist the unexecuted tail of a tool-call batch that was parked on approval.
    pub fn save_pending_calls<S: AsRef<str>>(
        &self,
        session_id: &str,
        approval_id: &str,
        calls: &[(Option<&str>, &str, S)],
    ) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        Self::insert_pending_calls(&conn, session_id, approval_id, calls)
    }

    /// Insert deferred tool calls inside an existing transaction. Shared by
    /// the standalone API and the atomic park path.
    fn insert_pending_calls<S: AsRef<str>>(
        conn: &Connection,
        session_id: &str,
        approval_id: &str,
        calls: &[(Option<&str>, &str, S)],
    ) -> Result<()> {
        for (seq, (tool_call_id, name, args_json)) in calls.iter().enumerate() {
            conn.execute(
                "INSERT INTO pending_tool_calls(id,session_id,approval_id,tool_call_id,name,args_json,seq)
                 VALUES(?1,?2,?3,?4,?5,?6,?7)",
                params![
                    Uuid::new_v4().to_string(),
                    session_id,
                    approval_id,
                    *tool_call_id,
                    *name,
                    args_json.as_ref(),
                    seq as i64
                ],
            )?;
        }
        Ok(())
    }

    /// Park a session behind an approval in a single SQLite transaction: the
    /// approval row, the deferred tool calls, and the guarded state change all
    /// commit together or none of them do.
    pub fn park_with_approval(
        &self,
        approval: &Approval,
        tail: &[(Option<&str>, &str, &str)],
        session_id: &str,
    ) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute_batch("BEGIN IMMEDIATE")?;
        let result = (|| -> Result<()> {
            // The parked approval must be pending and carry a TTL even when the
            // caller supplied a partially populated Approval value.
            let row = Approval {
                id: approval.id.clone(),
                session_id: approval.session_id.clone(),
                tool_name: approval.tool_name.clone(),
                args_json: approval.args_json.clone(),
                risk: approval.risk.clone(),
                status: "pending".to_string(),
                reason: approval.reason.clone(),
                created_at: if approval.created_at.is_empty() {
                    now()
                } else {
                    approval.created_at.clone()
                },
                tool_call_id: approval.tool_call_id.clone(),
                expires_at: Some(match &approval.expires_at {
                    Some(expires_at) => expires_at.clone(),
                    None => (Utc::now() + Duration::seconds(900)).to_rfc3339(),
                }),
            };
            Self::insert_approval(&conn, &row)?;
            Self::insert_pending_calls(&conn, session_id, &row.id, tail)?;
            conn.execute(
                "UPDATE sessions SET state='waiting_approval', owner_id=NULL,
                 lease_expires_at=NULL, updated_at=?2 WHERE id=?1",
                params![session_id, now()],
            )?;
            Ok(())
        })();
        match result {
            Ok(()) => {
                conn.execute_batch("COMMIT")?;
                Ok(())
            }
            Err(e) => {
                let _ = conn.execute_batch("ROLLBACK");
                Err(e)
            }
        }
    }

    /// Take (and remove) the pending tail in one transaction so a resumed run
    /// cannot execute the same deferred calls twice.
    pub fn take_pending_calls(
        &self,
        session_id: &str,
        approval_id: &str,
    ) -> Result<Vec<PendingCall>> {
        let conn = self.conn.lock().unwrap();
        conn.execute_batch("BEGIN IMMEDIATE")?;
        let result = (|| -> Result<Vec<PendingCall>> {
            let mut stmt = conn.prepare(
                "SELECT tool_call_id,name,args_json FROM pending_tool_calls
                 WHERE session_id=?1 AND approval_id=?2 ORDER BY seq ASC",
            )?;
            let rows = stmt.query_map(params![session_id, approval_id], |r| {
                Ok(PendingCall {
                    tool_call_id: r.get(0)?,
                    name: r.get(1)?,
                    args_json: r.get(2)?,
                })
            })?;
            let mut out = Vec::new();
            for row in rows {
                out.push(row?);
            }
            conn.execute(
                "DELETE FROM pending_tool_calls WHERE session_id=?1 AND approval_id=?2",
                params![session_id, approval_id],
            )?;
            Ok(out)
        })();
        match result {
            Ok(out) => {
                conn.execute_batch("COMMIT")?;
                Ok(out)
            }
            Err(e) => {
                let _ = conn.execute_batch("ROLLBACK");
                Err(e)
            }
        }
    }

    pub fn record_coverage(
        &self,
        session_id: &str,
        target: &str,
        method: &str,
        path: &str,
    ) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR IGNORE INTO coverage(id,session_id,target,method,path,created_at)
             VALUES(?1,?2,?3,?4,?5,?6)",
            params![
                Uuid::new_v4().to_string(),
                session_id,
                target,
                method,
                path,
                now()
            ],
        )?;
        Ok(())
    }

    /// Requirement-keyed coverage decision. Attempted-and-denied is a valid
    /// `blocked` row, so a ROE-restricted engagement still has honest coverage.
    pub fn record_coverage_decision(&self, decision: CoverageDecision<'_>) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO coverage(id,session_id,target,method,path,created_at,
             requirement_id,status,rationale,evidence_ref)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)
             ON CONFLICT(session_id,target,method,path,requirement_id) DO UPDATE SET
               status=excluded.status, rationale=excluded.rationale,
               evidence_ref=excluded.evidence_ref",
            params![
                Uuid::new_v4().to_string(),
                decision.session_id,
                decision.target,
                decision.method,
                decision.path,
                now(),
                decision.requirement_id,
                decision.status,
                decision.rationale,
                decision.evidence_ref
            ],
        )?;
        Ok(())
    }

    pub fn covered_requirement_count(&self, session_id: &str) -> Result<usize> {
        let conn = self.conn.lock().unwrap();
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM coverage WHERE session_id=?1 AND status='covered'",
            params![session_id],
            |r| r.get(0),
        )?;
        Ok(count as usize)
    }

    pub fn coverage_count(&self, session_id: &str) -> Result<usize> {
        let conn = self.conn.lock().unwrap();
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM coverage WHERE session_id=?1",
            params![session_id],
            |r| r.get(0),
        )?;
        Ok(count as usize)
    }

    pub fn list_coverage(&self, session_id: &str) -> Result<Vec<Coverage>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id,session_id,target,method,path,created_at,requirement_id,status,rationale,evidence_ref
             FROM coverage WHERE session_id=?1 ORDER BY rowid ASC",
        )?;
        let rows = stmt.query_map(params![session_id], |r| {
            Ok(Coverage {
                id: r.get(0)?,
                session_id: r.get(1)?,
                target: r.get(2)?,
                method: r.get(3)?,
                path: r.get(4)?,
                created_at: r.get(5)?,
                requirement_id: r.get::<_, Option<String>>(6)?.unwrap_or_default(),
                status: r
                    .get::<_, Option<String>>(7)?
                    .unwrap_or_else(|| "covered".to_string()),
                rationale: r.get::<_, Option<String>>(8)?.unwrap_or_default(),
                evidence_ref: r.get::<_, Option<String>>(9)?.unwrap_or_default(),
            })
        })?;
        let mut out = vec![];
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    pub fn add_hypothesis(&self, session_id: &str, statement: &str) -> Result<Hypothesis> {
        self.add_structured_hypothesis(session_id, statement, "", statement, "", "")
    }

    pub fn add_structured_hypothesis(
        &self,
        session_id: &str,
        statement: &str,
        requirement_id: &str,
        claim: &str,
        preconditions: &str,
        oracle_type: &str,
    ) -> Result<Hypothesis> {
        let ts = now();
        let row = Hypothesis {
            id: Uuid::new_v4().to_string(),
            session_id: session_id.to_string(),
            statement: statement.to_string(),
            status: "open".to_string(),
            created_at: ts.clone(),
            requirement_id: requirement_id.to_string(),
            claim: claim.to_string(),
            preconditions: preconditions.to_string(),
            oracle_type: oracle_type.to_string(),
            rationale: String::new(),
            evidence_ref: String::new(),
            updated_at: Some(ts.clone()),
        };
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO hypotheses(id,session_id,statement,status,created_at,
             requirement_id,claim,preconditions,oracle_type,rationale,evidence_ref,updated_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",
            params![
                row.id,
                row.session_id,
                row.statement,
                row.status,
                row.created_at,
                row.requirement_id,
                row.claim,
                row.preconditions,
                row.oracle_type,
                row.rationale,
                row.evidence_ref,
                row.updated_at
            ],
        )?;
        Ok(row)
    }

    pub fn list_hypotheses(&self, session_id: &str) -> Result<Vec<Hypothesis>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id,session_id,statement,status,created_at,requirement_id,claim,
             preconditions,oracle_type,rationale,evidence_ref,updated_at
             FROM hypotheses WHERE session_id=?1 ORDER BY rowid ASC",
        )?;
        let rows = stmt.query_map(params![session_id], |r| {
            Ok(Hypothesis {
                id: r.get(0)?,
                session_id: r.get(1)?,
                statement: r.get(2)?,
                status: r.get(3)?,
                created_at: r.get(4)?,
                requirement_id: r.get::<_, Option<String>>(5)?.unwrap_or_default(),
                claim: r.get::<_, Option<String>>(6)?.unwrap_or_default(),
                preconditions: r.get::<_, Option<String>>(7)?.unwrap_or_default(),
                oracle_type: r.get::<_, Option<String>>(8)?.unwrap_or_default(),
                rationale: r.get::<_, Option<String>>(9)?.unwrap_or_default(),
                evidence_ref: r.get::<_, Option<String>>(10)?.unwrap_or_default(),
                updated_at: r.get(11)?,
            })
        })?;
        let mut out = vec![];
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    pub fn set_hypothesis_status(&self, id: &str, status: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE hypotheses SET status=?2, updated_at=?3 WHERE id=?1",
            params![id, status, now()],
        )?;
        Ok(())
    }

    pub fn hypothesis_transition(
        &self,
        id: &str,
        status: &str,
        rationale: &str,
        evidence_ref: &str,
    ) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE hypotheses SET status=?2, rationale=?3, evidence_ref=?4, updated_at=?5 WHERE id=?1",
            params![id, status, rationale, evidence_ref, now()],
        )?;
        Ok(())
    }

    pub fn record_approved_target(&self, session_id: &str, target: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR IGNORE INTO approved_targets(session_id,target,created_at) VALUES(?1,?2,?3)",
            params![session_id, target, now()],
        )?;
        Ok(())
    }

    pub fn list_approved_targets(&self, session_id: &str) -> Result<Vec<String>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT target FROM approved_targets WHERE session_id=?1 ORDER BY target")?;
        let rows = stmt.query_map(params![session_id], |r| r.get::<_, String>(0))?;
        let mut out = vec![];
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    /// Append one billing record; aggregates are derived at read time.
    pub fn record_token_usage(
        &self,
        session_id: &str,
        prompt_tokens: u64,
        completion_tokens: u64,
        cost_usd: f64,
    ) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO token_usage(id,session_id,prompt_tokens,completion_tokens,cost_usd,created_at)
             VALUES(?1,?2,?3,?4,?5,?6)",
            params![
                Uuid::new_v4().to_string(),
                session_id,
                prompt_tokens as i64,
                completion_tokens as i64,
                cost_usd,
                now()
            ],
        )?;
        Ok(())
    }

    pub fn token_usage(&self, session_id: &str) -> Result<TokenUsage> {
        let conn = self.conn.lock().unwrap();
        let (prompt, completion, cost): (Option<i64>, Option<i64>, Option<f64>) = conn.query_row(
            "SELECT SUM(prompt_tokens), SUM(completion_tokens), SUM(cost_usd)
             FROM token_usage WHERE session_id=?1",
            params![session_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )?;
        Ok(TokenUsage {
            prompt_tokens: prompt.unwrap_or(0).max(0) as u64,
            completion_tokens: completion.unwrap_or(0).max(0) as u64,
            cost_usd: cost.unwrap_or(0.0),
        })
    }

    /// Total tokens consumed by a session as a plain count. There is no
    /// `tokens_used` column: the billing ledger is `token_usage`, so this sums
    /// its prompt and completion tokens. Sessions without billing rows return
    /// zero. Kept separate from [`Store::token_usage`] because that pre-existing
    /// API returns the richer [`TokenUsage`] breakdown used by the runner and UI.
    pub fn token_usage_total(&self, session_id: &str) -> Result<usize> {
        let usage = self.token_usage(session_id)?;
        Ok(usage
            .prompt_tokens
            .saturating_add(usage.completion_tokens)
            .try_into()
            .unwrap_or(usize::MAX))
    }

    /// Pin a session to a goal digest. Repeated calls replace the lock.
    pub fn set_goal_lock(&self, session_id: &str, digest: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO goal_locks(session_id,digest,created_at) VALUES(?1,?2,?3)
             ON CONFLICT(session_id) DO UPDATE SET digest=excluded.digest, created_at=excluded.created_at",
            params![session_id, digest, now()],
        )?;
        Ok(())
    }

    pub fn get_goal_lock(&self, session_id: &str) -> Result<Option<String>> {
        let conn = self.conn.lock().unwrap();
        let digest = conn
            .query_row(
                "SELECT digest FROM goal_locks WHERE session_id=?1",
                params![session_id],
                |r| r.get(0),
            )
            .optional()?;
        Ok(digest)
    }

    pub fn set_session_flag(&self, session_id: &str, flag: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR IGNORE INTO session_flags(session_id,flag,created_at) VALUES(?1,?2,?3)",
            params![session_id, flag, now()],
        )?;
        Ok(())
    }

    /// Physically remove a session flag so a resumed run does not re-trigger
    /// the behavior it guarded (for example a stop/pause flag).
    pub fn clear_session_flag(&self, session_id: &str, flag: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "DELETE FROM session_flags WHERE session_id=?1 AND flag=?2",
            params![session_id, flag],
        )?;
        Ok(())
    }

    pub fn has_session_flag(&self, session_id: &str, flag: &str) -> Result<bool> {
        let conn = self.conn.lock().unwrap();
        let found: Option<i64> = conn
            .query_row(
                "SELECT 1 FROM session_flags WHERE session_id=?1 AND flag=?2",
                params![session_id, flag],
                |r| r.get(0),
            )
            .optional()?;
        Ok(found.is_some())
    }

    /// Distinct coverage targets in lexical order, used for progress reporting.
    pub fn coverage_targets(&self, session_id: &str) -> Result<Vec<String>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT DISTINCT target FROM coverage WHERE session_id=?1 ORDER BY target ASC",
        )?;
        let rows = stmt.query_map(params![session_id], |r| r.get::<_, String>(0))?;
        let mut out = vec![];
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    pub fn create_engagement(&self, program_url: &str) -> Result<Engagement> {
        let ts = now();
        let e = Engagement {
            id: Uuid::new_v4().to_string(),
            program_url: program_url.to_string(),
            state: "idle".to_string(),
            created_at: ts.clone(),
            updated_at: ts,
        };
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO engagements(id,program_url,state,created_at,updated_at) VALUES(?1,?2,?3,?4,?5)",
            params![e.id, e.program_url, e.state, e.created_at, e.updated_at],
        )?;
        Ok(e)
    }

    pub fn get_engagement(&self, id: &str) -> Result<Option<Engagement>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id,program_url,state,created_at,updated_at FROM engagements WHERE id=?1",
        )?;
        let row = stmt
            .query_row(params![id], |r| {
                Ok(Engagement {
                    id: r.get(0)?,
                    program_url: r.get(1)?,
                    state: r.get(2)?,
                    created_at: r.get(3)?,
                    updated_at: r.get(4)?,
                })
            })
            .optional()?;
        Ok(row)
    }

    pub fn list_engagements(&self, limit: usize) -> Result<Vec<Engagement>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id,program_url,state,created_at,updated_at FROM engagements ORDER BY rowid DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit as i64], |r| {
            Ok(Engagement {
                id: r.get(0)?,
                program_url: r.get(1)?,
                state: r.get(2)?,
                created_at: r.get(3)?,
                updated_at: r.get(4)?,
            })
        })?;
        let mut out = vec![];
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    pub fn set_engagement_state(&self, id: &str, state: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE engagements SET state=?2, updated_at=?3 WHERE id=?1",
            params![id, state, now()],
        )?;
        Ok(())
    }

    pub fn save_brief(
        &self,
        engagement_id: &str,
        raw_html: &str,
        extracted_json: &str,
        scope_json: &str,
        roe_json: &str,
    ) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO brief_snapshots(id,engagement_id,raw_html,extracted_json,scope_json,roe_json,created_at)
             VALUES(?1,?2,?3,?4,?5,?6,?7)",
            params![
                Uuid::new_v4().to_string(),
                engagement_id,
                raw_html,
                extracted_json,
                scope_json,
                roe_json,
                now()
            ],
        )?;
        Ok(())
    }

    pub fn create_task(
        &self,
        engagement_id: &str,
        statement: &str,
        playbook_id: &str,
        target: Option<&str>,
        priority: i64,
    ) -> Result<Task> {
        let t = Task {
            id: Uuid::new_v4().to_string(),
            engagement_id: engagement_id.to_string(),
            statement: statement.to_string(),
            playbook_id: playbook_id.to_string(),
            target: target.map(|s| s.to_string()),
            priority,
            status: "open".to_string(),
            created_at: now(),
        };
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO tasks(id,engagement_id,statement,playbook_id,target,priority,status,created_at)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
            params![
                t.id,
                t.engagement_id,
                t.statement,
                t.playbook_id,
                t.target,
                t.priority,
                t.status,
                t.created_at
            ],
        )?;
        Ok(t)
    }

    pub fn list_tasks(&self, engagement_id: &str) -> Result<Vec<Task>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id,engagement_id,statement,playbook_id,target,priority,status,created_at
             FROM tasks WHERE engagement_id=?1 ORDER BY rowid ASC",
        )?;
        let rows = stmt.query_map(params![engagement_id], |r| {
            Ok(Task {
                id: r.get(0)?,
                engagement_id: r.get(1)?,
                statement: r.get(2)?,
                playbook_id: r.get(3)?,
                target: r.get(4)?,
                priority: r.get(5)?,
                status: r.get(6)?,
                created_at: r.get(7)?,
            })
        })?;
        let mut out = vec![];
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    pub fn update_task_status(&self, id: &str, status: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE tasks SET status=?2 WHERE id=?1",
            params![id, status],
        )?;
        Ok(())
    }

    pub fn add_clue(
        &self,
        engagement_id: &str,
        task_id: Option<&str>,
        source_tool: &str,
        key: &str,
        value_json: &str,
    ) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO clues(id,engagement_id,task_id,source_tool,\"key\",value_json,created_at)
             VALUES(?1,?2,?3,?4,?5,?6,?7)",
            params![
                Uuid::new_v4().to_string(),
                engagement_id,
                task_id,
                source_tool,
                key,
                value_json,
                now()
            ],
        )?;
        Ok(())
    }

    pub fn list_clues(&self, engagement_id: &str) -> Result<Vec<Clue>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id,engagement_id,task_id,source_tool,\"key\",value_json,created_at
             FROM clues WHERE engagement_id=?1 ORDER BY rowid ASC",
        )?;
        let rows = stmt.query_map(params![engagement_id], |r| {
            Ok(Clue {
                id: r.get(0)?,
                engagement_id: r.get(1)?,
                task_id: r.get(2)?,
                source_tool: r.get(3)?,
                key: r.get(4)?,
                value_json: r.get(5)?,
                created_at: r.get(6)?,
            })
        })?;
        let mut out = vec![];
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    pub fn add_evidence(
        &self,
        finding_id: &str,
        kind: &str,
        path: Option<&str>,
        sha256: &str,
        request: Option<&str>,
        response: Option<&str>,
    ) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO evidence(id,finding_id,kind,path,sha256,request,response,created_at)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
            params![
                Uuid::new_v4().to_string(),
                finding_id,
                kind,
                path,
                sha256,
                request,
                response,
                now()
            ],
        )?;
        Ok(())
    }

    /// Hash raw captured bytes with SHA-256 and persist the evidence row.
    /// Returns the 64-hex digest so callers can stamp it onto findings/reports.
    pub fn add_evidence_bytes(
        &self,
        finding_id: &str,
        kind: &str,
        request: &[u8],
        response: &[u8],
        artifact: Option<&[u8]>,
    ) -> Result<String> {
        let hash = sha256_evidence_bytes(request, response, artifact);
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO evidence(id,finding_id,kind,path,sha256,request,response,request_bytes,response_bytes,artifact_bytes,created_at)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
            params![
                Uuid::new_v4().to_string(),
                finding_id,
                kind,
                artifact.map(|a| String::from_utf8_lossy(a).into_owned()),
                hash,
                String::from_utf8_lossy(request).into_owned(),
                String::from_utf8_lossy(response).into_owned(),
                request,
                response,
                artifact,
                now()
            ],
        )?;
        Ok(hash)
    }

    /// Findings that passed verification. Only these may appear in reports.
    pub fn verified_findings(&self, session_id: &str) -> Result<Vec<Finding>> {
        let findings = self.list_findings(session_id)?;
        Ok(findings
            .into_iter()
            .filter(|f| matches!(f.status.as_str(), "validated" | "confirmed"))
            .collect())
    }

    /// Recompute every evidence digest for findings in a session and confirm
    /// the stored SHA-256 values still match the captured bytes.
    pub fn verify_evidence(&self, session_id: &str) -> Result<bool> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT e.sha256, e.request_bytes, e.response_bytes, e.artifact_bytes
             FROM evidence e JOIN findings f ON f.id = e.finding_id
             WHERE f.session_id = ?1",
        )?;
        let rows = stmt.query_map(params![session_id], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, Option<Vec<u8>>>(1)?.unwrap_or_default(),
                r.get::<_, Option<Vec<u8>>>(2)?.unwrap_or_default(),
                r.get::<_, Option<Vec<u8>>>(3)?.unwrap_or_default(),
            ))
        })?;
        for row in rows {
            let (stored, request, response, artifact) = row?;
            let artifact = (!artifact.is_empty()).then_some(artifact.as_slice());
            if stored != sha256_evidence_bytes(&request, &response, artifact) {
                return Ok(false);
            }
        }
        Ok(true)
    }

    pub fn save_report(
        &self,
        engagement_id: &str,
        format: &str,
        path: &str,
        sha256: &str,
    ) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO reports(id,engagement_id,format,path,sha256,created_at)
             VALUES(?1,?2,?3,?4,?5,?6)",
            params![
                Uuid::new_v4().to_string(),
                engagement_id,
                format,
                path,
                sha256,
                now()
            ],
        )?;
        Ok(())
    }

    pub fn append_trace(
        &self,
        engagement_id: &str,
        run_id: &str,
        kind: &str,
        payload_json: &str,
    ) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO trace_events(id,engagement_id,run_id,kind,payload_json,created_at)
             VALUES(?1,?2,?3,?4,?5,?6)",
            params![
                Uuid::new_v4().to_string(),
                engagement_id,
                run_id,
                kind,
                payload_json,
                now()
            ],
        )?;
        Ok(())
    }

    /// Persist a cross-process control state for an engagement.
    pub fn upsert_engagement_control(&self, engagement_id: &str, state: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO engagement_controls(engagement_id,state,updated_at) VALUES(?1,?2,?3)
             ON CONFLICT(engagement_id) DO UPDATE SET state=excluded.state, updated_at=excluded.updated_at",
            params![engagement_id, state, now()],
        )?;
        Ok(())
    }

    pub fn get_engagement_control(&self, engagement_id: &str) -> Result<Option<String>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt =
            conn.prepare("SELECT state FROM engagement_controls WHERE engagement_id=?1")?;
        let row = stmt
            .query_row(params![engagement_id], |r| r.get::<_, String>(0))
            .optional()?;
        Ok(row)
    }

    pub fn latest_report_path(&self, engagement_id: &str) -> Result<Option<String>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT path FROM reports WHERE engagement_id=?1 ORDER BY rowid DESC LIMIT 1",
        )?;
        let row = stmt
            .query_row(params![engagement_id], |r| r.get::<_, String>(0))
            .optional()?;
        Ok(row)
    }
}

const SENSITIVE_KEYS: &[&str] = &[
    "api_key",
    "apikey",
    "api-key",
    "token",
    "secret",
    "client_secret",
    "password",
    "passwd",
    "pwd",
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "connection_string",
    "database_url",
    "dsn",
    "private_key",
    "credential",
];

fn is_sensitive_key(key: &str) -> bool {
    let k = key.trim().trim_matches(['"', '\'']).to_ascii_lowercase();
    SENSITIVE_KEYS
        .iter()
        .any(|sensitive| k == *sensitive || k.contains(sensitive))
}

fn redact_json_value(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, child) in map.iter_mut() {
                if is_sensitive_key(key) {
                    *child = serde_json::Value::String("[REDACTED]".into());
                } else {
                    redact_json_value(child);
                }
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                redact_json_value(item);
            }
        }
        _ => {}
    }
}

fn redact_bearer(out: &mut String) {
    let bytes = out.as_bytes();
    let mut result = String::with_capacity(out.len());
    let mut i = 0;
    while i < bytes.len() {
        if i + 7 <= bytes.len() && bytes[i..i + 7].eq_ignore_ascii_case(b"bearer ") {
            result.push_str("[REDACTED]");
            i += 7;
            while i < bytes.len() && !bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            continue;
        }
        let ch = out[i..].chars().next().unwrap();
        result.push(ch);
        i += ch.len_utf8();
    }
    *out = result;
}

fn redact_text_pairs(out: &mut String) {
    for key in SENSITIVE_KEYS {
        let mut search = 0;
        loop {
            let lower = out.to_ascii_lowercase();
            let Some(pos) = lower[search..].find(key) else {
                break;
            };
            let abs = search + pos;
            let mut i = abs + key.len();
            let bytes = out.as_bytes();
            while i < bytes.len() && (bytes[i] as char).is_whitespace() {
                i += 1;
            }
            if i < bytes.len() && (bytes[i] == b'"' || bytes[i] == b'\'') {
                i += 1;
            }
            while i < bytes.len() && (bytes[i] as char).is_whitespace() {
                i += 1;
            }
            if i < bytes.len() && (bytes[i] == b'=' || bytes[i] == b':') {
                i += 1;
                while i < bytes.len() && (bytes[i] as char).is_whitespace() {
                    i += 1;
                }
                if i < bytes.len() && (bytes[i] == b'"' || bytes[i] == b'\'') {
                    i += 1;
                }
                let start = i;
                while i < bytes.len() {
                    let c = bytes[i] as char;
                    if c.is_whitespace() || matches!(c, '"' | '\'' | '&' | ',' | ';' | '}' | ']') {
                        break;
                    }
                    i += 1;
                }
                if i > start {
                    out.replace_range(start..i, "[REDACTED]");
                    search = start + "[REDACTED]".len();
                    continue;
                }
            }
            search = abs + key.len();
            if search >= out.len() {
                break;
            }
        }
    }
}

fn redact_prefixes(out: &mut String) {
    for prefix in ["sk-", "ghp_", "gho_", "xoxb-", "xoxp-"] {
        let mut search = 0;
        while let Some(pos) = out[search..].find(prefix) {
            let start = search + pos;
            let mut end = start + prefix.len();
            while end < out.len() && !out[end..].starts_with(char::is_whitespace) {
                end += out[end..].chars().next().unwrap().len_utf8();
            }
            if end > start + prefix.len() {
                out.replace_range(start..end, "[REDACTED]");
                search = start + "[REDACTED]".len();
            } else {
                search = start + prefix.len();
            }
            if search >= out.len() {
                break;
            }
        }
    }
}

fn is_email_local_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '%' | '+' | '-')
}

fn is_email_domain_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '.' | '-')
}

/// Replace `local@domain.tld` tokens, keeping other uses of `@` intact.
fn redact_emails(out: &mut String) {
    let mut search = 0;
    while let Some(rel) = out[search..].find('@') {
        let at = search + rel;
        let mut start = at;
        while let Some(c) = out[..start].chars().next_back() {
            if is_email_local_char(c) {
                start -= c.len_utf8();
            } else {
                break;
            }
        }
        let mut end = at + 1;
        while end < out.len() {
            let c = out[end..].chars().next().unwrap();
            if is_email_domain_char(c) {
                end += c.len_utf8();
            } else {
                break;
            }
        }
        let local = &out[start..at];
        let domain = &out[at + 1..end];
        let (label, tld) = domain.rsplit_once('.').unwrap_or(("", ""));
        let looks_email = !local.is_empty()
            && !label.is_empty()
            && tld.len() >= 2
            && tld.bytes().all(|b| b.is_ascii_alphabetic());
        if looks_email {
            out.replace_range(start..end, "[REDACTED]");
            search = start + "[REDACTED]".len();
        } else {
            search = at + 1;
        }
    }
}

fn is_number_separator(c: char) -> bool {
    matches!(c, ' ' | '-' | '(' | ')')
}

/// Year-first groups such as `2026-11-19 10` are timestamps, not phone numbers.
fn looks_like_date(chunks: &[usize], digits: &str) -> bool {
    chunks.len() >= 3
        && chunks[0] == 4
        && (digits.starts_with("19") || digits.starts_with("20"))
        && chunks[1..].iter().all(|&n| n <= 2)
}

fn is_phone_chunks(chunks: &[usize], first_digit: char) -> bool {
    match chunks {
        [3, 3, 4] => true,
        [1, 3, 3, 4] => first_digit == '1',
        _ => false,
    }
}

fn is_card_chunks(chunks: &[usize]) -> bool {
    chunks.len() >= 2
        && chunks[..chunks.len() - 1].iter().all(|&n| n == 4)
        && (1..=4).contains(chunks.last().unwrap())
}

/// Redact phone numbers, payment cards and SSNs while leaving short numbers
/// and dates alone. Separators are limited to spaces, dashes and parentheses.
fn redact_pii_numbers(out: &mut String) {
    let mut search = 0;
    loop {
        let bytes = out.as_bytes();
        let mut candidate = None;
        let mut j = search;
        while j < bytes.len() {
            let c = bytes[j] as char;
            if c.is_ascii_digit()
                || ((c == '+' || c == '(')
                    && j + 1 < bytes.len()
                    && (bytes[j + 1] as char).is_ascii_digit())
            {
                candidate = Some(j);
                break;
            }
            j += 1;
        }
        let Some(start) = candidate else {
            break;
        };

        let mut i = start;
        if bytes[i] == b'+' || bytes[i] == b'(' {
            i += 1;
        }
        let mut chunks = Vec::new();
        let mut current = 0usize;
        let mut digits = String::new();
        let mut end = i;
        while end < bytes.len() {
            let c = bytes[end] as char;
            if c.is_ascii_digit() {
                digits.push(c);
                current += 1;
                end += 1;
            } else if is_number_separator(c) {
                let mut k = end;
                while k < bytes.len() && is_number_separator(bytes[k] as char) {
                    k += 1;
                }
                if k < bytes.len() && (bytes[k] as char).is_ascii_digit() {
                    if current > 0 {
                        chunks.push(current);
                        current = 0;
                    }
                    end = k;
                } else {
                    break;
                }
            } else {
                break;
            }
        }
        if current > 0 {
            chunks.push(current);
        }

        let total: usize = chunks.iter().sum();
        let first_digit = digits.chars().next().unwrap_or_default();
        let is_ssn = chunks.as_slice() == [3, 2, 4];
        let is_card = (13..=19).contains(&total) && (chunks.len() == 1 || is_card_chunks(&chunks));
        let is_phone = if chunks.len() == 1 {
            total == 10 || (total == 11 && first_digit == '1')
        } else {
            is_phone_chunks(&chunks, first_digit)
        };
        let bounded = (start == 0 || !out.as_bytes()[start - 1].is_ascii_alphanumeric())
            && (end >= out.len() || !out.as_bytes()[end].is_ascii_alphanumeric());
        let should_redact =
            (is_card || is_ssn || is_phone) && !looks_like_date(&chunks, &digits) && bounded;

        if should_redact {
            out.replace_range(start..end, "[REDACTED]");
            search = start + "[REDACTED]".len();
        } else {
            search = end.max(start + 1);
        }
    }
}

/// Redact secrets and personally identifiable information from structured
/// JSON, key/value text, bearer tokens, well-known token prefixes, email
/// addresses, phone numbers, card numbers and SSNs. Used at every report and
/// CLI output boundary.
pub fn redact(input: &str) -> String {
    let mut out = if let Ok(mut value) = serde_json::from_str::<serde_json::Value>(input) {
        if value.is_object() || value.is_array() {
            redact_json_value(&mut value);
            value.to_string()
        } else {
            input.to_string()
        }
    } else {
        input.to_string()
    };
    redact_bearer(&mut out);
    redact_text_pairs(&mut out);
    redact_prefixes(&mut out);
    redact_emails(&mut out);
    redact_pii_numbers(&mut out);
    out
}
pub fn redact_sensitive(input: &str) -> String {
    redact(input)
}
pub fn redact_secrets(input: &str) -> String {
    redact(input)
}
pub fn redact_text(input: &str) -> String {
    redact(input)
}

/// Versioned, hash-bound authorization snapshot for a program brief.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationSnapshot {
    pub engagement_id: String,
    pub version: i64,
    pub source_url: String,
    pub content_hash: String,
    pub scope_hash: String,
    pub roe_hash: String,
    pub observed_at: String,
    pub state: String,
    pub created_at: String,
}

/// Out-of-band request to revalidate an engagement's authorization on resume.
/// `state` is `requested` until it is resolved to `cleared` or `blocked`;
/// `observed_hash` records the authorization snapshot that was inspected.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevalidationRequest {
    pub engagement_id: String,
    pub state: String,
    pub observed_hash: String,
    pub requested_at: String,
    pub updated_at: String,
}

/// An out-of-band operator acknowledgement for one ambiguous line or version.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationAck {
    pub program_url: String,
    pub content_hash: String,
    pub subject_kind: String,
    pub subject_hash: String,
    pub subject_text: String,
    pub decision: String,
    pub operator: String,
    pub note: String,
    pub created_at: String,
}

/// Advisory, operator-supplied safe-harbor receipt for a specific brief version.
/// This is a typed audit record only: it is never consulted by scope or ROE
/// gating, cannot be created by an LLM or tool flag, and never authorizes an
/// action. All timestamps are ISO-8601 strings so expiry can be compared
/// lexicographically.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafeHarborReceipt {
    pub id: String,
    pub program_url: String,
    pub brief_content_hash: String,
    pub scope_version: String,
    pub terms_hash: String,
    pub operator: String,
    pub acquired_at: String,
    pub expires_at: String,
    pub decision: String,
    pub note: String,
}

/// An unmapped ROE rule kept visible (never silently dropped).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenAuthorizationRule {
    pub engagement_id: String,
    pub snapshot_hash: String,
    pub rule_hash: String,
    pub rule_text: String,
    pub state: String,
    pub created_at: String,
}

impl Store {
    pub fn save_authorization_snapshot(&self, snapshot: &AuthorizationSnapshot) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR IGNORE INTO authorization_snapshots(
             id, engagement_id, version, source_url, content_hash, scope_hash,
             roe_hash, observed_at, state, created_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
            params![
                Uuid::new_v4().to_string(),
                snapshot.engagement_id,
                snapshot.version,
                snapshot.source_url,
                snapshot.content_hash,
                snapshot.scope_hash,
                snapshot.roe_hash,
                snapshot.observed_at,
                snapshot.state,
                snapshot.created_at
            ],
        )?;
        Ok(())
    }

    pub fn count_authorization_snapshots(&self, engagement_id: &str) -> Result<i64> {
        let conn = self.conn.lock().unwrap();
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM authorization_snapshots WHERE engagement_id=?1",
            params![engagement_id],
            |row| row.get(0),
        )?;
        Ok(count)
    }

    /// Durable record that an engagement must re-check its authorization before
    /// the next resume. Repeated requests keep the original `requested_at`.
    pub fn request_authorization_revalidation(&self, engagement_id: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let ts = now();
        conn.execute(
            "INSERT INTO authorization_revalidation(
               engagement_id, state, observed_hash, requested_at, updated_at)
             VALUES (?1, 'requested', '', ?2, ?2)
             ON CONFLICT(engagement_id) DO UPDATE SET
               state='requested', updated_at=excluded.updated_at",
            params![engagement_id, ts],
        )?;
        Ok(())
    }

    pub fn get_authorization_revalidation(
        &self,
        engagement_id: &str,
    ) -> Result<Option<RevalidationRequest>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT engagement_id, state, observed_hash, requested_at, updated_at
             FROM authorization_revalidation WHERE engagement_id=?1",
        )?;
        let row = stmt
            .query_row(params![engagement_id], |r| {
                Ok(RevalidationRequest {
                    engagement_id: r.get(0)?,
                    state: r.get(1)?,
                    observed_hash: r.get(2)?,
                    requested_at: r.get(3)?,
                    updated_at: r.get(4)?,
                })
            })
            .optional()?;
        Ok(row)
    }

    /// Resolve a pending revalidation. `state` must be `cleared` or `blocked`;
    /// any other value is rejected so a typo cannot silently clear a block.
    pub fn finish_authorization_revalidation(
        &self,
        engagement_id: &str,
        state: &str,
        observed_hash: &str,
    ) -> Result<()> {
        if state != "cleared" && state != "blocked" {
            return Err(anyhow::anyhow!(
                "invalid revalidation state: {state} (expected cleared or blocked)"
            ));
        }
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE authorization_revalidation SET state=?2, observed_hash=?3, updated_at=?4
             WHERE engagement_id=?1",
            params![engagement_id, state, observed_hash, now()],
        )?;
        Ok(())
    }

    /// Highest-version authorization snapshot recorded for an engagement.
    pub fn latest_authorization_snapshot(
        &self,
        engagement_id: &str,
    ) -> Result<Option<AuthorizationSnapshot>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT engagement_id, version, source_url, content_hash, scope_hash,
                    roe_hash, observed_at, state, created_at
             FROM authorization_snapshots WHERE engagement_id=?1
             ORDER BY version DESC LIMIT 1",
        )?;
        let row = stmt
            .query_row(params![engagement_id], |r| {
                Ok(AuthorizationSnapshot {
                    engagement_id: r.get(0)?,
                    version: r.get(1)?,
                    source_url: r.get(2)?,
                    content_hash: r.get(3)?,
                    scope_hash: r.get(4)?,
                    roe_hash: r.get(5)?,
                    observed_at: r.get(6)?,
                    state: r.get(7)?,
                    created_at: r.get(8)?,
                })
            })
            .optional()?;
        Ok(row)
    }

    pub fn save_authorization_ack(&self, ack: &AuthorizationAck) -> Result<bool> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR IGNORE INTO authorization_acks(
             id, program_url, content_hash, subject_kind, subject_hash,
             subject_text, decision, operator, note, created_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
            params![
                Uuid::new_v4().to_string(),
                ack.program_url,
                ack.content_hash,
                ack.subject_kind,
                ack.subject_hash,
                ack.subject_text,
                ack.decision,
                ack.operator,
                ack.note,
                now()
            ],
        )?;
        Ok(conn.changes() > 0)
    }

    pub fn has_authorization_ack(
        &self,
        program_url: &str,
        content_hash: &str,
        subject_kind: &str,
        subject_hash: &str,
    ) -> Result<bool> {
        let conn = self.conn.lock().unwrap();
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM authorization_acks
             WHERE program_url=?1 AND content_hash=?2 AND subject_kind=?3
               AND subject_hash=?4 AND decision='acknowledged'",
            params![program_url, content_hash, subject_kind, subject_hash],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    /// Idempotent insert of an operator-supplied safe-harbor receipt. The
    /// receipt is advisory metadata only; no caller may use it to authorize a
    /// tool call or relax a scope/ROE decision. Returns true only when a new
    /// row was inserted.
    pub fn save_safe_harbor_receipt(&self, receipt: &SafeHarborReceipt) -> Result<bool> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR IGNORE INTO safe_harbor_receipts(
              id, program_url, brief_content_hash, scope_version, terms_hash,
              operator, acquired_at, expires_at, decision, note)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
            params![
                receipt.id,
                receipt.program_url,
                receipt.brief_content_hash,
                receipt.scope_version,
                receipt.terms_hash,
                receipt.operator,
                receipt.acquired_at,
                receipt.expires_at,
                receipt.decision,
                receipt.note,
            ],
        )?;
        Ok(conn.changes() > 0)
    }

    /// All receipts recorded for a program, newest acquisition first.
    pub fn list_safe_harbor_receipts(&self, program_url: &str) -> Result<Vec<SafeHarborReceipt>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, program_url, brief_content_hash, scope_version, terms_hash,
                    operator, acquired_at, expires_at, decision, note
             FROM safe_harbor_receipts WHERE program_url=?1
             ORDER BY acquired_at DESC, id DESC",
        )?;
        let rows = stmt.query_map(params![program_url], |r| {
            Ok(SafeHarborReceipt {
                id: r.get(0)?,
                program_url: r.get(1)?,
                brief_content_hash: r.get(2)?,
                scope_version: r.get(3)?,
                terms_hash: r.get(4)?,
                operator: r.get(5)?,
                acquired_at: r.get(6)?,
                expires_at: r.get(7)?,
                decision: r.get(8)?,
                note: r.get(9)?,
            })
        })?;
        let mut out = vec![];
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    /// Return the newest acknowledged, unexpired receipt for one exact brief
    /// hash. `now` and `expires_at` are ISO-8601 strings, so a lexical compare
    /// is sufficient. A receipt is never an authorization decision: callers
    /// may only surface it as advisory provenance.
    pub fn valid_safe_harbor_receipt(
        &self,
        program_url: &str,
        brief_content_hash: &str,
        now: &str,
    ) -> Result<Option<SafeHarborReceipt>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, program_url, brief_content_hash, scope_version, terms_hash,
                    operator, acquired_at, expires_at, decision, note
             FROM safe_harbor_receipts
             WHERE program_url=?1 AND brief_content_hash=?2
               AND decision='acknowledged' AND expires_at > ?3
             ORDER BY acquired_at DESC, id DESC LIMIT 1",
        )?;
        let row = stmt
            .query_row(params![program_url, brief_content_hash, now], |r| {
                Ok(SafeHarborReceipt {
                    id: r.get(0)?,
                    program_url: r.get(1)?,
                    brief_content_hash: r.get(2)?,
                    scope_version: r.get(3)?,
                    terms_hash: r.get(4)?,
                    operator: r.get(5)?,
                    acquired_at: r.get(6)?,
                    expires_at: r.get(7)?,
                    decision: r.get(8)?,
                    note: r.get(9)?,
                })
            })
            .optional()?;
        Ok(row)
    }

    pub fn save_open_authorization_rule(&self, rule: &OpenAuthorizationRule) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR IGNORE INTO authorization_open_rules(
             id, engagement_id, snapshot_hash, rule_hash, rule_text, state, created_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7)",
            params![
                Uuid::new_v4().to_string(),
                rule.engagement_id,
                rule.snapshot_hash,
                rule.rule_hash,
                rule.rule_text,
                rule.state,
                now()
            ],
        )?;
        Ok(())
    }

    pub fn list_open_authorization_rules(
        &self,
        engagement_id: &str,
    ) -> Result<Vec<OpenAuthorizationRule>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT engagement_id, snapshot_hash, rule_hash, rule_text, state, created_at
             FROM authorization_open_rules WHERE engagement_id=?1 ORDER BY rowid",
        )?;
        let rows = stmt
            .query_map(params![engagement_id], |row| {
                Ok(OpenAuthorizationRule {
                    engagement_id: row.get(0)?,
                    snapshot_hash: row.get(1)?,
                    rule_hash: row.get(2)?,
                    rule_text: row.get(3)?,
                    state: row.get(4)?,
                    created_at: row.get(5)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }
}

/// Generic durable eval-trace record. The kernel reads this for telemetry;
/// it never interprets the payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceRecord {
    pub engagement_id: String,
    pub run_id: String,
    pub kind: String,
    pub payload_json: String,
    pub created_at: String,
}

impl Store {
    /// Durable event counts by kind for one session.
    pub fn event_kind_counts(
        &self,
        session_id: &str,
    ) -> Result<std::collections::BTreeMap<String, usize>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt =
            conn.prepare("SELECT kind, COUNT(*) FROM events WHERE session_id=?1 GROUP BY kind")?;
        let rows = stmt
            .query_map(params![session_id], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, usize>(1)?))
            })?
            .collect::<rusqlite::Result<std::collections::BTreeMap<_, _>>>()?;
        Ok(rows)
    }

    /// Read the durable eval trace for one engagement, oldest first.
    pub fn list_trace(&self, engagement_id: &str, limit: usize) -> Result<Vec<TraceRecord>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT engagement_id, run_id, kind, payload_json, created_at
             FROM trace_events WHERE engagement_id=?1 ORDER BY rowid ASC LIMIT ?2",
        )?;
        let rows = stmt
            .query_map(params![engagement_id, limit], |row| {
                Ok(TraceRecord {
                    engagement_id: row.get(0)?,
                    run_id: row.get(1)?,
                    kind: row.get(2)?,
                    payload_json: row.get(3)?,
                    created_at: row.get(4)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }
}

pub fn persist_tool_result(
    store: &Store,
    session_id: &str,
    tool_name: &str,
    args: &serde_json::Value,
    result: &agentbug_tools::ToolResult,
) {
    if !result.ok {
        return;
    }
    // Any tool may produce an authoritative capture (HTTP, PoC replay). Keep
    // it at session scope so a later `save_finding` can bind real bytes to the
    // finding instead of trusting LLM-supplied request/response arguments.
    if let Some((request, response, canary)) = result
        .structured
        .as_ref()
        .and_then(agentbug_tools::capture_from_structured)
    {
        let _ =
            store.put_session_capture(session_id, request.as_bytes(), response.as_bytes(), &canary);
    }
    let effective_args = if args.is_object() {
        args.clone()
    } else if let Some(s) = result.structured.as_ref() {
        if s.is_object() {
            s.clone()
        } else {
            serde_json::json!({})
        }
    } else {
        serde_json::json!({})
    };
    // Never persist raw secrets captured in tool arguments/evidence.
    let redacted_args: serde_json::Value =
        serde_json::from_str(&redact(&effective_args.to_string()))
            .unwrap_or_else(|_| effective_args.clone());
    let args = &redacted_args;
    let n = tool_name.to_ascii_lowercase().replace('-', "_");
    let is_finding = n.contains("finding");
    let is_asset = n.contains("asset");
    let is_artifact = n.contains("artifact");
    if is_finding {
        let title = args
            .get("title")
            .and_then(|v| v.as_str())
            .unwrap_or("(untitled)");
        let severity = args
            .get("severity")
            .and_then(|v| v.as_str())
            .unwrap_or("info");
        let asset = args.get("asset").and_then(|v| v.as_str());
        let vuln_type = args.get("vuln_type").and_then(|v| v.as_str());
        let description = args
            .get("description")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let reproduction = args.get("reproduction").and_then(|v| v.as_str());
        let impact = args.get("impact").and_then(|v| v.as_str());
        let remediation = args.get("remediation").and_then(|v| v.as_str());
        let evidence = args.get("evidence").and_then(|v| v.as_str());
        let request = args.get("request").and_then(|v| v.as_str());
        let response = args.get("response").and_then(|v| v.as_str());
        let cvss = args.get("cvss").and_then(|v| v.as_str());
        let cwe = args.get("cwe").and_then(|v| v.as_str());
        let falsification = (
            args.get("counterevidence").and_then(|v| v.as_str()),
            args.get("confidence").and_then(|v| v.as_str()),
            args.get("confidence_rationale").and_then(|v| v.as_str()),
            args.get("severity_change_conditions")
                .and_then(|v| v.as_str()),
            args.get("oracle_type").and_then(|v| v.as_str()),
        );
        match store.add_finding_with_evidence(
            session_id,
            title,
            severity,
            asset,
            vuln_type,
            description,
            reproduction,
            impact,
            remediation,
            evidence,
            request,
            response,
            cvss,
            cwe,
        ) {
            Ok(Some(finding)) => {
                let _ = store.set_finding_falsification(
                    &finding.id,
                    falsification.0,
                    falsification.1,
                    falsification.2,
                    falsification.3,
                    falsification.4,
                );
                tracing::info!(session=%session_id, title=%title, "finding persisted");
                // The authoritative bytes come from the tool's capture, never
                // from the LLM-supplied request/response arguments above.
                let own_capture = result
                    .structured
                    .as_ref()
                    .and_then(agentbug_tools::capture_from_structured);
                let capture = if own_capture.is_some() {
                    own_capture
                } else {
                    store
                        .take_session_capture(session_id)
                        .ok()
                        .flatten()
                        .map(|c| {
                            (
                                String::from_utf8_lossy(&c.request_bytes).to_string(),
                                String::from_utf8_lossy(&c.response_bytes).to_string(),
                                c.canary,
                            )
                        })
                };
                if let Some((request, response, canary)) = capture {
                    if let Err(e) = store.attach_capture(
                        &finding.id,
                        request.as_bytes(),
                        response.as_bytes(),
                        &canary,
                    ) {
                        tracing::warn!(error=%e, session=%session_id, "failed to attach capture");
                    }
                }
            }
            Ok(None) => {
                tracing::info!(session=%session_id, title=%title, "duplicate finding skipped")
            }
            Err(e) => tracing::warn!(error=%e, session=%session_id, "failed to persist finding"),
        }
    }
    if is_asset {
        let kind = args.get("kind").and_then(|v| v.as_str()).unwrap_or("asset");
        let value = args.get("value").and_then(|v| v.as_str()).unwrap_or("");
        let metadata = args.get("metadata").map(|v| v.to_string());
        if let Err(e) = store.upsert_asset(session_id, kind, value, metadata.as_deref()) {
            tracing::warn!(error=%e, session=%session_id, "failed to persist asset");
        }
    }
    if is_artifact {
        let kind = args
            .get("kind")
            .and_then(|v| v.as_str())
            .unwrap_or("artifact");
        let path = args.get("path").and_then(|v| v.as_str());
        let content = args.get("content").and_then(|v| v.as_str());
        let metadata = args.get("metadata").map(|v| v.to_string());
        if let Err(e) = store.add_artifact(session_id, kind, path, content, metadata.as_deref()) {
            tracing::warn!(error=%e, session=%session_id, "failed to persist artifact");
        }
    }
    if n == "task_put" {
        let engagement = args
            .get("engagement_id")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .unwrap_or(session_id);
        let statement = args.get("statement").and_then(|v| v.as_str()).unwrap_or("");
        if !statement.is_empty() {
            let playbook_id = args
                .get("playbook_id")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let target = args.get("target").and_then(|v| v.as_str());
            let priority = args
                .get("priority")
                .or_else(|| args.get("severity"))
                .and_then(|v| v.as_str())
                .map(parse_priority)
                .unwrap_or(0);
            match store.create_task(engagement, statement, playbook_id, target, priority) {
                Ok(task) => tracing::info!(session=%session_id, task=%task.id, "task persisted"),
                Err(e) => tracing::warn!(error=%e, session=%session_id, "failed to persist task"),
            }
        }
    }
    if n == "clue_put" {
        let engagement = args
            .get("engagement_id")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .unwrap_or(session_id);
        let key = args.get("key").and_then(|v| v.as_str()).unwrap_or("");
        if !key.is_empty() {
            let task_id = args.get("task_id").and_then(|v| v.as_str());
            let source_tool = args
                .get("source_tool")
                .and_then(|v| v.as_str())
                .unwrap_or("clue_put");
            let value = args
                .get("value")
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            let value_json = serde_json::to_string(&value).unwrap_or_else(|_| "null".into());
            if let Err(e) = store.add_clue(engagement, task_id, source_tool, key, &value_json) {
                tracing::warn!(error=%e, session=%session_id, "failed to persist clue");
            }
        }
    }
    if n.contains("validat") {
        // Never promote a finding from a tool result: the tool's oracle can be
        // supplied by the LLM itself. Only the engagement verifier, which
        // replays stored bytes against an independent canary, may set
        // `validated`. Keep the tool output as advisory evidence only.
        tracing::info!(
            session = %session_id,
            "ignoring tool-reported validation; engagement verifier is authoritative"
        );
        // The paired control bytes come from the tool, never from LLM args.
        // They are stored as role-tagged captures for the verifier; this path
        // still never promotes a finding.
        if let Some(finding_id) = args.get("finding_id").and_then(|v| v.as_str()) {
            if let Some(paired) = result
                .structured
                .as_ref()
                .and_then(|v| v.get("paired_capture"))
            {
                for (role, key) in [("paired_benign", "benign"), ("paired_payload", "payload")] {
                    if let Some(capture) = paired.get(key) {
                        let request = capture
                            .get("request")
                            .and_then(|v| v.as_str())
                            .unwrap_or("");
                        let response = capture
                            .get("response")
                            .and_then(|v| v.as_str())
                            .unwrap_or("");
                        let canary = capture.get("canary").and_then(|v| v.as_str()).unwrap_or("");
                        if !request.is_empty() && !response.is_empty() && !canary.is_empty() {
                            let _ = store.attach_role_capture(
                                finding_id,
                                role,
                                request.as_bytes(),
                                response.as_bytes(),
                                canary,
                                Some(canary),
                            );
                        }
                    }
                }
            }
        }
    }
}

/// Normalize a tool-reported priority into the durable integer priority used
/// by `tasks`. Numeric strings pass through; common labels use a fixed rank.
fn parse_priority(raw: &str) -> i64 {
    if let Ok(n) = raw.parse::<i64>() {
        return n;
    }
    match raw.to_ascii_lowercase().as_str() {
        "critical" => 4,
        "high" => 3,
        "medium" | "med" => 2,
        "low" => 1,
        _ => 0,
    }
}

/// Monotonic domain progress signal used by the kernel stall detector.
/// Confirmed findings, assets and artifacts count; raw coverage rows do not.
pub fn domain_progress_count(store: &Store, session_id: &str) -> usize {
    let confirmed_findings = store
        .list_findings(session_id)
        .map(|findings| {
            findings
                .into_iter()
                .filter(|finding| {
                    let status = finding.status.to_ascii_lowercase();
                    matches!(status.as_str(), "validated" | "confirmed" | "verified")
                })
                .count()
        })
        .unwrap_or(0);
    let assets = store.list_assets(session_id).map(|v| v.len()).unwrap_or(0);
    let artifacts = store
        .list_artifacts(session_id)
        .map(|v| v.len())
        .unwrap_or(0);
    confirmed_findings + assets + artifacts
}

/// A durable inbox item. The in-memory `Inbox` remains a compatibility source;
/// this row is authoritative for callers that need delivery to survive restart.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInboxItem {
    pub id: String,
    pub session_id: String,
    pub kind: String,
    pub delivery: String,
    pub payload_json: String,
    pub state: String,
    pub created_at: String,
    pub enqueued_seq: i64,
}

fn inbox_item_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<SessionInboxItem> {
    Ok(SessionInboxItem {
        id: row.get(0)?,
        session_id: row.get(1)?,
        kind: row.get(2)?,
        delivery: row.get(3)?,
        payload_json: row.get(4)?,
        state: row.get(5)?,
        created_at: row.get(6)?,
        enqueued_seq: row.get(7)?,
    })
}

impl Store {
    /// First admission wins: a retry with the same id is ignored entirely.
    pub fn enqueue_inbox(
        &self,
        id: &str,
        session_id: &str,
        kind: &str,
        delivery: &str,
        payload_json: &str,
    ) -> Result<bool> {
        let conn = self.conn.lock().unwrap();
        let seq: i64 = conn.query_row(
            "SELECT COALESCE(MAX(enqueued_seq), 0) + 1 FROM session_inbox WHERE session_id=?1",
            params![session_id],
            |row| row.get(0),
        )?;
        conn.execute(
            "INSERT OR IGNORE INTO session_inbox
             (id, session_id, kind, delivery, payload_json, state, created_at, enqueued_seq)
             VALUES (?1, ?2, ?3, ?4, ?5, 'pending', ?6, ?7)",
            params![id, session_id, kind, delivery, payload_json, now(), seq],
        )?;
        Ok(conn.changes() > 0)
    }

    /// Promote the next item: controls first, then steer-delivery, then queued
    /// items when `include_queue` is true. Promotion is non-consuming.
    pub fn promote_inbox(
        &self,
        session_id: &str,
        include_queue: bool,
    ) -> Result<Option<SessionInboxItem>> {
        let conn = self.conn.lock().unwrap();
        let found: Option<SessionInboxItem> = conn
            .query_row(
                "SELECT id, session_id, kind, delivery, payload_json, state, created_at, enqueued_seq
                 FROM session_inbox
                 WHERE session_id=?1 AND state='pending'
                   AND (?2=1 OR kind='control' OR delivery='steer')
                 ORDER BY CASE kind WHEN 'control' THEN 0 ELSE 1 END ASC,
                          CASE delivery WHEN 'steer' THEN 0 ELSE 1 END ASC,
                          enqueued_seq ASC
                 LIMIT 1",
                params![session_id, include_queue as i64],
                inbox_item_from_row,
            )
            .optional()?;
        if let Some(item) = &found {
            conn.execute(
                "UPDATE session_inbox SET state='steered' WHERE id=?1 AND state='pending'",
                params![item.id],
            )?;
        }
        Ok(found)
    }

    /// Atomically deliver: mark consumed and insert the visible message in one
    /// transaction. A second delivery of the same id is a no-op.
    pub fn deliver_inbox(
        &self,
        id: &str,
        visible: Option<(&str, &str)>,
    ) -> Result<Option<SessionInboxItem>> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        let item: Option<SessionInboxItem> = tx
            .query_row(
                "SELECT id, session_id, kind, delivery, payload_json, state, created_at, enqueued_seq
                 FROM session_inbox WHERE id=?1 AND state IN ('pending','steered')",
                params![id],
                inbox_item_from_row,
            )
            .optional()?;
        let Some(item) = item else {
            return Ok(None);
        };
        if let Some((role, content)) = visible {
            tx.execute(
                "INSERT INTO messages(id, session_id, role, content, tool_call_id, tool_calls_json, name)
                 VALUES (?1, ?2, ?3, ?4, NULL, NULL, NULL)",
                params![Uuid::new_v4().to_string(), item.session_id, role, content],
            )?;
        }
        tx.execute(
            "UPDATE session_inbox SET state='delivered' WHERE id=?1",
            params![id],
        )?;
        tx.commit()?;
        Ok(Some(item))
    }

    pub fn cancel_inbox(&self, id: &str) -> Result<bool> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE session_inbox SET state='cancelled'
             WHERE id=?1 AND state IN ('pending','steered')",
            params![id],
        )?;
        Ok(conn.changes() > 0)
    }

    pub fn resteer_inbox(&self, id: &str, delivery: &str) -> Result<bool> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE session_inbox SET delivery=?2, state='pending'
             WHERE id=?1 AND state IN ('pending','steered')",
            params![id, delivery],
        )?;
        Ok(conn.changes() > 0)
    }

    pub fn list_pending_inbox(&self, session_id: &str) -> Result<Vec<SessionInboxItem>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, session_id, kind, delivery, payload_json, state, created_at, enqueued_seq
             FROM session_inbox
             WHERE session_id=?1 AND state IN ('pending','steered')
             ORDER BY enqueued_seq ASC",
        )?;
        let rows = stmt
            .query_map(params![session_id], inbox_item_from_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn resume_attempt(&self, session_id: &str) -> Result<u64> {
        let conn = self.conn.lock().unwrap();
        Ok(conn.query_row(
            "SELECT COALESCE(resume_attempts, 0) FROM sessions WHERE id=?1",
            params![session_id],
            |row| row.get::<_, i64>(0),
        )? as u64)
    }

    pub fn increment_resume_attempt(&self, session_id: &str) -> Result<u64> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE sessions SET resume_attempts=COALESCE(resume_attempts,0)+1 WHERE id=?1",
            params![session_id],
        )?;
        Ok(conn.query_row(
            "SELECT COALESCE(resume_attempts, 0) FROM sessions WHERE id=?1",
            params![session_id],
            |row| row.get::<_, i64>(0),
        )? as u64)
    }

    pub fn reset_resume_attempt(&self, session_id: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE sessions SET resume_attempts=0 WHERE id=?1",
            params![session_id],
        )?;
        Ok(())
    }

    /// Convert assistant tool calls that never received a result into terminal
    /// tool messages. Idempotent: a second run finds nothing to settle.
    pub fn settle_unanswered_tool_calls(
        &self,
        session_id: &str,
        status_text: &str,
    ) -> Result<usize> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT tool_calls_json FROM messages WHERE session_id=?1 AND role='assistant'",
        )?;
        let raws: Vec<String> = stmt
            .query_map(params![session_id], |row| row.get::<_, Option<String>>(0))?
            .filter_map(Result::ok)
            .flatten()
            .collect();
        let mut answered: HashSet<String> = HashSet::new();
        let mut stmt = conn.prepare(
            "SELECT tool_call_id FROM messages WHERE session_id=?1 AND role='tool' AND tool_call_id IS NOT NULL",
        )?;
        for id in (stmt.query_map(params![session_id], |row| row.get::<_, String>(0))?).flatten() {
            answered.insert(id);
        }
        drop(stmt);
        let mut missing = Vec::new();
        for raw in raws {
            if let Ok(Value::Array(calls)) = serde_json::from_str::<Value>(&raw) {
                for call in calls {
                    if let (Some(id), Some(name)) = (
                        call.get("id").and_then(|v| v.as_str()),
                        call.get("name").and_then(|v| v.as_str()),
                    ) {
                        if !answered.contains(id) {
                            missing.push((id.to_string(), name.to_string()));
                        }
                    }
                }
            }
        }
        let mut settled = 0;
        for (id, name) in missing {
            conn.execute(
                "INSERT INTO messages(id, session_id, role, content, tool_call_id, tool_calls_json, name)
                 VALUES (?1, ?2, 'tool', ?3, ?4, NULL, ?5)",
                params![
                    Uuid::new_v4().to_string(),
                    session_id,
                    status_text,
                    id,
                    name
                ],
            )?;
            settled += 1;
        }
        Ok(settled)
    }

    /// Successful low-risk results eligible for repeat echo. The risk filter
    /// is applied to the stored, host-owned label; a tool re-registered under
    /// a different hint cannot make a dangerous result echoable.
    pub fn recent_echoable_results_for_signature(
        &self,
        session_id: &str,
        name: &str,
        args_sig: &str,
        limit: i64,
    ) -> Result<Vec<String>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT result_text FROM tool_calls
             WHERE session_id=?1 AND name=?2 AND args_sig=?3
               AND status='ok' AND ok=1 AND risk IN ('safe','read')
               AND result_text IS NOT NULL
             ORDER BY rowid DESC LIMIT ?4",
        )?;
        let rows = stmt
            .query_map(params![session_id, name, args_sig, limit], |row| {
                row.get::<_, String>(0)
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Drain any parked deferred calls into terminal tool messages.
    pub fn settle_pending_calls(&self, session_id: &str, status_text: &str) -> Result<usize> {
        let approval_ids: Vec<String> = {
            let conn = self.conn.lock().unwrap();
            let mut stmt =
                conn.prepare("SELECT id FROM approvals WHERE session_id=?1 AND status='pending'")?;
            let ids = stmt
                .query_map(params![session_id], |row| row.get::<_, String>(0))?
                .filter_map(Result::ok)
                .collect();
            ids
        };
        let mut settled = 0;
        for approval_id in approval_ids {
            for call in self.take_pending_calls(session_id, &approval_id)? {
                self.add_message_full(
                    session_id,
                    "tool",
                    status_text,
                    call.tool_call_id.as_deref(),
                    None,
                    Some(&call.name),
                )?;
                settled += 1;
            }
        }
        Ok(settled)
    }
}

/// Durable lifecycle record for one tool invocation. The risk value is the
/// host-owned classification, never the tool's self-reported hint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCallRow {
    pub id: String,
    pub session_id: String,
    pub tool_call_id: Option<String>,
    pub name: String,
    pub args_json: String,
    pub args_sig: String,
    pub status: String,
    pub risk: String,
    pub ok: Option<bool>,
    pub result_text: Option<String>,
    pub created_at: String,
    pub settled_at: Option<String>,
}

impl Store {
    pub fn start_tool_call(
        &self,
        session_id: &str,
        tool_call_id: Option<&str>,
        name: &str,
        args_json: &str,
        args_sig: &str,
        risk: &str,
    ) -> Result<String> {
        let id = Uuid::new_v4().to_string();
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO tool_calls
             (id, session_id, tool_call_id, name, args_json, args_sig, status, risk,
              ok, result_text, created_at, settled_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'running', ?7, NULL, NULL, ?8, NULL)",
            params![
                id,
                session_id,
                tool_call_id,
                name,
                args_json,
                args_sig,
                risk,
                now()
            ],
        )?;
        Ok(id)
    }

    /// Idempotent settlement: a second call on a settled row changes nothing.
    pub fn finish_tool_call(
        &self,
        id: &str,
        status: &str,
        ok: Option<bool>,
        result_text: Option<&str>,
    ) -> Result<bool> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE tool_calls SET status=?2, ok=?3, result_text=?4, settled_at=?5
             WHERE id=?1 AND status='running'",
            params![id, status, ok.map(|v| v as i64), result_text, now()],
        )?;
        Ok(conn.changes() > 0)
    }

    /// Successful, executed results for the same signature in this session,
    /// most recent first. Only these are eligible for repeat echo.
    pub fn recent_results_for_signature(
        &self,
        session_id: &str,
        name: &str,
        args_sig: &str,
        limit: i64,
    ) -> Result<Vec<String>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT result_text FROM tool_calls
             WHERE session_id=?1 AND name=?2 AND args_sig=?3
               AND status='ok' AND ok=1 AND result_text IS NOT NULL
             ORDER BY rowid DESC LIMIT ?4",
        )?;
        let rows = stmt
            .query_map(params![session_id, name, args_sig, limit], |row| {
                row.get::<_, String>(0)
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }
}

impl Store {
    pub fn save_rule_provenance(&self, rows: &[RuleProvenance]) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        for row in rows {
            conn.execute(
                "INSERT INTO brief_rule_provenance(id, engagement_id, rule_kind, rule_value,
                 source_url, section_pointer, verbatim_quote, verbatim_quote_hash,
                 content_hash, extractor, observed_at, created_at)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",
                params![
                    Uuid::new_v4().to_string(),
                    row.engagement_id,
                    row.rule_kind,
                    row.rule_value,
                    row.source_url,
                    row.section_pointer,
                    row.verbatim_quote,
                    row.verbatim_quote_hash,
                    row.content_hash,
                    row.extractor,
                    row.observed_at,
                    now()
                ],
            )?;
        }
        Ok(())
    }

    pub fn list_rule_provenance(&self, engagement_id: &str) -> Result<Vec<RuleProvenance>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT engagement_id, rule_kind, rule_value, source_url, section_pointer,
             verbatim_quote, verbatim_quote_hash, content_hash, extractor, observed_at
             FROM brief_rule_provenance WHERE engagement_id=?1 ORDER BY rowid",
        )?;
        let rows = stmt
            .query_map(params![engagement_id], |r| {
                Ok(RuleProvenance {
                    engagement_id: r.get(0)?,
                    rule_kind: r.get(1)?,
                    rule_value: r.get(2)?,
                    source_url: r.get(3)?,
                    section_pointer: r.get(4)?,
                    verbatim_quote: r.get(5)?,
                    verbatim_quote_hash: r.get(6)?,
                    content_hash: r.get(7)?,
                    extractor: r.get(8)?,
                    observed_at: r.get(9)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }
}

/// Provenance-bearing memory row. `role` and `scope_key` are opaque to the
/// kernel; the domain owns their meaning.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryItem {
    pub id: String,
    pub session_id: String,
    pub parent_session_id: Option<String>,
    pub source_kind: String,
    pub source_id: String,
    pub source_event_hash: Option<String>,
    pub role: Option<String>,
    pub task_id: Option<String>,
    pub scope_key: String,
    pub tier: String,
    pub content: String,
    pub sha256: String,
    pub created_at: String,
}

/// Input for [`Store::add_memory`], grouped to keep the method signature small.
pub struct MemoryWrite<'a> {
    pub session_id: &'a str,
    pub parent_session_id: Option<&'a str>,
    pub source_kind: &'a str,
    pub source_id: &'a str,
    pub source_event_hash: Option<&'a str>,
    pub role: Option<&'a str>,
    pub task_id: Option<&'a str>,
    pub scope_key: &'a str,
    pub tier: &'a str,
    pub content: &'a str,
}

impl Store {
    pub fn add_memory(&self, item: MemoryWrite<'_>) -> Result<String> {
        let MemoryWrite {
            session_id,
            parent_session_id,
            source_kind,
            source_id,
            source_event_hash,
            role,
            task_id,
            scope_key,
            tier,
            content,
        } = item;
        let id = Uuid::new_v4().to_string();
        let digest = sha256_hex(content);
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO memory_items(id, session_id, parent_session_id, source_kind,
             source_id, source_event_hash, role, task_id, scope_key, tier, content, sha256, created_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
            params![
                id, session_id, parent_session_id, source_kind, source_id,
                source_event_hash, role, task_id, scope_key, tier, content, digest, now()
            ],
        )?;
        Ok(id)
    }

    /// Scope-gated retrieval: rows from another goal digest are never returned.
    pub fn list_memory(
        &self,
        session_id: &str,
        scope_key: &str,
        tier: &str,
        role: Option<&str>,
        limit: i64,
    ) -> Result<Vec<MemoryItem>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, session_id, parent_session_id, source_kind, source_id,
                    source_event_hash, role, task_id, scope_key, tier, content, sha256, created_at
             FROM memory_items
             WHERE session_id=?1 AND scope_key=?2 AND tier=?3
               AND (?4 IS NULL OR role=?4)
             ORDER BY rowid DESC LIMIT ?5",
        )?;
        let rows = stmt
            .query_map(params![session_id, scope_key, tier, role, limit], |row| {
                Ok(MemoryItem {
                    id: row.get(0)?,
                    session_id: row.get(1)?,
                    parent_session_id: row.get(2)?,
                    source_kind: row.get(3)?,
                    source_id: row.get(4)?,
                    source_event_hash: row.get(5)?,
                    role: row.get(6)?,
                    task_id: row.get(7)?,
                    scope_key: row.get(8)?,
                    tier: row.get(9)?,
                    content: row.get(10)?,
                    sha256: row.get(11)?,
                    created_at: row.get(12)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn verify_memory_hashes(&self, session_id: &str) -> Result<bool> {
        let conn = self.conn.lock().unwrap();
        let mut stmt =
            conn.prepare("SELECT sha256, content FROM memory_items WHERE session_id=?1")?;
        let rows = stmt
            .query_map(params![session_id], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows
            .into_iter()
            .all(|(digest, content)| digest == sha256_hex(&content)))
    }

    pub fn put_session_result(
        &self,
        session_id: &str,
        parent_session_id: Option<&str>,
        parent_tool_call_id: Option<&str>,
        role: &str,
        status: &str,
        payload_json: &str,
    ) -> Result<()> {
        let digest = sha256_hex(payload_json);
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO session_results(session_id, parent_session_id, parent_tool_call_id,
             role, status, payload_json, sha256, created_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)
             ON CONFLICT(session_id) DO UPDATE SET
               parent_session_id=excluded.parent_session_id,
               parent_tool_call_id=excluded.parent_tool_call_id,
               role=excluded.role, status=excluded.status,
               payload_json=excluded.payload_json, sha256=excluded.sha256",
            params![
                session_id,
                parent_session_id,
                parent_tool_call_id,
                role,
                status,
                payload_json,
                digest,
                now()
            ],
        )?;
        Ok(())
    }

    pub fn get_session_result(&self, session_id: &str) -> Result<Option<(String, String, String)>> {
        let conn = self.conn.lock().unwrap();
        Ok(conn
            .query_row(
                "SELECT role, status, payload_json FROM session_results WHERE session_id=?1",
                params![session_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_harbor_receipt_is_idempotent_hash_scoped_and_expires() {
        let store = Store::open(":memory:").unwrap();
        let receipt = SafeHarborReceipt {
            id: "receipt-1".to_string(),
            program_url: "https://hackerone.com/acme".to_string(),
            brief_content_hash: "hash-1".to_string(),
            scope_version: "v1".to_string(),
            terms_hash: "terms-1".to_string(),
            operator: "operator".to_string(),
            acquired_at: "2026-01-01T00:00:00Z".to_string(),
            expires_at: "2026-12-31T00:00:00Z".to_string(),
            decision: "acknowledged".to_string(),
            note: "out of band".to_string(),
        };
        assert!(store.save_safe_harbor_receipt(&receipt).unwrap());
        // Idempotent by id.
        assert!(!store.save_safe_harbor_receipt(&receipt).unwrap());
        assert_eq!(
            store
                .list_safe_harbor_receipts(&receipt.program_url)
                .unwrap()
                .len(),
            1
        );

        let now = "2026-06-01T00:00:00Z";
        let valid = store
            .valid_safe_harbor_receipt(&receipt.program_url, &receipt.brief_content_hash, now)
            .unwrap()
            .expect("valid receipt");
        assert_eq!(valid.id, receipt.id);
        // Scoped to the exact brief hash and program URL.
        assert!(store
            .valid_safe_harbor_receipt(&receipt.program_url, "hash-2", now)
            .unwrap()
            .is_none());
        assert!(store
            .valid_safe_harbor_receipt("https://hackerone.com/other", "hash-1", now)
            .unwrap()
            .is_none());
        assert_eq!(
            store
                .list_safe_harbor_receipts("https://hackerone.com/other")
                .unwrap()
                .len(),
            0
        );
        // Expired at the boundary.
        assert!(store
            .valid_safe_harbor_receipt(
                &receipt.program_url,
                &receipt.brief_content_hash,
                "2027-01-01T00:00:00Z"
            )
            .unwrap()
            .is_none());

        // A non-acknowledged receipt is never "valid" and cannot be promoted
        // into a permission by a flag.
        let mut denied = receipt.clone();
        denied.id = "receipt-2".to_string();
        denied.decision = "observed".to_string();
        assert!(store.save_safe_harbor_receipt(&denied).unwrap());
        assert!(store
            .valid_safe_harbor_receipt(
                &denied.program_url,
                &denied.brief_content_hash,
                "2026-02-01T00:00:00Z"
            )
            .unwrap()
            .is_some()); // the still-valid acknowledged receipt wins
        assert_eq!(
            store
                .list_safe_harbor_receipts(&receipt.program_url)
                .unwrap()
                .len(),
            2
        );
        let mut observed = denied.clone();
        observed.id = "receipt-3".to_string();
        observed.brief_content_hash = "hash-3".to_string();
        assert!(store.save_safe_harbor_receipt(&observed).unwrap());
        assert!(store
            .valid_safe_harbor_receipt(&observed.program_url, "hash-3", now)
            .unwrap()
            .is_none());
    }

    #[test]
    fn create_session_and_messages() {
        let store = Store::open(":memory:").unwrap();
        let s = store.create_session("test goal").unwrap();
        assert_eq!(s.state, "idle");
        assert!(s.owner_id.is_none());
        assert!(s.lease_expires_at.is_none());
        store.set_session_state(&s.id, "running").unwrap();
        store.add_message(&s.id, "user", "hello").unwrap();
        let got = store.get_session(&s.id).unwrap().unwrap();
        assert_eq!(got.state, "running");
    }

    #[test]
    fn claim_and_release() {
        let store = Store::open(":memory:").unwrap();
        let s = store.create_session("g").unwrap();
        // claim by owner A
        store.claim_session(&s.id, "owner-a", 30).unwrap();
        let s2 = store.get_session(&s.id).unwrap().unwrap();
        assert_eq!(s2.owner_id.as_deref(), Some("owner-a"));
        assert!(s2.lease_expires_at.is_some());

        // owner B cannot claim while valid lease
        let err = store.claim_session(&s.id, "owner-b", 30).unwrap_err();
        assert!(err.to_string().contains("claimed by another owner"));

        // release by A
        store.release_claim(&s.id, "owner-a").unwrap();
        let s3 = store.get_session(&s.id).unwrap().unwrap();
        assert!(s3.owner_id.is_none());

        // now B can claim
        store.claim_session(&s.id, "owner-b", 30).unwrap();
        let s4 = store.get_session(&s.id).unwrap().unwrap();
        assert_eq!(s4.owner_id.as_deref(), Some("owner-b"));
    }

    #[test]
    fn expired_lease_reclaim() {
        let store = Store::open(":memory:").unwrap();
        let s = store.create_session("g").unwrap();
        // claim with 0-second lease (immediately expired)
        store.claim_session(&s.id, "owner-a", 0).unwrap();
        // wait a tiny bit to ensure expiry
        std::thread::sleep(std::time::Duration::from_millis(10));
        // owner B can reclaim
        store.claim_session(&s.id, "owner-b", 30).unwrap();
        let s2 = store.get_session(&s.id).unwrap().unwrap();
        assert_eq!(s2.owner_id.as_deref(), Some("owner-b"));
    }

    #[test]
    fn renew_lease() {
        let store = Store::open(":memory:").unwrap();
        let s = store.create_session("g").unwrap();
        store.claim_session(&s.id, "owner-a", 10).unwrap();
        store.renew_lease(&s.id, "owner-a", 60).unwrap();
        let s2 = store.get_session(&s.id).unwrap().unwrap();
        assert!(s2.lease_expires_at.is_some());
        // wrong owner cannot renew
        let err = store.renew_lease(&s.id, "owner-b", 60).unwrap_err();
        assert!(err.to_string().contains("not owned"));
    }

    #[test]
    fn mark_stale_running_interrupted() {
        let store = Store::open(":memory:").unwrap();
        let s1 = store.create_session("g1").unwrap();
        store.set_session_state(&s1.id, "running").unwrap();
        // no owner/lease -> stale
        let ids = store.mark_stale_running_interrupted().unwrap();
        assert_eq!(ids, vec![s1.id.clone()]);
        let s1b = store.get_session(&s1.id).unwrap().unwrap();
        assert_eq!(s1b.state, "interrupted");
        assert!(s1b.owner_id.is_none());

        // running with valid lease should NOT be interrupted
        let s2 = store.create_session("g2").unwrap();
        store.set_session_state(&s2.id, "running").unwrap();
        store.claim_session(&s2.id, "owner-x", 60).unwrap();
        let ids2 = store.mark_stale_running_interrupted().unwrap();
        assert!(ids2.is_empty());
        assert_eq!(store.get_session(&s2.id).unwrap().unwrap().state, "running");
    }

    #[test]
    fn transition_state_guarded() {
        let store = Store::open(":memory:").unwrap();
        let s = store.create_session("g").unwrap();
        assert_eq!(s.state, "idle");
        assert!(store.transition_state(&s.id, &["idle"], "running").unwrap());
        assert_eq!(store.get_session(&s.id).unwrap().unwrap().state, "running");
        // wrong from state -> no-op
        assert!(!store
            .transition_state(&s.id, &["idle"], "completed")
            .unwrap());
        assert_eq!(store.get_session(&s.id).unwrap().unwrap().state, "running");
        assert!(store
            .transition_state(&s.id, &["running", "waiting_approval"], "completed")
            .unwrap());
        assert_eq!(
            store.get_session(&s.id).unwrap().unwrap().state,
            "completed"
        );
    }

    #[test]
    fn set_state_release_clears_claim() {
        let store = Store::open(":memory:").unwrap();
        let s = store.create_session("g").unwrap();
        store.claim_session(&s.id, "o", 60).unwrap();
        store.set_state_release(&s.id, "waiting_approval").unwrap();
        let s2 = store.get_session(&s.id).unwrap().unwrap();
        assert_eq!(s2.state, "waiting_approval");
        assert!(s2.owner_id.is_none());
        assert!(s2.lease_expires_at.is_none());
    }

    #[test]
    fn approval_lifecycle() {
        let store = Store::open(":memory:").unwrap();
        let s = store.create_session("g").unwrap();
        let a = store
            .create_approval(
                &s.id,
                "shell_exec",
                r#"{"cmd":"echo hi"}"#,
                "exec",
                "needs ok",
                None,
            )
            .unwrap();
        let p = store.get_pending_approval(&s.id).unwrap().unwrap();
        assert_eq!(p.id, a.id);
        assert_eq!(p.tool_name, "shell_exec");
        store
            .resolve_approval(&a.id, "approved", Some("ok"))
            .unwrap();
        assert!(store.get_pending_approval(&s.id).unwrap().is_none());
    }

    #[test]
    fn event_logging() {
        let store = Store::open(":memory:").unwrap();
        let s = store.create_session("g").unwrap();
        store
            .add_event(&s.id, "info", "session.start", "started")
            .unwrap();
        store
            .add_event(&s.id, "warn", "tool.timeout", "timeout")
            .unwrap();
        let events = store.list_events(&s.id, 10).unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].kind, "session.start");
        assert_eq!(events[1].kind, "tool.timeout");
    }

    #[test]
    fn redaction_covers_json_headers_and_multiple_bearers() {
        let input = r#"{"api_key": "plaintext", "nested": {"token": "abc123"}, "Authorization": "Bearer one", "note": "Bearer two"}"#;
        let out = redact(input);
        assert!(!out.contains("plaintext"));
        assert!(!out.contains("abc123"));
        assert!(!out.contains("one"));
        assert!(!out.contains("two"));
        assert_eq!(out.matches("[REDACTED]").count(), 4);

        let text = "Set-Cookie: session=abc123; Bearer first and Bearer second api_key='xyz'";
        let out = redact(text);
        assert!(!out.contains("abc123"));
        assert!(!out.contains("first"));
        assert!(!out.contains("second"));
        assert!(!out.contains("xyz"));
    }

    #[test]
    fn approval_resolution_is_single_use() {
        let store = Store::open(":memory:").unwrap();
        let s = store.create_session("g").unwrap();
        let a = store
            .create_approval(&s.id, "shell_exec", "{}", "exec", "why", None)
            .unwrap();
        store.resolve_approval(&a.id, "approved", None).unwrap();
        assert!(store.resolve_approval(&a.id, "approved", None).is_err());
    }

    #[test]
    fn budget_counters_are_durable_and_windowed() {
        let store = Store::open(":memory:").unwrap();
        let s = store.create_session("g").unwrap();
        store.ensure_budget(&s.id).unwrap();
        store.record_step(&s.id).unwrap();
        store.record_tool_call(&s.id, true).unwrap();
        store.record_tool_call(&s.id, false).unwrap();
        let usage = store.budget_usage(&s.id).unwrap();
        assert_eq!(usage.steps_used, 1);
        assert_eq!(usage.tool_calls_used, 2);
        assert_eq!(usage.network_calls_used, 1);
        assert_eq!(usage.calls_in_window, 2);
    }

    #[test]
    fn budget_offsets_are_additive_and_idempotent() {
        let store = Store::open(":memory:").unwrap();
        let plain = store.create_session("plain").unwrap();
        let child = store.create_session("child").unwrap();
        store.ensure_budget(&plain.id).unwrap();
        store.ensure_budget(&child.id).unwrap();
        assert_eq!(store.budget_usage(&plain.id).unwrap().steps_used, 0);
        assert_eq!(store.budget_usage(&child.id).unwrap().steps_used, 0);

        store.seed_budget_offsets(&child.id, 3, 2, 1, 99).unwrap();
        // A retry must not re-apply the inherited usage.
        store
            .seed_budget_offsets(&child.id, 30, 20, 10, 999)
            .unwrap();
        store.record_step(&child.id).unwrap();
        store.record_tool_call(&child.id, true).unwrap();
        let usage = store.budget_usage(&child.id).unwrap();
        assert_eq!(usage.steps_used, 4);
        assert_eq!(usage.tool_calls_used, 3);
        assert_eq!(usage.network_calls_used, 2);
        assert_eq!(usage.calls_in_window, 1);
        store.record_token_usage(&child.id, 40, 8, 0.0).unwrap();
        assert_eq!(store.token_usage_total(&child.id).unwrap(), 48);

        // Zero offsets are the default and leave the row behaving as before.
        store.seed_budget_offsets(&plain.id, 0, 0, 0, 0).unwrap();
        store.record_step(&plain.id).unwrap();
        let plain_usage = store.budget_usage(&plain.id).unwrap();
        assert_eq!(plain_usage.steps_used, 1);
        assert_eq!(plain_usage.tool_calls_used, 0);
        assert_eq!(plain_usage.network_calls_used, 0);
        assert_eq!(store.token_usage_total(&plain.id).unwrap(), 0);
    }

    #[test]
    fn pending_tool_calls_are_taken_once() {
        let store = Store::open(":memory:").unwrap();
        let s = store.create_session("g").unwrap();
        let calls = [
            (Some("c1"), "echo", r#"{"text":"one"}"#),
            (None, "echo", r#"{"text":"two"}"#),
        ];
        store
            .save_pending_calls(&s.id, "approval-1", &calls)
            .unwrap();
        let taken = store.take_pending_calls(&s.id, "approval-1").unwrap();
        assert_eq!(taken.len(), 2);
        assert_eq!(taken[0].tool_call_id.as_deref(), Some("c1"));
        assert!(store
            .take_pending_calls(&s.id, "approval-1")
            .unwrap()
            .is_empty());
    }

    #[test]
    fn owned_transition_checks_owner_and_from_state() {
        let store = Store::open(":memory:").unwrap();
        let s = store.create_session("g").unwrap();
        store.claim_session(&s.id, "owner-a", 60).unwrap();
        assert!(store
            .transition_state_owned(&s.id, "owner-a", &["idle"], "running")
            .unwrap());
        assert!(!store
            .transition_state_owned(&s.id, "owner-b", &["running"], "completed")
            .unwrap());
        assert!(!store
            .transition_state_owned(&s.id, "owner-a", &["idle"], "completed")
            .unwrap());
    }

    #[test]
    fn finding_dedupe_by_key() {
        let store = Store::open(":memory:").unwrap();
        let s = store.create_session("g").unwrap();
        let first = store
            .add_finding_with_evidence(
                &s.id,
                "SQL Injection",
                "high",
                Some("https://example.com/login"),
                Some("sqli"),
                "desc",
                Some("repro"),
                Some("impact"),
                Some("fix"),
                Some("evidence text"),
                Some("POST /login"),
                Some("HTTP/1.1 200"),
                Some("CVSS:3.1/AV:N/AC:L"),
                Some("CWE-89"),
            )
            .unwrap()
            .expect("first insert should succeed");
        assert_eq!(
            first.dedupe_key.as_deref(),
            Some("sql injection|https://example.com/login|sqli")
        );
        assert!(first.evidence_hash.is_some());

        // Same key, different casing -> deduped, no insert.
        let dup = store
            .add_finding_with_evidence(
                &s.id,
                "sql injection",
                "high",
                Some("https://example.com/login"),
                Some("SQLI"),
                "other desc",
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
            )
            .unwrap();
        assert!(dup.is_none());
        assert_eq!(store.list_findings(&s.id).unwrap().len(), 1);

        // Different key -> inserted.
        let second = store
            .add_finding_with_evidence(
                &s.id, "XSS", "medium", None, None, "desc", None, None, None, None, None, None,
                None, None,
            )
            .unwrap();
        assert!(second.is_some());
        let loaded = store.list_findings(&s.id).unwrap();
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0].request.as_deref(), Some("POST /login"));
        assert_eq!(loaded[0].cwe.as_deref(), Some("CWE-89"));
        assert_eq!(loaded[0].cvss.as_deref(), Some("CVSS:3.1/AV:N/AC:L"));
    }

    #[test]
    fn approval_ttl_filtering() {
        let store = Store::open(":memory:").unwrap();
        let s = store.create_session("g").unwrap();

        let valid = store
            .create_approval(&s.id, "shell", "{}", "exec", "reason", None)
            .unwrap();
        assert!(valid.expires_at.is_some());

        let expired = store
            .create_approval_with_ttl(&s.id, "shell", "{}", "exec", "reason", None, -60)
            .unwrap();
        assert!(expired.expires_at.is_some());

        let pending = store.get_pending_approval(&s.id).unwrap().unwrap();
        assert_eq!(pending.id, valid.id);
        assert_eq!(pending.expires_at, valid.expires_at);
        let listed = store.list_pending_approvals(&s.id).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, valid.id);

        let n = store.expire_stale_approvals().unwrap();
        assert_eq!(n, 1);
        assert_eq!(
            store.get_pending_approval(&s.id).unwrap().unwrap().id,
            valid.id
        );
        assert_eq!(store.list_pending_approvals(&s.id).unwrap().len(), 1);
    }

    #[test]
    fn coverage_and_hypothesis_crud() {
        let store = Store::open(":memory:").unwrap();
        let s = store.create_session("g").unwrap();

        store
            .record_coverage(&s.id, "https://example.com", "GET", "/")
            .unwrap();
        store
            .record_coverage(&s.id, "https://example.com", "GET", "/")
            .unwrap();
        store
            .record_coverage(&s.id, "https://example.com", "POST", "/login")
            .unwrap();
        assert_eq!(store.coverage_count(&s.id).unwrap(), 2);
        let coverage = store.list_coverage(&s.id).unwrap();
        assert_eq!(coverage.len(), 2);
        assert!(coverage.iter().all(|c| c.session_id == s.id));
        assert!(coverage
            .iter()
            .any(|c| c.method == "POST" && c.path == "/login"));

        let h = store
            .add_hypothesis(&s.id, "Login may be vulnerable to SQLi")
            .unwrap();
        assert_eq!(h.status, "open");
        let h2 = store
            .add_hypothesis(&s.id, "Endpoint may leak tokens")
            .unwrap();
        let hypotheses = store.list_hypotheses(&s.id).unwrap();
        assert_eq!(hypotheses.len(), 2);

        store.set_hypothesis_status(&h.id, "confirmed").unwrap();
        let hypotheses = store.list_hypotheses(&s.id).unwrap();
        assert_eq!(
            hypotheses.iter().find(|x| x.id == h.id).unwrap().status,
            "confirmed"
        );
        assert_eq!(
            hypotheses.iter().find(|x| x.id == h2.id).unwrap().status,
            "open"
        );

        store
            .record_approved_target(&s.id, "https://example.com")
            .unwrap();
        store
            .record_approved_target(&s.id, "https://example.com")
            .unwrap();
        assert_eq!(
            store.list_approved_targets(&s.id).unwrap(),
            vec!["https://example.com".to_string()]
        );
    }

    #[test]
    fn report_includes_evidence_coverage_and_hypotheses() {
        let store = Store::open(":memory:").unwrap();
        let s = store.create_session("g").unwrap();
        store
            .add_finding_with_evidence(
                &s.id,
                "Leak",
                "high",
                None,
                None,
                "desc",
                None,
                None,
                None,
                Some("api_key=supersecret"),
                Some("GET /admin HTTP/1.1 Authorization: Bearer abc123"),
                Some("HTTP/1.1 200 OK"),
                Some("7.5"),
                Some("CWE-200"),
            )
            .unwrap();
        store
            .record_coverage(&s.id, "https://example.com", "GET", "/admin")
            .unwrap();
        store
            .add_hypothesis(&s.id, "Admin panel is public")
            .unwrap();

        let report = store.export_report(&s.id).unwrap();
        assert!(report.contains("## Coverage"));
        assert!(report.contains("## Hypotheses"));
        assert!(report.contains("Request:"));
        assert!(report.contains("Response:"));
        assert!(report.contains("CVSS:"));
        assert!(report.contains("CWE:"));
        assert!(!report.contains("supersecret"));
        assert!(!report.contains("abc123"));
    }

    #[test]
    fn event_hash_chain_and_tamper_detection() {
        let store = Store::open(":memory:").unwrap();
        let s = store.create_session("g").unwrap();
        assert!(store.verify_event_chain(&s.id).unwrap());

        store
            .add_event(&s.id, "info", "session.start", "started")
            .unwrap();
        store
            .add_event(&s.id, "warn", "tool.timeout", "timeout")
            .unwrap();
        let events = store.list_events(&s.id, 10).unwrap();
        assert_eq!(events.len(), 2);
        assert!(events[0].prev_hash.is_none());
        assert_eq!(events[0].hash.len(), 64);
        assert_eq!(
            events[1].prev_hash.as_deref(),
            Some(events[0].hash.as_str())
        );
        assert_eq!(events[1].hash.len(), 64);
        assert!(store.verify_event_chain(&s.id).unwrap());

        // Tamper with a message directly; the stored hash no longer recomputes.
        let tampered_id = events[1].id.clone();
        {
            let conn = store.conn.lock().unwrap();
            conn.execute(
                "UPDATE events SET message='tampered' WHERE id=?1",
                params![tampered_id],
            )
            .unwrap();
        }
        assert!(!store.verify_event_chain(&s.id).unwrap());

        // Restore it, then break the link by tampering with the stored hash.
        {
            let conn = store.conn.lock().unwrap();
            conn.execute(
                "UPDATE events SET message='timeout' WHERE id=?1",
                params![tampered_id],
            )
            .unwrap();
            conn.execute(
                "UPDATE events SET hash='deadbeef' WHERE id=?1",
                params![events[0].id],
            )
            .unwrap();
        }
        assert!(!store.verify_event_chain(&s.id).unwrap());
    }

    #[test]
    fn token_usage_accumulates_per_session() {
        let store = Store::open(":memory:").unwrap();
        let s = store.create_session("g").unwrap();
        let empty = store.token_usage(&s.id).unwrap();
        assert_eq!(empty.prompt_tokens, 0);
        assert_eq!(empty.completion_tokens, 0);
        assert_eq!(empty.cost_usd, 0.0);

        store.record_token_usage(&s.id, 100, 20, 0.001).unwrap();
        store.record_token_usage(&s.id, 50, 10, 0.0005).unwrap();
        let usage = store.token_usage(&s.id).unwrap();
        assert_eq!(usage.prompt_tokens, 150);
        assert_eq!(usage.completion_tokens, 30);
        assert!((usage.cost_usd - 0.0015).abs() < 1e-9);

        let other = store.create_session("other").unwrap();
        assert_eq!(store.token_usage(&other.id).unwrap().prompt_tokens, 0);
    }

    #[test]
    fn finding_validation_is_persisted() {
        let store = Store::open(":memory:").unwrap();
        let s = store.create_session("g").unwrap();
        let f = store
            .add_finding(
                &s.id, "Leak", "high", None, None, "desc", None, None, None, None,
            )
            .unwrap();
        assert!(f.validated_at.is_none());
        assert!(f.validation_detail.is_none());

        store
            .set_finding_validation(&f.id, "confirmed", Some("reproduced locally"))
            .unwrap();
        let findings = store.list_findings(&s.id).unwrap();
        assert_eq!(findings[0].status, "confirmed");
        assert!(findings[0].validated_at.is_some());
        assert_eq!(
            findings[0].validation_detail.as_deref(),
            Some("reproduced locally")
        );

        store
            .set_finding_validation(&f.id, "dismissed", None)
            .unwrap();
        let findings = store.list_findings(&s.id).unwrap();
        assert_eq!(findings[0].status, "dismissed");
        assert!(findings[0].validation_detail.is_none());
        assert!(findings[0].validated_at.is_some());
    }

    #[test]
    fn goal_locks_and_session_flags_are_scoped() {
        let store = Store::open(":memory:").unwrap();
        let s = store.create_session("g").unwrap();
        let other = store.create_session("other").unwrap();

        assert!(store.get_goal_lock(&s.id).unwrap().is_none());
        store.set_goal_lock(&s.id, "digest-1").unwrap();
        assert_eq!(
            store.get_goal_lock(&s.id).unwrap().as_deref(),
            Some("digest-1")
        );
        store.set_goal_lock(&s.id, "digest-2").unwrap();
        assert_eq!(
            store.get_goal_lock(&s.id).unwrap().as_deref(),
            Some("digest-2")
        );
        assert!(store.get_goal_lock(&other.id).unwrap().is_none());

        assert!(!store.has_session_flag(&s.id, "paused").unwrap());
        store.set_session_flag(&s.id, "paused").unwrap();
        store.set_session_flag(&s.id, "paused").unwrap();
        store.set_session_flag(&s.id, "verified").unwrap();
        assert!(store.has_session_flag(&s.id, "paused").unwrap());
        assert!(store.has_session_flag(&s.id, "verified").unwrap());
        assert!(!store.has_session_flag(&s.id, "missing").unwrap());
        assert!(!store.has_session_flag(&other.id, "paused").unwrap());
    }

    #[test]
    fn coverage_targets_are_distinct_and_sorted() {
        let store = Store::open(":memory:").unwrap();
        let s = store.create_session("g").unwrap();
        store
            .record_coverage(&s.id, "https://b.example", "GET", "/")
            .unwrap();
        store
            .record_coverage(&s.id, "https://a.example", "GET", "/")
            .unwrap();
        store
            .record_coverage(&s.id, "https://a.example", "POST", "/login")
            .unwrap();
        assert_eq!(
            store.coverage_targets(&s.id).unwrap(),
            vec![
                "https://a.example".to_string(),
                "https://b.example".to_string()
            ]
        );
        assert!(store.coverage_targets(&s.id).unwrap().len() == 2);
    }

    #[test]
    fn redaction_covers_pii_without_hiding_short_numbers() {
        let out = redact("Contact alice.smith@example.com or call (415) 555-2671 today.");
        assert!(!out.contains("alice.smith@example.com"));
        assert!(!out.contains("415"));
        assert!(!out.contains("555-2671"));
        assert!(out.contains("Contact"));
        assert!(out.contains("today."));

        let out = redact("Card 4111 1111 1111 1111 and SSN 123-45-6789");
        assert!(!out.contains("4111"));
        assert!(!out.contains("123-45-6789"));
        assert_eq!(out.matches("[REDACTED]").count(), 2);

        let out = redact("phone 4155552671 card 4111111111111111");
        assert!(!out.contains("4155552671"));
        assert!(!out.contains("4111111111111111"));
        assert_eq!(out.matches("[REDACTED]").count(), 2);

        let out = redact(r#"{"to":"bob@example.org"}"#);
        assert!(!out.contains("bob@example.org"));
        assert!(out.contains("[REDACTED]"));

        let plain = "port 8080 on 2026-11-19 at 10:30";
        assert_eq!(redact(plain), plain);

        let hash = "sha256 95793ae14070830fc9da3c937c27dc9a0123456789abcdef1";
        assert_eq!(redact(hash), hash);
    }

    #[test]
    fn engagement_crud_and_state_transitions() {
        let store = Store::open(":memory:").unwrap();
        let e = store
            .create_engagement("https://example.com/program")
            .unwrap();
        assert_eq!(e.program_url, "https://example.com/program");
        assert_eq!(e.state, "idle");
        assert_eq!(e.created_at, e.updated_at);

        let got = store.get_engagement(&e.id).unwrap().unwrap();
        assert_eq!(got.program_url, e.program_url);
        assert!(store.get_engagement("missing").unwrap().is_none());

        store.set_engagement_state(&e.id, "running").unwrap();
        let running = store.get_engagement(&e.id).unwrap().unwrap();
        assert_eq!(running.state, "running");
        assert!(running.updated_at >= running.created_at);

        store.set_engagement_state(&e.id, "completed").unwrap();
        assert_eq!(
            store.get_engagement(&e.id).unwrap().unwrap().state,
            "completed"
        );

        let other = store.create_engagement("https://other.example").unwrap();
        let listed = store.list_engagements(10).unwrap();
        assert_eq!(listed.len(), 2);
        assert!(listed.iter().any(|x| x.id == e.id));
        assert!(listed.iter().any(|x| x.id == other.id));

        let limited = store.list_engagements(1).unwrap();
        assert_eq!(limited.len(), 1);
        assert_eq!(limited[0].id, other.id);
    }

    #[test]
    fn tasks_and_clues_crud() {
        let store = Store::open(":memory:").unwrap();
        let e = store.create_engagement("https://example.com").unwrap();
        let other = store.create_engagement("https://other.example").unwrap();

        let t1 = store
            .create_task(
                &e.id,
                "Test login",
                "auth-basic",
                Some("https://example.com/login"),
                5,
            )
            .unwrap();
        let t2 = store
            .create_task(&e.id, "Test search", "xss", None, 0)
            .unwrap();
        assert_eq!(t1.engagement_id, e.id);
        assert_eq!(t1.status, "open");
        assert_eq!(t1.playbook_id, "auth-basic");
        assert_eq!(t1.target.as_deref(), Some("https://example.com/login"));
        assert_eq!(t1.priority, 5);
        assert!(t2.target.is_none());
        assert_eq!(t2.priority, 0);

        store.create_task(&other.id, "Other", "p", None, 0).unwrap();
        let tasks = store.list_tasks(&e.id).unwrap();
        assert_eq!(tasks.len(), 2);
        assert!(tasks.iter().all(|t| t.engagement_id == e.id));

        store.update_task_status(&t1.id, "in_progress").unwrap();
        let tasks = store.list_tasks(&e.id).unwrap();
        assert_eq!(
            tasks.iter().find(|t| t.id == t1.id).unwrap().status,
            "in_progress"
        );
        assert_eq!(tasks.iter().find(|t| t.id == t2.id).unwrap().status, "open");

        store
            .add_clue(&e.id, Some(&t1.id), "nmap", "open_ports", r#"[80,443]"#)
            .unwrap();
        store
            .add_clue(&e.id, None, "http", "title", r#""Example""#)
            .unwrap();
        store
            .add_clue(&other.id, None, "http", "title", r#""Other""#)
            .unwrap();
        let clues = store.list_clues(&e.id).unwrap();
        assert_eq!(clues.len(), 2);
        assert!(clues.iter().all(|c| c.engagement_id == e.id));
        let with_task = clues.iter().find(|c| c.task_id.is_some()).unwrap();
        assert_eq!(with_task.task_id.as_deref(), Some(t1.id.as_str()));
        assert_eq!(with_task.source_tool, "nmap");
        assert_eq!(with_task.key, "open_ports");
        assert_eq!(with_task.value_json, r#"[80,443]"#);
        assert!(clues.iter().any(|c| c.task_id.is_none()));
    }

    #[test]
    fn brief_evidence_report_and_trace_writes() {
        let store = Store::open(":memory:").unwrap();
        let e = store.create_engagement("https://example.com").unwrap();

        store
            .save_brief(
                &e.id,
                "<html>hello</html>",
                r#"["title"]"#,
                r#"{"in":["example.com"]}"#,
                r#"{"rules":[]}"#,
            )
            .unwrap();
        store
            .add_evidence(
                "finding-1",
                "http",
                Some("artifacts/1.txt"),
                "abc123",
                Some("GET /"),
                Some("HTTP/1.1 200"),
            )
            .unwrap();
        store
            .add_evidence("finding-1", "screenshot", None, "deadbeef", None, None)
            .unwrap();
        store
            .save_report(&e.id, "markdown", "reports/report.md", "sha-report")
            .unwrap();
        store
            .append_trace(&e.id, "run-1", "tool.call", r#"{"tool":"nmap"}"#)
            .unwrap();
        store
            .append_trace(&e.id, "run-1", "llm.step", r#"{"step":1}"#)
            .unwrap();

        let conn = store.conn.lock().unwrap();
        let brief_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM brief_snapshots WHERE engagement_id=?1",
                params![&e.id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(brief_count, 1);

        let evidence_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM evidence WHERE finding_id=?1",
                params!["finding-1"],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(evidence_count, 2);

        let report_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM reports WHERE engagement_id=?1",
                params![&e.id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(report_count, 1);

        let trace_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM trace_events WHERE engagement_id=?1",
                params![&e.id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(trace_count, 2);
    }

    #[test]
    fn schema_creation_is_idempotent() {
        let path =
            std::env::temp_dir().join(format!("agentbug-store-schema-{}.db", Uuid::new_v4()));
        let created;
        {
            let store = Store::open(&path).unwrap();
            {
                let conn = store.conn.lock().unwrap();
                let mut stmt = conn
                    .prepare("SELECT name FROM sqlite_master WHERE type IN ('table','index')")
                    .unwrap();
                let names: Vec<String> = stmt
                    .query_map([], |r| r.get(0))
                    .unwrap()
                    .map(|r| r.unwrap())
                    .collect();
                for expected in [
                    "engagements",
                    "brief_snapshots",
                    "tasks",
                    "clues",
                    "evidence",
                    "reports",
                    "trace_events",
                    "idx_brief_snapshots_engagement",
                    "idx_tasks_engagement",
                    "idx_clues_engagement",
                    "idx_evidence_finding",
                    "idx_reports_engagement",
                    "idx_trace_events_engagement",
                ] {
                    assert!(
                        names.iter().any(|n| n.as_str() == expected),
                        "missing schema object: {expected}"
                    );
                }
            }
            created = store.create_engagement("https://persist.example").unwrap();
        }

        {
            let store = Store::open(&path).unwrap();
            assert_eq!(
                store
                    .get_engagement(&created.id)
                    .unwrap()
                    .unwrap()
                    .program_url,
                "https://persist.example"
            );
        }

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(path.with_extension("db-wal"));
        let _ = std::fs::remove_file(path.with_extension("db-shm"));
    }

    #[test]
    fn evidence_bytes_hash_is_reproducible_sha256() {
        let store = Store::open(":memory:").unwrap();
        let session = store.create_session("g").unwrap();
        let finding = store
            .add_finding(
                &session.id,
                "Reflected XSS",
                "high",
                None,
                None,
                "desc",
                None,
                None,
                None,
                None,
            )
            .unwrap();
        let request = b"GET /search?q=FUZZ HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let response = b"HTTP/1.1 200 OK\r\n\r\n<html>canary</html>";
        let artifact = b"canary-42";

        let first = store
            .add_evidence_bytes(&finding.id, "http", request, response, Some(artifact))
            .unwrap();
        let second = store
            .add_evidence_bytes(&finding.id, "http", request, response, Some(artifact))
            .unwrap();
        assert_eq!(first, second);
        assert_eq!(first.len(), 64);
        assert!(first.bytes().all(|b| b.is_ascii_hexdigit()));

        let mut input = Vec::new();
        input.extend_from_slice(request);
        input.extend_from_slice(response);
        input.extend_from_slice(artifact);
        assert_eq!(first, format!("{:x}", Sha256::digest(&input)));
        assert_eq!(
            first,
            Store::evidence_hash(
                Some(std::str::from_utf8(artifact).unwrap()),
                Some(std::str::from_utf8(request).unwrap()),
                Some(std::str::from_utf8(response).unwrap()),
            )
        );
        assert!(store.verify_evidence(&session.id).unwrap());

        // A different byte sequence must produce a different digest.
        let other = store
            .add_evidence_bytes(&finding.id, "http", request, response, Some(b"canary-43"))
            .unwrap();
        assert_ne!(first, other);
    }

    #[test]
    fn verify_evidence_detects_tampering() {
        let store = Store::open(":memory:").unwrap();
        let session = store.create_session("g").unwrap();
        let finding = store
            .add_finding(
                &session.id,
                "t",
                "high",
                None,
                None,
                "d",
                None,
                None,
                None,
                None,
            )
            .unwrap();
        store
            .add_evidence_bytes(&finding.id, "http", b"GET /", b"HTTP/1.1 200", None)
            .unwrap();
        assert!(store.verify_evidence(&session.id).unwrap());
        {
            let conn = store.conn.lock().unwrap();
            conn.execute(
                "UPDATE evidence SET sha256='tampered' WHERE finding_id=?1",
                params![finding.id],
            )
            .unwrap();
        }
        assert!(!store.verify_evidence(&session.id).unwrap());
    }

    #[test]
    fn verified_findings_filters_to_validated_and_confirmed() {
        let store = Store::open(":memory:").unwrap();
        let session = store.create_session("g").unwrap();
        let open = store
            .add_finding(
                &session.id,
                "open",
                "low",
                None,
                None,
                "d",
                None,
                None,
                None,
                None,
            )
            .unwrap();
        let validated = store
            .add_finding(
                &session.id,
                "val",
                "medium",
                None,
                None,
                "d",
                None,
                None,
                None,
                None,
            )
            .unwrap();
        let confirmed = store
            .add_finding(
                &session.id,
                "conf",
                "high",
                None,
                None,
                "d",
                None,
                None,
                None,
                None,
            )
            .unwrap();
        let rejected = store
            .add_finding(
                &session.id,
                "rej",
                "info",
                None,
                None,
                "d",
                None,
                None,
                None,
                None,
            )
            .unwrap();
        store
            .set_finding_validation(&validated.id, "validated", None)
            .unwrap();
        store
            .set_finding_validation(&confirmed.id, "confirmed", None)
            .unwrap();
        store
            .set_finding_validation(&rejected.id, "rejected", None)
            .unwrap();

        let verified: Vec<String> = store
            .verified_findings(&session.id)
            .unwrap()
            .into_iter()
            .map(|f| f.id)
            .collect();
        assert_eq!(verified.len(), 2);
        assert!(verified.contains(&validated.id));
        assert!(verified.contains(&confirmed.id));
        assert!(!verified.contains(&open.id));
        assert!(!verified.contains(&rejected.id));
    }

    #[test]
    fn tool_capture_round_trip_and_tamper() {
        let store = Store::open(":memory:").unwrap();
        let session = store.create_session("g").unwrap();
        let finding = store
            .add_finding(
                &session.id,
                "SSRF",
                "high",
                None,
                None,
                "desc",
                None,
                None,
                None,
                None,
            )
            .unwrap();
        assert!(store.get_capture(&finding.id).unwrap().is_none());
        assert!(store.get_capture("unknown").unwrap().is_none());

        let request = b"GET /probe HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let response = b"HTTP/1.1 200 OK\r\n\r\ncanary-42";
        store
            .attach_capture(&finding.id, request, response, "canary-42")
            .unwrap();
        let capture = store.get_capture(&finding.id).unwrap().unwrap();
        assert_eq!(capture.finding_id, finding.id);
        assert_eq!(capture.request_bytes, request);
        assert_eq!(capture.response_bytes, response);
        assert_eq!(capture.canary, "canary-42");
        assert!(!capture.created_at.is_empty());

        // Re-attaching replaces rather than duplicates the capture.
        store
            .attach_capture(&finding.id, b"POST /probe", b"HTTP/1.1 500", "canary-99")
            .unwrap();
        let capture = store.get_capture(&finding.id).unwrap().unwrap();
        assert_eq!(capture.request_bytes, b"POST /probe");
        assert_eq!(capture.response_bytes, b"HTTP/1.1 500");
        assert_eq!(capture.canary, "canary-99");

        // The stored row is authoritative: direct tampering is visible to the
        // verifier, so an LLM-supplied "canary" can never vouch for a finding.
        {
            let conn = store.conn.lock().unwrap();
            conn.execute(
                "UPDATE tool_captures SET response_bytes=?2, canary='forged' WHERE finding_id=?1",
                params![
                    finding.id,
                    b"HTTP/1.1 200 OK\r\n\r\nnot the canary".as_slice()
                ],
            )
            .unwrap();
        }
        let tampered = store.get_capture(&finding.id).unwrap().unwrap();
        assert_eq!(tampered.canary, "forged");
        assert_ne!(tampered.response_bytes, response);
        assert!(!String::from_utf8_lossy(&tampered.response_bytes).contains("canary-42"));
    }

    #[test]
    fn clear_session_flag_removes_only_the_target_flag() {
        let store = Store::open(":memory:").unwrap();
        let s = store.create_session("g").unwrap();
        let other = store.create_session("other").unwrap();
        store.set_session_flag(&s.id, "stop").unwrap();
        store.set_session_flag(&s.id, "paused").unwrap();
        store.set_session_flag(&other.id, "stop").unwrap();

        store.clear_session_flag(&s.id, "stop").unwrap();
        assert!(!store.has_session_flag(&s.id, "stop").unwrap());
        assert!(store.has_session_flag(&s.id, "paused").unwrap());
        assert!(store.has_session_flag(&other.id, "stop").unwrap());

        // Clearing a missing flag is a no-op.
        store.clear_session_flag(&s.id, "missing").unwrap();
        assert!(!store.has_session_flag(&s.id, "missing").unwrap());
    }

    #[test]
    fn park_with_approval_is_atomic() {
        let store = Store::open(":memory:").unwrap();
        let s = store.create_session("g").unwrap();
        store.claim_session(&s.id, "owner", 60).unwrap();
        let approval = Approval {
            id: "ap-ok".into(),
            session_id: s.id.clone(),
            tool_name: "shell".into(),
            args_json: "{}".into(),
            risk: "network-write".into(),
            status: "pending".into(),
            reason: Some("needs approval".into()),
            created_at: String::new(),
            tool_call_id: Some("tc-1".into()),
            expires_at: None,
        };
        let tail = [
            (Some("tc-2"), "echo", "{\"x\":\"two\"}"),
            (None, "echo", "{\"x\":\"three\"}"),
        ];
        store.park_with_approval(&approval, &tail, &s.id).unwrap();

        let parked = store.get_session(&s.id).unwrap().unwrap();
        assert_eq!(parked.state, "waiting_approval");
        assert!(parked.owner_id.is_none());
        assert!(parked.lease_expires_at.is_none());

        let pending = store.get_pending_approval(&s.id).unwrap().unwrap();
        assert_eq!(pending.id, "ap-ok");
        assert_eq!(pending.status, "pending");
        assert!(pending.expires_at.is_some());

        let taken = store.take_pending_calls(&s.id, "ap-ok").unwrap();
        assert_eq!(taken.len(), 2);
        assert_eq!(taken[0].tool_call_id.as_deref(), Some("tc-2"));
        assert_eq!(taken[0].args_json, "{\"x\":\"two\"}");
        assert!(taken[1].tool_call_id.is_none());

        // A duplicate approval id aborts the whole transaction: no deferred
        // calls, no state change and no overwrite of the existing approval.
        let s2 = store.create_session("g2").unwrap();
        {
            let conn = store.conn.lock().unwrap();
            conn.execute(
                "INSERT INTO approvals(id,session_id,action,status,reason,tool_name,args_json,risk,created_at,tool_call_id,expires_at)
                 VALUES('dupe',?1,'shell','pending','original','shell','{}','exec','2026-01-01T00:00:00Z',NULL,NULL)",
                params![s2.id],
            )
            .unwrap();
        }
        let bad = Approval {
            id: "dupe".into(),
            session_id: s2.id.clone(),
            tool_name: "shell".into(),
            args_json: "{}".into(),
            risk: "network-write".into(),
            status: "pending".into(),
            reason: Some("overwritten".into()),
            created_at: now(),
            tool_call_id: None,
            expires_at: None,
        };
        assert!(store
            .park_with_approval(
                &bad,
                &[(Some("tc-bad"), "echo", "{\"rollback\":true}")],
                &s2.id
            )
            .is_err());
        assert_eq!(store.get_session(&s2.id).unwrap().unwrap().state, "idle");
        {
            let conn = store.conn.lock().unwrap();
            let count: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM pending_tool_calls WHERE session_id=?1 AND args_json=?2",
                    params![s2.id, "{\"rollback\":true}"],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(count, 0);
            let reason: String = conn
                .query_row("SELECT reason FROM approvals WHERE id='dupe'", [], |r| {
                    r.get(0)
                })
                .unwrap();
            assert_eq!(reason, "original");
        }
    }

    #[test]
    fn resolve_approval_rejects_expired() {
        let store = Store::open(":memory:").unwrap();
        let s = store.create_session("g").unwrap();
        let expired = store
            .create_approval_with_ttl(&s.id, "shell", "{}", "exec", "stale", None, -60)
            .unwrap();
        assert!(store
            .resolve_approval(&expired.id, "approved", None)
            .is_err());

        // The rejected resolution leaves the row untouched and still pending.
        let conn = store.conn.lock().unwrap();
        let status: String = conn
            .query_row(
                "SELECT status FROM approvals WHERE id=?1",
                params![expired.id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(status, "pending");
        drop(conn);

        // A null expiry remains resolvable for legacy rows.
        let legacy_id = "no-expiry";
        {
            let conn = store.conn.lock().unwrap();
            conn.execute(
                "INSERT INTO approvals(id,session_id,action,status,reason,tool_name,args_json,risk,created_at,tool_call_id,expires_at)
                 VALUES(?1,?2,'shell','pending','legacy','shell','{}','exec','2026-01-01T00:00:00Z',NULL,NULL)",
                params![legacy_id, s.id],
            )
            .unwrap();
        }
        store.resolve_approval(legacy_id, "approved", None).unwrap();
    }

    #[test]
    fn list_findings_by_status_filters_by_session_and_status() {
        let store = Store::open(":memory:").unwrap();
        let s = store.create_session("g").unwrap();
        let other = store.create_session("other").unwrap();
        let first = store
            .add_finding(
                &s.id, "one", "high", None, None, "d", None, None, None, None,
            )
            .unwrap();
        let second = store
            .add_finding(
                &s.id, "two", "high", None, None, "d", None, None, None, None,
            )
            .unwrap();
        store
            .add_finding(
                &other.id, "three", "high", None, None, "d", None, None, None, None,
            )
            .unwrap();
        store
            .set_finding_validation(&second.id, "validated", None)
            .unwrap();

        let open = store.list_findings_by_status(&s.id, "open").unwrap();
        assert_eq!(open.len(), 1);
        assert_eq!(open[0].id, first.id);
        let validated = store.list_findings_by_status(&s.id, "validated").unwrap();
        assert_eq!(validated.len(), 1);
        assert_eq!(validated[0].id, second.id);
        assert!(store
            .list_findings_by_status(&other.id, "validated")
            .unwrap()
            .is_empty());
    }

    #[test]
    fn durable_inbox_enqueue_is_first_admission_wins() {
        let store = Store::open(":memory:").unwrap();
        assert!(store
            .enqueue_inbox("id-1", "s", "user", "queue", r#"{"text":"first"}"#)
            .unwrap());
        assert!(!store
            .enqueue_inbox("id-1", "s", "user", "queue", r#"{"text":"second"}"#)
            .unwrap());
        let items = store.list_pending_inbox("s").unwrap();
        assert_eq!(items.len(), 1);
        assert!(items[0].payload_json.contains("first"));
    }

    #[test]
    fn durable_inbox_promotion_prioritizes_control_then_steer() {
        let store = Store::open(":memory:").unwrap();
        store
            .enqueue_inbox("q", "s", "user", "queue", "{}")
            .unwrap();
        store
            .enqueue_inbox("st", "s", "steer", "steer", "{}")
            .unwrap();
        store
            .enqueue_inbox("c", "s", "control", "queue", r#"{"op":"cancel"}"#)
            .unwrap();
        let first = store.promote_inbox("s", false).unwrap().unwrap();
        assert_eq!(first.id, "c");
        let second = store.promote_inbox("s", false).unwrap().unwrap();
        assert_eq!(second.id, "st");
        assert!(store.promote_inbox("s", false).unwrap().is_none());
        let queued = store.promote_inbox("s", true).unwrap().unwrap();
        assert_eq!(queued.id, "q");
    }

    #[test]
    fn durable_inbox_delivery_is_atomic_and_double_deliver_safe() {
        let store = Store::open(":memory:").unwrap();
        store
            .enqueue_inbox("u", "s", "user", "steer", r#"{"text":"hello"}"#)
            .unwrap();
        let item = store.promote_inbox("s", true).unwrap().unwrap();
        assert!(store
            .deliver_inbox(&item.id, Some(("user", "hello")))
            .unwrap()
            .is_some());
        assert!(store
            .deliver_inbox(&item.id, Some(("user", "hello")))
            .unwrap()
            .is_none());
        let messages = store.list_messages("s").unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].content, "hello");
        assert!(store.list_pending_inbox("s").unwrap().is_empty());
    }

    #[test]
    fn durable_inbox_cancel_and_resteer_apply_only_while_pending() {
        let store = Store::open(":memory:").unwrap();
        store
            .enqueue_inbox("i", "s", "user", "queue", "{}")
            .unwrap();
        assert!(store.resteer_inbox("i", "steer").unwrap());
        assert_eq!(store.promote_inbox("s", false).unwrap().unwrap().id, "i");
        assert!(store.cancel_inbox("i").unwrap());
        assert!(!store.cancel_inbox("i").unwrap());
        assert!(store.list_pending_inbox("s").unwrap().is_empty());
    }

    #[test]
    fn resume_attempt_counter_is_bounded_and_resettable() {
        let store = Store::open(":memory:").unwrap();
        let session = store.create_session("goal").unwrap();
        assert_eq!(store.resume_attempt(&session.id).unwrap(), 0);
        for expected in 1..=10 {
            assert_eq!(
                store.increment_resume_attempt(&session.id).unwrap(),
                expected
            );
        }
        store.reset_resume_attempt(&session.id).unwrap();
        assert_eq!(store.resume_attempt(&session.id).unwrap(), 0);
    }

    #[test]
    fn settling_unanswered_calls_is_idempotent() {
        let store = Store::open(":memory:").unwrap();
        let session = store.create_session("goal").unwrap();
        store
            .add_message_full(
                &session.id,
                "assistant",
                "calling tools",
                None,
                Some(r#"[{"id":"a","name":"echo"},{"id":"b","name":"echo"}]"#),
                None,
            )
            .unwrap();
        store
            .add_message_full(&session.id, "tool", "ok", Some("a"), None, Some("echo"))
            .unwrap();
        let text = "interrupted";
        assert_eq!(
            store
                .settle_unanswered_tool_calls(&session.id, text)
                .unwrap(),
            1
        );
        assert_eq!(
            store
                .settle_unanswered_tool_calls(&session.id, text)
                .unwrap(),
            0
        );
        let messages = store.list_messages(&session.id).unwrap();
        assert_eq!(messages.len(), 3);
        assert_eq!(messages[2].tool_call_id.as_deref(), Some("b"));
    }

    #[test]
    fn schema_creation_is_idempotent_with_durable_inbox() {
        let dir = std::env::temp_dir().join(format!(
            "agentbug-durable-inbox-schema-{}",
            std::process::id()
        ));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("store.db");
        let _ = std::fs::remove_file(&path);
        {
            let store = Store::open(&path).unwrap();
            store
                .enqueue_inbox("persist", "s", "user", "queue", "{}")
                .unwrap();
        }
        let store = Store::open(&path).unwrap();
        assert_eq!(store.list_pending_inbox("s").unwrap().len(), 1);
        assert!(!store
            .enqueue_inbox("persist", "s", "user", "queue", "{}")
            .unwrap());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn tool_call_lifecycle_is_idempotent_and_queryable() {
        let store = Store::open(":memory:").unwrap();
        let id = store
            .start_tool_call("s", Some("call-1"), "echo", "{}", "echo|{}", "safe")
            .unwrap();
        assert_eq!(
            store
                .recent_results_for_signature("s", "echo", "echo|{}", 4)
                .unwrap()
                .len(),
            0
        );
        assert!(store
            .finish_tool_call(&id, "ok", Some(true), Some("done"))
            .unwrap());
        assert!(!store
            .finish_tool_call(&id, "ok", Some(true), Some("again"))
            .unwrap());
        let results = store
            .recent_results_for_signature("s", "echo", "echo|{}", 4)
            .unwrap();
        assert_eq!(results, vec!["done".to_string()]);
    }

    #[test]
    fn tool_call_results_are_scoped_by_signature_and_host_risk_is_stored() {
        let store = Store::open(":memory:").unwrap();
        let a = store
            .start_tool_call("s", None, "echo", "{}", "sig-a", "network")
            .unwrap();
        store
            .finish_tool_call(&a, "ok", Some(true), Some("A"))
            .unwrap();
        assert!(store
            .recent_results_for_signature("s", "echo", "sig-b", 4)
            .unwrap()
            .is_empty());
        let conn = store.conn.lock().unwrap();
        let risk: String = conn
            .query_row("SELECT risk FROM tool_calls WHERE id=?1", params![a], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(risk, "network");
    }

    #[test]
    fn echoable_results_only_include_low_risk_successes() {
        let store = Store::open(":memory:").unwrap();
        for (id, risk, ok, status, text) in [
            ("a", "safe", true, "ok", "A"),
            ("b", "read", true, "ok", "B"),
            ("c", "network", true, "ok", "C"),
            ("d", "write", true, "ok", "D"),
            ("e", "safe", false, "error", "E"),
        ] {
            let row = store
                .start_tool_call("s", None, "echo", "{}", "sig", risk)
                .unwrap();
            assert!(!row.is_empty());
            let _ = id;
            store
                .finish_tool_call(&row, status, Some(ok), Some(text))
                .unwrap();
        }
        let results = store
            .recent_echoable_results_for_signature("s", "echo", "sig", 8)
            .unwrap();
        assert_eq!(results, vec!["B".to_string(), "A".to_string()]);
    }

    #[test]
    fn memory_items_are_scope_gated_and_hash_verified() {
        let store = Store::open(":memory:").unwrap();
        store
            .add_memory(MemoryWrite {
                session_id: "s",
                parent_session_id: None,
                source_kind: "tool_call",
                source_id: "t1",
                source_event_hash: None,
                role: Some("research"),
                task_id: None,
                scope_key: "scope-a",
                tier: "episodic",
                content: "fact-a",
            })
            .unwrap();
        store
            .add_memory(MemoryWrite {
                session_id: "s",
                parent_session_id: None,
                source_kind: "tool_call",
                source_id: "t2",
                source_event_hash: None,
                role: Some("testing"),
                task_id: None,
                scope_key: "scope-b",
                tier: "episodic",
                content: "fact-b",
            })
            .unwrap();
        let scoped = store
            .list_memory("s", "scope-a", "episodic", None, 8)
            .unwrap();
        assert_eq!(scoped.len(), 1);
        assert_eq!(scoped[0].content, "fact-a");
        let role_scoped = store
            .list_memory("s", "scope-a", "episodic", Some("testing"), 8)
            .unwrap();
        assert!(role_scoped.is_empty());
        assert!(store.verify_memory_hashes("s").unwrap());
    }

    #[test]
    fn session_result_is_upserted_once_per_child() {
        let store = Store::open(":memory:").unwrap();
        store
            .put_session_result(
                "child",
                Some("parent"),
                Some("call-1"),
                "verification",
                "ok",
                "{\"verdict\":\"confirmed\"}",
            )
            .unwrap();
        store
            .put_session_result(
                "child",
                Some("parent"),
                Some("call-1"),
                "verification",
                "ok",
                "{\"verdict\":\"ruled_out\"}",
            )
            .unwrap();
        let (role, status, payload) = store.get_session_result("child").unwrap().unwrap();
        assert_eq!(role, "verification");
        assert_eq!(status, "ok");
        assert!(payload.contains("ruled_out"));
    }
}

#[test]
fn role_captures_are_multirow_and_primary_reader_is_unchanged() {
    let store = Store::open(":memory:").unwrap();
    let session = store.create_session("goal").unwrap();
    let finding = store
        .add_finding(
            &session.id,
            "Candidate",
            "high",
            None,
            None,
            "description",
            None,
            None,
            None,
            None,
        )
        .unwrap();
    store
        .attach_capture(&finding.id, b"GET /primary", b"primary body", "canary-p")
        .unwrap();
    store
        .attach_role_capture(
            &finding.id,
            "paired_benign",
            b"GET /safe",
            b"benign body",
            "canary-b",
            Some("marker-b"),
        )
        .unwrap();
    store
        .attach_role_capture(
            &finding.id,
            "paired_payload",
            b"GET /payload",
            b"blocked",
            "canary-x",
            Some("marker-x"),
        )
        .unwrap();
    let primary = store.get_capture(&finding.id).unwrap().unwrap();
    assert_eq!(primary.canary, "canary-p");
    let benign = store
        .get_role_capture(&finding.id, "paired_benign")
        .unwrap()
        .unwrap();
    assert_eq!(benign.marker.as_deref(), Some("marker-b"));
    assert_eq!(benign.response_bytes, b"benign body");
    assert!(store
        .get_role_capture(&finding.id, "paired_payload")
        .unwrap()
        .is_some());
    assert!(store
        .get_role_capture(&finding.id, "primary")
        .unwrap()
        .is_none());
}

#[test]
fn finding_verdict_never_stamps_validation() {
    let store = Store::open(":memory:").unwrap();
    let session = store.create_session("goal").unwrap();
    let finding = store
        .add_finding(
            &session.id,
            "Candidate",
            "high",
            None,
            None,
            "description",
            None,
            None,
            None,
            None,
        )
        .unwrap();
    assert!(finding.verdict.is_none());
    store
        .set_finding_verdict(&finding.id, "ruled_out", Some("paired control available"))
        .unwrap();
    let updated = store
        .list_findings(&session.id)
        .unwrap()
        .into_iter()
        .find(|f| f.id == finding.id)
        .unwrap();
    assert_eq!(updated.verdict.as_deref(), Some("ruled_out"));
    assert!(updated.validated_at.is_none());
    assert!(store.verified_findings(&session.id).unwrap().is_empty());
    assert!(store
        .set_finding_verdict(&finding.id, "bogus", None)
        .is_err());
}

#[test]
fn http_capture_flows_to_a_later_finding_without_llm_bytes() {
    let store = Store::open(":memory:").unwrap();
    let session = store.create_session("goal").unwrap();
    let http_result = agentbug_tools::ToolResult {
        ok: true,
        output: "status 200".to_string(),
        structured: Some(serde_json::json!({
            "ok": true,
            "capture": {
                "request": "GET /reflect?q=canary HTTP/1.1",
                "response": "HTTP/1.1 200 OK\nreflected canary",
                "canary": "agentbug-canary-abc"
            }
        })),
    };
    persist_tool_result(
        &store,
        &session.id,
        "http_request",
        &serde_json::json!({"url": "http://127.0.0.1/reflect"}),
        &http_result,
    );
    assert!(store.take_session_capture(&session.id).unwrap().is_some());
    // Put it back: the real flow consumes it when the finding is saved.
    store
        .put_session_capture(
            &session.id,
            b"GET /reflect?q=canary HTTP/1.1",
            b"HTTP/1.1 200 OK\nreflected canary",
            "agentbug-canary-abc",
        )
        .unwrap();

    let finding_args = serde_json::json!({
        "title": "Reflected canary",
        "severity": "high",
        "description": "tool bytes only",
        "request": "LLM must not be trusted",
        "response": "LLM must not be trusted"
    });
    persist_tool_result(
        &store,
        &session.id,
        "save_finding",
        &finding_args,
        &agentbug_tools::ToolResult {
            ok: true,
            output: "saved".to_string(),
            structured: None,
        },
    );
    let findings = store.list_findings(&session.id).unwrap();
    assert_eq!(findings.len(), 1);
    let capture = store.get_capture(&findings[0].id).unwrap().unwrap();
    assert_eq!(capture.canary, "agentbug-canary-abc");
    assert!(String::from_utf8_lossy(&capture.response_bytes).contains("reflected canary"));
    assert!(store.take_session_capture(&session.id).unwrap().is_none());
}

#[test]
fn rule_provenance_round_trips_and_does_not_change_scope_decisions() {
    let store = Store::open(":memory:").unwrap();
    let rows = vec![RuleProvenance {
        engagement_id: "e".to_string(),
        rule_kind: "scope_in".to_string(),
        rule_value: "example.com".to_string(),
        source_url: "https://hackerone.com/acme".to_string(),
        section_pointer: "In scope".to_string(),
        verbatim_quote: "- example.com".to_string(),
        verbatim_quote_hash: sha256_hex("- example.com"),
        content_hash: sha256_hex("brief"),
        extractor: "deterministic".to_string(),
        observed_at: "1".to_string(),
    }];
    store.save_rule_provenance(&rows).unwrap();
    let loaded = store.list_rule_provenance("e").unwrap();
    assert_eq!(loaded.len(), 1);
    assert_eq!(loaded[0].rule_value, "example.com");
    assert_eq!(loaded[0].verbatim_quote_hash, sha256_hex("- example.com"));
    assert_eq!(loaded[0].content_hash, sha256_hex("brief"));
}

#[test]
fn blocked_coverage_is_recorded_as_requirement_keyed_row() {
    let store = Store::open(":memory:").unwrap();
    let session = store.create_session("goal").unwrap();
    store
        .record_coverage_decision(CoverageDecision {
            session_id: &session.id,
            target: "app.clockify.me",
            method: "GET",
            path: "/api/users/1",
            requirement_id: "WSTG-ATHZ-04",
            status: "blocked",
            rationale: "matches out-of-scope wildcard",
            evidence_ref: "call-1",
        })
        .unwrap();
    let rows = store.list_coverage(&session.id).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].status, "blocked");
    assert_eq!(rows[0].requirement_id, "WSTG-ATHZ-04");
    assert_eq!(store.coverage_count(&session.id).unwrap(), 1);
    assert_eq!(store.covered_requirement_count(&session.id).unwrap(), 0);
    store
        .record_coverage_decision(CoverageDecision {
            session_id: &session.id,
            target: "app.clockify.me",
            method: "GET",
            path: "/api/users/1",
            requirement_id: "WSTG-ATHZ-04",
            status: "covered",
            rationale: "",
            evidence_ref: "capture-1",
        })
        .unwrap();
    assert_eq!(store.list_coverage(&session.id).unwrap().len(), 1);
    assert_eq!(store.covered_requirement_count(&session.id).unwrap(), 1);
}

#[test]
fn structured_hypothesis_transitions_round_trip() {
    let store = Store::open(":memory:").unwrap();
    let session = store.create_session("goal").unwrap();
    let legacy = store.add_hypothesis(&session.id, "legacy").unwrap();
    assert_eq!(legacy.status, "open");
    assert_eq!(legacy.requirement_id, "");
    let h = store
        .add_structured_hypothesis(
            &session.id,
            "Investigate api.example.com",
            "WSTG-INFO",
            "exposed admin API",
            "low-priv user",
            "differential",
        )
        .unwrap();
    assert_eq!(h.requirement_id, "WSTG-INFO");
    assert_eq!(h.oracle_type, "differential");
    store
        .hypothesis_transition(&h.id, "tested", "probe recorded", "capture-1")
        .unwrap();
    let rows = store.list_hypotheses(&session.id).unwrap();
    let updated = rows.iter().find(|row| row.id == h.id).unwrap();
    assert_eq!(updated.status, "tested");
    assert_eq!(updated.rationale, "probe recorded");
    assert_eq!(updated.evidence_ref, "capture-1");
    assert!(updated.updated_at.is_some());
}

#[test]
fn authorization_ack_is_hash_scoped_and_idempotent() {
    let store = Store::open(":memory:").unwrap();
    let ack = AuthorizationAck {
        program_url: "https://hackerone.com/acme".to_string(),
        content_hash: "content-1".to_string(),
        subject_kind: "unparsed_roe".to_string(),
        subject_hash: "rule-1".to_string(),
        subject_text: "Do not scan staging".to_string(),
        decision: "acknowledged".to_string(),
        operator: "operator".to_string(),
        note: String::new(),
        created_at: String::new(),
    };
    assert!(store.save_authorization_ack(&ack).unwrap());
    assert!(!store.save_authorization_ack(&ack).unwrap());
    assert!(store
        .has_authorization_ack(
            &ack.program_url,
            &ack.content_hash,
            &ack.subject_kind,
            &ack.subject_hash
        )
        .unwrap());
    assert!(!store
        .has_authorization_ack(
            &ack.program_url,
            "content-2",
            &ack.subject_kind,
            &ack.subject_hash
        )
        .unwrap());
    assert!(!store
        .has_authorization_ack(
            &ack.program_url,
            &ack.content_hash,
            &ack.subject_kind,
            "rule-2"
        )
        .unwrap());
}

#[test]
fn authorization_revalidation_is_idempotent_and_scoped() {
    let store = Store::open(":memory:").unwrap();
    assert!(store
        .get_authorization_revalidation("eng-1")
        .unwrap()
        .is_none());

    store.request_authorization_revalidation("eng-1").unwrap();
    let first = store
        .get_authorization_revalidation("eng-1")
        .unwrap()
        .unwrap();
    assert_eq!(first.state, "requested");
    assert_eq!(first.observed_hash, "");

    store.request_authorization_revalidation("eng-1").unwrap();
    let again = store
        .get_authorization_revalidation("eng-1")
        .unwrap()
        .unwrap();
    assert_eq!(again.requested_at, first.requested_at);
    assert_eq!(again.state, "requested");

    // Read is scoped by engagement id.
    assert!(store
        .get_authorization_revalidation("eng-2")
        .unwrap()
        .is_none());

    store
        .finish_authorization_revalidation("eng-1", "blocked", "snapshot-hash")
        .unwrap();
    let done = store
        .get_authorization_revalidation("eng-1")
        .unwrap()
        .unwrap();
    assert_eq!(done.state, "blocked");
    assert_eq!(done.observed_hash, "snapshot-hash");
    assert!(store
        .finish_authorization_revalidation("eng-1", "unknown", "x")
        .is_err());

    // The snapshot reader returns the newest version for this engagement only.
    for (engagement_id, version) in [("eng-1", 1), ("eng-1", 2), ("eng-2", 9)] {
        store
            .save_authorization_snapshot(&AuthorizationSnapshot {
                engagement_id: engagement_id.to_string(),
                version,
                source_url: "https://example.test/brief".to_string(),
                content_hash: format!("hash-{engagement_id}-{version}"),
                scope_hash: "scope".to_string(),
                roe_hash: "roe".to_string(),
                observed_at: "1".to_string(),
                state: "ingested".to_string(),
                created_at: "1".to_string(),
            })
            .unwrap();
    }
    let latest = store
        .latest_authorization_snapshot("eng-1")
        .unwrap()
        .unwrap();
    assert_eq!(latest.version, 2);
    assert_eq!(latest.content_hash, "hash-eng-1-2");
    assert!(store
        .latest_authorization_snapshot("missing")
        .unwrap()
        .is_none());
}

#[test]
fn authorization_snapshot_and_open_rule_round_trip() {
    let store = Store::open(":memory:").unwrap();
    let snapshot = AuthorizationSnapshot {
        engagement_id: "e".to_string(),
        version: 1,
        source_url: "https://hackerone.com/acme".to_string(),
        content_hash: "content-1".to_string(),
        scope_hash: "scope".to_string(),
        roe_hash: "roe".to_string(),
        observed_at: "1".to_string(),
        state: "ingested".to_string(),
        created_at: "1".to_string(),
    };
    store.save_authorization_snapshot(&snapshot).unwrap();
    assert_eq!(store.count_authorization_snapshots("e").unwrap(), 1);
    store.save_authorization_snapshot(&snapshot).unwrap();
    assert_eq!(store.count_authorization_snapshots("e").unwrap(), 1);
    let rule = OpenAuthorizationRule {
        engagement_id: "e".to_string(),
        snapshot_hash: "content-1".to_string(),
        rule_hash: "rule-1".to_string(),
        rule_text: "Do not scan staging".to_string(),
        state: "pending".to_string(),
        created_at: "1".to_string(),
    };
    store.save_open_authorization_rule(&rule).unwrap();
    let rows = store.list_open_authorization_rules("e").unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].state, "pending");
}
