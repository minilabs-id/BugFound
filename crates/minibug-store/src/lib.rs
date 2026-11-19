use anyhow::{Context, Result};
use chrono::{Duration, Utc};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Coverage {
    pub id: String,
    pub session_id: String,
    pub target: String,
    pub method: String,
    pub path: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hypothesis {
    pub id: String,
    pub session_id: String,
    pub statement: String,
    pub status: String,
    pub created_at: String,
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
               validated_at TEXT, validation_detail TEXT
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
               path TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, UNIQUE(session_id,target,method,path)
             );
             CREATE TABLE IF NOT EXISTS hypotheses(
               id TEXT PRIMARY KEY, session_id TEXT NOT NULL, statement TEXT NOT NULL,
               status TEXT NOT NULL DEFAULT 'open', created_at TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS approved_targets(
               session_id TEXT NOT NULL, target TEXT NOT NULL, created_at TEXT NOT NULL,
               PRIMARY KEY(session_id,target)
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
               calls_in_window INTEGER NOT NULL DEFAULT 0
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
             INSERT OR IGNORE INTO schema_version(version, applied_at)
               VALUES(1, strftime('%Y-%m-%dT%H:%M:%SZ','now'));",
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
        let _ = conn.execute("ALTER TABLE events ADD COLUMN prev_hash TEXT", []);
        let _ = conn.execute("ALTER TABLE events ADD COLUMN hash TEXT", []);
        let _ = conn.execute("ALTER TABLE messages ADD COLUMN tool_call_id TEXT", []);
        let _ = conn.execute("ALTER TABLE messages ADD COLUMN tool_calls_json TEXT", []);
        let _ = conn.execute("ALTER TABLE messages ADD COLUMN name TEXT", []);
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
        conn.execute(
            "INSERT INTO approvals(id,session_id,action,status,reason,tool_name,args_json,risk,created_at,tool_call_id,expires_at)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
            params![
                a.id,
                a.session_id,
                a.tool_name,
                a.status,
                a.reason,
                a.tool_name,
                a.args_json,
                a.risk,
                a.created_at,
                a.tool_call_id,
                a.expires_at,
            ],
        )?;
        Ok(a)
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

    /// Resolve an approval only if it is still pending. Two concurrent
    /// resolvers cannot both approve the same action.
    pub fn resolve_approval(&self, id: &str, status: &str, reason: Option<&str>) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let affected = conn.execute(
            "UPDATE approvals SET status=?2, reason=COALESCE(?3, reason)
             WHERE id=?1 AND status='pending'",
            params![id, status, reason],
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

    fn evidence_hash(
        evidence: Option<&str>,
        request: Option<&str>,
        response: Option<&str>,
    ) -> String {
        let mut hasher = DefaultHasher::new();
        evidence.hash(&mut hasher);
        request.hash(&mut hasher);
        response.hash(&mut hasher);
        format!("{:016x}", hasher.finish())
    }

    pub fn list_findings(&self, session_id: &str) -> Result<Vec<Finding>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id,session_id,title,severity,asset,vuln_type,description,reproduction,impact,remediation,evidence,status,created_at,updated_at,request,response,cvss,cwe,dedupe_key,evidence_hash,validated_at,validation_detail
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
            })
        })?;
        let mut out = vec![];
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// Record the validation outcome of a finding, stamping the time it was checked.
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
        out.push_str("# MiniBug Report\n\n");
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

    /// Durable usage snapshot. The requests-per-minute window rolls over after 60s.
    pub fn budget_usage(&self, session_id: &str) -> Result<BudgetUsage> {
        let conn = self.conn.lock().unwrap();
        let row: Option<(i64, i64, i64, i64, i64)> = conn
            .query_row(
                "SELECT steps_used, tool_calls_used, network_calls_used, window_start_ms, calls_in_window
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
            "SELECT id,session_id,target,method,path,created_at FROM coverage WHERE session_id=?1 ORDER BY rowid ASC",
        )?;
        let rows = stmt.query_map(params![session_id], |r| {
            Ok(Coverage {
                id: r.get(0)?,
                session_id: r.get(1)?,
                target: r.get(2)?,
                method: r.get(3)?,
                path: r.get(4)?,
                created_at: r.get(5)?,
            })
        })?;
        let mut out = vec![];
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    pub fn add_hypothesis(&self, session_id: &str, statement: &str) -> Result<Hypothesis> {
        let h = Hypothesis {
            id: Uuid::new_v4().to_string(),
            session_id: session_id.to_string(),
            statement: statement.to_string(),
            status: "open".to_string(),
            created_at: now(),
        };
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO hypotheses(id,session_id,statement,status,created_at) VALUES(?1,?2,?3,?4,?5)",
            params![h.id, h.session_id, h.statement, h.status, h.created_at],
        )?;
        Ok(h)
    }

    pub fn list_hypotheses(&self, session_id: &str) -> Result<Vec<Hypothesis>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id,session_id,statement,status,created_at FROM hypotheses WHERE session_id=?1 ORDER BY rowid ASC",
        )?;
        let rows = stmt.query_map(params![session_id], |r| {
            Ok(Hypothesis {
                id: r.get(0)?,
                session_id: r.get(1)?,
                statement: r.get(2)?,
                status: r.get(3)?,
                created_at: r.get(4)?,
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
            "UPDATE hypotheses SET status=?2 WHERE id=?1",
            params![id, status],
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
        let should_redact = (is_card || is_ssn || is_phone) && !looks_like_date(&chunks, &digits);

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

#[cfg(test)]
mod tests {
    use super::*;

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
    }
}
