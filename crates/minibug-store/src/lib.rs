use anyhow::{Context, Result};
use chrono::{Duration, Utc};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub id: String,
    pub session_id: String,
    pub level: String,
    pub kind: String,
    pub message: String,
    pub created_at: String,
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
               tool_name TEXT, args_json TEXT, risk TEXT, created_at TEXT, tool_call_id TEXT
             );
             CREATE TABLE IF NOT EXISTS events(
               id TEXT PRIMARY KEY, session_id TEXT NOT NULL, level TEXT NOT NULL, kind TEXT NOT NULL, message TEXT NOT NULL, created_at TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS findings(
               id TEXT PRIMARY KEY, session_id TEXT NOT NULL, title TEXT NOT NULL, severity TEXT NOT NULL,
               asset TEXT, vuln_type TEXT, description TEXT NOT NULL, reproduction TEXT, impact TEXT,
               remediation TEXT, evidence TEXT, status TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
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
             CREATE INDEX IF NOT EXISTS idx_messages_session ON messages(session_id);
             CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id);
             CREATE INDEX IF NOT EXISTS idx_approvals_session ON approvals(session_id);
             CREATE INDEX IF NOT EXISTS idx_findings_session ON findings(session_id);
             CREATE INDEX IF NOT EXISTS idx_assets_session ON assets(session_id);
             CREATE INDEX IF NOT EXISTS idx_artifacts_session ON artifacts(session_id);
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
        let a = Approval {
            id: Uuid::new_v4().to_string(),
            session_id: session_id.to_string(),
            tool_name: tool_name.to_string(),
            args_json: args_json.to_string(),
            risk: risk.to_string(),
            status: "pending".to_string(),
            reason: Some(reason.to_string()),
            created_at: now(),
            tool_call_id: tool_call_id.map(|s| s.to_string()),
        };
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO approvals(id,session_id,action,status,reason,tool_name,args_json,risk,created_at,tool_call_id)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
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
            ],
        )?;
        Ok(a)
    }

    pub fn get_pending_approval(&self, session_id: &str) -> Result<Option<Approval>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id,session_id,COALESCE(tool_name,action),COALESCE(args_json,'{}'),COALESCE(risk,''),status,reason,COALESCE(created_at,''),tool_call_id
             FROM approvals WHERE session_id=?1 AND status='pending' ORDER BY rowid DESC LIMIT 1",
        )?;
        let row = stmt
            .query_row(params![session_id], |r| {
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
                })
            })
            .optional()?;
        Ok(row)
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
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO events(id,session_id,level,kind,message,created_at) VALUES(?1,?2,?3,?4,?5,?6)",
            params![id, session_id, level, kind, message, now()],
        )?;
        Ok(())
    }

    pub fn list_events(&self, session_id: &str, limit: usize) -> Result<Vec<Event>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id,session_id,level,kind,message,created_at FROM events WHERE session_id=?1 ORDER BY rowid DESC LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![session_id, limit as i64], |r| {
            Ok(Event {
                id: r.get(0)?,
                session_id: r.get(1)?,
                level: r.get(2)?,
                kind: r.get(3)?,
                message: r.get(4)?,
                created_at: r.get(5)?,
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
            "SELECT id,session_id,level,kind,message,created_at FROM events ORDER BY rowid DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit as i64], |r| {
            Ok(Event {
                id: r.get(0)?,
                session_id: r.get(1)?,
                level: r.get(2)?,
                kind: r.get(3)?,
                message: r.get(4)?,
                created_at: r.get(5)?,
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
        };
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO findings(id,session_id,title,severity,asset,vuln_type,description,reproduction,impact,remediation,evidence,status,created_at,updated_at)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)",
            params![
                f.id, f.session_id, f.title, f.severity, f.asset, f.vuln_type, f.description,
                f.reproduction, f.impact, f.remediation, f.evidence, f.status, f.created_at, f.updated_at
            ],
        )?;
        Ok(f)
    }

    pub fn list_findings(&self, session_id: &str) -> Result<Vec<Finding>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id,session_id,title,severity,asset,vuln_type,description,reproduction,impact,remediation,evidence,status,created_at,updated_at
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
            })
        })?;
        let mut out = vec![];
        for r in rows {
            out.push(r?);
        }
        Ok(out)
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

/// Redact secrets from structured JSON, key/value text, bearer tokens and
/// well-known token prefixes. Used at every report and CLI output boundary.
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
}
