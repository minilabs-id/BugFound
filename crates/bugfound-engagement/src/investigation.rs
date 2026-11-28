//! Persistent investigation state — the V3 continuity boundary (ADR-V3-002).
//!
//! This module owns the *domain* shape of the state; `bugfound-store` owns only
//! revision, hash and ordering. Nothing here is on the V1 execution path yet:
//! Phase P0 introduces the substrate, later phases rewire the orchestrator.

use crate::catalog::{Catalog, Technique};
use anyhow::{Context, Result};
use bugfound_store::{InvestigationEvent, InvestigationEventInput, InvestigationStateRow, Store};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::sync::OnceLock;
use uuid::Uuid;

/// Canonical hypothesis-status vocabulary. Every consumer (planner, context
/// projection, engagement verifier) must go through the helpers below instead
/// of copying string literals (C19). `tested` is a recognised, non-terminal
/// state: it records that a coverage round ran, not that the line is closed.
pub mod status {
    pub const VALIDATED: &str = "validated";
    pub const CONFIRMED: &str = "confirmed";
    pub const CONFIRMED_CANDIDATE: &str = "confirmed-candidate";
    pub const RULED_OUT: &str = "ruled_out";
    pub const BLOCKED: &str = "blocked";
    pub const NOT_APPLICABLE: &str = "not-applicable";
    pub const OPEN: &str = "open";
    pub const OPEN_PROOF_GAP: &str = "open_proof_gap";
    pub const TESTED: &str = "tested";
    pub const UNKNOWN: &str = "unknown";

    /// The single table: (canonical spelling, is terminal).
    pub const VOCABULARY: &[(&str, bool)] = &[
        (VALIDATED, true),
        (CONFIRMED, true),
        (CONFIRMED_CANDIDATE, true),
        (RULED_OUT, true),
        (BLOCKED, true),
        (NOT_APPLICABLE, true),
        (OPEN, false),
        (OPEN_PROOF_GAP, false),
        (TESTED, false),
    ];
}

/// Canonicalise aliases and spellings. Both `not_applicable` and
/// `not-applicable` collapse to the single canonical `not-applicable`; unknown
/// values collapse to `unknown` and are never treated as terminal.
pub fn normalize_status(value: &str) -> &'static str {
    let value = value.trim();
    for (canonical, _) in status::VOCABULARY {
        if canonical.eq_ignore_ascii_case(value) {
            return canonical;
        }
    }
    if value.eq_ignore_ascii_case("not_applicable") || value.eq_ignore_ascii_case("not applicable")
    {
        return status::NOT_APPLICABLE;
    }
    status::UNKNOWN
}

/// True only for closed hypothesis outcomes. Shared by the planner, the
/// context projection and the engagement orchestrator.
pub fn is_terminal_status(value: &str) -> bool {
    let canonical = normalize_status(value);
    status::VOCABULARY
        .iter()
        .any(|(name, terminal)| *terminal && *name == canonical)
}

/// True when the value is part of the canonical vocabulary (including `tested`).
pub fn is_known_status(value: &str) -> bool {
    normalize_status(value) != status::UNKNOWN
}

/// Operator TLP handling labels (FIRST TLP v2.0) accepted on seed state.
pub const TLP_LABELS: &[&str] = &["TLP:CLEAR", "TLP:GREEN", "TLP:AMBER", "TLP:RED"];

/// Normalise a ROE-supplied TLP label. Bare `RED`/`GREEN` spellings are
/// accepted; empty or unrecognised values fall back to the backwards-compatible
/// `TLP:AMBER` default rather than silently upgrading handling restrictions.
pub fn normalize_tlp_label(value: &str) -> String {
    let trimmed = value.trim();
    let candidate = match trimmed.get(..4) {
        Some(prefix) if prefix.eq_ignore_ascii_case("TLP:") => &trimmed[4..],
        _ => trimmed,
    };
    TLP_LABELS
        .iter()
        .find(|label| (*label)[4..].eq_ignore_ascii_case(candidate))
        .map(|label| (*label).to_string())
        .unwrap_or_else(default_tlp)
}

/// One actionable step proposed by the planner. `technique_id` refers to the
/// versioned domain catalog (V3 Phase P3), not to a hard-coded playbook.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct PlanStep {
    pub id: String,
    pub hypothesis_id: String,
    pub technique_id: String,
    pub target: String,
    pub rationale: String,
    pub expected_evidence: String,
    pub depends_on: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Plan {
    pub revision: u64,
    /// Pinned catalog revision used to select these steps.
    #[serde(default)]
    pub catalog_version: String,
    pub steps: Vec<PlanStep>,
}

/// A reflection is structured feedback from the verifier or operator. Verifier
/// rejections must be written back so later steps do not repeat a dead end.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reflection {
    pub kind: String,
    pub reason: String,
    pub step_id: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct InvestigationState {
    pub engagement_id: String,
    pub phase: String,
    pub revision: u64,
    pub assets: Vec<Value>,
    pub hypotheses: Vec<Value>,
    pub coverage: Vec<Value>,
    pub tasks: Vec<Value>,
    pub plan: Plan,
    pub open_questions: Vec<String>,
    pub reflections: Vec<Reflection>,
    pub stop_reason: Option<String>,
    /// Handling label inherited from the engagement ROE (FIRST TLP v2.0).
    #[serde(default = "default_tlp")]
    pub tlp_label: String,
    pub backfilled_from: String,
}

impl Default for InvestigationState {
    fn default() -> Self {
        Self {
            engagement_id: String::new(),
            phase: "init".into(),
            revision: 0,
            assets: Vec::new(),
            hypotheses: Vec::new(),
            coverage: Vec::new(),
            tasks: Vec::new(),
            plan: Plan::default(),
            open_questions: Vec::new(),
            reflections: Vec::new(),
            stop_reason: None,
            tlp_label: default_tlp(),
            backfilled_from: String::new(),
        }
    }
}

impl InvestigationState {
    /// Bind the ROE handling label to a seed state. Call this once when the
    /// engagement state is first created from `RoePolicy.tlp_label` (C22).
    pub fn set_tlp_label(&mut self, label: &str) {
        self.tlp_label = normalize_tlp_label(label);
    }

    /// Builder form of [`InvestigationState::set_tlp_label`].
    pub fn with_tlp_label(mut self, label: &str) -> Self {
        self.set_tlp_label(label);
        self
    }
}

/// Fresh seed state for a new engagement, carrying the ROE handling label.
/// `Default` stays at `TLP:AMBER` for backwards compatibility; callers that
/// have a parsed brief should pass its label here.
pub fn seed_state(engagement_id: impl Into<String>, tlp_label: &str) -> InvestigationState {
    InvestigationState {
        engagement_id: engagement_id.into(),
        ..InvestigationState::default()
    }
    .with_tlp_label(tlp_label)
}

/// A step proposed by the planner. `action_key` is the deterministic idempotency
/// key used to detect repeated, low-value actions across rounds.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NextStep {
    pub id: String,
    pub playbook_id: String,
    pub hypothesis_id: String,
    pub target: String,
    pub rationale: String,
    pub priority: f64,
    pub action_key: String,
    #[serde(default)]
    pub catalog_version: String,
}

impl From<NextStep> for PlanStep {
    fn from(step: NextStep) -> Self {
        Self {
            id: step.id,
            hypothesis_id: step.hypothesis_id,
            technique_id: step.playbook_id,
            target: step.target,
            rationale: step.rationale,
            ..PlanStep::default()
        }
    }
}

#[derive(Debug, Clone)]
pub struct PlannerContext {
    pub round: usize,
    pub max_steps: usize,
    /// Techniques whose safe bounds require state-changing actions are only
    /// offered when the operator and ROE explicitly allow them.
    pub allow_state_change: bool,
    /// Authorised in-scope patterns from the brief. Used to decide whether a
    /// technique that needs a target is applicable even before assets are found.
    pub scope_in: Vec<String>,
}

/// The planner is the only component allowed to choose the next investigation
/// step. A deterministic reference planner ships first; an LLM-backed planner
/// can replace it behind this trait without changing the orchestrator seam.
pub trait Planner {
    fn next_steps(&self, state: &InvestigationState, ctx: &PlannerContext) -> Vec<NextStep>;
}

/// Rank open hypotheses by information value and penalise actions already
/// taken, so a later round cannot silently replay the same work.
#[derive(Debug, Clone)]
pub struct HeuristicPlanner {
    catalog: Catalog,
}

impl Default for HeuristicPlanner {
    fn default() -> Self {
        Self {
            catalog: Catalog::v1(),
        }
    }
}

impl HeuristicPlanner {
    pub fn with_catalog(catalog: Catalog) -> Self {
        Self { catalog }
    }
}

impl Planner for HeuristicPlanner {
    fn next_steps(&self, state: &InvestigationState, ctx: &PlannerContext) -> Vec<NextStep> {
        let mut repeats: std::collections::HashMap<String, usize> =
            std::collections::HashMap::new();
        for reflection in &state.reflections {
            if reflection.kind == "action_key" {
                *repeats.entry(reflection.reason.clone()).or_insert(0) += 1;
            }
        }

        let value_str = |value: &serde_json::Value, key: &str| -> String {
            value
                .get(key)
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .to_string()
        };

        let mut steps: Vec<NextStep> = self
            .catalog
            .techniques_for_planner()
            .into_iter()
            .filter_map(|technique: &Technique| {
                // `applicable` runs the catalog's fail-closed precondition gate
                // (C18) with the operator context before any step is offered.
                if !self
                    .catalog
                    .applicable(technique, state, ctx.allow_state_change, &ctx.scope_in)
                {
                    return None;
                }
                let playbook_id = technique.id.clone();
                // Prefer a target already attached to a task for this
                // technique; otherwise use the first observed asset. A task
                // absence must not remove the capability — the catalog owns it.
                let target = state
                    .tasks
                    .iter()
                    .find(|task| value_str(task, "playbook_id") == playbook_id)
                    .map(|task| value_str(task, "target"))
                    .filter(|target| !target.is_empty())
                    .or_else(|| {
                        state.assets.iter().find_map(|asset| {
                            let value = value_str(asset, "value");
                            (!value.is_empty()).then_some(value)
                        })
                    })
                    .unwrap_or_default();
                let hypothesis = state.hypotheses.iter().find(|hypothesis| {
                    value_str(hypothesis, "requirement_id") == playbook_id
                });
                if hypothesis
                    .map(|hypothesis| is_terminal_status(&value_str(hypothesis, "status")))
                    .unwrap_or(false)
                {
                    return None;
                }
                let covered = state
                    .coverage
                    .iter()
                    .filter(|row| value_str(row, "target") == target)
                    .count();
                let assets = state
                    .assets
                    .iter()
                    .filter(|asset| value_str(asset, "value").contains(&target))
                    .count();
                let action_key = bugfound_store::idempotency_key(
                    &state.engagement_id,
                    &playbook_id,
                    &target,
                );
                let repeated = *repeats.get(&action_key).unwrap_or(&0);
                let priority = 1.0
                    + if hypothesis.is_some() { 1.0 } else { 0.0 }
                    + if covered == 0 { 1.0 } else { -0.5 }
                    + if assets > 0 { 0.5 } else { 0.0 }
                    - (repeated as f64) * 2.0;
                Some(NextStep {
                    id: action_key.chars().take(16).collect(),
                    hypothesis_id: hypothesis
                        .map(|hypothesis| value_str(hypothesis, "id"))
                        .unwrap_or_default(),
                    playbook_id,
                    target: target.clone(),
                    rationale: format!(
                        "round {} selected with priority {priority:.2} (covered={covered}, assets={assets}, repeats={repeated})",
                        ctx.round
                    ),
                    priority,
                    action_key,
                    catalog_version: technique.version.clone(),
                })
            })
            .collect();
        steps.sort_by(|a, b| {
            b.priority
                .total_cmp(&a.priority)
                .then_with(|| a.action_key.cmp(&b.action_key))
        });
        steps.truncate(ctx.max_steps.max(1));
        steps
    }
}

/// Refresh the domain view from durable tables before planning. Without this,
/// a later round would rank stale state and replay finished work.
pub fn refresh_state(store: &Store, state: &mut InvestigationState) -> Result<()> {
    let session = state.engagement_id.as_str();
    state.hypotheses = store
        .list_hypotheses(session)?
        .into_iter()
        .map(serde_json::to_value)
        .collect::<Result<Vec<_>, _>>()?;
    state.coverage = store
        .list_coverage(session)?
        .into_iter()
        .map(serde_json::to_value)
        .collect::<Result<Vec<_>, _>>()?;
    state.assets = store
        .list_assets(session)?
        .into_iter()
        .map(serde_json::to_value)
        .collect::<Result<Vec<_>, _>>()?;
    state.tasks = store
        .list_tasks(session)?
        .into_iter()
        .map(serde_json::to_value)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(())
}

/// Select this round's tasks from the investigation state. This is the seam
/// that replaces `search_round_tasks` when adaptive planning is enabled: the
/// planner chooses, the harness still authorises every resulting action.
pub fn select_round_tasks(
    store: &Store,
    engagement_id: &str,
    round: usize,
    max_steps: usize,
    scope_in: &[String],
    allow_state_change: bool,
) -> Result<Vec<bugfound_store::Task>> {
    let (mut state, _revision) = load(store, engagement_id)?;
    refresh_state(store, &mut state)?;
    let mut steps = HeuristicPlanner::default().next_steps(
        &state,
        &PlannerContext {
            round,
            max_steps,
            allow_state_change,
            scope_in: scope_in.to_vec(),
        },
    );
    // Wire the previously orphaned coverage-driven `prioritize_targets` into
    // the production decision path: uncovered, hypothesis-mentioned targets
    // receive a small evidence-value bonus before the final ranking.
    let covered: Vec<String> = state
        .coverage
        .iter()
        .filter_map(|row| row.get("target").and_then(serde_json::Value::as_str))
        .map(str::to_string)
        .collect();
    let hypotheses: Vec<bugfound_store::Hypothesis> = state
        .hypotheses
        .iter()
        .filter_map(|value| serde_json::from_value(value.clone()).ok())
        .collect();
    let ranked = crate::domain::prioritize_targets(scope_in, &covered, &hypotheses);
    for step in &mut steps {
        if let Some(position) = ranked.iter().position(|target| target == &step.target) {
            step.priority += 0.25 / (1.0 + position as f64);
        }
    }
    steps.sort_by(|a, b| {
        b.priority
            .total_cmp(&a.priority)
            .then_with(|| a.action_key.cmp(&b.action_key))
    });
    steps.truncate(max_steps.max(1));
    select_round_tasks_with_steps(store, engagement_id, round, steps, "planner")
}

/// Persist an already-chosen step list. Both the deterministic and the LLM
/// planner funnel through here, so audit/state/dedupe behavior is identical.
pub fn select_round_tasks_with_steps(
    store: &Store,
    engagement_id: &str,
    round: usize,
    steps: Vec<NextStep>,
    planner_actor: &str,
) -> Result<Vec<bugfound_store::Task>> {
    let (mut state, revision) = load(store, engagement_id)?;
    refresh_state(store, &mut state)?;
    state.plan = Plan {
        revision: round as u64,
        catalog_version: Catalog::version_label().into(),
        steps: steps.iter().cloned().map(PlanStep::from).collect(),
    };
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .to_string();
    for step in &steps {
        state.reflections.push(Reflection {
            kind: "action_key".into(),
            reason: step.action_key.clone(),
            step_id: step.id.clone(),
            created_at: timestamp.clone(),
        });
    }
    let _ = audit(
        store,
        AuditInput {
            engagement_id,
            run_id: engagement_id,
            step_id: &round.to_string(),
            call_id: "planner",
            kind: "plan_generated",
            actor: planner_actor,
            payload: &serde_json::json!({
                "round": round,
                "steps": steps.len(),
                "techniques": steps.iter().map(|step| step.playbook_id.clone()).collect::<Vec<_>>(),
            }),
        },
    )?;
    save(store, &state, revision)?;

    Ok(steps
        .into_iter()
        .map(|step| bugfound_store::Task {
            id: step.id,
            engagement_id: engagement_id.to_string(),
            statement: step.rationale,
            playbook_id: step.playbook_id,
            target: Some(step.target),
            priority: (step.priority * 1000.0) as i64,
            status: "open".into(),
            created_at: timestamp.clone(),
        })
        .collect())
}

fn default_tlp() -> String {
    "TLP:AMBER".to_string()
}

/// Load the state, backfilling from legacy engagement tables on first access.
pub fn load(store: &Store, engagement_id: &str) -> Result<(InvestigationState, u64)> {
    let row: InvestigationStateRow = store.ensure_investigation_state(engagement_id)?;
    let mut state: InvestigationState =
        serde_json::from_str(&row.state_json).context("deserialize investigation state")?;
    state.revision = row.revision;
    Ok((state, row.revision))
}

/// Atomically replace the state. Passing a stale revision fails instead of
/// overwriting newer work (optimistic concurrency).
pub fn save(store: &Store, state: &InvestigationState, expected_revision: u64) -> Result<u64> {
    let json = serde_json::to_string(state).context("serialize investigation state")?;
    store.put_investigation_state(&state.engagement_id, &json, Some(expected_revision))
}

/// Input for one audit record. `kind` is one of `plan_generated`,
/// `policy_decision`, `approval_requested`, `approval_resolved`, `tool_invoked`,
/// `tool_result_redacted`, `verdict`, `state_transition`, `compaction`,
/// `stop_reason` (convention, not enum — the store does not need the vocabulary).
#[derive(Debug, Clone, Copy)]
pub struct AuditInput<'a> {
    pub engagement_id: &'a str,
    pub run_id: &'a str,
    pub step_id: &'a str,
    pub call_id: &'a str,
    pub kind: &'a str,
    pub actor: &'a str,
    pub payload: &'a Value,
}

pub fn audit(store: &Store, input: AuditInput<'_>) -> Result<InvestigationEvent> {
    let payload_json = serde_json::to_string(input.payload).context("serialize audit payload")?;
    store.append_investigation_event(InvestigationEventInput {
        engagement_id: input.engagement_id,
        run_id: input.run_id,
        step_id: input.step_id,
        call_id: input.call_id,
        kind: input.kind,
        actor: input.actor,
        payload_json: &payload_json,
    })
}

/// Operator-supplied secret used to key checkpoint state digests (C21).
pub const CHECKPOINT_KEY_ENV: &str = "BUGFOUND_CHECKPOINT_KEY";
/// Digest version marker. Any digest without this prefix is a legacy v1 digest
/// and must never authenticate a resume.
const CHECKPOINT_DIGEST_PREFIX: &str = "bf-ckpt-v2:";

fn ephemeral_checkpoint_key() -> &'static str {
    static KEY: OnceLock<String> = OnceLock::new();
    KEY.get_or_init(|| {
        tracing::warn!(
            "{CHECKPOINT_KEY_ENV} is unset; checkpoints use an ephemeral process key and cannot be resumed across restarts"
        );
        format!(
            "ephemeral:{}:{}",
            Uuid::new_v4(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        )
    })
}

/// Resolve the operator key from the environment; `None` when absent/blank.
/// Library callers can pass an explicit key to the `*_with_key` functions.
pub fn checkpoint_key_from_env() -> Option<String> {
    std::env::var(CHECKPOINT_KEY_ENV)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn effective_checkpoint_key() -> String {
    checkpoint_key_from_env().unwrap_or_else(|| ephemeral_checkpoint_key().to_string())
}

/// HMAC-SHA256 (RFC 2104) built on `sha2`, so no extra crate is required.
fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut key_block = [0u8; 64];
    if key.len() > 64 {
        key_block[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0u8; 64];
    let mut opad = [0u8; 64];
    for (index, byte) in key_block.iter().enumerate() {
        ipad[index] = byte ^ 0x36;
        opad[index] = byte ^ 0x5c;
    }
    let mut inner = Vec::with_capacity(64 + message.len());
    inner.extend_from_slice(&ipad);
    inner.extend_from_slice(message);
    let inner_hash = Sha256::digest(&inner);
    let mut outer = Vec::with_capacity(96);
    outer.extend_from_slice(&opad);
    outer.extend_from_slice(&inner_hash);
    let digest = Sha256::digest(&outer);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn checkpoint_mac(key: &str, engagement_id: &str, revision: u64, json: &str) -> String {
    let payload = format!("{engagement_id}\0{revision}\0{json}");
    let mac = hmac_sha256(key.as_bytes(), payload.as_bytes());
    let hex: String = mac
        .iter()
        .map(|byte| {
            let byte = *byte;
            format!("{byte:02x}")
        })
        .collect();
    format!("{CHECKPOINT_DIGEST_PREFIX}{hex}")
}

/// P5: write an immutable, keyed checkpoint of the current state.
/// `agent_version` pins the planner/catalog/agent definition so a resumed run
/// cannot mix instructions from different revisions.
pub fn checkpoint_with_key(
    store: &Store,
    state: &InvestigationState,
    agent_version: &str,
    key: &str,
) -> Result<u64> {
    let json = serde_json::to_string(state).context("serialize checkpoint")?;
    let digest = checkpoint_mac(key, &state.engagement_id, state.revision, &json);
    store.save_checkpoint(
        &state.engagement_id,
        state.revision,
        &json,
        &digest,
        agent_version,
    )?;
    Ok(state.revision)
}

/// Environment-backed wrapper around [`checkpoint_with_key`]. Use the explicit
/// variant when the operator key comes from an application config surface.
pub fn checkpoint(store: &Store, state: &InvestigationState, agent_version: &str) -> Result<u64> {
    let key = effective_checkpoint_key();
    checkpoint_with_key(store, state, agent_version, &key)
}

/// P5: authenticated, version-checked resume. Legacy v1 digests, tampered
/// state, revision drift and agent-version drift all fail closed.
pub fn resume_checkpoint_with_key(
    store: &Store,
    engagement_id: &str,
    expected_revision: u64,
    expected_agent_version: &str,
    key: &str,
) -> Result<InvestigationState> {
    let row = store
        .latest_checkpoint(engagement_id)?
        .ok_or_else(|| anyhow::anyhow!("no investigation checkpoint for {engagement_id}"))?;
    if !row.state_hash.starts_with(CHECKPOINT_DIGEST_PREFIX) {
        return Err(anyhow::anyhow!(
            "legacy v1 checkpoint digest at revision {} rejected; re-key with {}",
            row.revision,
            CHECKPOINT_KEY_ENV
        ));
    }
    let expected_digest = checkpoint_mac(key, engagement_id, row.revision, &row.state_json);
    if expected_digest != row.state_hash {
        return Err(anyhow::anyhow!(
            "checkpoint digest mismatch at revision {}",
            row.revision
        ));
    }
    if row.revision != expected_revision {
        return Err(anyhow::anyhow!(
            "checkpoint revision {} does not exactly match expected {expected_revision}",
            row.revision
        ));
    }
    let version = store
        .checkpoint_agent_version(engagement_id, row.revision)?
        .unwrap_or_default();
    if version != expected_agent_version {
        return Err(anyhow::anyhow!(
            "checkpoint agent version '{version}' does not match '{expected_agent_version}'"
        ));
    }
    let mut state: InvestigationState =
        serde_json::from_str(&row.state_json).context("deserialize checkpoint")?;
    state.revision = row.revision;
    Ok(state)
}

/// Environment-backed wrapper around [`resume_checkpoint_with_key`].
pub fn resume_checkpoint(
    store: &Store,
    engagement_id: &str,
    expected_revision: u64,
    expected_agent_version: &str,
) -> Result<InvestigationState> {
    let key = effective_checkpoint_key();
    resume_checkpoint_with_key(
        store,
        engagement_id,
        expected_revision,
        expected_agent_version,
        &key,
    )
}

/// Orchestrator wiring seam for the `resume_from_checkpoint` config flag.
/// Disabled returns `None` without touching the checkpoint store.
pub fn resume_checkpoint_wiring(
    store: &Store,
    engagement_id: &str,
    expected_revision: u64,
    agent_version: &str,
    key: &str,
    enabled: bool,
) -> Result<Option<InvestigationState>> {
    if !enabled {
        return Ok(None);
    }
    resume_checkpoint_with_key(store, engagement_id, expected_revision, agent_version, key)
        .map(Some)
}

/// Load-or-resume helper for the orchestrator: returns the durable state when
/// the flag is off, otherwise the authenticated checkpoint state.
pub fn resume_or_load(
    store: &Store,
    engagement_id: &str,
    agent_version: &str,
    key: &str,
    enabled: bool,
) -> Result<(InvestigationState, u64)> {
    let (durable, revision) = load(store, engagement_id)?;
    if !enabled {
        return Ok((durable, revision));
    }
    let resumed = resume_checkpoint_with_key(store, engagement_id, revision, agent_version, key)?;
    let resumed_revision = resumed.revision;
    Ok((resumed, resumed_revision))
}

/// Compact context view. Raw tool outputs never enter this projection; only
/// identifiers, verdicts and counts, so the model sees high-signal context
/// under a bounded token budget.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextProjection {
    pub engagement_id: String,
    pub revision: u64,
    pub catalog_version: String,
    pub tlp_label: String,
    pub plan_steps: Vec<String>,
    pub open_hypotheses: Vec<String>,
    pub asset_count: usize,
    pub coverage_count: usize,
    pub reflection_count: usize,
    pub estimated_tokens: usize,
}

pub fn project_context(state: &InvestigationState, max_items: usize) -> ContextProjection {
    let plan_steps: Vec<String> = state
        .plan
        .steps
        .iter()
        .take(max_items)
        .map(|step| format!("{}@{}", step.technique_id, step.target))
        .collect();
    let open_hypotheses: Vec<String> = state
        .hypotheses
        .iter()
        .filter_map(|value| {
            let status = value
                .get("status")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default();
            if is_terminal_status(status) {
                return None;
            }
            Some(
                value
                    .get("id")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("unknown")
                    .to_string(),
            )
        })
        .take(max_items)
        .collect();
    let estimated_tokens = (plan_steps.len() + open_hypotheses.len()) * 24 + 64;
    ContextProjection {
        engagement_id: state.engagement_id.clone(),
        revision: state.revision,
        catalog_version: state.plan.catalog_version.clone(),
        tlp_label: state.tlp_label.clone(),
        plan_steps,
        open_hypotheses,
        asset_count: state.assets.len(),
        coverage_count: state.coverage.len(),
        reflection_count: state.reflections.len(),
        estimated_tokens,
    }
}

/// Distil a subagent/tool observation into a small digest. Full bytes stay in
/// the evidence store; only this summary re-enters the planner context.
pub fn digest_observation(text: &str, max_tokens: usize) -> String {
    let max_chars = max_tokens.saturating_mul(4).max(64);
    if text.chars().count() <= max_chars {
        return text.to_string();
    }
    let mut out: String = text.chars().take(max_chars).collect();
    out.push_str("\\n…[digest truncated]");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_round_trip_preserves_revision_and_plan() {
        let path =
            std::env::temp_dir().join(format!("bf-investigation-domain-{}.db", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let store = Store::open(&path).expect("store");
        let engagement = store
            .create_engagement("https://example.test")
            .expect("engagement");

        let (mut state, revision) = load(&store, &engagement.id).expect("load");
        assert_eq!(state.engagement_id, engagement.id);
        state.phase = "plan".into();
        state.plan.steps.push(PlanStep {
            id: "step-1".into(),
            hypothesis_id: "h-1".into(),
            technique_id: "WSTG-ATHZ-01".into(),
            target: "example.test".into(),
            expected_evidence: "response bytes".into(),
            ..PlanStep::default()
        });
        let next = save(&store, &state, revision).expect("save");
        assert_eq!(next, revision + 1);

        let (loaded, loaded_revision) = load(&store, &engagement.id).expect("reload");
        assert_eq!(loaded_revision, next);
        assert_eq!(loaded.phase, "plan");
        assert_eq!(loaded.plan.steps.len(), 1);
        assert!(
            save(&store, &state, revision).is_err(),
            "stale revision rejected"
        );

        let event = audit(
            &store,
            AuditInput {
                engagement_id: &engagement.id,
                run_id: "run-1",
                step_id: "step-1",
                call_id: "call-1",
                kind: "plan_generated",
                actor: "planner",
                payload: &serde_json::json!({"steps": 1}),
            },
        )
        .expect("audit");
        assert_eq!(event.actor, "planner");
        store
            .verify_investigation_event_chain(&engagement.id)
            .expect("chain valid");

        let _ = std::fs::remove_file(&path);
    }

    fn state_with_tasks() -> InvestigationState {
        let task = |id: &str| {
            serde_json::json!({
                "id": id,
                "playbook_id": id,
                "target": format!("host-{id}"),
            })
        };
        let hypothesis = |id: &str, status: &str| serde_json::json!({"id": format!("h-{id}"), "requirement_id": id, "status": status});
        InvestigationState {
            engagement_id: "engagement-1".into(),
            tasks: vec![
                task("wstg-info"),
                task("wstg-authz"),
                task("wstg-injection"),
            ],
            hypotheses: vec![
                hypothesis("wstg-info", "open"),
                hypothesis("wstg-authz", "ruled_out"),
                hypothesis("wstg-injection", "open"),
            ],
            assets: vec![serde_json::json!({"value": "host-wstg-info"})],
            ..InvestigationState::default()
        }
    }

    #[test]
    fn adaptive_reorder_skips_terminal_hypotheses() {
        let state = state_with_tasks();
        let steps = HeuristicPlanner::default().next_steps(
            &state,
            &PlannerContext {
                round: 2,
                max_steps: 10,
                allow_state_change: true,
                scope_in: vec!["127.0.0.1".to_string()],
            },
        );
        assert!(
            steps.iter().all(|step| step.playbook_id != "wstg-authz"),
            "terminal hypothesis must not be replayed"
        );
        assert!(steps.len() >= 2);
        assert!(
            steps
                .iter()
                .all(|step| step.catalog_version == crate::catalog::Catalog::version_label()),
            "every step must pin its catalog version"
        );
    }

    #[test]
    fn replan_on_coverage_delta_changes_priority() {
        let mut state = state_with_tasks();
        let before = HeuristicPlanner::default().next_steps(
            &state,
            &PlannerContext {
                round: 1,
                max_steps: 10,
                allow_state_change: true,
                scope_in: vec!["127.0.0.1".to_string()],
            },
        );
        let first_before = before.first().expect("step").playbook_id.clone();
        let target_before = before.first().expect("step").target.clone();

        state.coverage.push(serde_json::json!({
            "target": target_before,
            "status": "covered",
        }));
        let after = HeuristicPlanner::default().next_steps(
            &state,
            &PlannerContext {
                round: 2,
                max_steps: 10,
                allow_state_change: true,
                scope_in: vec!["127.0.0.1".to_string()],
            },
        );
        let score = |steps: &[NextStep], id: &str| -> f64 {
            steps
                .iter()
                .find(|step| step.playbook_id == id)
                .map(|step| step.priority)
                .unwrap_or(f64::MIN)
        };
        assert!(
            score(&after, &first_before) < score(&before, &first_before),
            "coverage delta must lower the priority of already-covered work"
        );
    }

    #[test]
    fn repeated_action_is_penalised() {
        let mut state = state_with_tasks();
        let initial = HeuristicPlanner::default().next_steps(
            &state,
            &PlannerContext {
                round: 1,
                max_steps: 10,
                allow_state_change: true,
                scope_in: vec!["127.0.0.1".to_string()],
            },
        );
        let repeated_id = initial.first().expect("step").playbook_id.clone();
        let action_key = initial.first().expect("step").action_key.clone();
        state.reflections.push(Reflection {
            kind: "action_key".into(),
            reason: action_key.clone(),
            step_id: "step-1".into(),
            created_at: "0".into(),
        });
        let steps = HeuristicPlanner::default().next_steps(
            &state,
            &PlannerContext {
                round: 3,
                max_steps: 10,
                allow_state_change: true,
                scope_in: vec!["127.0.0.1".to_string()],
            },
        );
        let repeated = steps
            .iter()
            .find(|step| step.action_key == action_key)
            .expect("step");
        let other = steps
            .iter()
            .find(|step| step.playbook_id != repeated_id)
            .expect("step");
        assert!(repeated.priority < other.priority);
    }

    #[test]
    fn no_actionable_steps_stops_the_loop() {
        let state = InvestigationState::default();
        let catalog = crate::catalog::Catalog::empty();
        let steps = HeuristicPlanner::with_catalog(catalog).next_steps(
            &state,
            &PlannerContext {
                round: 2,
                max_steps: 10,
                allow_state_change: true,
                scope_in: vec!["127.0.0.1".to_string()],
            },
        );
        assert!(steps.is_empty(), "no catalog technique must stop planning");
    }

    #[test]
    fn planner_uses_catalog_not_static_playbooks() {
        let mut state = state_with_tasks();
        state.tasks.clear(); // no static playbook rows at all
        let steps = HeuristicPlanner::default().next_steps(
            &state,
            &PlannerContext {
                round: 1,
                max_steps: 3,
                allow_state_change: true,
                scope_in: vec!["127.0.0.1".to_string()],
            },
        );
        assert_eq!(steps.len(), 3, "capability comes from the catalog");
    }

    #[test]
    fn select_round_tasks_persists_plan_and_dedupe() {
        let path =
            std::env::temp_dir().join(format!("bf-adaptive-round-{}.db", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let store = Store::open(&path).expect("store");
        let engagement = store
            .create_engagement("https://example.test")
            .expect("engagement");
        for playbook in ["wstg-info", "wstg-authz", "wstg-injection"] {
            store
                .create_task(&engagement.id, playbook, playbook, None, 0)
                .expect("task");
            store
                .add_structured_hypothesis(&engagement.id, playbook, playbook, playbook, "", "")
                .expect("hypothesis");
        }
        store
            .upsert_asset(&engagement.id, "host", "host-wstg-info", None)
            .expect("asset");
        let scope = vec!["host-wstg-info".to_string()];
        let first =
            select_round_tasks(&store, &engagement.id, 1, 2, &scope, true).expect("round 1");
        assert_eq!(first.len(), 2, "max_steps bounds the round");
        let second =
            select_round_tasks(&store, &engagement.id, 2, 2, &scope, true).expect("round 2");
        assert!(
            first
                .iter()
                .map(|task| &task.playbook_id)
                .collect::<Vec<_>>()
                != second
                    .iter()
                    .map(|task| &task.playbook_id)
                    .collect::<Vec<_>>(),
            "repetition penalty must reorder later rounds"
        );
        let (state, _) = load(&store, &engagement.id).expect("state");
        assert_eq!(state.plan.revision, 2);
        assert!(state.reflections.iter().any(|r| r.kind == "action_key"));
        store
            .verify_investigation_event_chain(&engagement.id)
            .expect("audit chain");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn checkpoint_resume_is_version_checked_and_fails_closed() {
        let path = std::env::temp_dir().join(format!("bf-checkpoint-{}.db", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let store = Store::open(&path).expect("store");
        let engagement = store
            .create_engagement("https://example.test")
            .expect("engagement");

        let (mut state, revision) = load(&store, &engagement.id).expect("load");
        state.phase = "testing".into();
        save(&store, &state, revision).expect("save");
        state.revision = revision + 1;
        let saved = checkpoint(&store, &state, "agent-v3.0").expect("checkpoint");
        assert_eq!(saved, state.revision);

        let resumed =
            resume_checkpoint(&store, &engagement.id, saved, "agent-v3.0").expect("resume");
        assert_eq!(resumed.phase, "testing");
        assert_eq!(resumed.revision, saved);

        assert!(
            resume_checkpoint(&store, &engagement.id, saved, "agent-v2.9").is_err(),
            "agent version mismatch must fail closed"
        );
        assert!(
            resume_checkpoint(&store, &engagement.id, u64::MAX, "agent-v3.0").is_err(),
            "older checkpoint must fail closed"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn context_projection_is_bounded_and_drops_noise() {
        let mut state = state_with_tasks();
        state.plan.steps = vec![
            PlanStep {
                technique_id: "wstg-info".into(),
                target: "host-info".into(),
                ..PlanStep::default()
            },
            PlanStep {
                technique_id: "wstg-authz".into(),
                target: "host-authz".into(),
                ..PlanStep::default()
            },
        ];
        state.coverage.push(serde_json::json!({
            "target": "host-wstg-info",
            "status": "covered",
        }));
        let projection = project_context(&state, 2);
        assert_eq!(projection.plan_steps.len(), 2);
        assert!(projection.open_hypotheses.len() <= 2);
        assert_eq!(projection.coverage_count, 1);
        assert!(projection.estimated_tokens < 512);
        let serialized = serde_json::to_string(&projection).expect("serialize");
        assert!(
            !serialized.contains("raw tool output"),
            "tool noise leaked into context"
        );
    }

    #[test]
    fn digest_observation_caps_size() {
        let text = "x".repeat(10_000);
        let digest = digest_observation(&text, 100);
        assert!(digest.chars().count() <= 500);
        assert!(digest.ends_with("[digest truncated]"));
        assert_eq!(digest_observation("short", 100), "short");
    }

    #[test]
    fn terminal_status_vocabulary_is_shared_and_normalised() {
        for value in [
            "validated",
            "confirmed",
            "confirmed-candidate",
            "ruled_out",
            "blocked",
            "not-applicable",
            "not_applicable",
            "NOT APPLICABLE",
        ] {
            assert!(is_terminal_status(value), "{value} must be terminal");
            assert!(is_known_status(value), "{value} must be known");
        }
        assert_eq!(normalize_status("not_applicable"), status::NOT_APPLICABLE);
        assert_eq!(normalize_status("not-applicable"), status::NOT_APPLICABLE);
        for value in ["open", "open_proof_gap", "tested", "unknown-value"] {
            assert!(!is_terminal_status(value), "{value} must stay open");
        }
        assert!(is_known_status("tested"), "tested is a recognised status");
        assert!(!is_known_status("unknown-value"));

        // The context projection must use the same helper as the planner.
        let mut state = InvestigationState::default();
        state.hypotheses.push(serde_json::json!({
            "id": "h-1", "status": "confirmed-candidate"
        }));
        state.hypotheses.push(serde_json::json!({
            "id": "h-2", "status": "not_applicable"
        }));
        state.hypotheses.push(serde_json::json!({
            "id": "h-3", "status": "tested"
        }));
        let projection = project_context(&state, 10);
        assert_eq!(projection.open_hypotheses, vec!["h-3"]);
    }

    #[test]
    fn seed_state_carries_roe_tlp_label() {
        let seeded = seed_state("eng-tlp", "tlp:red");
        assert_eq!(seeded.engagement_id, "eng-tlp");
        assert_eq!(seeded.tlp_label, "TLP:RED");
        let mutated = InvestigationState::default().with_tlp_label("GREEN");
        assert_eq!(mutated.tlp_label, "TLP:GREEN");
        assert_eq!(InvestigationState::default().tlp_label, "TLP:AMBER");
        assert_eq!(normalize_tlp_label("not-a-label"), "TLP:AMBER");
        assert_eq!(project_context(&seeded, 1).tlp_label, "TLP:RED");
    }

    #[test]
    fn wstg_authz_is_skipped_without_two_identities() {
        let mut state = InvestigationState {
            tasks: vec![serde_json::json!({
                "id": "t-authz", "playbook_id": "wstg-authz", "target": "example.test"
            })],
            hypotheses: vec![serde_json::json!({
                "id": "h-authz", "requirement_id": "wstg-authz", "status": "open"
            })],
            ..InvestigationState::default()
        };
        let ctx = PlannerContext {
            round: 1,
            max_steps: 10,
            allow_state_change: true,
            scope_in: vec!["example.test".to_string()],
        };
        let steps = HeuristicPlanner::default().next_steps(&state, &ctx);
        assert!(
            steps.iter().all(|step| step.playbook_id != "wstg-authz"),
            "wstg-authz must be gated by two identities"
        );

        state.assets.push(serde_json::json!({
            "kind": "identity", "value": "alice@example.test"
        }));
        state.assets.push(serde_json::json!({
            "kind": "identity", "value": "bob@example.test"
        }));
        state.assets.push(serde_json::json!({
            "kind": "object", "value": "doc-42"
        }));
        let steps = HeuristicPlanner::default().next_steps(&state, &ctx);
        assert!(
            steps.iter().any(|step| step.playbook_id == "wstg-authz"),
            "wstg-authz becomes selectable once both preconditions are observed"
        );
    }

    #[test]
    fn checkpoint_digest_is_keyed_and_fails_closed() {
        let path =
            std::env::temp_dir().join(format!("bf-checkpoint-keyed-{}.db", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let store = Store::open(&path).expect("store");
        let key = "operator-checkpoint-key-0123456789";
        let engagement = store
            .create_engagement("https://example.test")
            .expect("engagement");
        let (mut state, revision) = load(&store, &engagement.id).expect("load");
        state.phase = "testing".into();
        state.revision = revision + 1;
        let saved = checkpoint_with_key(&store, &state, "agent-v3.0", key).expect("checkpoint");
        let row = store
            .latest_checkpoint(&engagement.id)
            .expect("row")
            .expect("checkpoint row");
        assert!(row.state_hash.starts_with(CHECKPOINT_DIGEST_PREFIX));

        let resumed = resume_checkpoint_with_key(&store, &engagement.id, saved, "agent-v3.0", key)
            .expect("resume with correct key");
        assert_eq!(resumed.phase, "testing");
        assert!(
            resume_checkpoint_with_key(&store, &engagement.id, saved, "agent-v3.0", "wrong-key")
                .is_err(),
            "wrong operator key must fail closed"
        );
        for expected in [saved.saturating_sub(1), saved.saturating_add(1)] {
            assert!(
                resume_checkpoint_with_key(&store, &engagement.id, expected, "agent-v3.0", key)
                    .is_err(),
                "checkpoint revision must match exactly"
            );
        }
        assert!(
            resume_checkpoint_wiring(&store, &engagement.id, saved, "agent-v3.0", key, false)
                .expect("wiring off")
                .is_none()
        );
        assert!(
            resume_checkpoint_wiring(&store, &engagement.id, saved, "agent-v3.0", key, true)
                .expect("wiring on")
                .is_some()
        );
        let (loaded, loaded_revision) =
            resume_or_load(&store, &engagement.id, "agent-v3.0", key, false).expect("load path");
        assert_eq!(loaded_revision, revision);
        // Flag off returns the durable state (which may be a backfilled
        // `legacy` state), not a freshly seeded `init` state.
        assert_eq!(loaded.engagement_id, engagement.id);

        // Tampered state with an otherwise valid MAC must be rejected.
        let tampered = store
            .create_engagement("https://tampered.test")
            .expect("tampered engagement");
        let mut forged = state.clone();
        forged.phase = "privilege_escalated".into();
        let good_json = serde_json::to_string(&state).expect("json");
        let good_mac = checkpoint_mac(key, &tampered.id, 1, &good_json);
        store
            .save_checkpoint(
                &tampered.id,
                1,
                &serde_json::to_string(&forged).expect("forged"),
                &good_mac,
                "agent-v3.0",
            )
            .expect("save tampered checkpoint");
        assert!(
            resume_checkpoint_with_key(&store, &tampered.id, 1, "agent-v3.0", key).is_err(),
            "tampered state must fail closed"
        );

        // A legacy unkeyed v1 digest must never authenticate a resume.
        let legacy = store
            .create_engagement("https://legacy.test")
            .expect("legacy engagement");
        let legacy_digest =
            bugfound_store::idempotency_key(&legacy.id, "checkpoint", &format!("1:{good_json}"));
        store
            .save_checkpoint(&legacy.id, 1, &good_json, &legacy_digest, "agent-v3.0")
            .expect("save legacy checkpoint");
        assert!(
            resume_checkpoint_with_key(&store, &legacy.id, 1, "agent-v3.0", key).is_err(),
            "legacy v1 digest must be rejected"
        );
        let _ = std::fs::remove_file(&path);
    }
}
