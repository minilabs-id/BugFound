//! Versioned bug-bounty technique catalog (V3 Phase P3).
//!
//! WSTG/ASVS/API/CWE are a **knowledge catalog**, not an execution order. A
//! technique record carries preconditions, safe bounds, expected artifact and
//! version-pinned mappings. The planner scores applicable techniques against
//! the investigation state; it never walks a fixed list.
//!
//! Deferred loading: `search` returns compact views (id/version/title/tool
//! hint) under a result cap; `get` returns the full record only for the ids the
//! planner actually selects. This mirrors tool-search / progressive disclosure
//! so catalog metadata does not flood the model context.

use crate::investigation::InvestigationState;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Mapping {
    pub catalog: String,
    pub id: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Technique {
    pub id: String,
    pub version: String,
    pub family: String,
    /// Metadata for filtering only — never an execution order.
    pub phase: String,
    pub title: String,
    pub tool_hint: String,
    pub preconditions: Vec<String>,
    pub safe_bounds: String,
    pub expected_artifact: String,
    pub benefits: String,
    pub limitations: String,
    pub mappings: Vec<Mapping>,
    pub requires_asset: bool,
    pub requires_state_change: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TechniqueView {
    pub id: String,
    pub version: String,
    pub title: String,
    pub tool_hint: String,
}

#[derive(Debug, Clone, Default)]
pub struct SearchQuery {
    pub family: Option<String>,
    pub text: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Catalog {
    version: String,
    techniques: Vec<Technique>,
}

fn mapping(catalog: &str, id: &str, version: &str) -> Mapping {
    Mapping {
        catalog: catalog.to_string(),
        id: id.to_string(),
        version: version.to_string(),
    }
}

impl Catalog {
    /// The shipped catalog revision. Every plan and finding that used a
    /// technique records this string so results remain auditable as standards
    /// evolve.
    pub const fn version_label() -> &'static str {
        "bugfound-catalog-1 (WSTG-4.2 / ASVS-5.0 / API-2023 / CWE-4.13)"
    }

    /// Empty catalog — used to test the "no actionable step" stop condition.
    pub fn empty() -> Self {
        Self {
            version: Self::version_label().into(),
            techniques: Vec::new(),
        }
    }

    pub fn v1() -> Self {
        let wstg = "4.2";
        let asvs = "5.0.0";
        let api = "2023";
        let techniques = vec![
            Technique {
                id: "wstg-info".into(),
                version: Self::version_label().into(),
                family: "recon".into(),
                phase: "intelligence_gathering".into(),
                title: "Map the in-scope attack surface".into(),
                tool_hint: "dns_lookup,http_probe".into(),
                preconditions: vec!["in_scope_target".into()],
                safe_bounds: "read-only; no state changes".into(),
                expected_artifact: "asset inventory with source and scope status".into(),
                benefits: "cheap breadth; feeds every later technique".into(),
                limitations: "does not prove a vulnerability".into(),
                mappings: vec![
                    mapping("WSTG", "WSTG-INFO-01", wstg),
                    mapping("ASVS", "v5.0.0-1.1.2", asvs),
                ],
                requires_asset: false,
                requires_state_change: false,
            },
            Technique {
                id: "wstg-config".into(),
                version: Self::version_label().into(),
                family: "configuration".into(),
                phase: "vulnerability_analysis".into(),
                title: "Review deployment and configuration exposure".into(),
                tool_hint: "http_probe".into(),
                preconditions: vec!["reachable_asset".into()],
                safe_bounds: "read-only headers and error pages".into(),
                expected_artifact: "configuration observation with captured bytes".into(),
                benefits: "finds low-effort exposure".into(),
                limitations: "version banners may be misleading".into(),
                mappings: vec![mapping("WSTG", "WSTG-CONF-01", wstg)],
                requires_asset: true,
                requires_state_change: false,
            },
            Technique {
                id: "wstg-authz".into(),
                version: Self::version_label().into(),
                family: "authorization".into(),
                phase: "vulnerability_validation".into(),
                title: "Test authorization / IDOR with a negative control".into(),
                tool_hint: "http_request,http_diff".into(),
                preconditions: vec!["two_identities".into(), "object_reference".into()],
                safe_bounds: "read-only cross-owner requests".into(),
                expected_artifact: "differential pair with benign control and digests".into(),
                benefits: "strong deterministic oracle (differential)".into(),
                limitations: "needs a second identity; may be out of scope".into(),
                mappings: vec![
                    mapping("WSTG", "WSTG-ATHZ-04", wstg),
                    mapping("OWASP-API", "API1", api),
                    mapping("CWE", "CWE-639", "4.13"),
                ],
                requires_asset: true,
                requires_state_change: false,
            },
            Technique {
                id: "wstg-auth".into(),
                version: Self::version_label().into(),
                family: "authentication".into(),
                phase: "vulnerability_validation".into(),
                title: "Test authentication handling".into(),
                tool_hint: "http_probe,http_request".into(),
                preconditions: vec!["login_flow".into()],
                safe_bounds: "no credential stuffing without written authorization".into(),
                expected_artifact: "login-flow observation with response bytes".into(),
                benefits: "high-severity class".into(),
                limitations: "rate limits and lockouts can skew results".into(),
                mappings: vec![mapping("WSTG", "WSTG-ATHN-02", wstg)],
                requires_asset: true,
                requires_state_change: false,
            },
            Technique {
                id: "wstg-session".into(),
                version: Self::version_label().into(),
                family: "session".into(),
                phase: "vulnerability_validation".into(),
                title: "Test session management and CSRF defences".into(),
                tool_hint: "http_request".into(),
                preconditions: vec!["session_cookie".into()],
                safe_bounds: "read-only token inspection; no logout of other users".into(),
                expected_artifact: "cookie flags and rotation observations".into(),
                benefits: "covers state-invariants when paired controls exist".into(),
                limitations: "state_delta oracle is not yet implemented".into(),
                mappings: vec![mapping("WSTG", "WSTG-SESS-02", wstg)],
                requires_asset: true,
                requires_state_change: false,
            },
            Technique {
                id: "wstg-injection".into(),
                version: Self::version_label().into(),
                family: "injection".into(),
                phase: "vulnerability_validation".into(),
                title: "Test reflected input with tool-minted canary".into(),
                tool_hint: "http_request".into(),
                preconditions: vec!["input_parameter".into()],
                safe_bounds: "minimal non-destructive probes only".into(),
                expected_artifact: "canary reflection in stored 2xx response bytes".into(),
                benefits: "strong deterministic oracle (canary echo)".into(),
                limitations: "does not cover blind/stateful/timing classes".into(),
                mappings: vec![
                    mapping("WSTG", "WSTG-INPV-01", wstg),
                    mapping("OWASP", "A05", "2025"),
                ],
                requires_asset: true,
                requires_state_change: false,
            },
            Technique {
                id: "wstg-business".into(),
                version: Self::version_label().into(),
                family: "business_logic".into(),
                phase: "vulnerability_validation".into(),
                title: "Test business logic and state invariants".into(),
                tool_hint: "http_request,sequencer".into(),
                preconditions: vec!["state_changing_flow".into()],
                safe_bounds: "requires explicit ROE state-change authorization".into(),
                expected_artifact: "before/after state snapshots with named control".into(),
                benefits: "finds issues scanners miss".into(),
                limitations: "state_delta oracle currently returns open_proof_gap".into(),
                mappings: vec![mapping("WSTG", "WSTG-BUSL-01", wstg)],
                requires_asset: true,
                requires_state_change: true,
            },
            Technique {
                id: "wstg-api".into(),
                version: Self::version_label().into(),
                family: "api".into(),
                phase: "vulnerability_analysis".into(),
                title: "Test API schema exposure and object-level authorization".into(),
                tool_hint: "http_probe,http_diff".into(),
                preconditions: vec!["api_endpoint".into()],
                safe_bounds: "read-only schema and differential object access".into(),
                expected_artifact: "schema observation plus paired control".into(),
                benefits: "covers BOLA/BFLA and mass assignment".into(),
                limitations: "documentation may be incomplete".into(),
                mappings: vec![
                    mapping("WSTG", "WSTG-APIT-01", wstg),
                    mapping("OWASP-API", "API3", api),
                ],
                requires_asset: true,
                requires_state_change: false,
            },
            Technique {
                id: "wstg-client".into(),
                version: Self::version_label().into(),
                family: "client".into(),
                phase: "vulnerability_validation".into(),
                title: "Test client-side controls".into(),
                tool_hint: "http_request,http_diff".into(),
                preconditions: vec!["browser_or_script_surface".into()],
                safe_bounds: "no external navigation; lab only".into(),
                expected_artifact: "captured reflected/stored payload bytes".into(),
                benefits: "covers XSS and CORS misconfiguration".into(),
                limitations: "no browser engine in V1; adapters are external CLIs".into(),
                mappings: vec![mapping("WSTG", "WSTG-CLNT-01", wstg)],
                requires_asset: true,
                requires_state_change: false,
            },
        ];
        Self {
            version: Self::version_label().into(),
            techniques,
        }
    }

    pub fn version(&self) -> &str {
        &self.version
    }

    /// Full records for planner ranking. Prefer `search` when only a compact
    /// candidate list is needed (deferred loading).
    pub fn techniques_for_planner(&self) -> Vec<&Technique> {
        self.techniques.iter().collect()
    }

    pub fn len(&self) -> usize {
        self.techniques.len()
    }

    pub fn is_empty(&self) -> bool {
        self.techniques.is_empty()
    }

    /// Compact, result-capped lookup — the progressive-disclosure counterpart
    /// of `get`. A planner can scan candidates without loading full metadata.
    pub fn search(&self, query: &SearchQuery, max_results: usize) -> Vec<TechniqueView> {
        self.techniques
            .iter()
            .filter(|technique| {
                query
                    .family
                    .as_ref()
                    .map(|family| &technique.family == family)
                    .unwrap_or(true)
                    && query
                        .text
                        .as_ref()
                        .map(|text| {
                            technique
                                .title
                                .to_lowercase()
                                .contains(&text.to_lowercase())
                                || technique.id.contains(text.as_str())
                        })
                        .unwrap_or(true)
            })
            .take(max_results)
            .map(|technique| TechniqueView {
                id: technique.id.clone(),
                version: technique.version.clone(),
                title: technique.title.clone(),
                tool_hint: technique.tool_hint.clone(),
            })
            .collect()
    }

    pub fn get(&self, id: &str) -> Option<&Technique> {
        self.techniques.iter().find(|technique| technique.id == id)
    }

    /// Append a technique to an existing catalog. Extension catalogs (and
    /// tests) can derive from the shipped revision without editing this file.
    pub fn with_technique(mut self, technique: Technique) -> Self {
        self.techniques.push(technique);
        self
    }

    /// Fail-closed precondition gate. A technique is only applicable when
    /// *every* declared precondition id is recognised and satisfied by
    /// observable state or an explicit operator capability. Unknown ids are
    /// never assumed true (C18).
    pub fn preconditions_met(
        &self,
        technique: &Technique,
        state: &InvestigationState,
        allow_state_change: bool,
        scope_in: &[String],
    ) -> bool {
        technique
            .preconditions
            .iter()
            .all(|id| precondition_met(id, state, allow_state_change, scope_in))
    }

    /// Precondition gate. Techniques that cannot be safely executed in the
    /// current state are not offered to the planner at all.
    pub fn applicable(
        &self,
        technique: &Technique,
        state: &InvestigationState,
        allow_state_change: bool,
        scope_in: &[String],
    ) -> bool {
        if !self.preconditions_met(technique, state, allow_state_change, scope_in) {
            return false;
        }
        if technique.requires_state_change && !allow_state_change {
            return false;
        }
        if !technique.requires_asset {
            return true;
        }
        let target = state
            .tasks
            .iter()
            .filter_map(|task| task.get("target").and_then(serde_json::Value::as_str))
            .any(|target| !target.is_empty());
        target || !state.assets.is_empty() || !scope_in.is_empty()
    }
}

/// Rows that can carry observable precondition evidence. These are the same
/// durable tables the planner already projects; no new state surface is needed.
fn evidence_rows(state: &InvestigationState) -> impl Iterator<Item = &serde_json::Value> {
    state
        .assets
        .iter()
        .chain(state.tasks.iter())
        .chain(state.hypotheses.iter())
}

fn field<'a>(value: &'a serde_json::Value, names: &[&str]) -> Option<&'a str> {
    names
        .iter()
        .filter_map(|name| value.get(*name))
        .find_map(serde_json::Value::as_str)
}

fn has_surface(state: &InvestigationState, scope_in: &[String]) -> bool {
    !scope_in.is_empty()
        || state
            .assets
            .iter()
            .any(|asset| field(asset, &["value", "url", "id"]).is_some_and(|s| !s.is_empty()))
        || state
            .tasks
            .iter()
            .any(|task| field(task, &["target", "value"]).is_some_and(|s| !s.is_empty()))
}

fn has_marker(state: &InvestigationState, needles: &[&str]) -> bool {
    let mut haystacks: Vec<String> = evidence_rows(state)
        .map(|row| row.to_string().to_ascii_lowercase())
        .collect();
    haystacks.extend(
        state
            .open_questions
            .iter()
            .map(|question| question.to_ascii_lowercase()),
    );
    haystacks
        .iter()
        .any(|text| needles.iter().any(|needle| text.contains(needle)))
}

/// Distinct identity labels explicitly recorded in the durable state. A single
/// row mentioning "identity" is never enough: two different principals must be
/// observable before an IDOR-style technique becomes selectable.
fn identity_labels(state: &InvestigationState) -> Vec<String> {
    let mut labels: Vec<String> = Vec::new();
    for row in evidence_rows(state) {
        let text = row.to_string().to_ascii_lowercase();
        if !(text.contains("identity") || text.contains("principal")) {
            continue;
        }
        let label = field(row, &["identity", "principal", "value", "id", "name"])
            .unwrap_or_default()
            .to_string();
        if !label.is_empty() && !labels.iter().any(|seen| seen.eq_ignore_ascii_case(&label)) {
            labels.push(label);
        }
    }
    labels
}

/// Evaluate a single precondition id against the current state and operator
/// context. The list is exhaustive on purpose: an unrecognised id returns
/// `false`, so a typo or a future precondition cannot silently bypass the gate.
pub fn precondition_met(
    id: &str,
    state: &InvestigationState,
    allow_state_change: bool,
    scope_in: &[String],
) -> bool {
    match id.trim() {
        "in_scope_target" => !scope_in.is_empty() || has_surface(state, scope_in),
        "reachable_asset" => !state.assets.is_empty() || has_surface(state, scope_in),
        "input_parameter" => has_surface(state, scope_in),
        "two_identities" => identity_labels(state).len() >= 2,
        "object_reference" => has_marker(state, &["object", "idor", "resource"]),
        "login_flow" => has_marker(
            state,
            &["login", "signin", "sign-in", "authentication flow"],
        ),
        "session_cookie" => has_marker(state, &["cookie", "session", "csrf"]),
        "api_endpoint" => has_marker(state, &["api", "openapi", "swagger", "graphql"]),
        "browser_or_script_surface" => {
            has_marker(state, &["browser", "script", "javascript", "xss"])
        }
        // State-changing techniques are additionally gated by `requires_state_change`;
        // the precondition itself records that the operator/ROE authorised the flow.
        "state_changing_flow" => allow_state_change,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_is_versioned_and_mappings_are_pinned() {
        let catalog = Catalog::v1();
        assert_eq!(catalog.version(), Catalog::version_label());
        let technique = catalog.get("wstg-authz").expect("technique");
        assert!(technique.mappings.iter().all(|m| !m.version.is_empty()));
        assert!(technique.mappings.iter().any(|m| m.catalog == "OWASP-API"));
    }

    #[test]
    fn search_is_deferred_and_capped() {
        let catalog = Catalog::v1();
        let views = catalog.search(&SearchQuery::default(), 3);
        assert_eq!(views.len(), 3);
        assert!(views.iter().all(|view| view.version == catalog.version()));
        let full = catalog.get(&views[0].id).expect("full record");
        assert!(!full.safe_bounds.is_empty());
        assert!(!full.expected_artifact.is_empty());
    }

    #[test]
    fn precondition_gates_state_change_techniques() {
        let catalog = Catalog::v1();
        let technique = catalog.get("wstg-business").expect("technique");
        let state = InvestigationState::default();
        assert!(!catalog.applicable(technique, &state, false, &[]));
        assert!(
            !catalog.applicable(technique, &state, true, &[]),
            "no asset yet"
        );
        assert!(catalog.applicable(technique, &state, true, &["example.com".into()]));
    }

    #[test]
    fn wstg_authz_requires_two_identities_and_an_object_reference() {
        let catalog = Catalog::v1();
        let technique = catalog.get("wstg-authz").expect("technique");
        let mut state = InvestigationState::default();
        state.tasks.push(serde_json::json!({
            "playbook_id": "wstg-authz",
            "target": "example.test",
        }));
        let scope = vec!["example.test".to_string()];
        assert!(
            !catalog.applicable(technique, &state, true, &scope),
            "no identities must not authorise an IDOR-style technique"
        );

        state.assets.push(serde_json::json!({
            "kind": "identity", "value": "alice@example.test"
        }));
        assert!(
            !catalog.applicable(technique, &state, true, &scope),
            "one identity is not two"
        );
        state.assets.push(serde_json::json!({
            "kind": "identity", "value": "bob@example.test"
        }));
        assert!(
            !catalog.applicable(technique, &state, true, &scope),
            "an object reference is still required"
        );
        state.assets.push(serde_json::json!({
            "kind": "object", "value": "doc-42"
        }));
        assert!(catalog.applicable(technique, &state, true, &scope));
    }

    #[test]
    fn unknown_precondition_fails_closed() {
        let catalog = Catalog::v1();
        let mut technique = catalog.get("wstg-info").expect("technique").clone();
        technique.preconditions = vec!["not-a-real-precondition".into()];
        let state = InvestigationState::default();
        assert!(!catalog.preconditions_met(&technique, &state, true, &["example.test".into()]));
        assert!(!precondition_met(
            "not-a-real-precondition",
            &state,
            true,
            &["example.test".into()]
        ));
    }
}
