//! V4 evidence-verifier authority (ADR-V3-005).
//!
//! Only this module can produce a `Proven` verdict. The planner, tools and any
//! model-authored text are advisory: their claims are recorded as `Observed`
//! and cannot change a finding's verification status.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Observed,
    Reproducible,
    Proven,
    Inconclusive,
    Rejected,
}

impl Verdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Observed => "observed",
            Self::Reproducible => "reproducible",
            Self::Proven => "proven",
            Self::Inconclusive => "inconclusive",
            Self::Rejected => "rejected",
        }
    }
}

/// Confidence follows CVSS v3.1 Report Confidence semantics; `Unknown` covers
/// intermittent or non-reproducible evidence and must never become a bare
/// numeric severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Confirmed,
    Reasonable,
    Unknown,
}

impl Confidence {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Confirmed => "confirmed",
            Self::Reasonable => "reasonable",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OracleOutcome {
    CanaryEcho,
    Differential,
    OobHit,
    StateDelta,
    Timing,
    BrowserDeferred,
    Unavailable,
}

impl OracleOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CanaryEcho => "canary_echo",
            Self::Differential => "differential",
            Self::OobHit => "oob_hit",
            Self::StateDelta => "state_delta",
            Self::Timing => "timing",
            Self::BrowserDeferred => "browser_deferred",
            Self::Unavailable => "unavailable",
        }
    }

    /// Oracles that can currently promote a candidate from tool-captured bytes.
    fn is_deterministic(self) -> bool {
        matches!(self, Self::CanaryEcho | Self::Differential | Self::OobHit)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlOutcome {
    Passed,
    RuledOut,
    Missing,
}

/// OOB interaction lookup. The live collaborator binary exposes an admin API;
/// the verifier consumes interactions through this trait so it stays testable
/// and does not make network calls from the decision path.
pub trait OobOracle {
    fn has_interaction(&self, key: &str) -> bool;
}

#[derive(Debug, Clone, Default)]
pub struct NoOob;

impl OobOracle for NoOob {
    fn has_interaction(&self, _key: &str) -> bool {
        false
    }
}

#[derive(Debug, Clone, Default)]
pub struct EvidenceOob {
    keys: std::collections::BTreeSet<String>,
}

impl EvidenceOob {
    pub fn from_keys(keys: impl IntoIterator<Item = String>) -> Self {
        Self {
            keys: keys.into_iter().collect(),
        }
    }
}

impl OobOracle for EvidenceOob {
    fn has_interaction(&self, key: &str) -> bool {
        self.keys.contains(key)
    }
}

/// Live OOB consumer for the self-hosted collaborator admin API.
/// The admin listener is loopback-only; plain HTTP is sufficient. Fail closed
/// (no interaction) on any parse/connection error.
pub struct HttpOobOracle {
    host: String,
    port: u16,
    token: String,
}

impl HttpOobOracle {
    pub fn new(endpoint: &str, token: &str) -> Option<Self> {
        // An unauthenticated admin read is never a valid promotion source.
        // Callers that have no token must configure `None` instead.
        if token.trim().is_empty() {
            return None;
        }
        let rest = endpoint.strip_prefix("http://")?;
        let (authority, _) = rest.split_once('/').unwrap_or((rest, ""));
        let (host, port) = match authority.rsplit_once(':') {
            Some((host, port)) => (host.to_string(), port.parse::<u16>().ok()?),
            None => (authority.to_string(), 80),
        };
        if !host.eq_ignore_ascii_case("127.0.0.1")
            && !host.eq_ignore_ascii_case("localhost")
            && !host.eq_ignore_ascii_case("::1")
        {
            return None; // loopback only
        }
        Some(Self {
            host,
            port,
            token: token.to_string(),
        })
    }
}

impl OobOracle for HttpOobOracle {
    fn has_interaction(&self, key: &str) -> bool {
        use std::io::{Read, Write};
        // An empty finding key is never evidence; do not even open a socket.
        if key.trim().is_empty() {
            return false;
        }
        let Ok(mut stream) = std::net::TcpStream::connect((self.host.as_str(), self.port)) else {
            return false;
        };
        let _ = stream.set_read_timeout(Some(std::time::Duration::from_millis(500)));
        // Filter by the per-finding OOB token bound at finding creation. The
        // collaborator admin API still requires the operator's shared secret
        // as a bearer credential; the query token is never an admin credential.
        let request = format!(
            "GET /interactions?token={} HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\nConnection: close\r\n\r\n",
            key, self.host, self.token
        );
        if stream.write_all(request.as_bytes()).is_err() {
            return false;
        }
        let mut response = String::new();
        if stream.read_to_string(&mut response).is_err() {
            return false;
        }
        let body = response
            .split_once("\r\n\r\n")
            .map(|(_, body)| body)
            .unwrap_or("");
        let Ok(rows) = serde_json::from_str::<serde_json::Value>(body) else {
            return false;
        };
        // Exact token equality only. Substring matching let an unrelated
        // interaction (or a token embedded in a payload) promote a finding.
        rows.as_array()
            .map(|rows| {
                rows.iter()
                    .any(|row| row.get("token").and_then(serde_json::Value::as_str) == Some(key))
            })
            .unwrap_or(false)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Verification {
    pub verdict: Verdict,
    pub confidence: Confidence,
    pub oracle: String,
    pub catalog_version: String,
    pub tlp_label: String,
    pub counterevidence: String,
    pub reason: String,
}

impl Verification {
    pub fn is_proven(&self) -> bool {
        self.verdict == Verdict::Proven
    }
}

#[derive(Debug, Clone, Default)]
pub struct Verifier;

impl Verifier {
    /// The only path to `Verdict::Proven`. Paired controls are mandatory: a
    /// negative control rules the candidate out before any oracle is trusted.
    #[allow(clippy::too_many_arguments)]
    pub fn decide(
        &self,
        oracle: OracleOutcome,
        control: ControlOutcome,
        catalog_version: &str,
        tlp_label: &str,
        counterevidence: &str,
        oob: &dyn OobOracle,
        interaction_key: &str,
        roe_ok: bool,
    ) -> Verification {
        let base = Verification {
            verdict: Verdict::Observed,
            confidence: Confidence::Unknown,
            oracle: oracle.as_str().into(),
            catalog_version: catalog_version.to_string(),
            tlp_label: tlp_label.to_string(),
            counterevidence: counterevidence.to_string(),
            reason: String::new(),
        };
        if control == ControlOutcome::RuledOut {
            return Verification {
                verdict: Verdict::Rejected,
                reason: "paired negative control ruled the candidate out".into(),
                ..base
            };
        }
        // ROE denial is authoritative for *every* oracle, including OobHit.
        if !roe_ok {
            return Verification {
                verdict: Verdict::Rejected,
                reason: "rules of engagement deny this finding".into(),
                ..base
            };
        }
        if oracle == OracleOutcome::OobHit
            && (interaction_key.trim().is_empty() || !oob.has_interaction(interaction_key))
        {
            return Verification {
                verdict: Verdict::Inconclusive,
                reason: "no stored OOB interaction matches the finding key".into(),
                ..base
            };
        }
        if !oracle.is_deterministic() {
            return Verification {
                verdict: Verdict::Inconclusive,
                confidence: Confidence::Unknown,
                reason: format!(
                    "oracle {} is not a deterministic promotion oracle in V3",
                    oracle.as_str()
                ),
                ..base
            };
        }
        if control == ControlOutcome::Missing {
            return Verification {
                verdict: Verdict::Inconclusive,
                reason: "paired control missing".into(),
                ..base
            };
        }
        Verification {
            verdict: Verdict::Proven,
            confidence: if counterevidence.trim().is_empty() {
                Confidence::Reasonable
            } else {
                Confidence::Confirmed
            },
            reason: "deterministic oracle with paired control".into(),
            ..base
        }
    }

    /// Model-authored claims are advisory input, never authority.
    pub fn from_model_claim(text: &str, catalog_version: &str, tlp_label: &str) -> Verification {
        Verification {
            verdict: Verdict::Observed,
            confidence: Confidence::Unknown,
            oracle: "model_claim".into(),
            catalog_version: catalog_version.to_string(),
            tlp_label: tlp_label.to_string(),
            counterevidence: String::new(),
            reason: format!(
                "advisory model text: {}",
                text.chars().take(120).collect::<String>()
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn model_claim_never_confirms() {
        let verification = Verifier::from_model_claim(
            "This finding is CONFIRMED with high confidence",
            "catalog-1",
            "TLP:AMBER",
        );
        assert_eq!(verification.verdict, Verdict::Observed);
        assert!(!verification.is_proven());
    }

    #[test]
    fn deterministic_oracle_with_control_promotes() {
        let verification = Verifier.decide(
            OracleOutcome::Differential,
            ControlOutcome::Passed,
            "catalog-1",
            "TLP:AMBER",
            "checked benign control",
            &NoOob,
            "unused",
            true,
        );
        assert!(verification.is_proven());
        assert_eq!(verification.confidence, Confidence::Confirmed);
    }

    #[test]
    fn negative_control_rules_out_before_oracle() {
        let verification = Verifier.decide(
            OracleOutcome::CanaryEcho,
            ControlOutcome::RuledOut,
            "catalog-1",
            "TLP:CLEAR",
            "",
            &NoOob,
            "unused",
            true,
        );
        assert_eq!(verification.verdict, Verdict::Rejected);
    }

    #[test]
    fn oob_oracle_consumes_only_stored_interactions() {
        let oob = EvidenceOob::from_keys(["finding-1".to_string()]);
        let missing = Verifier.decide(
            OracleOutcome::OobHit,
            ControlOutcome::Passed,
            "catalog-1",
            "TLP:AMBER",
            "",
            &oob,
            "finding-2",
            true,
        );
        assert_eq!(missing.verdict, Verdict::Inconclusive);

        let present = Verifier.decide(
            OracleOutcome::OobHit,
            ControlOutcome::Passed,
            "catalog-1",
            "TLP:AMBER",
            "",
            &oob,
            "finding-1",
            true,
        );
        assert!(present.is_proven());
        assert_eq!(present.oracle, "oob_hit");

        // ROE denial outranks a stored OOB interaction.
        let denied = Verifier.decide(
            OracleOutcome::OobHit,
            ControlOutcome::Passed,
            "catalog-1",
            "TLP:AMBER",
            "",
            &oob,
            "finding-1",
            false,
        );
        assert_eq!(denied.verdict, Verdict::Rejected);
        assert!(!denied.is_proven());
    }

    #[test]
    fn http_oob_oracle_reads_loopback_admin_api() {
        use std::io::{Read, Write};
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        listener
            .set_nonblocking(true)
            .expect("nonblocking listener");
        let port = listener.local_addr().expect("addr").port();
        let connections = Arc::new(AtomicUsize::new(0));
        let server_connections = Arc::clone(&connections);
        let server = std::thread::spawn(move || {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
            while server_connections.load(Ordering::SeqCst) < 2
                && std::time::Instant::now() < deadline
            {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        server_connections.fetch_add(1, Ordering::SeqCst);
                        stream
                            .set_nonblocking(false)
                            .expect("blocking client stream");
                        let mut buffer = [0u8; 2048];
                        let n = stream.read(&mut buffer).unwrap_or(0);
                        let request = String::from_utf8_lossy(&buffer[..n]).to_string();
                        assert!(
                            request
                                .to_ascii_lowercase()
                                .contains("authorization: bearer admin-secret"),
                            "admin request must carry the bearer credential: {request}"
                        );
                        let key = if request.contains("GET /interactions?token=finding-7 HTTP/1.1")
                        {
                            "finding-7"
                        } else {
                            assert!(
                                request.contains("GET /interactions?token=finding-8 HTTP/1.1"),
                                "the query token must be the bound finding token: {request}"
                            );
                            "finding-8"
                        };
                        // Exact token field, plus a payload that merely contains
                        // another token: substring matching must not promote.
                        let body = format!(
                            r#"[{{"token":"{key}","detail":"callback mentioning other-token"}}]"#
                        );
                        let response = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        );
                        let _ = stream.write_all(response.as_bytes());
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(std::time::Duration::from_millis(2));
                    }
                    Err(_) => break,
                }
            }
        });
        let oracle = HttpOobOracle::new(&format!("http://127.0.0.1:{port}"), "admin-secret")
            .expect("parse endpoint");
        assert!(oracle.has_interaction("finding-7"));
        assert!(oracle.has_interaction("finding-8"));
        assert!(!oracle.has_interaction(""), "empty key must fail closed");
        assert!(
            !oracle.has_interaction("other-token"),
            "substrings must not match"
        );
        assert!(HttpOobOracle::new("http://example.com:8080", "admin-secret").is_none());
        assert!(
            HttpOobOracle::new(&format!("http://127.0.0.1:{port}"), "").is_none(),
            "empty admin token must be rejected"
        );
        server.join().expect("server thread");
        assert_eq!(
            connections.load(Ordering::SeqCst),
            2,
            "empty-key checks must not perform network I/O"
        );
    }

    #[test]
    fn unavailable_oracles_stay_inconclusive() {
        for oracle in [
            OracleOutcome::StateDelta,
            OracleOutcome::Timing,
            OracleOutcome::BrowserDeferred,
            OracleOutcome::Unavailable,
        ] {
            let verification = Verifier.decide(
                oracle,
                ControlOutcome::Passed,
                "catalog-1",
                "TLP:AMBER",
                "",
                &NoOob,
                "unused",
                true,
            );
            assert_eq!(verification.verdict, Verdict::Inconclusive);
        }
    }
}
