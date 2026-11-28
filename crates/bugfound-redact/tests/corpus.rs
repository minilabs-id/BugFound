//! Shared redaction corpus. Every consumer (tools, store, collaborator,
//! proxy) must produce the same results for this input, so the corpus lives
//! in the leaf crate and is reused through the `pub use` re-exports.

use bugfound_redact::{
    redact, redact_canary_text, redact_json, redact_secrets, redact_sensitive, redact_text,
    redacted_json, scrub_canaries, CANARY_PREFIX, REDACTED, REDACTED_CANARY,
};
use serde_json::json;

/// (input, secrets that must be absent from the redacted rendering)
const CORPUS: &[(&str, &[&str])] = &[
    (
        "Authorization: Bearer alpha and Bearer beta",
        &["alpha", "beta"],
    ),
    (
        "Authorization: Basic dXNlcjpwYXNzd29yZA==",
        &["dXNlcjpwYXNzd29yZA=="],
    ),
    ("x-api-key: sk-abcdefghijklmnop", &["sk-abcdefghijklmnop"]),
    ("token = ghp_abcdefghijklmnop", &["ghp_abcdefghijklmnop"]),
    ("secret: gho_abcdefgh", &["gho_abcdefgh"]),
    ("api_key=glpat-abcdef123", &["glpat-abcdef123"]),
    (
        "client_secret: AKIAABCDEFGHIJKLMNOP",
        &["AKIAABCDEFGHIJKLMNOP"],
    ),
    ("xoxb-token-abcdef", &["xoxb-token-abcdef"]),
    ("xoxp-abcdef", &["xoxp-abcdef"]),
    (
        "connection_string: postgres://user:pw@db.internal/prod",
        &["postgres://user:pw@db.internal/prod"],
    ),
    (
        "database_url=mysql://user:secret@host/db",
        &["mysql://user:secret@host/db"],
    ),
    ("dsn: postgres://u:p@h/db", &["postgres://u:p@h/db"]),
    ("private_key: PEMDATA123", &["PEMDATA123"]),
    ("credential=deadbeefcred", &["deadbeefcred"]),
    ("cookie: session=abc123; Path=/", &["abc123"]),
    ("set-cookie: session=xyz; Secure", &["xyz"]),
    ("password: \"hunter2\"", &["hunter2"]),
    ("api-key='xyz123'", &["xyz123"]),
    ("session=abc123", &["abc123"]),
    ("mail alice@example.com", &["alice@example.com"]),
    ("SSN 123-45-6789", &["123-45-6789"]),
    ("phone +1-555-123-4567", &["555-123-4567"]),
    ("card 4111111111111111", &["4111111111111111"]),
];

const NEGATIVE_CONTROLS: &[&str] = &[
    "2026-11-19 10:00",
    "1700000000000",
    "sha256 95793ae14070830fc9da3c937c27dc9a0123456789abcdef1",
    "eng-1",
    "port 8080 status 200 version 1.2.3",
    "Basic authentication is required",
    "plain text with no secrets",
];

#[test]
fn corpus_redacts_every_forbidden_secret() {
    for (input, forbidden) in CORPUS {
        let out = redact(input);
        for secret in *forbidden {
            assert!(!out.contains(secret), "leaked {secret:?} in {out:?}");
        }
        assert!(out.contains(REDACTED), "missing marker in {out:?}");
    }
}

#[test]
fn negative_controls_are_unchanged() {
    for input in NEGATIVE_CONTROLS {
        assert_eq!(redact(input), *input, "mutated negative control {input:?}");
    }
}

#[test]
fn cookie_attributes_survive_key_value_redaction() {
    let out = redact("cookie: session=abc123; Path=/; HttpOnly");
    assert!(!out.contains("abc123"));
    assert!(out.contains("Path=/"));
    assert!(out.contains("HttpOnly"));

    let out = redact("Set-Cookie: session=xyz; Domain=example.com; Secure");
    assert!(!out.contains("xyz"));
    assert!(out.contains("Domain=example.com"));
    assert!(out.contains("Secure"));
}

#[test]
fn aliases_match_the_canonical_redactor() {
    let input = "Bearer alpha token=beta secret=gamma";
    let expected = redact(input);
    assert_eq!(redact_sensitive(input), expected);
    assert_eq!(redact_secrets(input), expected);
    assert_eq!(redact_text(input), expected);
}

#[test]
fn json_pipeline_redacts_nested_fields_and_clears_all_secrets() {
    let input = r#"{"api_key":"plaintext","nested":{"token":"abc123","rows":[{"password":"p4ss"}]},"Authorization":"Bearer one","cookie":"session=s1","note":"Bearer two"}"#;
    let out = redact(input);
    for secret in ["plaintext", "abc123", "p4ss", "one", "two", "session=s1"] {
        assert!(!out.contains(secret), "leaked {secret:?} in {out:?}");
    }
    assert!(out.matches(REDACTED).count() >= 6);

    let value = json!({"outer": [{"dsn": "secret-dsn"}, {"ok": "plain"}]});
    let mut mutated = value.clone();
    redact_json(&mut mutated);
    assert_eq!(mutated, redacted_json(&value));
    assert_eq!(mutated["outer"][0]["dsn"], json!(REDACTED));
    assert_eq!(mutated["outer"][1]["ok"], json!("plain"));
}

#[test]
fn canary_corpus_is_scrubbed_recursively() {
    assert!(CANARY_PREFIX.starts_with("bugfound-canary"));
    let raw = "echo bugfound-canary-a1b2c3d4 and bugfound-canary-deadbeef";
    let out = redact_canary_text(raw);
    assert!(!out.contains("bugfound-canary-a1b2c3d4"));
    assert!(!out.contains("bugfound-canary-deadbeef"));
    assert_eq!(out.matches(REDACTED_CANARY).count(), 2);

    let value = json!({
        "canary": "bugfound-canary-abc",
        "nested": {"note": "see bugfound-canary-abc", "rows": ["bugfound-canary-abc"]}
    });
    let scrubbed = scrub_canaries(&value);
    assert_eq!(scrubbed["canary"], json!(REDACTED_CANARY));
    // Free-text fields keep their surrounding words; only the token is scrubbed.
    assert!(scrubbed["nested"]["note"]
        .as_str()
        .unwrap()
        .contains(REDACTED_CANARY));
    assert_eq!(scrubbed["nested"]["rows"][0], json!(REDACTED_CANARY));
    assert!(!serde_json::to_string(&scrubbed)
        .unwrap()
        .contains(CANARY_PREFIX));

    // Redaction and canary scrubbing are separate pipelines; both must run on
    // model-visible views while raw capture bytes stay authoritative.
    let both = redact_canary_text(&redact("Bearer s3cr3t bugfound-canary-abc"));
    assert!(!both.contains("s3cr3t"));
    assert!(!both.contains(CANARY_PREFIX));
    assert!(both.contains(REDACTED));
    assert!(both.contains(REDACTED_CANARY));
}
