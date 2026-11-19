use minibug_engagement::{cvss_base, extract_profile_from_text, wstg_playbooks};

#[test]
fn heuristic_extracts_scope_from_local_html() {
    let html = r#"
        <html><body>
          <h1>Program: Acme Corp</h1>
          <p>In scope:</p>
          <ul><li>- *.acme.com</li><li>- 10.0.0.0/8</li></ul>
          <p>Out of scope:</p>
          <ul><li>- admin.acme.com</li></ul>
          <p>Report findings to security@acme.com. Do not submit automatically.</p>
        </body></html>
    "#;
    let profile = extract_profile_from_text(html, "https://acme.com/security");

    assert_eq!(profile.engagement, "Acme Corp");
    assert_eq!(profile.program_url, "https://acme.com/security");
    assert_eq!(profile.scope.in_scope, vec!["*.acme.com", "10.0.0.0/8"]);
    assert_eq!(profile.scope.out_of_scope, vec!["admin.acme.com"]);
    assert!(profile
        .rules
        .iter()
        .any(|rule| rule == "allow *.acme.com" || rule == "deny admin.acme.com"));
    assert!(profile
        .reporting_rules
        .iter()
        .any(|rule| rule.to_ascii_lowercase().contains("report")));
}

#[test]
fn heuristic_without_scope_stays_empty_for_fail_closed() {
    let profile = extract_profile_from_text(
        "This page only says Welcome. No scope information is published here.",
        "https://example.com",
    );
    assert!(profile.scope.in_scope.is_empty());
}

#[test]
fn cvss_matches_first_v31_reference_vectors() {
    assert!((cvss_base("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") - 9.8).abs() < 0.001);
    assert!((cvss_base("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N") - 7.5).abs() < 0.001);
    assert!((cvss_base("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N") - 1.8).abs() < 0.001);
    assert_eq!(cvss_base(""), 0.0);
    assert_eq!(cvss_base("CVSS:3.1/AV:N/AC:L"), 0.0);
}

#[test]
fn planner_has_supported_playbook_count() {
    let playbooks = wstg_playbooks();
    assert!((6..=9).contains(&playbooks.len()));
    let ids: Vec<&str> = playbooks.iter().map(|(id, _)| *id).collect();
    assert!(ids.contains(&"wstg-info"));
    assert!(ids.contains(&"wstg-injection"));
    assert!(ids.contains(&"wstg-api"));
}
