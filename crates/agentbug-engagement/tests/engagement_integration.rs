use agentbug_engagement::{
    cvss_base, extract_profile_from_text, parse_roe, roe_overrides, wstg_playbooks,
    EngagementOptions,
};
use agentbug_policy::Mode;

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
fn roe_rules_are_translated_into_tool_enforcement() {
    let rules = vec![
        "Do not use automated scanners or tools that generate large amounts of network traffic. Use automated tools gently, with a maximum of 10 requests per second.".to_string(),
        "Add the string ' -BugBounty-boursobank-31337 ' to the User-Agent header in your requests.".to_string(),
    ];
    let (ua, rps) = roe_overrides(&rules);
    assert_eq!(rps, Some(10));
    assert!(ua.unwrap().contains("-BugBounty-boursobank-31337"));
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
fn full_brief_text_parses_into_fail_closed_roe() {
    let brief = r#"
Program: BoursoBank
In scope:
- *.boursobank.com
Rules of engagement:
Do not use automated scanners or tools that generate large amounts of network traffic.
Use automated tools gently, with a maximum of 10 requests per second.
Add the string ' -BugBounty-boursobank-31337 ' to the User-Agent header in your requests.
No DoS testing. Do not modify data. No disclosure.
"#;
    let roe = parse_roe(brief);
    assert!(roe
        .ua_marker
        .unwrap()
        .contains("-BugBounty-boursobank-31337"));
    assert_eq!(roe.max_rps, Some(10));
    // Fuzzing and state-changing actions stay denied by default even when the
    // brief mentions automated tools only to constrain them.
    assert!(!roe.allow_fuzzing);
    assert!(!roe.allow_state_change);
    assert!(!roe.allow_disclosure);
}

#[test]
fn engagement_options_default_denies_risk_and_has_no_auto_approval() {
    let options = EngagementOptions::default();
    assert_eq!(options.mode, Mode::FullAuto);
    assert_eq!(options.max_steps, 60);
    assert!(!options.allow_network_write);
    assert!(!options.allow_intrusive);
    assert!(!options.auto_approve_all);
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
