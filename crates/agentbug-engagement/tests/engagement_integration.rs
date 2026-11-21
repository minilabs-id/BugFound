use agentbug_engagement::{
    cvss_base, engage_with_local_brief_tx_and_roe, engage_with_local_brief_tx_and_roe_and_loop,
    extract_profile_from_text, normalize_scope_pattern, parse_roe, roe_classify, roe_overrides,
    roe_unparsed_constraints, search_round_tasks, wstg_playbooks, EngagementEvent,
    EngagementLoopOptions, EngagementOptions, EngagementRoeOptions, RoePolicyMode,
};
use agentbug_policy::Mode;
use agentbug_store::Store;
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

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
fn llm_scope_annotations_are_stripped() {
    let raw = "https://play.google.com/store/apps/details?id=com.boursorama.android.clients (Mobile application Android, asset value: High)";
    assert_eq!(
        normalize_scope_pattern(raw),
        "https://play.google.com/store/apps/details?id=com.boursorama.android.clients"
    );
}

#[test]
fn report_eligibility_lines_are_not_unparsed_constraints() {
    let text = r#"
- Lack or bypass of rate-limiting, brute force or captcha without compromise or large-scale abuse
- Exploits that are only possible on Android versions that are not currently supported
- Exploits that are only possible on iOS versions that are not currently supported
- Exploits that are only possible on a jailbroken/rooted device
"#;
    assert!(roe_unparsed_constraints(text).is_empty());
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

#[test]
fn cake_brief_lines_classify_without_abort() {
    use agentbug_engagement::roe_classifier::{classify_line, BriefLineClass};
    let csrf = "CSRF-able actions that do not require authentication (or a session) to exploit";
    let reward = "We determine bounty amounts based on a variety of factors, including (but not limited to) Impact, classification and sensitivity of the data, ease of exploitation and overall risk to our applications.";
    let csrf_class = classify_line(csrf);
    assert_eq!(csrf_class.class, BriefLineClass::ProhibitedVulnClass);
    assert_eq!(csrf_class.rule_id, "csrf_without_auth");
    let reward_class = classify_line(reward);
    assert_eq!(reward_class.class, BriefLineClass::ReportOrRewardPolicy);

    let (policy, unparsed) = agentbug_engagement::roe_classify(&format!("{csrf}\n{reward}"));
    assert!(unparsed.is_empty(), "unexpected: {unparsed:?}");
    assert!(policy.denied_finding_classes.iter().any(|c| c == "CWE-352"));
}

#[test]
fn unknown_technical_prohibition_still_aborts() {
    let line = "Do not scan the staging API with automated tools between 2am and 4am.";
    let (_policy, unparsed) = agentbug_engagement::roe_classify(line);
    assert_eq!(unparsed, vec![line.to_string()]);
}

// ---------------------------------------------------------------------------
// Config-only ROE policy mode (strict by default, permissive audited opt-in)
// ---------------------------------------------------------------------------

const UNPARSED_LINE: &str = "Do not scan the staging API with automated tools between 2am and 4am.";

static TEMP_SEQ: AtomicU64 = AtomicU64::new(0);

struct TestPaths {
    db: PathBuf,
    workspace: PathBuf,
}

fn temp_paths(name: &str) -> TestPaths {
    let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let stem = format!(
        "agentbug-roe-{}-{}-{}-{}",
        name,
        std::process::id(),
        nonce,
        seq
    );
    TestPaths {
        db: std::env::temp_dir().join(format!("{stem}.db")),
        workspace: std::env::temp_dir().join(format!("{stem}-ws")),
    }
}

impl Drop for TestPaths {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.db);
        let db = self.db.to_string_lossy();
        let _ = std::fs::remove_file(format!("{db}-wal"));
        let _ = std::fs::remove_file(format!("{db}-shm"));
        let _ = std::fs::remove_dir_all(&self.workspace);
    }
}

fn brief_with_unparsed() -> String {
    format!(
        "Program: Acme Corp\nIn scope:\n- *.acme.test\nOut of scope:\n- admin.acme.test\nRules of engagement:\n{UNPARSED_LINE}\n"
    )
}

fn run_local_brief(
    paths: &TestPaths,
    brief: &str,
    options: EngagementOptions,
    roe_options: EngagementRoeOptions,
) -> (anyhow::Result<String>, Vec<EngagementEvent>) {
    let (tx, rx) = std::sync::mpsc::channel::<EngagementEvent>();
    let result = engage_with_local_brief_tx_and_roe(
        &paths.db,
        &paths.workspace,
        brief,
        options,
        roe_options,
        tx,
    );
    let events: Vec<EngagementEvent> = rx.try_iter().collect();
    (result, events)
}

fn started_id(events: &[EngagementEvent]) -> &str {
    events
        .iter()
        .find_map(|event| match event {
            EngagementEvent::Started { engagement_id } => Some(engagement_id.as_str()),
            _ => None,
        })
        .expect("Started event must be emitted")
}

fn trace_payloads(db: &Path, engagement_id: &str, kind: &str) -> Vec<Value> {
    let conn = rusqlite::Connection::open(db).expect("open trace db");
    let mut stmt = conn
        .prepare("SELECT payload_json FROM trace_events WHERE engagement_id=?1 AND kind=?2 ORDER BY rowid")
        .expect("prepare trace query");
    stmt.query_map(rusqlite::params![engagement_id, kind], |row| {
        row.get::<_, String>(0)
    })
    .expect("query trace events")
    .map_while(Result::ok)
    .map(|payload| serde_json::from_str(&payload).expect("trace payload is JSON"))
    .collect()
}

fn permissive_options() -> EngagementRoeOptions {
    EngagementRoeOptions {
        mode: RoePolicyMode::PermissiveAudited,
    }
}

#[test]
fn strict_mode_aborts_unparsed_line_and_records_pending_open_rule() {
    let paths = temp_paths("strict");
    let brief = brief_with_unparsed();
    let (result, events) = run_local_brief(
        &paths,
        &brief,
        EngagementOptions::default(),
        EngagementRoeOptions::default(),
    );
    let error = result.expect_err("strict mode must abort on an unmappable brief line");
    assert!(
        error.to_string().contains("unparsed ROE constraints"),
        "{error:#}"
    );

    let id = started_id(&events);
    let open_traces = trace_payloads(&paths.db, id, "authorization.open_rule");
    assert_eq!(open_traces.len(), 1, "{open_traces:?}");
    assert_eq!(open_traces[0]["acknowledged"], false);
    assert!(open_traces[0]["rule"]
        .as_str()
        .unwrap()
        .contains(UNPARSED_LINE));

    let store = Store::open(&paths.db).unwrap();
    let rules = store.list_open_authorization_rules(id).unwrap();
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].state, "pending");

    assert!(trace_payloads(&paths.db, id, "authorization.permissive_mode_applied").is_empty());
    assert!(trace_payloads(&paths.db, id, "authorization.ack_applied").is_empty());
    assert!(events.iter().any(|event| matches!(
        event,
        EngagementEvent::Error { message } if message.contains("unparsed ROE constraints")
    )));
}

#[test]
fn permissive_audited_mode_auto_acks_and_forces_incomplete() {
    let paths = temp_paths("permissive");
    let brief = brief_with_unparsed();
    let (result, events) = run_local_brief(
        &paths,
        &brief,
        EngagementOptions::default(),
        permissive_options(),
    );
    let id = result.expect("permissive audited mode must let the engagement continue");

    let open_traces = trace_payloads(&paths.db, &id, "authorization.open_rule");
    assert_eq!(open_traces.len(), 1, "{open_traces:?}");
    let permissive_traces = trace_payloads(&paths.db, &id, "authorization.permissive_mode_applied");
    assert_eq!(permissive_traces.len(), 1, "{permissive_traces:?}");
    let ack_traces = trace_payloads(&paths.db, &id, "authorization.ack_applied");
    assert_eq!(ack_traces.len(), 1, "{ack_traces:?}");

    let content_hash = ack_traces[0]["content_hash"].as_str().unwrap();
    let applied = &permissive_traces[0];
    assert_eq!(applied["content_hash"].as_str(), Some(content_hash));
    assert_eq!(applied["count"], 1);
    assert_eq!(applied["mode"], "permissive_audited");
    assert_eq!(
        applied["operator"],
        "config:roe_policy_mode=permissive_audited"
    );
    assert_eq!(applied["inserted"][0], true);
    assert_eq!(applied["inserted_count"], 1);

    let program_url = events
        .iter()
        .find_map(|event| match event {
            EngagementEvent::BriefIngested { profile } => Some(profile.program_url.clone()),
            _ => None,
        })
        .expect("BriefIngested event must be emitted");
    let rule_hash = open_traces[0]["rule_hash"].as_str().unwrap();
    let store = Store::open(&paths.db).unwrap();
    assert!(store
        .has_authorization_ack(&program_url, content_hash, "unparsed_roe", rule_hash)
        .unwrap());

    let outcomes = trace_payloads(&paths.db, &id, "engagement.outcome");
    assert_eq!(outcomes.len(), 1, "{outcomes:?}");
    assert_eq!(outcomes[0]["outcome"], "incomplete");
    assert_eq!(
        outcomes[0]["reason"],
        "operator acknowledgement applied to unparsed ROE constraint(s)"
    );
    assert!(events.iter().any(|event| matches!(
        event,
        EngagementEvent::Finished { summary } if summary.contains(" incomplete with ")
    )));
}

#[test]
fn permissive_audited_mode_preserves_denied_finding_classes_and_tool_gates() {
    let paths = temp_paths("gates");
    let brief = format!(
        "Program: Acme Corp\nIn scope:\n- *.acme.test\nRules of engagement:\nCSRF-able actions that do not require authentication (or a session) to exploit\n{UNPARSED_LINE}\n"
    );
    let options = EngagementOptions {
        auto_approve_all: true,
        allow_intrusive: true,
        allow_network_write: true,
        ..Default::default()
    };
    let (result, events) = run_local_brief(&paths, &brief, options, permissive_options());
    let _id = result.expect("permissive audited mode must let the engagement continue");

    let gate_details: Vec<&str> = events
        .iter()
        .filter_map(|event| match event {
            EngagementEvent::Action { tool, detail, .. } if tool == "tool_registry" => {
                Some(detail.as_str())
            }
            _ => None,
        })
        .collect();
    assert!(
        gate_details.iter().any(|detail| detail
            .contains("ROE forbids state changes: http_request and validate_poc withheld")),
        "{gate_details:?}"
    );
    assert!(
        gate_details
            .iter()
            .any(|detail| detail.contains("active_scan withheld")),
        "{gate_details:?}"
    );

    let report_path = events
        .iter()
        .find_map(|event| match event {
            EngagementEvent::ReportReady { path } => Some(path.clone()),
            _ => None,
        })
        .expect("ReportReady event must be emitted");
    let report = std::fs::read_to_string(&report_path).expect("read canonical report");
    assert!(
        report.contains("Excluded finding class: CWE-352"),
        "{report}"
    );
    assert!(
        report.contains("Automated fuzzing not authorised"),
        "{report}"
    );
    assert!(
        report.contains("State-changing requests not authorised"),
        "{report}"
    );
    assert!(report.contains("No external disclosure"), "{report}");
    assert!(
        !report.contains("### F-001: CSRF"),
        "a denied finding class must never be promoted"
    );
}

#[test]
fn changed_brief_hash_requires_new_acks() {
    let paths = temp_paths("hash");
    let brief_a = brief_with_unparsed();
    let (first, _) = run_local_brief(
        &paths,
        &brief_a,
        EngagementOptions::default(),
        permissive_options(),
    );
    first.expect("first permissive run must succeed");

    let brief_b = brief_a.replace("Program: Acme Corp", "Program: Acme Corp Security");
    assert_ne!(brief_a, brief_b);
    assert_eq!(roe_classify(&brief_b).1, vec![UNPARSED_LINE.to_string()]);

    // Same unmapped line, different brief hash: the ack from the first run must
    // not authorize this version in strict mode.
    let (second, events) = run_local_brief(
        &paths,
        &brief_b,
        EngagementOptions::default(),
        EngagementRoeOptions::default(),
    );
    let error = second.expect_err("ack is scoped to one exact brief hash");
    assert!(
        error.to_string().contains("unparsed ROE constraints"),
        "{error:#}"
    );
    let id = started_id(&events);
    let open_traces = trace_payloads(&paths.db, id, "authorization.open_rule");
    assert_eq!(open_traces.len(), 1);
    assert_eq!(open_traces[0]["acknowledged"], false);
    assert!(trace_payloads(&paths.db, id, "authorization.permissive_mode_applied").is_empty());
}

#[test]
fn permissive_mode_is_config_only_not_auto_approve() {
    let paths = temp_paths("autoapprove");
    let brief = brief_with_unparsed();
    let options = EngagementOptions {
        auto_approve_all: true,
        ..Default::default()
    };
    let (result, events) =
        run_local_brief(&paths, &brief, options, EngagementRoeOptions::default());
    let error = result.expect_err("auto_approve_all must never authorize unmapped ROE lines");
    assert!(
        error.to_string().contains("unparsed ROE constraints"),
        "{error:#}"
    );
    let id = started_id(&events);
    assert!(trace_payloads(&paths.db, id, "authorization.permissive_mode_applied").is_empty());
    assert!(trace_payloads(&paths.db, id, "authorization.ack_applied").is_empty());
}

#[test]
fn permissive_mode_is_idempotent_across_runs() {
    let paths = temp_paths("idempotent");
    let brief = brief_with_unparsed();
    let roe_options = permissive_options();

    let (first, _) = run_local_brief(&paths, &brief, EngagementOptions::default(), roe_options);
    let first_id = first.expect("first permissive run must succeed");
    let (second, _) = run_local_brief(&paths, &brief, EngagementOptions::default(), roe_options);
    let second_id = second.expect("second permissive run must succeed");
    assert_ne!(first_id, second_id);

    let first_trace = trace_payloads(
        &paths.db,
        &first_id,
        "authorization.permissive_mode_applied",
    );
    let second_trace = trace_payloads(
        &paths.db,
        &second_id,
        "authorization.permissive_mode_applied",
    );
    assert_eq!(first_trace.len(), 1, "{first_trace:?}");
    assert_eq!(second_trace.len(), 1, "{second_trace:?}");
    assert_eq!(first_trace[0]["inserted"][0], true);
    assert_eq!(second_trace[0]["inserted"][0], false);
    assert_eq!(second_trace[0]["inserted_count"], 0);
    assert_eq!(
        first_trace[0]["content_hash"],
        second_trace[0]["content_hash"]
    );

    let conn = rusqlite::Connection::open(&paths.db).unwrap();
    let ack_rows: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM authorization_acks WHERE subject_kind='unparsed_roe' AND decision='acknowledged'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(ack_rows, 1, "a hash-scoped ack must be inserted only once");

    for id in [&first_id, &second_id] {
        let outcomes = trace_payloads(&paths.db, id, "engagement.outcome");
        assert_eq!(outcomes.len(), 1);
        assert_eq!(outcomes[0]["outcome"], "incomplete");
    }
}

// ---------------------------------------------------------------------------
// Bounded search rounds (offline, no submission, gates unchanged)
// ---------------------------------------------------------------------------

fn search_brief() -> String {
    "Program: Acme Corp\nIn scope:\n- *.acme.test\nOut of scope:\n- admin.acme.test\nRules of engagement:\n"
        .to_string()
}

fn run_local_brief_loop(
    paths: &TestPaths,
    brief: &str,
    max_rounds: usize,
) -> (anyhow::Result<String>, Vec<EngagementEvent>) {
    let (tx, rx) = std::sync::mpsc::channel::<EngagementEvent>();
    let result = engage_with_local_brief_tx_and_roe_and_loop(
        &paths.db,
        &paths.workspace,
        brief,
        EngagementOptions::default(),
        EngagementRoeOptions::default(),
        EngagementLoopOptions { max_rounds },
        tx,
    );
    (result, rx.try_iter().collect())
}

fn engagement_sessions(db: &Path, engagement_id: &str) -> Vec<agentbug_store::Session> {
    let marker = format!("engagement_id={engagement_id}");
    Store::open(db)
        .unwrap()
        .list_sessions(500)
        .unwrap()
        .into_iter()
        .filter(|session| session.goal.contains(&marker))
        .collect()
}

fn report_from(events: &[EngagementEvent]) -> String {
    let path = events
        .iter()
        .find_map(|event| match event {
            EngagementEvent::ReportReady { path } => Some(path.clone()),
            _ => None,
        })
        .expect("ReportReady event must be emitted");
    std::fs::read_to_string(path).expect("read canonical report")
}

#[test]
fn search_rounds_retry_needs_review_playbook_with_different_angle() {
    let paths = temp_paths("search-retry");
    let (result, events) = run_local_brief_loop(&paths, &search_brief(), 2);
    let id = result.expect("bounded search engagement must complete");

    // The offline runner issues no probes, so every playbook is needs-review in
    // round 1 and is therefore retried once in round 2.
    let rounds = trace_payloads(&paths.db, &id, "search.round");
    assert_eq!(rounds.len(), 2, "{rounds:?}");
    assert_eq!(rounds[0]["round"], 1);
    assert_eq!(rounds[0]["max_rounds"], 2);
    assert_eq!(rounds[0]["retried_tasks"].as_array().unwrap().len(), 0);
    assert_eq!(rounds[1]["round"], 2);
    assert_eq!(rounds[1]["max_rounds"], 2);
    assert!(!rounds[1]["retried_tasks"].as_array().unwrap().is_empty());

    let round_actions: Vec<&EngagementEvent> = events
        .iter()
        .filter(
            |event| matches!(event, EngagementEvent::Action { tool, .. } if tool == "search_round"),
        )
        .collect();
    assert_eq!(round_actions.len(), 2);

    let sessions = engagement_sessions(&paths.db, &id);
    let second_angle: Vec<&agentbug_store::Session> = sessions
        .iter()
        .filter(|session| session.goal.contains("Round 2/2"))
        .collect();
    assert!(!second_angle.is_empty(), "{:?}", sessions.len());
    assert!(
        second_angle
            .iter()
            .all(|session| session.goal.contains("DIFFERENT angle")
                && session.goal.contains("Do not repeat identical probes")
                && session
                    .goal
                    .contains("Do not submit anything to any external system")),
        "second-round goals must carry the bounded different-angle instruction and no-submit line"
    );
    assert!(
        sessions
            .iter()
            .any(|session| !session.goal.contains("Round 2/2")),
        "round 1 goals must remain unchanged"
    );

    // After the last round a still-empty playbook remains needs-review and the
    // report records the bounded retry (never a submission).
    let tasks = Store::open(&paths.db).unwrap().list_tasks(&id).unwrap();
    assert!(tasks.iter().all(|task| task.status == "needs-review"));
    assert!(report_from(&events).contains("Search rounds: 2 of 2"));
}

#[test]
fn max_rounds_one_preserves_existing_behavior() {
    let paths = temp_paths("search-single");
    let (result, events) = run_local_brief_loop(&paths, &search_brief(), 1);
    let id = result.expect("single-round engagement must complete");

    let rounds = trace_payloads(&paths.db, &id, "search.round");
    assert_eq!(rounds.len(), 1, "{rounds:?}");
    assert_eq!(rounds[0]["round"], 1);
    assert_eq!(rounds[0]["max_rounds"], 1);
    assert!(engagement_sessions(&paths.db, &id)
        .iter()
        .all(|session| !session.goal.contains("Round 2")));
    assert!(report_from(&events).contains("Search rounds: 1 of 1"));
}

#[test]
fn completed_playbooks_are_revisited_in_later_rounds() {
    // A completed playbook from round 1 must be retried in round 2 with a
    // different angle when the operator configured more than one round.
    let store = Store::open(":memory:").unwrap();
    let id = store
        .create_engagement("https://example.com/program")
        .unwrap()
        .id;
    store
        .create_task(&id, "task", "WSTG-INFO", None, 0)
        .unwrap();
    store
        .update_task_status(&store.list_tasks(&id).unwrap()[0].id, "done")
        .unwrap();
    let tasks = agentbug_engagement::search_round_tasks(&store, &id, 2).unwrap();
    assert_eq!(tasks.len(), 1);
}

#[test]
fn final_report_is_written_after_last_round() {
    let paths = temp_paths("search-report");
    let (result, events) = run_local_brief_loop(&paths, &search_brief(), 3);
    let id = result.expect("bounded search engagement must complete");

    let rounds = trace_payloads(&paths.db, &id, "search.round");
    assert_eq!(rounds.len(), 3, "{rounds:?}");
    assert_eq!(rounds[2]["round"], 3);
    assert_eq!(rounds[2]["max_rounds"], 3);

    let conn = rusqlite::Connection::open(&paths.db).unwrap();
    let last_round_row: i64 = conn
        .query_row(
            "SELECT MAX(rowid) FROM trace_events WHERE engagement_id=?1 AND kind='search.round'",
            rusqlite::params![id],
            |row| row.get(0),
        )
        .unwrap();
    let report_row: i64 = conn
        .query_row(
            "SELECT MAX(rowid) FROM trace_events WHERE engagement_id=?1 AND kind='report.ready'",
            rusqlite::params![id],
            |row| row.get(0),
        )
        .unwrap();
    assert!(
        report_row > last_round_row,
        "the report must be written after the final search round"
    );

    let report = report_from(&events);
    assert!(report.contains("## Methodology"), "{report}");
    assert!(report.contains("Search rounds: 3 of 3"), "{report}");
}
