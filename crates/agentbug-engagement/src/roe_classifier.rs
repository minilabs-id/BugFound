//! Deterministic brief-line classification for Rules of Engagement text.
//!
//! No LLM, no I/O, no environment. The classifier replaces ad-hoc
//! negative+security substring triples with an ordered, precedence-based
//! table. Reward/report policy lines never abort; genuine technical
//! prohibitions that cannot be mapped still fail closed.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BriefLineClass {
    ActionableTechnical,
    ProhibitedVulnClass,
    ReportOrRewardPolicy,
    ScopeOrAsset,
    Noise,
    Unknown,
}

impl BriefLineClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ActionableTechnical => "actionable_technical",
            Self::ProhibitedVulnClass => "prohibited_vuln_class",
            Self::ReportOrRewardPolicy => "report_or_reward_policy",
            Self::ScopeOrAsset => "scope_or_asset",
            Self::Noise => "noise",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ClassifiedLine<'a> {
    pub line: &'a str,
    pub class: BriefLineClass,
    pub rule_id: &'static str,
}

fn tokenize(text: &str) -> Vec<String> {
    text.to_ascii_lowercase()
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|part| !part.is_empty())
        .map(str::to_string)
        .collect()
}

fn has_phrase(tokens: &[String], phrase: &str) -> bool {
    let needle = tokenize(phrase);
    if needle.is_empty() || needle.len() > tokens.len() {
        return false;
    }
    tokens
        .windows(needle.len())
        .any(|window| window == needle.as_slice())
}

/// Explicit reward/report policy signals. These are checked before any
/// generic prohibition logic: a bounty-amount sentence is not a tool rule.
const REWARD_SIGNALS: &[&str] = &[
    "bounty",
    "reward",
    "rewards",
    "rewarded",
    "payout",
    "amount",
    "response time",
    "duplicate",
    "already reported",
    "known issue",
    "safe harbor",
    "safe harbour",
    "not limited to",
    "including but not limited",
    "not currently supported",
    "jailbroken",
    "rooted device",
    "lack or bypass of rate limiting",
    "lack or bypass of rate-limiting",
    "brute force or captcha",
    "without compromise",
    "large-scale abuse",
    "large scale abuse",
    "informational",
    "best practice",
    "theoretical",
    "not applicable",
    "third-party",
    "third party",
    "impact, classification and sensitivity",
    "ease of exploitation",
    "overall risk to our applications",
];

/// Vulnerability-class vocabulary from the deterministic CWE rule table.
const VULN_CLASSES: &[(&str, &str)] = &[
    ("csrf", "csrf_without_auth"),
    ("cross-site request forgery", "csrf_without_auth"),
    ("user enumeration", "user_enumeration"),
    ("full path disclosure", "full_path_disclosure"),
    ("full-path disclosure", "full_path_disclosure"),
    ("open redirect", "open_redirect"),
    ("sql injection", "sqli"),
    ("cross-site scripting", "xss"),
    ("information disclosure", "information_disclosure"),
    ("insecure direct object reference", "idor"),
];

/// Operational markers that make an unmapped line abortable.
const OPERATIONAL: &[&str] = &[
    "do not scan",
    "do not test",
    "do not send",
    "do not use",
    "must not",
    "never",
    "prohibited",
    "forbidden",
    "avoid",
    "refrain",
    "maximum",
    "requests per second",
    "rate limit",
    "state change",
    "modify data",
];

/// Classify one brief line. First positive match in precedence order wins.
pub fn classify_line(line: &str) -> ClassifiedLine<'_> {
    let trimmed = line.trim();
    let tokens = tokenize(trimmed);
    if trimmed.is_empty() || tokens.len() < 3 {
        return ClassifiedLine {
            line,
            class: BriefLineClass::Noise,
            rule_id: "empty_or_short",
        };
    }
    // Reward/report policy wins over generic negative+security heuristics.
    if REWARD_SIGNALS
        .iter()
        .any(|phrase| has_phrase(&tokens, phrase))
    {
        return ClassifiedLine {
            line,
            class: BriefLineClass::ReportOrRewardPolicy,
            rule_id: "reward_or_report_policy",
        };
    }
    for (needle, rule) in VULN_CLASSES {
        if has_phrase(&tokens, needle) {
            return ClassifiedLine {
                line,
                class: BriefLineClass::ProhibitedVulnClass,
                rule_id: rule,
            };
        }
    }
    if OPERATIONAL.iter().any(|phrase| has_phrase(&tokens, phrase)) {
        return ClassifiedLine {
            line,
            class: BriefLineClass::ActionableTechnical,
            rule_id: "operational_marker",
        };
    }
    let single_token = trimmed.trim_start_matches(['-', '*']).trim();
    let looks_like_pattern = !single_token.is_empty()
        && !single_token.contains(char::is_whitespace)
        && (single_token.starts_with("*.")
            || single_token.contains('.')
            || single_token.contains('/')
            || single_token.contains(':'));
    if looks_like_pattern {
        return ClassifiedLine {
            line,
            class: BriefLineClass::ScopeOrAsset,
            rule_id: "scope_pattern",
        };
    }
    ClassifiedLine {
        line,
        class: BriefLineClass::Unknown,
        rule_id: "no_signal",
    }
}

pub fn classify_brief(text: &str) -> Vec<ClassifiedLine<'_>> {
    text.lines().map(classify_line).collect()
}

/// A line is abortable only when it is an operational/technical rule we could
/// not map. Prohibited vuln classes are abortable only when the caller did not
/// recognize their rule id; reward/scope/noise lines never abort.
pub fn is_abortable(class: BriefLineClass, recognized: bool) -> bool {
    match class {
        BriefLineClass::ActionableTechnical | BriefLineClass::ProhibitedVulnClass => !recognized,
        BriefLineClass::ReportOrRewardPolicy
        | BriefLineClass::ScopeOrAsset
        | BriefLineClass::Noise
        | BriefLineClass::Unknown => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cake_reward_line_is_not_actionable() {
        let line = "We determine bounty amounts based on a variety of factors, including (but not limited to) Impact, classification and sensitivity of the data, ease of exploitation and overall risk to our applications.";
        let classified = classify_line(line);
        assert_eq!(classified.class, BriefLineClass::ReportOrRewardPolicy);
        assert!(!is_abortable(classified.class, false));
    }

    #[test]
    fn cake_csrf_line_is_prohibited_vuln_class() {
        let line = "CSRF-able actions that do not require authentication (or a session) to exploit";
        let classified = classify_line(line);
        assert_eq!(classified.class, BriefLineClass::ProhibitedVulnClass);
        assert_eq!(classified.rule_id, "csrf_without_auth");
        assert!(!is_abortable(classified.class, true));
    }

    #[test]
    fn unknown_operational_prohibition_still_aborts() {
        let line = "Do not scan the staging API with automated tools between 2am and 4am.";
        let classified = classify_line(line);
        assert_eq!(classified.class, BriefLineClass::ActionableTechnical);
        assert!(is_abortable(classified.class, false));
    }

    #[test]
    fn classification_is_order_independent() {
        let a = classify_line("We pay rewards based on impact.");
        let b = classify_line("Do not modify data.");
        assert_eq!(a.class, BriefLineClass::ReportOrRewardPolicy);
        assert_eq!(b.class, BriefLineClass::ActionableTechnical);
    }
}
