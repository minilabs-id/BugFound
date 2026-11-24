# 08 - Bounty Platforms: HackerOne vs Bugcrowd Program Intelligence -> BugFound

> **About these notes.** These are point-in-time analyses of third-party reference
> projects, kept for design input. They describe the reference projects at the
> snapshots examined and are not claims about the current BugFound code; verify
> current behavior in `crates/`.

Read-only research deliverable. No implementation code was modified; only this file was
written. Local source clones are shallow and git-ignored (research/README.md:3-5); record
their commits when citing this document.

## 0. Source corpus, evidence classes, and caveats

| Source | Local path / external URL | Pin / retrieval | What it actually contains |
| --- | --- | --- | --- |
| HackerOne docs (community mirror) | `research/hackerone-docs/docs/programs/*.md`, `research/hackerone-docs/docs/hackers/*.md` | HEAD `ba9ef9b2b3ddd4465312f0c6b94bf6863dd9f5bb`, "Fix Setting Response Targets article" (2018-05-16). Paths in frontmatter are `/programs/<page>.html`, `/hackers/<page>.html`. | ~79 program pages + ~30 researcher pages. Substantive but **stale (~2018)**; treat as historical semantics, verify against the live platform before design decisions. |
| Bugcrowd docs (local "official mintlify" mirror) | `research/bugcrowd-docs/` | HEAD `558fda7d191d241514613afc92e8714db457e41a`, "Initial commit" (2026-11-13). | **No platform content at all.** It is the unmodified Mintlify starter kit: `README.md:1` "Mintlify Starter Kit"; `docs.json:2` name "Mintlify Starter Kit"; `index.mdx:6` "Write a short description of your product here"; only `index.mdx`, `quickstart.mdx`, `AGENTS.md`, `docs.json`. The local mirror cannot substantiate any Bugcrowd rule. |
| Bugcrowd docs (official public site, **external evidence**) | `https://docs.bugcrowd.com/` -> Customers / Researchers / Customer API sections | Fetched 2026-11-20; site footer "Copyright © 2026 Bugcrowd"; no local snapshot was created (write-only constraint). Cited below as `EXT BC / <section>` with URL and section heading. Re-fetch before treating as pinned. | Current product docs: Engagement Brief, Scope & Rewards, VRT Scope Rules, Brief Changelog, Engagement Status, Disclose.io & Safe Harbor, Reporting a Bug, Submission Limit, Known Issues, plus full nav taxonomy. |
| BugFound implementation (current, no changes) | `crates/bugfound-engagement/src/lib.rs`, `crates/bugfound-policy/src/lib.rs`, `crates/bugfound-engagement/tests/engagement_integration.rs`, `crates/bugfound-cli/src/main.rs`, `docs/engagement.md`, `docs/report-format.md` | Workspace as inspected. | `BriefReader` (`fetch_brief`), `extract_profile_from_text`, `extract_profile_with_llm`, `parse_roe`, `unparsed_constraints`, `EngagementProfile`, `RoePolicy`, `parse_scope_brief`, `build_canonical_report`, `verify_findings`. |

**Evidence-class rule for this document:** `[H1 path:lines]` = exact local-file evidence.
`EXT BC / <page>` = official public web docs, not present in the local mirror. Where the two
evidence classes disagree, the Bugcrowd local mirror is simply absent, not authoritative.

## 1. Extracted patterns - how programs define engagement rules

### 1.1 HackerOne: asset-centric scope, two eligibility bits, and a severity cap

`research/hackerone-docs/docs/programs/defining-scope.md:7-39` (Sec "Defining Scope", "Why
Should I Define My Scope?", "To Create and Edit your Existing Scope"):

- Scope is "a collection of assets you want hackers to hack"; when assets are listed,
  hackers **must select the applicable asset for each report** (`:7`). Special requirements
  are attached to the particular asset (`:7`).
- Out-of-scope assets are separately listed: hackers cannot submit to them and see a red
  warning (`:11`).
- `Eligibility for Bounty` is a distinct flag from `Eligibility for Submission`; a mixed
  bounty/VDP program must mark assets explicitly (`:12`, `:36`). This is a **report-eligibility
  axis**, not a tool-permission axis.
- `Environmental Score` caps the maximum report severity using C/I/A of that asset's data;
  "it might be impossible ... to have a Critical vulnerability in a static marketing asset"
  (`:14`, `:37`). Severity is therefore a function of asset, not just finding.
- Per-asset table (`:31-38`): Types (CIDR, Domain, iOS App Store/Testflight/.ipa, Android
  Play Store/.apk, Windows Microsoft Store, Source Code, Executable, Hardware/IoT, Other),
  Identifier, Eligibility for Submission, Eligibility for Bounty, Environmental Score,
  Instruction (surfaced on profile **and** submission form).
- `research/hackerone-docs/docs/programs/asset-types.md:6-22`: typed identifiers matter
  (CIDR ranges, URL validated by `uri_validator.rb`, Apple/Google/Windows store IDs);
  Source Code / Executable / Hardware identifiers are **not** validated.

`research/hackerone-docs/docs/programs/scope-best-practices.md:11-25`: prefer granularity
(avoid one wildcard across distinct hosts); explicitly list out-of-scope assets and explain
why in the instructions field; explicitly whitelist bounty-eligible assets; set the
Environmental Score per asset. `policy-and-scope.md:7-9`: the policy section publishes the
VDP guidance plus the scope list.

### 1.2 Bugcrowd: target groups plus a vulnerability-class exclusion matrix

`EXT BC / Customers > Engagement Management > Engagement Scope and Rewards`
(`https://docs.bugcrowd.com/customers/engagement-management/engagement-scope-and-reward/`,
Sec "Specifying Scope and Rewards", "Scope Groups", "Viewing Target Flags"):

- Scope is configured as **scope groups**: a group has Title/Description, an
  "This target group is In scope" checkbox, and an independent "This target group pays
  monetary rewards" checkbox with a recommended or custom reward range. An out-of-scope
  group is simply a group whose in-scope box is unchecked.
- **Target flags** mark changes on the researcher-facing brief: `New`, `Now OOS`,
  `Now in-scope`; flags display for **four weeks** from the add/change date. Scope change is
  designed to be visible and time-bounded to researchers.

`EXT BC / Customers > Engagement Management > Engagement VRT Scope Rules`
(`.../engagement-vrt-scope-rules/`, Sec "What it is", "Adding a new rule",
"What happens when the VRT gets updated"):

- VRT (Vulnerability Rating Taxonomy) classifies submissions by broad vulnerability class.
- A **VRT Scope Rule** is a pair: (selected VRT categories/sub-categories/items) x
  (All targets OR selected targets/groups), plus notes. It marks vulnerability classes
  out-of-scope or attaches requirements, and is shown on the engagement brief, the
  submission form, and the Security Inbox.
- Edits require **publishing the brief** to become visible.
- Bugcrowd periodically updates the VRT and supplies mappings; removed items keep rules
  visible on the brief but no longer appear on new submissions. Recommendation: review VRT
  scope rules "any time the VRT is updated, or at least twice a year".

`EXT BC / Customers > Engagement Management > Engagement Brief`
(`.../engagement-brief/`, Sec "Building an Engagement Brief", "Defining Scope and Rewards",
"Safe Harbour Status", "Configuring Collaborations"):

- Brief fields: Name, Tagline, Details (Markdown testing objectives/requirements), Scope and
  rewards, Additional information, Resources. A **scope rank** is computed from target count,
  wildcard-domain count, and number of distinct target categories.
- Collaborations let researchers share a submission and split monetary/point rewards.

**Pattern:** Bugcrowd exclusions are two-dimensional (asset/target group x vulnerability
class) and are published as versioned, time-flagged state. A flat "in_scope/out_of_scope
string list" cannot express either dimension.

### 1.3 Eligibility vs operational constraints are orthogonal axes

Both platforms separate *what may be submitted and paid for* from *what the tester may do*.

| Axis | HackerOne evidence | Bugcrowd evidence (external) |
| --- | --- | --- |
| Report/asset eligibility | `defining-scope.md:35-36` (Submission/Bounty flags); `submit-report-form.md:20` weakness Show/Hide/Disable; `hackers/weakness.md:11-15` (CWE subset, enable/disable/hide per program) | EXT BC in-scope group flag, VRT Scope Rules, P5 Informational opt-in (`customers/submission-management/p5-opt-in/` in nav) |
| Reporter eligibility | `signal-requirements.md:7-29`: Strict/Standard/Lenient/off Signal threshold; below-threshold hackers get capped reports, reset every 30 days | EXT BC `.../reporting-a-bug/submissions-limit/`: 6 submissions/week when 90-day accuracy <50%, new accounts 1 awaiting review + 6/week, 7-day minimum throttle, mandatory identity verification for Managed Bug Bounty; VDPs/Pen Tests excluded |
| Operational constraints (tester behavior) | No dedicated platform page in the 2018 mirror; lives in per-program ROE text. Representative brief in `crates/bugfound-engagement/src/lib.rs:2550-2561`: max 10 rps, quoted UA marker, "No DoS testing. Do not modify data. No disclosure." | EXT BC `.../reporting-a-bug/`: -1 point for submitting against an out-of-scope target; repeated out-of-scope testing loses program/platform privileges. Detailed permitted techniques remain in the program brief. |
| Availability gating | `pausing-report-submissions.md:7-19`: program can pause submissions; H1 can auto-pause on failing response SLAs; re-enable only when no failing SLA reports | EXT BC `.../engagement-brief/engagement-status/`: statuses Launching, Launch paused, In progress, In progress-paused, Finalizing, Completed, Canceling, Canceled; in paused/canceling states researchers can read the brief but **cannot submit or complete the methodology** |

BugFound already encodes this distinction in one place: `unparsed_constraints` deliberately
excludes report-eligibility/qualifier lines from the fail-closed check via `NON_ACTIONABLE`
(`lib.rs:1724-1745`, e.g. "duplicate", "informational", "already reported", "out of scope",
"third party"), with the comment that these "describe what the program will/not reward, not
what tools may do" (`:1721-1723`). That is the correct enforcement decision - but it **throws
the information away** instead of retaining it as program intelligence.

### 1.4 Reward structures

- H1 `bounties.md:7-27`: bounty for reported **and resolved** bugs; median/competitive/top
  recommendations per severity; awards can be increased but never removed; awarding a
  significant out-of-scope bug is explicitly allowed; bounties for out-of-H1 reports via API.
  `bonuses.md:10-24` separates bounty (severity/reputation signal) from bonus (non-severity
  behaviors: high-quality reports, following instructions, time-boxed promotions).
  `severity.md:7-32` uses CVSS v3 with optional hacker-submitted severity; recommends
  describing a custom methodology on the Security Page.
- H1 `security-page.md:14-24` requires a `Reward Structure` field; `good-policies.md:11`
  asks programs to define the reward structure in policy.
- Bugcrowd (external): rewards live in scope groups (recommended/custom ranges), a Reward
  Pool (`customers/fund-management/reward-pool-management/`), VRT P1-P5 priority with P5
  informational opt-in, and collaboration reward splits.

**Pattern:** reward structure is per-asset/class and can be time-boxed; it is not a scalar.
BugFound's `RoePolicy` has no reward field and its `EngagementProfile` stores only free-text
`reporting_rules` lines matched by a keyword filter (`lib.rs:1400-1418`).

### 1.5 Disclosure policy and safe harbor

H1 `public-disclosure.md:9-15`: three program settings - **Disclosure by Default** (default
for verified programs; disclosure within 30 days if admin agrees), **Disclosure requiring
Mutual Agreement** (opt-in), **Disclosure Disabled**. `:17-49` adds Full vs Limited disclosure
(full = summary, vulnerability info, timeline; limited = summary+timeline only), admin
approval, and permanent string redaction. `good-policies.md:11` recommends stating agreement
with HackerOne's disclosure guidelines; `security-page.md:18-22` lists Disclosure Policy and
Disclosure Rules as separate fields.

Bugcrowd (external) makes safe harbor a **structured, asserted status**:
`EXT BC / Researchers > Disclosure > Disclose.io and Safe Harbor`
(`.../researchers/disclosure/disclose-io-and-safe-harbor/`, Sec "Disclose.io", "Safe Harbor"):

- Disclose.io core terms balance legal completeness, researcher safe harbor, program-owner
  safe harbor, and readability. Programs displaying the logo commit to safe harbor for
  good-faith research.
- Recommended requirements: **Scope** = exhaustive in-scope properties explicitly granted
  safe harbor, plus a non-exhaustive out-of-scope list (outside both, authorization/safe
  harbor is implicitly absent); **Rewards** = whether valid *and unique* issues are
  compensated and in what form/magnitude; **Official communication channels** = exhaustive
  list; **Disclosure policy** = Coordinated / Discretionary / Non-Disclosure.
- **Full safe harbor** if all requirements met; **Partial safe harbor** otherwise. Both are
  displayed as distinct icons on program briefs/pages and are filterable by researchers.
- `EXT BC / Reporting a Bug` adds: owners select Nondisclosure / Coordinated Disclosure /
  Custom Disclosure on the brief; all submissions including Duplicates, Out of Scope, and
  Not Applicable are covered by Standard Disclosure Terms; unauthorized disclosure can cost
  program access/platform privileges.

**Pattern:** safe harbor and authorization are explicit, graded, per-program claims with a
direct relationship to the in-scope list - not a paragraph of prose. They are still claims:
`docs/engagement.md:188-189` already states a program page is "a statement of intent, not a
legal grant", which should remain the user-facing rule.

### 1.6 Duplication

H1 `duplicate-reports.md:7-23`: a report is a duplicate when the vulnerability was already
reported. Options: add the second hacker as an external participant on the original report,
or just link the original report number in comments; tying to the original is recommended
for accountability and reputation. `report-states.md:28-34`: `Duplicate` is a closed state,
public disclosure is unavailable, and reputation depends on the original report's state;
other outcomes are `Resolved`, `Informative`, `Not Applicable`, `Spam`, `Needs More Info`.

Bugcrowd (external) exposes duplication as **prior art, not just a verdict**:
`EXT BC / Researchers > Engagement Management > Viewing Known Issues`
(`.../researchers/engagement-management/viewing-known-issues/`):

- Known issues are vulnerabilities reported by other researchers or already known to the
  company, grouped **by target and VRT classification**; statuses triaged, unresolved, or
  informational count as known issues. Purpose includes reducing duplicate submissions.
- Optional feature, not present on every engagement. The brief shows Unique P1-P4 valid
  issues and Total findings (Unique + Duplicate).
- Customer side has `Import Known Issues` (`customers/program-management/known-issues-imports/`)
  and researcher side has "Understanding Substates", "Blockers", "Reporter Association".

**Pattern:** "duplicate" is platform state with a canonical original and a prior-art feed;
local finding-ID uniqueness is a weaker property.

### 1.7 Submission requirements

- H1 `submit-report-form.md:16-20`: Introduction Text, Markdown **Report Template**
  (pre-populated fields), and **Weakness Configuration** per weakness (Show with optional
  contextual instructions / Hide / Disable with explanation). `quality-reports.md:6-9`:
  detailed description, clear reproducible steps or working POC; screenshots/videos only
  where the program says it accepts them. `hackers/submitting-reports.md:13-22`: choose asset,
  choose weakness, optional severity/CVSS, POC stating what/steps/impact, optional attachments.
- Bugcrowd (external) `.../reporting-a-bug/`: minimum fields are Summary Title, Target,
  Technical Severity (VRT classification; suggested severity is not guaranteed to be applied),
  URL/Location (optional), Vulnerability details, Attachments. Description is pre-populated
  with **Overview / Walkthrough and POC / Vulnerability Evidence / Demonstrated Impact**.
  25,000-character description cap; up to 20 attachments <400 MB (the same page also says 5
  files <100 MB in a different subsections - the docs themselves are inconsistent); a
  confirmation checkbox attesting the program brief was followed and terms accepted; the
  submission cannot be edited after reporting.

**Pattern:** the report contract is platform- and program-specific, structured, and includes
classification plus an attestation. BugFound deliberately does not submit
(`docs/engagement.md:7-10`), so the requirement is local: produce a submission-ready draft.

### 1.8 Rate limits and prohibited methods

- Neither platform's generic docs define a platform-wide **network request rate limit**.
  Those live in the program brief. BugFound's `parse_roe` regexes
  (`lib.rs:1577-1579`) only recognize `N requests? per second` and
  `N requests? (total|in total|per engagement|maximum)`; the fixture brief uses 10 rps and a
  quoted UA marker (`lib.rs:2550-2561`).
- What the docs *do* specify is conduct and submission throttling: H1
  `hackers/examples-of-misconduct.md:11-35` bans extortion, automated report spam
  ("scanners, scripts, browser automation frameworks"), and harassment; H1
  `set-up-ip-whitelisting.md:7-11` is about team access, not tester traffic; Bugcrowd's
  Submission Limit throttles **report volume**, plus identity verification, 2FA compliance and
  per-engagement NDA in its researcher nav.
- Therefore a program-intelligence model must keep three rate concepts distinct:
  (a) network request budget from the brief, (b) report-submission quota from the platform,
  (c) agent token/step budgets from operator config (`EngagementOptions`, `lib.rs:96-123`).

## 2. HackerOne vs Bugcrowd semantics and terminology

| Concept | HackerOne (local mirror) | Bugcrowd (official external docs) | BugFound today |
| --- | --- | --- | --- |
| Top-level container | Program: Response (private VDP) or Bounty; managed/hosted; private by default, public is explicit (`program-start-up-guide.md:16-20`, `start-h1-bounty.md:7-9`, `public-vs-private.md:7-25`) | Security Program containing one or more Engagements with lifecycle states (`Launching` ... `Canceled`) (EXT BC nav + Engagement Status) | `EngagementProfile.program_url` string; no program type/visibility |
| Scope unit | Typed **Asset** with identifier (CIDR/URL/store IDs/etc.) (`asset-types.md:8-20`) | **Target** inside a scope **group**; group carries in-scope and pays-rewards flags (EXT BC Scope & Rewards) | `ScopeConfig.in_scope/out_of_scope` string patterns (`bugfound-policy/src/lib.rs:171-223`) |
| Exclusions | Out-of-scope assets + `Environmental Score` severity cap + weakness `Disable`/`Hide` | Out-of-scope groups + VRT Scope Rules (class x target) + "Now OOS" flags | Flat deny list; `NON_ACTIONABLE` prose filters |
| Eligibility | Eligibility for Submission / for Bounty per asset; Signal threshold per researcher | In-scope flag; pays-rewards flag; full/partial Safe Harbor; P5 opt-in; Known Issues | Nothing structured; prose keyword filter |
| Severity | CVSS v3 (optional hacker severity) + per-asset environmental cap | VRT P1-P5 baseline priority (suggested, not guaranteed); CVSS management docs exist | `cvss_base` CVSS v3.1 + `map_cwe` static table (`lib.rs:1948-2117`) |
| Unit of submission | **Report** (states New/Triaged/Needs More Info/Resolved/Informative/Duplicate/N/A/Spam) | **Submission** (statuses, substates, blockers, collaborators) | Local `Finding` + optional verified state |
| Duplication | Duplicate closed state; link original report; reputation effect | Known Issues per target/VRT; Unique vs Duplicate counts; imported known issues | Local finding-ID HashSet only (`lib.rs:886-890,1000-1031`) |
| Disclosure | 3 settings + Full/Limited + redaction + 30 days | Nondisclosure / Coordinated / Custom; disclose.io full/partial safe harbor; Standard Disclosure Terms covers duplicates/OOS | Single `allow_disclosure` boolean default false |
| Reward | Bounty / Bonus / Swag; per-severity recommendations | Reward pool; group reward ranges; P1-P5; collaboration splits | No field |
| Report contract | Markdown report template + weakness states | Structured prefilled sections + VRT + 25k char limit + attestation | One canonical `ReportInput` renderer |
| Freshness | "Re-evaluate your policy on a recurring basis" (`good-policies.md:22`); no version API in mirror | Published Brief Changelog versions, target flags for four weeks, VRT review twice yearly, status with date+reason | One fetch at start; resume does not re-fetch (`docs/engagement.md:139-142`) |

**Terminology trap:** "engagement" means different things. In Bugcrowd it is a first-class,
stateful object with a published brief; in BugFound `EngagementProfile.engagement` is just a
display name derived from a `Program:` line or URL host (`lib.rs:1383-1387`). "Scope" in
HackerOne is an asset collection; in BugFound it is a pair of host-pattern lists. "Rule" in
BugFound mixes allow/deny scope lines, ROE prose, and reporting prose in three loose buckets
(`lib.rs:1389-1429`), whereas the platforms separate them into distinct typed objects.

## 3. What a robust program-intelligence data model must capture

Derived strictly from the patterns above. These are fields/relationships to model, not a
proposed implementation.

### 3.1 Entity inventory

1. **ProgramIdentity** - `platform` (hackerone/bugcrowd/custom), `handle`/id, canonical brief
   URL, program type (VDP/bounty/managed/hosted), visibility (public/private/invite-only),
   lifecycle status, `status_changed_at`, `status_reason`, `safe_harbor_level` (full/partial/
   absent/unknown), official communication channels, NDA/2FA/identity requirements.
   *Why:* H1 `public-vs-private.md:7-25` and EXT BC Engagement Status make visibility and
   active window part of whether testing is currently authorized.
2. **BriefDocument** - `source_url`, `fetched_at`, `published_at`, `version_label`,
   `content_hash`, raw snapshot reference, extraction method, and **per-rule provenance**
   (see 3.3). *Why:* EXT BC Brief Changelog publishes versions and target flags expire after
   four weeks; H1 `good-policies.md:22` expects recurring policy re-evaluation.
3. **ScopeEntry** - `asset_type`, `identifier`, target group, `in_scope`,
   `submission_eligible`, `bounty_eligible`, `environmental_score`/C-I-A caps, `reward_range`,
   `instructions`, `valid_from`/`valid_to`, `source_ref`, change flag (new/now-OOS/
   now-in-scope). *Why:* H1 `defining-scope.md:31-38`; EXT BC Scope & Rewards.
4. **EligibilityRule** - class taxonomy (`CWE weakness` vs `VRT item`), state
   (allow/deny/hidden/disabled), target scope of the rule, notes, source ref.
   *Why:* H1 `submit-report-form.md:20`, `hackers/weakness.md:11-15`; EXT BC VRT Scope Rules.
5. **OperationalConstraint** - dimension (network rps, total requests, UA marker, fuzzing/
   scanner, state changes, intrusive tools, disclosure, DoS), verdict
   (allowed/denied/**unknown**), exact quoted text, source ref. *Why:* per-program ROE;
   BugFound's fixture (`lib.rs:2550-2561`) demonstrates all four dimensions in one brief.
6. **DisclosurePolicy** - mode (coordinated/discretionary/non-disclosure/disabled/default/
   mutual), permission holder, embargo days, full-vs-limited, redaction list.
   *Why:* H1 `public-disclosure.md:9-49`; EXT BC safe harbor + Reporting a Bug.
7. **RewardPolicy** - per-group/class ranges, currency, bonuses/promotions with active dates,
   collaborator splits. *Why:* H1 `bounties.md:7-27`, `bonuses.md:17-24`; EXT BC reward pools.
8. **SubmissionSpec** - platform-specific required fields, template text, classification
   taxonomy, char/attachment limits, attestation text. *Why:* H1
   `submit-report-form.md:16-20`; EXT BC Reporting a Bug.
9. **DuplicatePolicy / PriorArt** - dedup keys, canonical original ID, known-issues feed
   (target + class + status), unique-vs-duplicate counters, reputation effects.
   *Why:* H1 `duplicate-reports.md:7-23`, `report-states.md:30-34`; EXT BC Known Issues.
10. **AuthorizationSnapshot** - the tuple actually used to permit an action: brief version,
    safe-harbor level, active status/window, operator confirmation timestamp, last
    revalidation time, scope-set fingerprint. *Why:* all of the above freshness evidence.

### 3.2 Cross-cutting design principles

- **Separate eligibility from operations.** Eligibility rules change what a report is worth
  or whether it will be accepted; operational constraints change what the agent may do. Keep
  fail-closed enforcement on operations, but retain eligibility as data for triage/report
  annotation. BugFound's `NON_ACTIONABLE` list is the right enforcement boundary, not the
  right storage boundary.
- **Model absence as Unknown, not False.** For `RoePolicy`, fail-closed false is correct for
  actions; for program intelligence, "not stated" must remain distinguishable from "explicitly
  forbidden" so the UI can ask the operator instead of silently guessing.
- **Version and bind.** Every action should record which brief version/scope fingerprint was
  in force when it was authorized (analogous to EXT BC "Latest"/"Unpublished" changelog
  labels and the four-week target flags).
- **Freshness is a first-class field, not a log afterthought.** Store `observed_at` and a TTL
  per snapshot; invalidate on status change, brief publication, or target flag change.
- **Provenance for every extracted rule.** A rule without its source cannot be reviewed when
  scope changes mid-program - exactly the dispute scenario the Bugcrowd changelog exists to
  prevent.
- **Keep the human authorization boundary.** Both platforms' safe-harbor language is a
  program's promise, not legal advice; BugFound must keep operator confirmation explicit
  (`docs/engagement.md:188-189`).

### 3.3 Provenance tuple (minimum)

`(source_url, published_version, section_path | DOM_selector, verbatim_quote,
extractor = deterministic|llm|manual, confidence, observed_at, rule_id)`

This is the concrete answer to "source references for extracted rules". It is also what
makes an LLM-extracted scope usable: the LLM may propose values, but the deterministic pass
must be able to cite the sentence/element that justified them.

## 4. Mapping to BugFound's current BriefReader / RoePolicy - concrete gaps

### 4.1 Multi-platform parsers - GAP: no platform detection or structured extraction

Current code:

- `fetch_brief` (`crates/bugfound-engagement/src/lib.rs:1212-1248`) is a single generic
  reqwest GET: no proxy, no redirects, private-host rejection, 45s timeout, 1 MB cap,
  browser UA. `html_to_text` (`:1325-1345`) regex-strips HTML and explicitly preserves `-`
  and `*.` line shapes for the scope heuristic.
- `parse_scope_brief` (`crates/bugfound-policy/src/lib.rs:171-223`) is a line scanner:
  a heading containing "out of scope"/"in scope" flips a boolean; lines starting with `-` are
  accepted as patterns only if they are single tokens containing `.`/`/`/`:`/`*.`; all other
  lines become a `notes` blob.
- `extract_profile_from_text` (`lib.rs:1366-1429`) derives rules from scope strings
  (`:1389-1399`) and `reporting_rules` from lines containing any of report/disclos/submit/
  contact/safe harbor/reward/bounty (`:1400-1418`).
- `extract_profile_with_llm` (`lib.rs:1433-1493`) asks only for
  `engagement, in_scope, out_of_scope, reporting_rules, notes` (`:1439-1441`); the LLM can
  widen nothing because deterministic scope intersection clamps it (`:783-805`).
- `parse_roe` (`lib.rs:1574-1677`) matches a small set of English phrases for UA marker, rps,
  request ceiling, fuzzing, state-change, and disclosure; `unparsed_constraints`
  (`:1685-1790`) fails closed on unmatched security-sounding constraints.

Doc-backed requirements that cannot be met:

- H1 per-asset `Eligibility for Submission`, `Eligibility for Bounty`, `Environmental Score`,
  `Instruction`, and typed identifiers (`defining-scope.md:31-38`, `asset-types.md:8-20`)
  have no field in `EngagementProfile`/`ScopeConfig`.
- Bugcrowd scope groups (in-scope flag, pays-rewards flag, reward range), VRT Scope Rules
  (class x target), target flags, safe-harbor level, and engagement lifecycle status
  (EXT BC pages in 1.2/1.5) are invisible to the regex/LLM pipeline.
- Public pages only: `docs/engagement.md:175-178` already notes no login/CAPTCHA support.
  Bugcrowd engagement briefs and Known Issues are researcher-facing and often require
  sign-in (EXT BC Known Issues: "You must be signed into the platform"); H1 private programs
  are invitation-only (`public-vs-private.md:9-14`). A generic HTML reader therefore cannot
  see the authoritative brief for a large class of programs.

**Gap summary:** add a `PlatformAdapter` layer (HackerOne / Bugcrowd / generic-brief /
security.txt) that emits the Section 3 model; keep the existing deterministic parser as the
generic fallback and as the clamp for LLM output. Structured data (platform APIs where
available, JSON-LD/DOM anchors, target-group tables) must take precedence over line regexes.

### 4.2 Scope freshness - GAP: one-time fetch, no version, no revalidation

- Brief fetched exactly once in `run_engagement` (`lib.rs:691`); deterministic parse at
  `:699-714`; saved via `store.save_brief` at `:813-819`. No `fetched_at`, `ETag`,
  `published_version`, or content hash is kept with the scope object (the report hash is
  computed much later at `:1058-1065`).
- `docs/engagement.md:139-142` explicitly says resume "does **not** re-fetch or re-read the
  program brief"; scope is only re-evaluated per network action by tool/runtime gates.
- Doc requirement: H1 `good-policies.md:22` "Re-evaluate your policy on a recurring basis";
  EXT BC Brief Changelog (published/unpublished versions, review changes), Scope & Rewards
  target flags (four weeks), VRT Scope Rules (review at least twice a year), Engagement Status
  (status + date of last change + reason, paused states forbid new submissions). OWASP WSTG
  research (docs/research/06_owasp_methodology.md Sec 1.4) independently says re-read scope
  regularly because it can change mid-program.

**Gap summary:** version scope snapshots; stamp `observed_at`/TTL; re-fetch on resume and
before active testing windows; compare published version/content hash; fail closed (pause and
ask the operator) if scope changed after authorization. At minimum, record the scope
fingerprint on every `action` trace event so a report can be audited against the version that
was live at the time.

### 4.3 Eligibility vs operational constraints - GAP: eligibility discarded

- `RoePolicy` (`lib.rs:128-136`) contains only operational fields (`ua_marker`, `max_rps`,
  `max_requests`, `allow_fuzzing`, `allow_state_change`, `allow_disclosure`).
- `ScopeConfig` has no bounty/submission eligibility or per-asset severity cap.
- Report-eligibility prose is intentionally treated as non-actionable
  (`lib.rs:1721-1745`), and `reporting_rules` is a flat keyword-matched line list
  (`:1400-1418`) that later only becomes extra strings in the report rules list
  (`:2278-2294`).

**Gap summary:** add an `EligibilityModel` (per-asset eligible/paid flags, class-level
allow/deny states, reporter requirements, known issues) kept separate from `RoePolicy`. Use
it to annotate findings ("out-of-scope class", "no bounty", "likely duplicate") and to drive
a warning/confirmation step - not to loosen tool gates. Note H1's Signal threshold
(`signal-requirements.md:7-29`) and Bugcrowd's submission throttling are reporter-level
eligibility rules the agent cannot satisfy on a user's behalf; surface them as operator
checks, not silently assume them.

### 4.4 Report requirements per platform - GAP: single canonical schema only

- `build_canonical_report` (`lib.rs:2267-2374`) constructs one `ReportInput` for
  `render_canonical_report` (`:2353-2373`) with program, engagement, scope_in/out, rules,
  findings, coverage, timeline, report_id. `docs/report-format.md` defines the canonical
  template; no platform variant exists.
- Doc requirement: H1 Markdown report template + weakness Show/Hide/Disable
  (`submit-report-form.md:16-20`), full-vs-limited disclosure and redaction
  (`public-disclosure.md:22-49`); Bugcrowd's Summary Title / Target / VRT Technical Severity /
  prefilled Overview-Walkthrough-Evidence-Impact sections / attachments / attestation
  (EXT BC Reporting a Bug).

**Gap summary:** keep the canonical report as the audit artifact, and add a platform-shaped
**draft renderer** that fills the platform's required sections from verified findings, maps
CWE to the relevant weakness/VRT class, emits an evidence attachment manifest, and applies
the program's full/limited/redaction settings. Auto-submission stays forbidden
(`docs/engagement.md:7-10`); the draft is for human review.

### 4.5 Duplicate detection - GAP: local uniqueness only

- Dedup is a `HashSet<String>` of already-seen local finding IDs (`lib.rs:886-890`,
  `:1000-1031`); `verify_findings` checks canary replay and evidence digests
  (`:2163-2249`) but does not ask whether the issue is novel for the platform.
- `duplicate` and `already reported` appear only in the `NON_ACTIONABLE` exclusion list
  (`lib.rs:1736-1738`) - deliberately not enforced, but also not captured.
- Doc requirement: H1 Duplicate state with an original report link and reputation effect
  (`duplicate-reports.md:7-23`, `report-states.md:30-34`); Bugcrowd Known Issues per target
  and VRT plus Unique/Total counts (EXT BC Known Issues).

**Gap summary:** model `DuplicatePolicy` and `PriorArt`; when a known-issues feed is available,
attach matching target/class prior art to a finding as an advisory field; record that local
uniqueness is not platform novelty in the report and in the event stream. Do not claim a
finding is "new" based only on local dedup.

### 4.6 Authorization freshness - GAP: no safe harbor, no active window, no attestation record

- `parse_roe` only flips `allow_disclosure` on explicit phrases and otherwise defaults false
  (`lib.rs:1627-1637`, `:1664-1674`); prohibition overrides win (`:1638-1674`). This is good
  fail-closed behavior for the tool gate but there is no `safe_harbor` field, no program
  status, no active window, and no record of who confirmed what when.
- `EngagementOptions` carries operator risk opt-ins (`allow_network_write`,
  `allow_intrusive`, `auto_approve_all`; `lib.rs:96-123`) and `run_start` traces them
  (`:619-638`), but they are not tied to a brief version or an authorization claim.
- Doc requirement: Bugcrowd full/partial safe harbor with disclose.io core terms and an
  **exhaustive in-scope list as the safe-harbor boundary**; Engagement Status paused/canceling
  states explicitly forbid submitting or completing the methodology; H1 pausing report
  submissions (`pausing-report-submissions.md:7-19`) and disclosure agreement guidance
  (`good-policies.md:11`).

**Gap summary:** add `AuthorizationSnapshot` (Section 3.1) binding brief version, safe-harbor
level, program status/window, operator confirmation time, and last revalidation. Refuse to
engage (or auto-pause) when status indicates paused/canceled/completed or when safe harbor is
partial/unknown and the operator has not explicitly accepted that state. Keep the existing
"program page is intent, not legal grant" wording
(`docs/engagement.md:188-189`) in the UI.

### 4.7 Source references for extracted rules - GAP: snapshots without rule-level pointers

- `save_brief` persists raw HTML plus serialized profile/scope/reporting rules
  (`lib.rs:813-819`); trace events append scope arrays and `max_rps`
  (`:733-744`, `:820-830`). These are whole-document snapshots, not per-rule citations.
- `html_to_text` (`:1325-1345`) discards DOM structure; the LLM returns bare arrays
  (`:1439-1441`); `normalize_scope_pattern` (`:1509-1521`) strips annotations such as
  "(Mobile application, value: High)" that could have served as provenance hints.
- Doc requirement: EXT BC Brief Changelog exists to "resolve miscommunications and
  disputes" and exposes per-version Preview/Publish, target flags, and redaction/revert;
  H1 attaches an `Instruction` to a specific asset (`defining-scope.md:38`).

**Gap summary:** attach the Section 3.3 provenance tuple to every `ScopeEntry`,
`EligibilityRule`, and `OperationalConstraint` produced by an adapter. Surface it in the
replay/trace and report so an auditor can answer "which sentence authorized this action?"
- this complements, not replaces, the existing deterministic evidence/canary verification
  (`:2119-2249`).

### 4.8 Smaller boundary gaps worth noting

- RPS regex recognizes only "requests per second"; minute/hour variants and "1 request/second"
  singular forms need coverage (`lib.rs:1577`). The request-ceiling regex is similarly narrow
  (`:1578-1579`). These are brief-language gaps, not platform semantics, and should be
  handled by the platform adapter with fail-closed fallback.
- LLM user-agent marker construction hard-codes `bugfound/0.1 <marker>` (`lib.rs:1588`);
  preserve the exact quoted string from the brief (the integration test only asserts
  containment, `tests/engagement_integration.rs:36-43`).
- `host_key` intersection strips scheme, port, `*.` and trailing dot (`lib.rs:1542-1566`).
  This is a reasonable clamp, but it silently collapses typed asset identifiers (store IDs,
  CIDRs, `*.` wildcards) into one host namespace; a typed `ScopeEntry` model would keep the
  original form for reporting and matching.
- `NON_ACTIONABLE` includes "lack or bypass of rate-limiting" and "brute force or captcha"
  (`lib.rs:1729-1732`) and is tested (`tests/engagement_integration.rs:73-82`). This correctly
  mirrors H1/Bugcrowd vulnerability-qualifier prose, but those lines should populate
  `EligibilityRule`, not merely be ignored.

## 5. Summary

- The local HackerOne mirror is rich but frozen at 2018; the local Bugcrowd mirror contains
  no platform documentation. Current Bugcrowd semantics were therefore taken from the
  official public docs and are labeled as external evidence throughout.
- Both platforms model **scope, eligibility, operational rules, disclosure, rewards, duplicate
  handling, and submission contracts as separate typed concepts**. HackerOne is
  asset-centric with two eligibility bits and an environmental severity cap; Bugcrowd is
  target-group-centric with a second (VRT class x target) exclusion matrix, published brief
  versions, four-week target flags, and a graded safe-harbor claim.
- BugFound's `BriefReader`/`RoePolicy` is a deliberately conservative single-brief,
  English-phrase, fail-closed reader. Its safety posture is sound; its **intelligence model is
  too flat**: no platform adapters, no typed eligibility, no version/freshness, no
  safe-harbor/status window, no per-platform report contract, no duplicate prior art, and no
  rule-level provenance.
- Highest-value next research/design steps, in evidence order: (1) provenance tuple per
  extracted rule; (2) versioned `BriefDocument` with revalidation on resume; (3) typed
  `ScopeEntry`/`EligibilityRule` split from `RoePolicy`; (4) `AuthorizationSnapshot` binding
  version + safe harbor + active status + operator confirmation; (5) platform-shaped report
  drafts with the canonical report kept as the audit artifact.
