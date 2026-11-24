# 07 - CWE Root-Cause Classification and CVSS Evidence-Derived Scoring -> BugFound

> **About these notes.** These are point-in-time analyses of third-party reference
> projects, kept for design input. They describe the reference projects at the
> snapshots examined and are not claims about the current BugFound code; verify
> current behavior in `crates/`.

Read-only research deliverable. No product code was modified. Only this file was written.
The CWE and CVSS clones are local reference corpora; their pinned commits are recorded in
section 0. Citations below are exact file + line/section references so a reviewer can
verify each claim against the local clone.

## 0. Source corpus and pinned commits

| Source | Local path | Pinned commit (HEAD at research time) | What it actually contains |
| --- | --- | --- | --- |
| CWE Content Development Repository (CDR) | `research/cwe/` | `ea5a2ea88febdf26d293e604ecd4b4dae183a93d` (`ea5a2ea`) | CWE *content development* process: submission guidelines, scope exclusions, submission problems, and hundreds of individual submission `.txt` files. It is NOT the CWE weakness catalog itself (no `cwe.xml`, no full View-1000 tree). Hierarchy/view/root-cause rules must be extracted from guidelines and submission reviews. |
| CVSS SIG resources | `research/cvss/` | `d766d0c8ab4368b67bf27dd0e411eb481f05fdbb` (`d766d0c`) | Official CVSS v4.0 Specification Document v1.2, SIG spec-change notes, NVD-RFI analysis, and the FIRST calculator validation corpus (vector files, enumerators, explainer). |

Implementation inspected (no changes): `crates/bugfound-engagement/src/lib.rs`,
`crates/bugfound-store/src/lib.rs`, `crates/bugfound-tools/src/lib.rs`,
`crates/bugfound-core/src/lib.rs`, `docs/report-format.md`, `docs/engagement.md`,
`eval/score.py`, `eval/golden.example.json`,
`crates/bugfound-engagement/tests/engagement_integration.rs`.

---

## 1. CWE reference: hierarchy, views, and root-cause classification

### 1.1 What the CWE reference says a weakness IS

`research/cwe/README.md:10-13` defines the CDR and its submitter/participant/observer roles;
`README.md:26-41` defines the 4 stages and 18 phases a submission passes through. The
important design point for BugFound is that a CWE ID is the outcome of a *review process*,
not a label chosen by keyword.

`research/cwe/documentation/submission-guidelines.md:55-58` ("Submission is not
Weakness-focused") states that weaknesses are "sometimes more easily understood based on
their attacks, or when expressed as a lack of a particular protection mechanism. This is
not how CWE entries are defined. It may require additional effort to conduct the
root-cause analysis to identify the underlying weakness."

`research/cwe/documentation/submission-guidelines.md:221-234` gives the concrete name/summary
rule: the name should contain (1) the intended behavior of the code, (2) the mistake (the
weakness), (3) the affected resource, (4) the affected technology; and the summary "should
avoid focusing on: (1) the attack, (2) the absence of a mitigation, or (3) the technical
impact. If a summary has a strong reliance on this information, this may be an indicator
that the entry is not weakness-focused."

`research/cwe/documentation/submission-problems.md:11-18` enumerates the corresponding
review labels: `SUB.UNCLEAR` (unclear weakness), `SUB.ATTACK` (too attack-focused),
`SUB.MITIGATION` (too mitigation-focused), `SUB.ABS.*` (abstraction), `SUB.RELS` (unclear
relationships). `submission-problems.md:56-73` and `:78-93` both state the same gate: an
initial submission cannot progress unless it includes a clear weakness.

### 1.2 Weakness hierarchy and views

`research/cwe/documentation/submission-guidelines.md:300-305` ("Relationships") is the key
section: "Identify the parent CWE(s) under which this weakness should be classified. Ensure
that these parents are Weakness types, not categories." It then names the hierarchy-oriented
views: **Development View (CWE-699)**, **Research View (CWE-1000)**, and **Hardware Design
View (CWE-1194)**.

`research/cwe/documentation/scope-exclusions.md:95-99` ("SCOPE.GROUPING - Grouping of issues
without a common behavior") reinforces the rule: "Weaknesses are based on specific behavior
and other shared criteria that can be hierarchically classified under a common ancestor in
the research view 1000. If no such ancestor is possible, then the submission is not likely a
weakness."

The machine-readable relationship shape is visible in a real full submission,
`research/cwe/submissions/ES2604-a5ac90a6-new-use-unbound-reusable-authentication-artifact.txt:543-576`:
```
# Relationships are of the form:
#   RelationshipType ID View-ID
# For example, CWE-78 (OS command injection) is a ChildOf CWE-77
# (command injection) under View-ID 1000 (the Research view).
# Values for RelType: ChildOf, MemberOf, ParentOf, PeerOf, etc.
# There should be at least one ChildOf relationship in view 1000.
RelType: ChildOf
ID: CWE-1462
View-ID: View-1000
RelType: MemberOf
ID: CWE-1217
View-ID: View-699
```
Concrete hierarchy facts available in the corpus: **CWE-78 ChildOf CWE-77** in View-1000
(OS command injection under command injection); CWE-1462 ChildOf in View-1000 and MemberOf
CWE-1217 in View-699; CWE-20 and CWE-159 used as parents in
`ES2503-a0f69c3b...:91-95`; CWE-706 "Use of Incorrectly-Resolved Name or Reference"
proposed as parent, CWE-41 "Improper Resolution of Path Equivalence" as the analogous
sibling, CWE-289 "Authentication Bypass by Alternate Name" as `CanFollow`, and CWE-180
"Validate Before Canonicalize" as a near-miss in `ES2503-a0f69c3b...:147-162`. This is a
root-cause graph (mistake -> more general mistake), not a flat keyword table.

### 1.3 Root cause vs symptom vs impact (the classification BugFound lacks)

`research/cwe/submissions/ES2503-a0f69c3b-new-inconsistent-email-normalization-leading-to-authentication-bypass.txt:51-59`
separates **Root Cause Analysis** ("the email verification system normalizes email addresses
inconsistently between the authentication process and the database check") from **Impact**
(`:61-75`: financial loss, redistribution, reputation, operational cost) and **Recommended**
mitigations (`:77-88`). The reviewer then rejects the *impact* as the identity in
`:105-125`: "The current submission is too attack focused because it focuses on the
technical impact which is 'authentication bypass' and also explains a proof of concept
attack ... it should focus on the weakness that is occurring, which is that the incoming
email address is not being properly normalized. There are other technical impacts that could
arise from improper normalization." This is the exact distinction BugFound must make:
`authentication bypass` is an impact, `improper normalization` is the weakness; mapping the
finding title "Authentication Bypass" to `CWE-287` is an impact-to-CWE shortcut.

`research/cwe/submissions/closed/ES2308-6b80112d-insufficient-input-validation--indirect-prompt-injection-vs-generative-ai-apps.txt:125-134`
shows the same review for prompt injection: "this submission cannot move to the next phase
until the root cause weakness is identified"; `:159-175` says the reported "vulnerability
topology" (where the attack comes from) is not the weakness and that "the underlying
weakness is the same: not neutralizing external data", and explicitly points to **CWE-79
and its extended description and the various ways XSS can be exploited** as the model:
general weakness entry + variations in examples, not one ID per delivery channel.

### 1.4 Common Consequences: the CWE bridge to CVSS impact metrics

`research/cwe/documentation/submission-guidelines.md:265-270` defines the Common
Consequences element: **Scope** (Confidentiality, Integrity, Availability, Access Control,
Accountability, Authentication, Authorization, Non-Repudiation, Other), **Impact**, and
**Likelihood** (High/Medium/Low/Unknown). This is the CWE-side vocabulary that should feed a
CVSS impact assessment: the weakness description says *which* security property is normally
violated; the evidence says *whether* it was violated in this instance.

`submission-guidelines.md:248-251` (Modes of Introduction) and `:253-263` (Potential
Mitigations, with effectiveness High/Moderate/Limited/Incidental/Defense-in-Depth) are the
basis for report "Root cause" and "Remediation" sections: the fix should target the
weakness (normalization, output encoding, object-level authorization check), not the attack
string.

### 1.5 Relationships to CAPEC and OWASP

- CAPEC is the attack-pattern side: `submission-problems.md:62-65` says an attack-focused
  submission "may be suitable for inclusion in CAPEC";
  `research/cwe/submissions/ES2111-835bef50-resource-consumption-incorrect-crypto-handshake.txt:330-335`
  records a submission being routed to the CAPEC team. Rule: CAPEC answers "how is it
  exploited", CWE answers "what is the mistake".
- OWASP is a mapping, not an authority on the CWE identity. The clearest example is
  `research/cwe/submissions/closed/ES2408-aaa6513c-mod-CWE-639-IDOR-BOLA.txt:25-55`: a
  proposed change to CWE-639's Alternate Terms because CWE-639 claimed BOLA (OWASP API
  Security Top 10) was "the same as IDOR", which the submitter disputed; CWE team accepted
  at `:105-108`. References at `:74-89` point at OWASP API1:2023 Broken Object Level
  Authorization and the WSTG API BOLA chapter. It confirms CWE-639 is the object-level
  authorization weakness and that IDOR/BOLA are alternate industry terms with nuance.
- `research/cwe/submissions/closed/ES2402-4f02537b-diagram-CWE-79.txt:25-34` is an accepted
  visualization modification for **CWE-79 "Improper Neutralization of Input During Web Page
  Generation ('Cross-site Scripting')"**, consistent with the CWE-79-as-general-weakness
  guidance above.

BugFound's own crosswalk already exists in `docs/report-format.md:162-189`, with a
"most specific CWE that fits the root cause" rule and rows for CWE-89, CWE-79, CWE-78,
CWE-639, CWE-862/863, CWE-22, CWE-601, CWE-352, CWE-918, CWE-287, CWE-200/312, CWE-16,
CWE-1104, CWE-770, CWE-840, CWE-502. `eval/golden.example.json:4-22` uses CWE-89, CWE-79,
CWE-639 as the three ground-truth classes.

### 1.6 Current BugFound CWE implementation (exact evidence)

`crates/bugfound-engagement/src/lib.rs:2077-2117` `map_cwe(title, vuln_type)`:
- builds one haystack from **title + vuln_type only** (`:2078`);
- iterates an ordered `const TABLE` of 30 `(needle, cwe)` substring pairs (`:2079-2110`);
- returns the **first substring hit** (`:2111-2114`);
- defaults to **`CWE-284`** (`:2116`).

Consequences of that design, read directly against the CWE guidance above:
- It classifies by *how the finding is named*, not by the mistake. A title containing
  "authentication" always returns CWE-287; "session" always returns CWE-384;
  "authorization"/"access control" always returns CWE-284. Per CWE guidance, those are
  impact/topology labels or whole classes, not root causes.
- CWE-639 is only emitted for the literal token `idor` (`:2100`); BOLA, object-level
  authorization, and cross-user object replay do not match. The CWE-639 submission shows
  these are the same weakness family.
- Descriptions, impact fields, reproduction, and the captured request/response bytes are
  never consulted. The reviewer logic in `ES2503-a0f69c3b...` would reject every one of
  these classifications as relying on attack/impact wording.
- Fallback CWE-284 ("Improper Access Control") is a class/pillar-level answer; CWE
  relationships require parents to be Weakness types, not categories, and specificity is
  the product rule (`docs/report-format.md:165-166`).
- `map_cwe` is only used in `build_canonical_report` (`:2316-2321`) as a fallback when the
  LLM-supplied `finding.cwe` is absent. The primary CWE is whatever the model wrote into
  `save_finding.cwe` (`crates/bugfound-core/src/lib.rs:428-429`,
  `crates/bugfound-tools/src/lib.rs:1521-1522`). So today the model supplies the taxonomy
  and the deterministic code only patches omissions - the reverse of the verifier design.

---

## 2. CVSS reference: metric groups, syntax, equations, and scoring mistakes

### 2.1 v4.0 metric groups and nomenclature

`research/cvss/spec-rev/specification-document.md:7-37` (spec v1.2) and `:78-134`: CVSS has
**four metric groups** - Base (Exploitability + Impact), Threat, Environmental, Supplemental.
Base is "intrinsic characteristics ... constant over time and across user environments" and
assumes "reasonable worst-case" (`:46-56`). Threat changes over time (Exploit Maturity);
Environmental is consumer-specific (compensating controls, CR/IR/AR, modified base metrics);
Supplemental provides context and **"will not have any impact on the final CVSS score"**
(`:121-131`).

`specification-document.md:170-206` defines the mandatory score nomenclature: **CVSS-B**
(base only), **CVSS-BT**, **CVSS-BE**, **CVSS-BTE**, and says the label "should be used
wherever a numerical CVSS value is displayed or communicated". `specification-document.md:34-37`
requires publishing both score and vector so others can understand the derivation.

### 2.2 v3.1 base scoring (the version BugFound implements)

`research/cvss/README.md:7-13` and `vectorFiles/` are v4.0-only; the v3.1 closed-form
equation is only present in the current product code. `crates/bugfound-engagement/src/lib.rs:1945-2039`
is a correct transcription of the FIRST CVSS v3.1 Base equation:

```
ISS      = 1 - (1-C)(1-I)(1-A)
Impact   = S:U ? 6.42*ISS : 7.52*(ISS-0.029) - 3.25*(ISS-0.02)^15
Exploit  = 8.22 * AV * AC * PR * UI
Base     = Roundup( min(10, S:U ? Impact+Exploit : 1.08*(Impact+Exploit)) )
```
with weights AV N/A/L/P = 0.85/0.62/0.55/0.2 (`:1980-1986`), AC L/H = 0.77/0.44
(`:1987-1991`), PR depending on scope (U: 0.85/0.62/0.27, C: 0.85/0.68/0.5;
`:1992-2005`), UI N/R = 0.85/0.62 (`:2006-2010`), C/I/A H/L/N = 0.56/0.22/0.0
(`:2045-2052`), and FIRST roundup at `:2054-2063`. Tests pin reference scores at
`crates/bugfound-engagement/tests/engagement_integration.rs:56-61` (9.8, 7.5, 1.8, and 0.0
for empty/incomplete vectors).

The v3.1 qualitative bands are recorded in `docs/report-format.md:149-160`: None 0.0, Low
0.1-3.9, Medium 4.0-6.9, High 7.0-8.9, Critical 9.0-10.0. The identical v4.0 bands are in
`specification-document.md:835-859` (Table 22) and apply to "all CVSS scores regardless of
nomenclature".

### 2.3 v4.0 vector syntax and strict validation

`specification-document.md:861-995`:
- vector starts with `CVSS:4.0/`, then `/`-delimited `KEY:VALUE` pairs, case-sensitive
  (`:867-873`);
- **Base metrics are mandatory, Threat/Environmental/Supplemental optional** with omitted
  values treated as Not Defined (`X`) (`:875-879`);
- **metric order is fixed** (Table 23, `:884-919`): AV, AC, AT, PR, UI, VC, VI, VA, SC,
  SI, SA, then E, then CR/IR/AR, MAV/MAC/MAT/MPR/MUI/MVC/MVI/MVA/MSC/MSI/MSA, then
  S/AU/R/V/RE/U; "every other ordering is invalid"; a metric may not appear twice
  (`:875-882`);
- invalid examples at `:970-995`: bad value `AV:F`, duplicate `E`, lowercase `ui`, missing
  `CVSS:4.0` prefix, missing mandatory `VA`, and wrong ordering.

The corpus operationalizes validation: `research/cvss/vectorFiles/base-threat-vectors`
has 419,904 Base+Threat vectors, `base-threat-scores` the paired
`{'vector': ..., 'score': ..., 'severity': ...}` rows; `macro-vectors`/`macro-scores` have
270 rows; `reference-vectors`/`reference-scores` have 66,314 rows including explicit
`Invalid vector string` results. `research/cvss/vectorEnum/base_enum.py:1-22` enumerates the
11 Base metrics with `itertools.product`. `research/cvss/helperScripts/cvss_explainer.js:84-89`
uses an **anchored** regex (start-of-string `CVSS:4.0/` then ordered metric groups,
end-of-string) before explaining any vector - the concrete validation pattern to copy.

### 2.4 v4.0 scoring has no closed-form equation

`specification-document.md:997-1032` describes expert ranking of ~15M CVSS-BTE vectors into
270 equivalence sets. `specification-document.md:1034-1231`: scores come from a **MacroVector
lookup table** (`cvss_lookup.js` in the reference calculator, `:1192-1194`, `:1225-1231`)
plus interpolation. Equivalence sets are EQ1=AV/PR/UI (Table 24, `:1102-1108`), EQ2=AC/AT
(Table 25, `:1110-1115`), EQ3=VC/VI/VA (Table 26, `:1117-1123`), EQ4=SC/SI/SA (Table 27,
`:1125-1131`), EQ5=E (Table 28, `:1138-1144`), EQ6=impact+CR/IR/AR (Tables 29-30,
`:1148-1167`), with joint EQ3+EQ6 levels. Algorithm at `:1196-1223`: the vector's score is
the highest-severity vector's MacroVector score minus the mean of the proportional severity
distances, rounded to one decimal. Defaults that matter: `E:X` = worst case `E:A`
(`:1146`), `CR/IR/AR:X` = `H` (`:1155-1156`), `MSI/MSA:X` falls back to base SI/SA
(`:1133-1136`).

### 2.5 Common scoring mistakes documented by the reference

From the spec:
1. Treating knowledge/effort of *finding* the bug as Attack Complexity - `specification-document.md:162-168`
   says assess as if the attacker has perfect knowledge.
2. Reading AC as "time or attempts": `:261-272` says AC is not time/attempts nor a race
   condition (that is Attack Requirements in v4, `:290-305`); deterministic repeatable
   success is AC:L (`:218-223`).
3. Putting target-specific controls in Base: `:224-226` says custom firewall filters/access
   lists belong in Environmental.
4. Letting a special configuration change Base: `:228-231` says assess the system in the
   vulnerable configuration.
5. Scoring the pre-exploitation state: `:357-371` says score the *final* impact / privilege
   delta only (read-only -> write means Integrity only).
6. Forgetting downstream systems: `:373-402` requires separate Vulnerable System vs
   Subsequent System impact sets; leave subsequent N when there is no external impact.
7. Treating Supplemental metrics as score modifiers: `:121-131`, `:690-700`.
8. Publishing a bare number without vector and without B/BT/BE/BTE label: `:34-37`, `:187-193`.
9. Ignoring strict vector order/duplicates/prefix (`:970-995`) - the current `cvss_base`
   parser cannot detect any of these (see 2.6).

From `research/cvss/spec-rev/nvd-rfi-cvss-improvements.md` (analysis of 72 NVD modernization
comments, report dated 2026-10-07):
- `:16-21`: of 1,332 CVEs with dual CNA/NVD scores only **17.7% had identical base scores**,
  **47.1% differed in severity band**, median gap 1.3 / max 7.2, 71% NVD higher;
  Attack Complexity differed in 39% of disagreements vs 7% for Attack Vector.
- `:23-29`: "Record which metric values were inferred rather than observed, and publish the
  score as the range the uncertain judgements imply ... an analyst who knows two records are
  tied is better served than one who believes 7.8 outranks 7.5."
- `:76-99`: publish per-metric disagreement; for AI-assisted scoring publish number of
  candidates generated, number retained after confidence threshold, and the threshold;
  measure Agreement / Stability / Resolution; note 2,047 CVEs share exactly 7.5.
- `:126-145`: per-field provenance - source identity (CNA, analyst, AI-assisted, AI-only),
  timestamp, model/version, confidence or review state, evidence references; distinguish
  "genuinely low risk" from "not yet analyzed".
- `:158-169`: gate AI enrichment on a held-out labeled set; route uncertain outputs to
  analysts; treat vector disagreement as a review trigger; **separate CVSS generation from
  validation** - "An AI system that evaluates its own output can reproduce its own errors".
- `:173-187` and `:254-258`: AC is the primary disagreement driver; expect ~47% band
  disagreement as normal; use CVSS as a technical baseline alongside EPSS/KEV/SSVC.
- `research/cvss/spec-rev/modifications.md:70-94`: proposal that PR:H should rarely produce
  a privilege delta, with assessment guidance to check whether the attacker already has
  complete control (no net gain). `:96-109` extends impact guidance to LLM systems: consider
  protected stored data, not general-access outputs.

### 2.6 Current BugFound CVSS implementation (exact evidence)

`crates/bugfound-engagement/src/lib.rs:1948-1954` parses the vector into a `HashMap` by
splitting on `/` and `:`; it does **not** check the version prefix, metric order, duplicate
metrics, or unknown keys. `:1955-1978` only checks presence of AV/AC/PR/UI/S/C/I/A; any other
`CVSS:x.y/...` string with those eight keys is scored as if it were v3.1. There is no v4.0
support (no AT/VC/VI/VA/SC/SI/SA, no MacroVector lookup). `severity_from_score` (`:2065-2075`)
uses `>=9.0 / >=7.0 / >=4.0 / else Low`, so 0.0 maps to "Low" rather than the spec's
"None", although `build_canonical_report:2301-2305` only calls it when `score > 0.0`.

The score is derived from the model, not evidence: `save_finding` declares `cvss` and `cwe`
as free-form strings (`crates/bugfound-tools/src/lib.rs:1521-1522`), core copies
`args["cvss"]`/`args["cwe"]` verbatim into the finding
(`crates/bugfound-core/src/lib.rs:428-429,443-444`), and `build_canonical_report` reads
`finding.cvss` as the vector and recomputes (`lib.rs:2299-2300`). If the model supplies a
numeric score string (e.g. `"9.8"`) rather than a vector, `cvss_base` returns 0.0 and the
report silently keeps the model's `severity` string (`:2301-2305`). `parse_report_finding`
in `crates/bugfound-tools/src/lib.rs:3216-3217,3254-3257` similarly treats `cvss`,
`cvss_vector`, `vector` as interchangeable. `eval/score.py:85-87` only recognizes
`CVSS:3.1/...` vectors.

---

## 3. Map to BugFound: concrete, evidence-backed improvements

### 3.1 CWE mapping: keyword substring -> root-cause reasoning

Replace the "first substring hit" decision at `lib.rs:2077-2117` with a two-stage, evidence-
grounded classifier. Use the CWE review process as the specification:

1. **Extract facts from the tool capture, not the title.** Inputs available today:
   `ToolCapture.request_bytes`/`response_bytes` and canary
   (`crates/bugfound-store/src/lib.rs:197-206,1144-1182`), `Finding.description`,
   `reproduction`, `impact`, `vuln_type` (`:66-98`). The current `map_cwe` ignores all of
   these.
2. **Classify the mistake (CWE) separately from the attack (CAPEC) and the impact
   (Common Consequences).** Apply `submission-guidelines.md:221-234`: reject an identity
   based only on "bypass", "leak", "RCE", "DoS" - those are impacts. Concretely:
   - "authentication bypass" with inconsistent email normalization -> improper
     normalization / incorrectly-resolved reference family (CWE-706 / CWE-20 / CWE-159),
     not automatically CWE-287 (evidence: `ES2503-a0f69c3b...:51-59,105-125,147-162`);
   - "prompt injection" with instructions/data concatenated -> neutralization of external
     data, using **CWE-79 as the general-weakness model**, not a new ID per channel
     (`ES2308-6b80112d...:125-134,159-175`);
   - "IDOR"/"BOLA"/cross-user object replay -> CWE-639 object-level authorization, rather
     than the current literal-only `idor` token at `lib.rs:2100`
     (`ES2408-aaa6513c...:25-55`).
3. **Return a hierarchy, not a single flat ID.** Store a primary Weakness-type CWE plus its
   `ChildOf` parent in View-1000 (and optional `MemberOf` in View-699), using the
   `RelType/ID/View-ID` shape from `ES2604-a5ac90a6...:543-576`. Never emit a category as
   the primary: `submission-guidelines.md:300-305`, `scope-exclusions.md:95-99`. Example:
   command injection should be `CWE-78 ChildOf CWE-77 (View-1000)`, not a bare "RCE" match.
4. **Record a rationale and a confidence alongside the ID** so a reviewer can audit the
   classification (nvd-rfi provenance pattern, see 3.4). Keep the existing
   `docs/report-format.md:165-166` "most specific CWE that fits the root cause" contract;
   the current default `CWE-284` (`lib.rs:2116`) should become an explicit
   "unclassified - needs review" state rather than a plausible-looking answer.
5. Keep OWASP as a secondary crosswalk only (`docs/report-format.md:162-189`, CWE-639
   submission); do not let an OWASP category choose the CWE.

### 3.2 CVSS: LLM-supplied vector -> evidence-derived scoring

Replace the flow `save_finding.cvss (LLM string) -> Finding.cvss -> cvss_base`
(`crates/bugfound-core/src/lib.rs:428-429`; `bugfound-engagement/src/lib.rs:2299-2300`) with
an explicit derivation stage that computes the vector from stored artifacts, then scores it:

1. **Validate before scoring.** Add an anchored, ordered, no-duplicate, version-aware parser
   like `cvss_explainer.js:84-89` and the invalid examples at
   `specification-document.md:970-995`. `cvss_base`'s current `HashMap` parser
   (`lib.rs:1948-1954`) accepts a v4 vector or a reordered vector and scores it as v3.1;
   reject those. Validate against the 419,904-row `vectorFiles/base-threat-vectors` +
   `base-threat-scores` and 270-row `macro-vectors` corpus (`cvss/README.md:7-13`).
2. **Derive each metric from an observed artifact and record the source per metric.**
   - AV: from how the tool reached the target in `request_bytes` (network URL fetch ->
     N; local file/console tool -> L) - `specification-document.md:244-251`.
   - AC: only claim `H` when the capture shows a defense that had to be defeated; v3.1/v4
     spec says deterministic repeatable success is `L`, and time/attempts/races are not AC
     (`:218-223,261-272`; race is AT:P at `:290-305`). This is the metric that drives 39% of
     real-world scorer disagreement (nvd-rfi `:16-21,173-187`), so it most needs evidence.
   - PR: infer from whether the capture carried an authenticated session/token; apply the
     PR:H "no net gain" guidance (`modifications.md:70-94`).
   - UI: N when the canary is reflected by the attacker's own request; R/P when a second
     user's action was required (CSRF / stored XSS), per `:334-349`.
   - C/I/A: from the actual captured response and the CWE Common Consequences scope
     (`submission-guidelines.md:265-270`), scoring the *final* delta, not the initial state
     (`specification-document.md:357-371`); keep Subsequent System impact N unless a
     concrete downstream asset was observed (`:373-402`).
3. **Preserve the version split.** Keep the v3.1 equation and its regression
   vectors (`engagement_integration.rs:56-61`) for v3.1 output. For v4.0, use the
   MacroVector lookup + interpolation from `specification-document.md:1034-1231` and the
   270-row `macro-scores` table; do not approximate v4 with the v3.1 formula. Label the
   result CVSS-B / -BT / -BE / -BTE per `:170-206`.
4. **Keep Temporal/Threat separate from Base.** BugFound can justify Threat E:P because a
   working PoC exists in `ToolCapture` (`specification-document.md:494-530`), but this is a
   consumer-side enrichment, not a change to Base (`:141-152`, modifications.md:125-135).
   Environmental CR/IR/AR remain operator-provided and default X=High (`:549-564`).
5. **Never let the model's own score silently win.** Today a non-vector `cvss` string gives
   score 0.0 and falls back to the model's severity (`lib.rs:2301-2305`). Instead, fail with
   an explicit "CVSS not assessable from evidence" and publish the evidence gap; this is the
   "genuinely low risk vs not yet analyzed" distinction from nvd-rfi `:142-145`.

### 3.3 Report severity sections

`render_canonical_report` (`crates/bugfound-tools/src/lib.rs:3043-3175`) currently emits a
single `- **Severity:**`, `- **CVSS:**`, `- **Vector:**`, `- **CWE:**` block (`:3100-3115`)
and a generic references appendix (`:3172-3174`). `docs/report-format.md:11-131` already
specifies richer sections that the renderer does not produce (severity-count table at
`:27-34`, OWASP field `:59`, candidate/verified/operator-confirmed status `:61`, canary and
captured request/response at `:88-96`, appendix glossary `:124-126`). Concrete additions:

- A **Severity rationale** subsection per finding: the derived vector, the numeric score,
  the qualitative band from the single Table 22 rule (0.0 None, 0.1-3.9 Low, 4.0-6.9
  Medium, 7.0-8.9 High, 9.0-10.0 Critical - `specification-document.md:845-853` and
  `docs/report-format.md:149-160`), and one line of evidence per metric. Reuse the
  per-metric layman narrative pattern in `cvss_explainer.js:8-72,107-120`, grouped into
  Exploitability / Impact / Subsequent systems.
- A **Root cause** subsection: intended behavior + mistake + affected resource/technology
  with the CWE name and its View-1000 parent (`submission-guidelines.md:221-234,300-305`);
  separate the observed impact from the weakness, as the CWE reviewers require.
- A **CWE / OWASP crosswalk** line using `docs/report-format.md:162-189`, with `N/A - no
  2021 category` rather than a forced mapping.
- An **Assessment provenance** block: source (tool capture vs LLM), model/ruleset version,
  timestamp, review state, and evidence hash (nvd-rfi `:126-145`). The renderer already has
  `evidence_hash` (`:3097,3121`) and `vector` (`:3108-3111`) fields to anchor it.
- An explicit **uncertainty/range** note when a metric is inferred rather than observed,
  per nvd-rfi `:23-29,216-220` ("7.5 +/- 0.8 (Attack Complexity inferred from vendor
  advisory)"). Keep the model's severity only as an untrusted candidate until this block is
  populated.

Note `eval/score.py:46-54,85-109` checks section names, a v3.1-only vector regex, and field
presence; new sections should be additive so existing checks keep passing, and the vector
regex should be extended for v4.0 if v4 output is emitted.

### 3.4 Verifier confidence

`verify_findings` (`crates/bugfound-engagement/src/lib.rs:2163-2249`) already implements a
strong deterministic gate: require a `ToolCapture` (`:2181-2183`), canary in response
(`:2186`), 2xx status line (`:2251-2258`), reject self-graded `<html>` echoes without the
canary (`:2189-2191,2260-2263`), reject claims of ROE-forbidden techniques (`:2192-2203`),
verify stored SHA-256 digests (`:2169-2173,2130-2138`), and records `advisory_match` only
as a detail string (`:2204-2211,2242-2244`). The verdict is only boolean `verified` /
`rejected` in the trace (`:2217-2235`) and the store has only `validated_at` +
`validation_detail` as strings (`crates/bugfound-store/src/lib.rs:94-97,1224-1237`).

Concrete confidence pattern (no new evidence source required - reuse existing signals):
- Replace the single boolean with a **numeric confidence plus named signal vector**, e.g.
  signals = `{capture_present, canary_in_response, http_2xx, not_self_graded,
  digest_reproducible, roe_technique_allowed}`; each is already computed at
  `lib.rs:2181-2211`. Publish `confidence = weighted(signals)` and a `review_state`
  (`validated` / `needs-review` / `rejected`), not just `validated`/else.
- Add **per-field provenance** to each scored finding: source identity (`tool-capture` vs
  `llm`), timestamp, model/ruleset version, review state, evidence references - exactly the
  nvd-rfi `:126-145` recommendation. `capture_digest` (`:2132-2138`) and `evidence_hash`
  (`crates/bugfound-store/src/lib.rs:1090-1101,232-241`) are the existing digests.
- Keep **generation and validation separated** (nvd-rfi `:158-169`): the model proposes the
  CWE/vector/severity, but the deterministic verifier must never accept the LLM's own
  `finding.response` as proof - today that value is explicitly "advisory only"
  (`lib.rs:2204-2211`). Promote `advisory_match` from a string fragment in
  `validation_detail` to a first-class, low-weight signal.
- Record **candidate generation / retention transparency** (nvd-rfi `:82-87`): the trace
  already records one `verifier` and one `finding` row per candidate (`:2216-2236`), but no
  confidence threshold or retained-count. Add both to the trace and report.
- Treat divergence as a review trigger (nvd-rfi `:163-164`): if the evidence-derived
  severity band differs from the LLM-supplied `finding.severity`, downgrade confidence and
  route to `needs-review` rather than silently overwriting at `lib.rs:2301-2305`.

---

## 4. Exact evidence index (file:section -> use)

| Evidence | Use |
| --- | --- |
| `research/cwe/documentation/submission-guidelines.md:55-58,221-234` | Root cause = mistake + intended behavior; not attack/mitigation/impact. |
| `research/cwe/documentation/submission-guidelines.md:265-270` | Common Consequences Scope/Impact/Likelihood -> CVSS impact. |
| `research/cwe/documentation/submission-guidelines.md:300-305`; `scope-exclusions.md:95-99` | Views 699/1000/1194; parent must be a Weakness; common ancestor in View-1000. |
| `research/cwe/documentation/submission-problems.md:11-18,56-93` | SUB.UNCLEAR / SUB.ATTACK / SUB.MITIGATION review gates. |
| `research/cwe/submissions/ES2604-a5ac90a6...txt:543-576` | `RelType/ID/View-ID` syntax; CWE-78 ChildOf CWE-77; ChildOf in View-1000. |
| `research/cwe/submissions/ES2503-a0f69c3b...txt:51-59,105-125,147-162` | Root cause vs impact; CWE-706/41/289/180 relationship reasoning; CWE-20/159. |
| `research/cwe/submissions/closed/ES2308-6b80112d...txt:159-175` | CWE-79 as general weakness + variations; topology is not weakness. |
| `research/cwe/submissions/closed/ES2408-aaa6513c...txt:25-55,105-108` | CWE-639 IDOR/BOLA alternate terms and OWASP crosswalk. |
| `research/cvss/spec-rev/specification-document.md:78-206` | Metric groups, assessment, CVSS-B/BT/BE/BTE nomenclature. |
| `specification-document.md:218-349,357-487` | AV/AC/AT/PR/UI and VC/SC/VI/SI/VA/SA definitions (evidence-to-metric rules). |
| `specification-document.md:489-531,532-687,688-834` | Threat E, Environmental CR/IR/AR and Modified Base, Supplemental (no score). |
| `specification-document.md:835-859` | Table 22 qualitative bands including None=0.0. |
| `specification-document.md:861-995` | Vector syntax, fixed order, mandatory base, invalid examples. |
| `specification-document.md:1034-1231` | v4.0 MacroVector + interpolation scoring; defaults E:X=A, CR/IR/AR:X=H. |
| `research/cvss/spec-rev/nvd-rfi-cvss-improvements.md:16-29,76-99,126-169,173-187` | Divergence data, inferred-vs-observed, provenance, candidate transparency, AI validation separation. |
| `research/cvss/spec-rev/modifications.md:43-94,96-135` | AV/AC/AT/PR clarifications, LLM impact guidance, threat enrichment. |
| `research/cvss/vectorFiles/*`, `vectorEnum/base_enum.py`, `helperScripts/cvss_explainer.js:84-89` | Validation corpus and anchored-regex + per-metric narrative pattern. |
| `crates/bugfound-engagement/src/lib.rs:1945-2117,2163-2374` | Current `cvss_base`, `map_cwe`, verifier, report builder (gaps). |
| `crates/bugfound-core/src/lib.rs:407-469`; `bugfound-tools/src/lib.rs:1500-1546,3216-3257` | LLM-supplied cvss/cwe ingress points. |
| `crates/bugfound-store/src/lib.rs:66-98,197-206,232-241,1144-1182,1224-1237` | Finding/ToolCapture/digest/validation storage available for evidence-derived scoring. |
| `docs/report-format.md:11-189`; `eval/score.py:46-54,85-109` | Required report sections, bands, CWE/OWASP contract, checker constraints. |
