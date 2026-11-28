#!/usr/bin/env python3
"""BugFound evaluation scorer — standard library only.

Scores canonical Markdown engagement reports and, when ground truth and replay
data are supplied, computes detection and reproducibility metrics. This is
scaffolding: it does not claim any benchmark result. An operator must run a real
engagement and record the output in eval/results/.

Usage:
    python eval/score.py report.md [report2.md ...] [--json] [--strict]
    python eval/score.py --dir eval/results [--json] [--strict]
    python eval/score.py --dir eval/results \
        --manifest eval/golden.example.json \
        --replay eval/results/<id>/replay.jsonl [--json] [--strict]
    python eval/score.py report.md --finding-map eval/golden.example.json \
        --manifest manifest.json --replay replay.jsonl [--json] [--strict]
    python eval/score.py --replay replay.jsonl  (replay-only; no report needed)
    python eval/score.py <replay.jsonl>         (.jsonl positional is a replay)
    python eval/score.py --self-test            (synthetic regression cases)

Inputs
    --manifest  JSON: {"expected_vulns": [...]} (see eval/golden.example.json).
                Entries may be strings or objects with id/type/cwe/aliases.
                Malformed structures are rejected with a clean error.
    --finding-map JSON: {"<report heading>": "<finding id>"}. Report headings
                carry no structured verdict, so a verdict is inherited only by a
                heading explicitly mapped to a replay finding id. Without a map
                every report-heading verdict stays None (never a true positive).
    --replay    JSONL, one event per line. Recognised kinds:
                  run_start {run_id}                    (run boundary)
                  action    {run_id, tool, target, ok}  (tool call / hypothesis)
                  finding   {run_id, id, type, cwe, verified}
                  tested    {run_id, type, verdict}     (negative hypotheses)
                  verifier  {run_id, finding_id, verified, type, cwe}
                  usage     {run_id, prompt_tokens, completion_tokens}
                  report    {run_id, sha256}
                ``event`` is accepted as an alias for ``kind`` (engagement
                replay logs) and the trace-event spellings of the same concepts
                are normalised. Unknown kinds and malformed lines are ignored
                with a warning. trace_events can be exported with
                eval/export_trace.py and joined into this replay log.

Verification (fail closed)
    A finding only counts as verified when the replay carries an EXPLICIT
    boolean verdict for it: a ``verifier`` event with ``verified: true/false``,
    or a real boolean ``verified`` on the ``finding`` event itself. Strings,
    missing fields, and absent verifier events never imply True. Findings with
    no verdict are reported as ``unverified_findings`` and are never promoted
    to true positives. Metrics that need missing evidence are printed as
    ``not_measured (<reason>)`` rather than a fabricated number.

Metrics (computed only when the relevant input is present)
    recall, precision, false_positive_rate (+ count and basis) from negative
    tested/verifier events only, false_discovery_rate_proxy = 1 - precision,
    reproducibility (finding + report-hash), tokens_per_finding.
    --max-fpr enforces only a measured false_positive_rate, never the proxy.
    Section/field checks run for every report regardless of inputs.
"""

import argparse
import contextlib
import io
import json
import os
import re
import sys
import tempfile
from collections import defaultdict

REQUIRED_SECTIONS = [
    "Executive Summary",
    "Scope & ROE",
    "Methodology",
    "Findings",
    "Coverage",
    "Timeline",
    "Appendices",
]
SECTION_ALIASES = {
    # The canonical renderer may emit either spelling; both satisfy the check.
    "Scope & ROE": ["scope & roe", "scope and roe", "scope"],
}
SEVERITIES = ["Critical", "High", "Medium", "Low", "None", "Unknown"]

# Both the engagement replay log ("event") and trace_events ("kind") feed this
# scorer; normalise their spellings once at load time.
KIND_ALIASES = {
    "started": "run_start",
    "engagement.start": "run_start",
    "finding.saved": "finding",
    "token_usage": "usage",
    "tokens": "usage",
    "verify": "verifier",
    "poc.verified": "verifier",
    "report.ready": "report",
    "report_ready": "report",
    "report.exported": "report",
    "probe": "tested",
    "test": "tested",
    "hypothesis": "tested",
}


def event_kind(event):
    raw = event.get("kind", event.get("event", ""))
    text = str(raw or "").strip().lower()
    return KIND_ALIASES.get(text, text)

CVSS_RE = re.compile(
    r"CVSS:3\.1/AV:[NALP]/AC:[LHP]/PR:[NLH]/UI:[NR]/S:[UC]/C:[NLH]/I:[NLH]/A:[NLH]"
)
CWE_RE = re.compile(r"CWE-\d+", re.IGNORECASE)
HASH_RE = re.compile(r"\b[0-9a-fA-F]{64}\b")
# Canonical renderer: "### F-01: ..."; engagement renderer: "### [High] ...".
FINDING_RE = re.compile(
    r"^###\s+((?:F-?\d+\s*:?|\[(?:Critical|High|Medium|Low|None|Info)\]).*)$",
    re.MULTILINE | re.IGNORECASE,
)
SEVERITY_RE = re.compile(
    r"Severity:\s*\**\s*(Critical|High|Medium|Low|None)", re.IGNORECASE
)
BRACKET_SEVERITY_RE = re.compile(
    r"\[(Critical|High|Medium|Low|None)\]", re.IGNORECASE
)
TYPE_RE = re.compile(r"(?:\*\*Type:\*\*|Type:)\s*(.+)", re.IGNORECASE)
# Canonical renderer headings start with a stable finding id: "### F-01: ...".
STABLE_HEADING_ID_RE = re.compile(r"^\s*(F-?\d+)\b", re.IGNORECASE)

FIELD_PATTERNS = {
    "steps": re.compile(r"steps to reproduce|reproduction|\brepro\b", re.IGNORECASE),
    "poc": re.compile(r"proof of concept|\bPoC\b", re.IGNORECASE),
    "impact": re.compile(r"\bimpact\b", re.IGNORECASE),
    "remediation": re.compile(r"remediation", re.IGNORECASE),
    "evidence_hash": HASH_RE,
}


def normalize(value):
    return re.sub(r"[^a-z0-9]+", " ", str(value).lower()).strip()


def cwe_key(value):
    match = re.search(r"cwe-?\s*(\d+)", str(value), re.IGNORECASE)
    return "cwe%s" % match.group(1) if match else normalize(value)


def identifiers_from(values):
    """Build a set of comparable identifiers from arbitrary strings."""
    result = set()
    for value in values:
        if value is None:
            continue
        text = str(value).strip()
        if not text:
            continue
        result.add(normalize(text))
        if "cwe" in text.lower():
            result.add(cwe_key(text))
    result.discard("")
    return result


def _heading_names(text):
    return [m.group(1).strip() for m in re.finditer(r"^##\s+(.+?)\s*$", text, re.MULTILINE)]


def _sections(text):
    parts = re.split(r"^##\s+(.+?)\s*$", text, flags=re.MULTILINE)
    result = {}
    for i in range(1, len(parts) - 1, 2):
        result[parts[i].strip()] = parts[i + 1]
    return result


def section_present(name, headings):
    normalized = [normalize(h) for h in headings]
    aliases = SECTION_ALIASES.get(name, [name])
    return any(normalize(a) in normalized for a in aliases)


def score_report(path):
    """Check one Markdown report; also return reported-finding identifiers."""
    with open(path, encoding="utf-8", errors="replace") as handle:
        text = handle.read()
    sections = _sections(text)
    headings = _heading_names(text)
    missing_sections = [s for s in REQUIRED_SECTIONS if not section_present(s, headings)]

    findings_text = sections.get("Findings", "")
    blocks = FINDING_RE.split(findings_text)
    findings = []
    reported = []
    for index in range(1, len(blocks) - 1, 2):
        heading = blocks[index].strip()
        block = blocks[index + 1]
        severity_match = SEVERITY_RE.search(block) or BRACKET_SEVERITY_RE.search(block)
        severity = severity_match.group(1).capitalize() if severity_match else "Unknown"
        missing_fields = [name for name, pattern in FIELD_PATTERNS.items() if not pattern.search(block)]
        cwes = [cwe_key(m.group(0)) for m in CWE_RE.finditer(block)]
        type_match = TYPE_RE.search(block)
        identifiers = set(cwes)
        identifiers.update(identifiers_from([type_match.group(1)] if type_match else []))
        first_line = heading or next(
            (line.strip("# *") for line in block.splitlines() if line.strip()), ""
        )
        identifiers.update(identifiers_from([first_line]))
        findings.append({
            "severity": severity,
            "cvss_vector": bool(CVSS_RE.search(block)),
            "cwe": bool(cwes),
            "missing_fields": missing_fields,
        })
        reported.append({
            "identifiers": identifiers,
            "heading": first_line,
            "source": "report",
        })

    counts = {severity: 0 for severity in SEVERITIES}
    for finding in findings:
        counts[finding["severity"] if finding["severity"] in counts else "Unknown"] += 1

    problems = []
    if missing_sections:
        problems.append("missing sections: " + ", ".join(missing_sections))
    for index, finding in enumerate(findings, 1):
        if not finding["cvss_vector"]:
            problems.append("finding %d: missing CVSS v3.1 vector" % index)
        if not finding["cwe"]:
            problems.append("finding %d: missing CWE" % index)
        if finding["missing_fields"]:
            problems.append("finding %d: missing %s" % (index, ", ".join(finding["missing_fields"])))

    return {
        "path": path,
        "findings": counts,
        "total_findings": len(findings),
        "missing_sections": missing_sections,
        "problems": problems,
        "reported": reported,
    }


def discover(directory):
    found = []
    for root, dirs, files in os.walk(directory):
        # Operator-recorded results are scored; synthetic examples shipped with
        # the harness are documentation, not benchmark inputs.
        dirs[:] = [name for name in dirs if not name.startswith("example-")]
        for name in files:
            lowered = name.lower()
            if lowered.endswith(".md") and lowered != "readme.md" and not name.startswith("EXAMPLE-"):
                found.append(os.path.join(root, name))
    return sorted(found)


def load_manifest(path):
    with open(path, encoding="utf-8") as handle:
        data = json.load(handle)
    if isinstance(data, list):
        entries = data
    elif isinstance(data, dict):
        entries = data.get("expected_vulns", [])
        if not isinstance(entries, list):
            raise ValueError("expected_vulns must be a list of strings or objects")
    else:
        raise ValueError("manifest must be a JSON object or list")
    ground_truth = []
    for index, entry in enumerate(entries):
        if isinstance(entry, str):
            entry = {"id": entry}
        elif not isinstance(entry, dict):
            raise ValueError(
                "expected_vulns[%d] must be a string or object, got %s"
                % (index, type(entry).__name__)
            )
        key = str(entry.get("id") or entry.get("type") or entry.get("name") or "vuln-%d" % (index + 1))
        aliases = entry.get("aliases") or []
        if isinstance(aliases, str):
            aliases = [aliases]
        elif not isinstance(aliases, list):
            raise ValueError(
                "expected_vulns[%d].aliases must be a string or list, got %s"
                % (index, type(aliases).__name__)
            )
        identifiers = identifiers_from([key, entry.get("cwe")] + list(aliases))
        ground_truth.append({"key": key, "identifiers": identifiers})
    return ground_truth


def load_finding_map(path):
    """Load {"<report heading>": "<finding id>"}; validate before use."""
    with open(path, encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError("finding map must be a JSON object of heading -> finding id")
    result = {}
    for heading, finding_id in data.items():
        if not isinstance(heading, str) or not isinstance(finding_id, (str, int)):
            raise ValueError("finding map entries must map a heading string to a finding id")
        result[heading] = str(finding_id)
    return result


def load_replay(path):
    events = []
    warnings = []
    with open(path, encoding="utf-8", errors="replace") as handle:
        for line_number, line in enumerate(handle, 1):
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError as error:
                warnings.append("replay line %d: invalid JSON (%s)" % (line_number, error.msg))
                continue
            if isinstance(event, dict):
                event["kind"] = event_kind(event)
                events.append(event)
            else:
                warnings.append("replay line %d: expected an object" % line_number)
    return events, warnings


# Verdict spellings that count as a *negative* for the FPR denominator. An
# explicit positive (observed/confirmed/true) must never inflate that denominator.
NEGATIVE_VERDICTS = {
    "false", "0", "no", "rejected", "not a finding", "not vulnerable",
}
POSITIVE_VERDICTS = {
    "true", "1", "yes", "confirmed", "observed", "verified", "positive",
    "vulnerable", "found", "success",
}


def _is_negative_verdict(value):
    """True only for explicit negative verdicts; positives never count."""
    if isinstance(value, bool):
        return not value
    if value is None:
        return False
    text = normalize(value)
    if text in POSITIVE_VERDICTS:
        return False
    return text in NEGATIVE_VERDICTS


def _is_false(value):
    if isinstance(value, bool):
        return not value
    return str(value).strip().lower() in ("false", "0", "no", "rejected")


def _match_keys(identifiers, index):
    keys = set()
    for identifier in identifiers:
        keys.update(index.get(identifier, ()))
    return keys


def _dedupe(reported):
    """Merge duplicate findings by matched ground-truth key, else by identifiers."""
    seen = set()
    unique = []
    for item in reported:
        keys = item.get("keys")
        marker = ("gt", frozenset(keys)) if keys else ("raw", frozenset(item["identifiers"]))
        if marker in seen:
            continue
        seen.add(marker)
        unique.append(item)
    return unique


def _event_tokens(event):
    """API token counts from a usage event; no len/4 estimates."""
    usage = event.get("usage") if isinstance(event.get("usage"), dict) else {}
    def first(*names):
        for name in names:
            value = event[name] if name in event else usage.get(name)
            if value is not None:
                return value
        return 0
    prompt = first("prompt_tokens", "input_tokens", "prompt")
    completion = first("completion_tokens", "output_tokens", "completion")
    try:
        total = int(prompt or 0) + int(completion or 0)
    except (TypeError, ValueError):
        total = 0
    if total:
        return total
    try:
        return int(first("total_tokens", "tokens") or 0)
    except (TypeError, ValueError):
        return 0


def _explicit_verdict(event):
    """Return True/False only from a real boolean verdict field, else None.

    Missing fields, strings, and other values are NOT verification evidence.
    This is the boundary that stops absent data from being read as ``verified``.
    """
    for name in ("verified", "verdict"):
        value = event.get(name)
        if isinstance(value, bool):
            return value
    return None


def _verdict_maps(replay_events):
    """Build (by_id, by_identifier, explicit_count) verdict maps.

    Both ``verifier`` events and ``finding`` events with a real boolean
    ``verified`` contribute. A verifier event without an explicit boolean is
    ignored: it verifies nothing.
    """
    by_id = {}
    by_identifier = defaultdict(set)
    count = 0
    for event in replay_events:
        if event["kind"] not in ("verifier", "finding"):
            continue
        verdict = _explicit_verdict(event)
        if verdict is None:
            continue
        count += 1
        finding_id = (
            event.get("finding_id") or event.get("id") or event.get("candidate")
        )
        if finding_id is not None:
            by_id[str(finding_id)] = verdict
        identifiers = identifiers_from([
            finding_id, event.get("type"), event.get("cwe"), event.get("candidate")
        ])
        for identifier in identifiers:
            by_identifier[identifier].add(verdict)
    return by_id, by_identifier, count


def _resolve_verdict(identifiers, finding_id, by_id, by_identifier):
    """Resolve an explicit verdict for a reported finding, or None.

    Conflicting verdicts for the same identifier also resolve to None so that
    ambiguity can never be promoted to a true positive.
    """
    if finding_id is not None and str(finding_id) in by_id:
        return by_id[str(finding_id)]
    values = set()
    for identifier in identifiers:
        values.update(by_identifier.get(identifier, ()))
    if len(values) == 1:
        return next(iter(values))
    return None


def _status(measured, reason=""):
    return {
        "status": "measured" if measured else "not_measured",
        "reason": "" if measured else reason,
    }


def compute_metrics(results, ground_truth, replay_events, finding_map=None):
    """Compute detection/reproducibility metrics dicts; values may be None.

    Only findings carrying an explicit boolean verdict can become true or false
    positives. Report headings inherit a verdict only when explicitly mapped to
    a finding id via ``finding_map``; identifier similarity alone is not enough.
    Findings without a verdict are counted in ``unverified_findings`` and never
    inflate detection metrics. Metrics lacking required evidence are reported as
    not_measured with a reason in ``measurement_status``.
    """
    index = defaultdict(set)
    for entry in ground_truth:
        for identifier in entry["identifiers"]:
            index[identifier].add(entry["key"])

    verdict_by_id, verdict_by_identifier, verdict_count = _verdict_maps(replay_events)

    reported = []
    for result in results:
        reported.extend(result.get("reported", []))
    for event in replay_events:
        if event["kind"] != "finding":
            continue
        finding_id = event.get("id") or event.get("finding_id")
        identifiers = identifiers_from(
            [finding_id, event.get("type"), event.get("cwe")]
            + list(event.get("aliases") or [])
        )
        own_verdict = _explicit_verdict(event)
        reported.append({
            "identifiers": identifiers,
            "finding_id": str(finding_id) if finding_id is not None else None,
            "verdict": (
                own_verdict if own_verdict is not None
                else _resolve_verdict(
                    identifiers, finding_id, verdict_by_id, verdict_by_identifier
                )
            ),
            "source": "replay",
        })
    # F8: report prose has no structured verdict. Without an explicit heading ->
    # finding-id mapping the verdict stays None; two same-type headings must not
    # be promoted by matching identifiers alone.
    finding_map = finding_map or {}
    by_heading = {normalize(heading): finding_id for heading, finding_id in finding_map.items()}
    for item in reported:
        if item["source"] == "report":
            heading = item.get("heading", "")
            mapped_id = finding_map.get(heading)
            if mapped_id is None:
                mapped_id = by_heading.get(normalize(heading))
            if mapped_id is None:
                # Stable finding id in the heading itself, never a type/name match.
                stable = STABLE_HEADING_ID_RE.match(heading)
                if stable:
                    mapped_id = stable.group(1)
            if mapped_id is not None:
                item["finding_id"] = str(mapped_id)
                # Look up by stable id only, never by identifier similarity.
                item["verdict"] = verdict_by_id.get(str(mapped_id))
            else:
                item["verdict"] = None

    report_verdicts = [
        {
            "heading": item.get("heading"),
            "finding_id": item.get("finding_id"),
            "verdict": item.get("verdict"),
        }
        for item in reported if item["source"] == "report"
    ]

    for item in reported:
        item["keys"] = _match_keys(item["identifiers"], index)
        if item["verdict"] is False:
            # An explicit rejection invalidates any ground-truth match.
            item["keys"] = set()
    reported = _dedupe(reported)

    truth_keys = {entry["key"] for entry in ground_truth}
    verified = [item for item in reported if item["verdict"] is True]
    rejected = [item for item in reported if item["verdict"] is False]
    unverified = [item for item in reported if item["verdict"] is None]
    true_positives = [item for item in verified if item["keys"]]
    false_positives = [
        item for item in reported
        if item["verdict"] is not None and not item["keys"]
    ]

    status = {}
    if not truth_keys:
        detection_reason = "no ground-truth manifest supplied"
    elif verdict_count == 0:
        detection_reason = "no explicit verifier verdicts in replay"
    else:
        detection_reason = ""
    detection_ready = not detection_reason

    covered = set()
    for item in true_positives:
        covered.update(item["keys"])
    recall = len(covered & truth_keys) / len(truth_keys) if detection_ready else None
    status["recall"] = _status(detection_ready, detection_reason)

    denominator = len(true_positives) + len(false_positives)
    if not detection_ready:
        precision_reason = detection_reason
    elif not denominator:
        precision_reason = "no verified findings to score"
    else:
        precision_reason = ""
    precision = len(true_positives) / denominator if not precision_reason else None
    status["precision"] = _status(not precision_reason, precision_reason)

    # F2: 1 - precision is a false *discovery* rate proxy, not an FPR. It is
    # reported separately and can never satisfy --max-fpr.
    fdr_proxy = 1.0 - precision if precision is not None else None
    status["false_discovery_rate_proxy"] = _status(
        fdr_proxy is not None, precision_reason or "precision not measured"
    )

    # F2/F3: a true FPR needs at least one negative tested hypothesis or
    # negative verifier verdict. Precedence stays tested > verifier > action.
    # A bare failed tool call (e.g. fs_read) is not a security negative.
    tested_negatives = []
    verifier_negatives = []
    action_negatives = []
    for event in replay_events:
        kind = event["kind"]
        if kind == "tested":
            # `tested` denotes a rejected hypothesis; an absent verdict is an
            # implicit negative. Explicit positives (observed/confirmed/true)
            # are excluded from the denominator.
            explicit = [event[name] for name in ("verdict", "verified", "ok") if name in event]
            if explicit and not any(_is_negative_verdict(value) for value in explicit):
                continue
            identifiers = identifiers_from([event.get("type"), event.get("id"), event.get("cwe")])
            if identifiers:
                tested_negatives.append(identifiers)
        elif kind == "verifier" and any(
            _is_negative_verdict(event.get(name)) for name in ("verdict", "verified", "ok")
        ):
            identifiers = identifiers_from([
                event.get("type"), event.get("cwe"), event.get("id"),
                event.get("finding_id"), event.get("candidate"),
            ])
            if identifiers:
                verifier_negatives.append(identifiers)
        elif kind == "action" and _is_false(event.get("ok", True)):
            identifiers = identifiers_from([
                event.get("type"), event.get("hypothesis"), event.get("cwe"),
            ])
            if identifiers:
                action_negatives.append(identifiers)

    reported_identifiers = [item["identifiers"] for item in reported]
    negatives = []
    fpr_basis = "not_measured"
    for candidates, basis in (
        (tested_negatives, "replay_tested_hypotheses"),
        (verifier_negatives, "replay_verifier_verdicts"),
        (action_negatives, "replay_failed_actions"),
    ):
        if candidates:
            negatives = candidates
            fpr_basis = basis
            break
    fpr = None
    if detection_ready and negatives:
        fp_negatives = sum(
            1 for identifiers in negatives
            if any(identifiers & candidate for candidate in reported_identifiers)
        )
        tn = len(negatives) - fp_negatives
        fpr = fp_negatives / (fp_negatives + tn) if (fp_negatives + tn) else None
    if not detection_ready:
        fpr_reason = detection_reason
    elif fpr is None:
        fpr_reason = "no negative tested hypotheses or verifier verdicts"
        fpr_basis = "not_measured"
    else:
        fpr_reason = ""
    status["false_positive_rate"] = _status(not fpr_reason, fpr_reason)
    status["false_positive_count"] = _status(detection_ready, detection_reason)

    # Reproducibility: findings reproduced in every run and modal report hash.
    runs = defaultdict(lambda: {"findings": set(), "hashes": []})
    for event in replay_events:
        kind = event["kind"]
        if kind not in ("run_start", "finding", "report"):
            continue
        run_id = str(event.get("run_id") or "default")
        run = runs[run_id]  # count run_start boundaries even without findings/hashes
        if kind == "finding":
            identifiers = identifiers_from(
                [event.get("id"), event.get("type"), event.get("cwe")]
            )
            keys = _match_keys(identifiers, index)
            marker = "gt:" + ",".join(sorted(keys)) if keys else "raw:" + "|".join(sorted(identifiers))
            run["findings"].add(marker)
        elif kind == "report" and event.get("sha256"):
            run["hashes"].append(str(event["sha256"]))
    run_count = len(runs)
    finding_repro = None
    hash_repro = None
    if run_count >= 2:
        all_findings = set()
        for run in runs.values():
            all_findings.update(run["findings"])
        if all_findings:
            finding_repro = sum(
                1 for marker in all_findings
                if all(marker in run["findings"] for run in runs.values())
            ) / len(all_findings)
        hashes = [run["hashes"][0] for run in runs.values() if run["hashes"]]
        if hashes:
            modal = max(set(hashes), key=hashes.count)
            hash_repro = hashes.count(modal) / run_count
    reproducibility = None
    if finding_repro is not None or hash_repro is not None:
        parts = [value for value in (finding_repro, hash_repro) if value is not None]
        reproducibility = sum(parts) / len(parts)
    if run_count < 2:
        repro_reason = "fewer than 2 runs observed in replay"
    elif reproducibility is None:
        repro_reason = "no per-run findings or report hashes"
    else:
        repro_reason = ""
    status["reproducibility"] = _status(not repro_reason, repro_reason)
    status["reproducibility_findings"] = _status(
        finding_repro is not None, "" if finding_repro is not None else repro_reason or "no per-run findings"
    )
    status["reproducibility_report_hash"] = _status(
        hash_repro is not None, "" if hash_repro is not None else repro_reason or "no report hashes"
    )

    # Tokens per verified finding (API usage from replay; no len/4 estimates).
    usage_events = [event for event in replay_events if event["kind"] == "usage"]
    total_tokens = sum(_event_tokens(event) for event in usage_events) if usage_events else None
    valid_findings = len(true_positives)
    tokens_per_finding = (
        total_tokens / valid_findings
        if total_tokens and valid_findings else None
    )
    if not usage_events:
        tpf_reason = "no token usage events in replay"
    elif not total_tokens:
        tpf_reason = "usage events carried no token counts"
    elif not truth_keys:
        tpf_reason = "no ground-truth manifest supplied"
    elif not valid_findings:
        tpf_reason = "no verified true positives to normalise by"
    else:
        tpf_reason = ""
    status["tokens_per_finding"] = _status(not tpf_reason, tpf_reason)
    status["total_tokens"] = _status(bool(usage_events), "no token usage events in replay")

    return {
        "recall": recall,
        "precision": precision,
        "false_positive_rate": fpr,
        "false_positive_count": len(false_positives) if detection_ready else None,
        "false_positive_basis": fpr_basis,
        "false_discovery_rate_proxy": fdr_proxy,
        "false_discovery_rate_proxy_basis": "1 - precision",
        "reproducibility": reproducibility,
        "reproducibility_findings": finding_repro,
        "reproducibility_report_hash": hash_repro,
        "runs_observed": run_count,
        "ground_truth_count": len(truth_keys),
        "reported_findings": len(reported),
        "true_positives": len(true_positives),
        "verified_findings": len(verified),
        "rejected_findings": len(rejected),
        "unverified_findings": len(unverified),
        "report_verdicts": report_verdicts,
        "explicit_verdicts_in_replay": verdict_count,
        "total_tokens": total_tokens,
        "valid_findings": valid_findings,
        "tokens_per_finding": tokens_per_finding,
        "measurement_status": status,
        "metrics_available": {name: value["status"] == "measured" for name, value in status.items()},
    }


def _format(value):
    return "n/a" if value is None else ("%.3f" % value if isinstance(value, float) else str(value))


def _format_metric(name, metrics):
    status = metrics.get("measurement_status", {}).get(name)
    if status and status["status"] == "not_measured":
        return "not_measured (%s)" % status["reason"]
    return _format(metrics[name])


def print_summary(results, metrics, notes):
    for result in results:
        print("Report: %s" % result["path"])
        counts = ", ".join("%s=%d" % (s, result["findings"][s]) for s in SEVERITIES)
        print("  findings: %d (%s)" % (result["total_findings"], counts))
        if result["missing_sections"]:
            print("  MISSING SECTIONS: %s" % ", ".join(result["missing_sections"]))
        for problem in result["problems"]:
            print("  - %s" % problem)
        print()
    total = sum(result["total_findings"] for result in results)
    problems = sum(len(result["problems"]) for result in results)
    print("TOTAL reports=%d findings=%d problems=%d" % (len(results), total, problems))
    print("\nMetrics:")
    for name in (
        "recall",
        "precision",
        "false_positive_rate",
        "false_discovery_rate_proxy",
        "false_positive_count",
        "reproducibility",
        "reproducibility_findings",
        "reproducibility_report_hash",
        "tokens_per_finding",
    ):
        print("  %-28s %s" % (name, _format_metric(name, metrics)))
    print("  %-28s %s" % ("false_positive_basis", metrics["false_positive_basis"]))
    print("  %-28s %s" % (
        "false_discovery_rate_proxy_basis", metrics["false_discovery_rate_proxy_basis"]
    ))
    print("  %-28s %s" % ("ground_truth", metrics["ground_truth_count"]))
    print("  %-28s %s" % ("reported_findings", metrics["reported_findings"]))
    print("  %-28s %s" % ("verified_findings", metrics["verified_findings"]))
    print("  %-28s %s" % ("rejected_findings", metrics["rejected_findings"]))
    print("  %-28s %s" % ("unverified_findings", metrics["unverified_findings"]))
    for note in notes:
        print("  NOTE: %s" % note)
    print("\nNo benchmark results are asserted here. Record real results in eval/results/.")


SELF_TEST_REPORT = """## Executive Summary
Synthetic report used by --self-test only.
## Scope & ROE
Synthetic.
## Methodology
Synthetic.
## Findings
### [High] Genuine reflected XSS
Severity: High
**Type:** reflected XSS
CWE-79
Steps to reproduce, proof of concept, impact and remediation.
### [High] Forged SQL injection (no verifier evidence)
Severity: High
**Type:** SQL injection
CWE-89
Steps to reproduce, proof of concept, impact and remediation.
## Coverage
Synthetic.
## Timeline
Synthetic.
## Appendices
Synthetic.
"""

SELF_TEST_FINDING_MAP_REPORT = """## Executive Summary
Synthetic report with two same-type headings (--self-test only).
## Scope & ROE
Synthetic.
## Methodology
Synthetic.
## Findings
### [High] Genuine reflected XSS
Severity: High
**Type:** reflected XSS
CWE-79
Steps to reproduce, proof of concept, impact and remediation.
### [High] Forged reflected XSS
Severity: High
**Type:** reflected XSS
CWE-79
Steps to reproduce, proof of concept, impact and remediation.
## Coverage
Synthetic.
## Timeline
Synthetic.
## Appendices
Synthetic.
"""


def self_test():
    """Run synthetic replay JSONL cases; return 0 only if every assertion holds."""
    checks = []

    def check(name, condition):
        checks.append((name, bool(condition)))

    def load(events, directory, label):
        path = os.path.join(directory, label + ".jsonl")
        with open(path, "w", encoding="utf-8") as handle:
            for event in events:
                handle.write(json.dumps(event) + "\n")
        replay, warnings = load_replay(path)
        check("%s jsonl loads without warnings" % label, not warnings)
        return replay

    xss = {"key": "xss", "identifiers": identifiers_from(["xss", "CWE-79"])}
    sqli = {"key": "sqli", "identifiers": identifiers_from(["sqli", "CWE-89"])}

    with tempfile.TemporaryDirectory() as directory:
        # 1. A finding with no verdict is unverified, never a true positive.
        replay = load([
            {"kind": "finding", "run_id": "r1", "id": "F-1",
             "type": "reflected XSS", "cwe": "CWE-79"},
        ], directory, "no_verdict")
        m = compute_metrics([], [xss], replay)
        check("finding without verdict is unverified", m["unverified_findings"] == 1)
        check("finding without verdict is not a true positive", m["true_positives"] == 0)
        check("no verifier -> recall is not_measured",
              m["measurement_status"]["recall"]["status"] == "not_measured")
        check("not_measured reason cites verifier evidence",
              "verifier" in m["measurement_status"]["recall"]["reason"])

        # 2. An explicit false verdict is a false positive, not a true positive.
        replay = load([
            {"kind": "finding", "run_id": "r1", "id": "F-2",
             "type": "reflected XSS", "cwe": "CWE-79", "verified": False},
        ], directory, "false_verdict")
        m = compute_metrics([], [xss], replay)
        check("explicit false verdict is rejected", m["rejected_findings"] == 1)
        check("explicit false verdict is not a true positive", m["true_positives"] == 0)
        check("explicit false verdict is counted as FP", m["false_positive_count"] == 1)

        # 3. A verifier event with an explicit true verdict is a true positive;
        #    absent usage keeps tokens_per_finding not_measured.
        replay = load([
            {"kind": "run_start", "run_id": "r1"},
            {"kind": "finding", "run_id": "r1", "id": "F-3",
             "type": "reflected XSS", "cwe": "CWE-79"},
            {"kind": "verifier", "run_id": "r1", "finding_id": "F-3", "verified": True},
        ], directory, "true_verdict")
        m = compute_metrics([], [xss], replay)
        check("run_start boundary is counted", m["runs_observed"] == 1)
        check("verifier true verdict is a true positive", m["true_positives"] == 1)
        check("verified finding is not unverified", m["unverified_findings"] == 0)
        check("no usage -> tokens_per_finding is not_measured",
              m["measurement_status"]["tokens_per_finding"]["status"] == "not_measured")

        # 4. A forged extra finding heading in a report is not promoted.
        report_path = os.path.join(directory, "forged-report.md")
        with open(report_path, "w", encoding="utf-8") as handle:
            handle.write(SELF_TEST_REPORT)
        result = score_report(report_path)
        check("report parser saw both finding headings", result["total_findings"] == 2)
        replay = load([
            {"kind": "finding", "run_id": "r1", "id": "F-4",
             "type": "reflected XSS", "cwe": "CWE-79", "verified": True},
        ], directory, "forged_heading")
        m = compute_metrics([result], [xss, sqli], replay)
        check("no map -> forged heading is not a true positive", m["true_positives"] == 0)
        check("no map -> both report headings remain unverified", m["unverified_findings"] == 2)
        check("forged report has two reported findings", m["reported_findings"] == 2)

        # 5. F2: no negatives -> FPR not_measured, but 1-precision proxy is available.
        replay = load([
            {"kind": "finding", "run_id": "r1", "id": "F-5a",
             "type": "reflected XSS", "cwe": "CWE-79", "verified": True},
            {"kind": "finding", "run_id": "r1", "id": "F-5b",
             "type": "SQL injection", "cwe": "CWE-89", "verified": False},
        ], directory, "no_negatives")
        m = compute_metrics([], [xss], replay)
        check("precision 0.5 from one TP and one FP", m["precision"] == 0.5)
        check("no negatives -> FPR is not_measured",
              m["measurement_status"]["false_positive_rate"]["status"] == "not_measured")
        check("no negatives -> FPR basis is not_measured",
              m["false_positive_basis"] == "not_measured")
        check("no negatives -> FDR proxy is 1 - precision",
              m["false_discovery_rate_proxy"] == 0.5)
        manifest_path = os.path.join(directory, "manifest-xss.json")
        with open(manifest_path, "w", encoding="utf-8") as handle:
            json.dump({"expected_vulns": [{"id": "xss", "type": "reflected XSS", "cwe": "CWE-79"}]}, handle)
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()) as err:
            strict_code = main([
                "--manifest", manifest_path,
                "--replay", os.path.join(directory, "no_negatives.jsonl"),
                "--strict", "--max-fpr", "0.1",
            ])
        check("strict --max-fpr refuses proxy-only basis", strict_code == 1)
        check("strict refusal explains the proxy", "proxy" in err.getvalue().lower())

        # 6. F3: an observed tested hypothesis must not enter the FPR denominator.
        replay = load([
            {"kind": "finding", "run_id": "r1", "id": "F-6",
             "type": "reflected XSS", "cwe": "CWE-79", "verified": True},
            {"kind": "tested", "run_id": "r1", "type": "open redirect",
             "cwe": "CWE-601", "verdict": "observed"},
            {"kind": "tested", "run_id": "r1", "type": "reflected XSS",
             "cwe": "CWE-79", "verdict": "rejected"},
        ], directory, "tested_verdicts")
        m = compute_metrics([], [xss], replay)
        check("negative tested verdict sets FPR basis",
              m["false_positive_basis"] == "replay_tested_hypotheses")
        check("positive tested verdict excluded from denominator",
              m["false_positive_rate"] == 1.0)

        # 7. F2/F3: verifier negatives alone give a measured FPR.
        replay = load([
            {"kind": "finding", "run_id": "r1", "id": "F-7",
             "type": "reflected XSS", "cwe": "CWE-79"},
            {"kind": "verifier", "run_id": "r1", "finding_id": "F-7", "verified": True},
            {"kind": "verifier", "run_id": "r1", "candidate": "SQL injection",
             "cwe": "CWE-89", "verified": False},
        ], directory, "verifier_negative")
        m = compute_metrics([], [xss], replay)
        check("verifier-only negatives basis",
              m["false_positive_basis"] == "replay_verifier_verdicts")
        check("verifier-only FPR is measured",
              m["measurement_status"]["false_positive_rate"]["status"] == "measured")
        check("verifier-only FPR is 0.0", m["false_positive_rate"] == 0.0)

        # 8. F8: two same-type report headings, only the explicitly mapped one
        #    may inherit the replay verdict.
        map_report = os.path.join(directory, "two-same-type.md")
        with open(map_report, "w", encoding="utf-8") as handle:
            handle.write(SELF_TEST_FINDING_MAP_REPORT)
        result = score_report(map_report)
        check("two same-type headings parsed", result["total_findings"] == 2)
        headings = [item["heading"] for item in result["reported"]]
        check("the two headings are distinct", headings[0] != headings[1])
        replay = load([
            {"kind": "finding", "run_id": "r1", "id": "F-8",
             "type": "reflected XSS", "cwe": "CWE-79", "verified": True},
        ], directory, "finding_map")
        unmapped = compute_metrics([result], [xss], replay)
        check("no map -> report headings stay unverified",
              all(row["verdict"] is None for row in unmapped["report_verdicts"]))
        mapped = compute_metrics([result], [xss], replay, {headings[0]: "F-8"})
        check("mapped heading inherits the stable-id verdict",
              mapped["report_verdicts"][0]["verdict"] is True)
        check("unmapped same-type heading stays None",
              mapped["report_verdicts"][1]["verdict"] is None)
        stable_report = os.path.join(directory, "stable-id.md")
        with open(stable_report, "w", encoding="utf-8") as handle:
            handle.write(SELF_TEST_REPORT.replace(
                "### [High] Genuine reflected XSS", "### F-8: Genuine reflected XSS"
            ))
        stable_result = score_report(stable_report)
        stable_metrics = compute_metrics([stable_result], [xss, sqli], replay)
        check("stable finding id in a heading inherits the verdict",
              stable_metrics["true_positives"] == 1)

        # 9. F9: malformed manifests fail cleanly, never with a traceback.
        malformed = os.path.join(directory, "bad-manifest.json")
        with open(malformed, "w", encoding="utf-8") as handle:
            json.dump({"expected_vulns": [42]}, handle)
        try:
            load_manifest(malformed)
            check("malformed manifest entry raises ValueError", False)
        except ValueError:
            check("malformed manifest entry raises ValueError", True)
        with open(malformed, "w", encoding="utf-8") as handle:
            json.dump({"expected_vulns": [{"id": "x", "aliases": {"bad": 1}}]}, handle)
        try:
            load_manifest(malformed)
            check("malformed aliases raise ValueError", False)
        except ValueError:
            check("malformed aliases raise ValueError", True)
        try:
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()) as err:
                main(["--manifest", malformed,
                      "--replay", os.path.join(directory, "no_negatives.jsonl")])
            exit_code = 0
        except SystemExit as error:
            exit_code = error.code
        check("malformed manifest exits non-zero cleanly", exit_code != 0)
        check("malformed manifest produces no traceback", "Traceback" not in err.getvalue())

    for name, passed in checks:
        print("[%s] %s" % ("PASS" if passed else "FAIL", name))
    failed = sum(1 for _, passed in checks if not passed)
    print("self-test: %d/%d passed" % (len(checks) - failed, len(checks)))
    return 1 if failed else 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("reports", nargs="*", help="Markdown report files")
    ap.add_argument("--dir", help="directory to scan recursively for .md reports")
    ap.add_argument("--json", action="store_true", help="emit JSON instead of text")
    ap.add_argument("--strict", action="store_true", help="exit 1 on report problems or threshold violations")
    ap.add_argument("--manifest", help="JSON ground-truth manifest (expected vulns)")
    ap.add_argument("--finding-map", help="JSON heading -> finding id map for report verdicts")
    ap.add_argument("--replay", help="JSONL replay log from an engagement")
    ap.add_argument("--min-recall", type=float, help="strict: require recall >= value")
    ap.add_argument("--min-precision", type=float, help="strict: require precision >= value")
    ap.add_argument("--max-fpr", type=float, help="strict: require FPR <= value")
    ap.add_argument("--self-test", action="store_true", help="run synthetic regression cases and exit")
    args = ap.parse_args(argv)

    if args.self_test:
        return self_test()

    paths = [path for path in args.reports if not path.lower().endswith(".jsonl")]
    replay_positional = [path for path in args.reports if path.lower().endswith(".jsonl")]
    if args.dir:
        paths.extend(discover(args.dir))
    if len(replay_positional) > 1:
        ap.error("only one replay (.jsonl) positional is supported")
    if replay_positional and args.replay:
        ap.error("give the replay either as a .jsonl positional or via --replay, not both")
    replay_path = args.replay or (replay_positional[0] if replay_positional else None)
    if not paths and not replay_path:
        ap.error("provide at least one report, a replay (.jsonl), or --dir")

    notes = []
    ground_truth = []
    finding_map = {}
    replay_events = []
    if args.manifest:
        try:
            ground_truth = load_manifest(args.manifest)
        except (OSError, ValueError, json.JSONDecodeError) as error:
            ap.error("cannot read manifest %s: %s" % (args.manifest, error))
    else:
        notes.append("no --manifest: recall/precision/FPR are not_measured")
    if args.finding_map:
        try:
            finding_map = load_finding_map(args.finding_map)
        except (OSError, ValueError, json.JSONDecodeError) as error:
            ap.error("cannot read finding map %s: %s" % (args.finding_map, error))
    if replay_path:
        try:
            replay_events, replay_warnings = load_replay(replay_path)
        except OSError as error:
            ap.error("cannot read replay %s: %s" % (replay_path, error))
        notes.extend(replay_warnings[:10])
        if not replay_events:
            notes.append("replay contained no usable events")
    else:
        notes.append("no --replay: reproducibility and tokens_per_finding are not computed")

    results = []
    for path in paths:
        try:
            results.append(score_report(path))
        except OSError as error:
            ap.error("cannot read report %s: %s" % (path, error))

    metrics = compute_metrics(results, ground_truth, replay_events, finding_map)
    payload = {
        "reports": [
            {key: value for key, value in result.items() if key != "reported"}
            for result in results
        ],
        "summary": {
            "reports": len(results),
            "findings": sum(result["total_findings"] for result in results),
            "problems": sum(len(result["problems"]) for result in results),
        },
        "metrics": metrics,
        "notes": notes,
        "claim": "scaffolding only — no benchmark results asserted",
    }
    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        print_summary(results, metrics, notes)

    if not args.strict:
        return 0
    if any(result["problems"] for result in results):
        return 1
    if args.max_fpr is not None:
        # --max-fpr is a real FPR gate: never satisfy it with 1 - precision.
        measured_bases = {
            "replay_tested_hypotheses", "replay_verifier_verdicts", "replay_failed_actions"
        }
        if (
            metrics["false_positive_basis"] not in measured_bases
            or metrics["measurement_status"]["false_positive_rate"]["status"] != "measured"
        ):
            print(
                "strict: --max-fpr requires a measured false_positive_rate from "
                "negative tested/verifier events; false_discovery_rate_proxy is not accepted",
                file=sys.stderr,
            )
            return 1
    checks = [
        (args.min_recall, metrics["recall"], lambda a, b: b >= a, "recall"),
        (args.min_precision, metrics["precision"], lambda a, b: b >= a, "precision"),
        (args.max_fpr, metrics["false_positive_rate"], lambda a, b: b <= a, "false_positive_rate"),
    ]
    for threshold, actual, compare, label in checks:
        if threshold is None:
            continue
        if actual is None:
            print("strict: %s unavailable; cannot enforce threshold %s" % (label, threshold), file=sys.stderr)
            return 1
        if not compare(threshold, actual):
            print("strict: %s=%s fails threshold %s" % (label, _format(actual), threshold), file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
