#!/usr/bin/env python3
"""AgentBug evaluation scorer — standard library only.

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

Inputs
    --manifest  JSON: {"expected_vulns": [...]} (see eval/golden.example.json).
                Entries may be strings or objects with id/type/cwe/aliases.
    --replay    JSONL, one event per line. Recognised kinds:
                  run_start {run_id}
                  finding    {run_id, id, type, cwe, verified}
                  tested     {run_id, type, verdict}   (negative hypotheses)
                  usage      {prompt_tokens, completion_tokens}
                  report     {run_id, sha256}
                Unknown kinds and malformed lines are ignored with a warning.

Metrics (computed only when the relevant input is present)
    recall, precision, false_positive_rate (+ count and basis),
    reproducibility (finding + report-hash), tokens_per_finding.
    Section/field checks run for every report regardless of inputs.
"""

import argparse
import json
import os
import re
import sys
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

CVSS_RE = re.compile(
    r"CVSS:3\.1/AV:[NALP]/AC:[LHP]/PR:[NLH]/UI:[NR]/S:[UC]/C:[NLH]/I:[NLH]/A:[NLH]"
)
CWE_RE = re.compile(r"CWE-\d+", re.IGNORECASE)
HASH_RE = re.compile(r"\b[0-9a-fA-F]{64}\b")
# Canonical renderer: "### F-01: ..."; engagement renderer: "### [High] ...".
FINDING_RE = re.compile(
    r"^###\s+(?:F-?\d+\s*:?|\[(?:Critical|High|Medium|Low|None|Info)\]).*$",
    re.MULTILINE | re.IGNORECASE,
)
SEVERITY_RE = re.compile(
    r"Severity:\s*\**\s*(Critical|High|Medium|Low|None)", re.IGNORECASE
)
BRACKET_SEVERITY_RE = re.compile(
    r"\[(Critical|High|Medium|Low|None)\]", re.IGNORECASE
)
TYPE_RE = re.compile(r"(?:\*\*Type:\*\*|Type:)\s*(.+)", re.IGNORECASE)

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
    for block in blocks[1:]:
        severity_match = SEVERITY_RE.search(block) or BRACKET_SEVERITY_RE.search(block)
        severity = severity_match.group(1).capitalize() if severity_match else "Unknown"
        missing_fields = [name for name, pattern in FIELD_PATTERNS.items() if not pattern.search(block)]
        cwes = [cwe_key(m.group(0)) for m in CWE_RE.finditer(block)]
        type_match = TYPE_RE.search(block)
        identifiers = set(cwes)
        identifiers.update(identifiers_from([type_match.group(1)] if type_match else []))
        first_line = next((line.strip("# *") for line in block.splitlines() if line.strip()), "")
        identifiers.update(identifiers_from([first_line]))
        findings.append({
            "severity": severity,
            "cvss_vector": bool(CVSS_RE.search(block)),
            "cwe": bool(cwes),
            "missing_fields": missing_fields,
        })
        reported.append({"identifiers": identifiers, "source": "report"})

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
    for root, _dirs, files in os.walk(directory):
        for name in files:
            if name.lower().endswith(".md") and name.lower() != "readme.md":
                found.append(os.path.join(root, name))
    return sorted(found)


def load_manifest(path):
    with open(path, encoding="utf-8") as handle:
        data = json.load(handle)
    if isinstance(data, list):
        entries = data
    else:
        entries = data.get("expected_vulns", [])
    ground_truth = []
    for index, entry in enumerate(entries):
        if isinstance(entry, str):
            entry = {"id": entry}
        key = str(entry.get("id") or entry.get("type") or entry.get("name") or "vuln-%d" % (index + 1))
        aliases = entry.get("aliases") or []
        if isinstance(aliases, str):
            aliases = [aliases]
        identifiers = identifiers_from([key, entry.get("cwe")] + list(aliases))
        ground_truth.append({"key": key, "identifiers": identifiers})
    return ground_truth


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
                events.append(event)
            else:
                warnings.append("replay line %d: expected an object" % line_number)
    return events, warnings


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


def compute_metrics(results, ground_truth, replay_events):
    """Compute detection/reproducibility metrics dicts; values may be None."""
    index = defaultdict(set)
    for entry in ground_truth:
        for identifier in entry["identifiers"]:
            index[identifier].add(entry["key"])

    reported = []
    for result in results:
        reported.extend(result.get("reported", []))
    for event in replay_events:
        if normalize(event.get("kind")) == "finding":
            identifiers = identifiers_from(
                [event.get("id"), event.get("type"), event.get("cwe")]
                + list(event.get("aliases") or [])
            )
            reported.append({
                "identifiers": identifiers,
                "verified": not _is_false(event.get("verified", True)),
                "source": "replay",
            })
    for item in reported:
        item["keys"] = _match_keys(item["identifiers"], index)
        if _is_false(item.get("verified", True)):
            item["keys"] = set()
    reported = _dedupe(reported)

    truth_keys = {entry["key"] for entry in ground_truth}
    true_positives = [item for item in reported if item["keys"]]
    false_positives = [
        item for item in reported
        if not item["keys"] or _is_false(item.get("verified", True))
    ]
    covered = set()
    for item in true_positives:
        covered.update(item["keys"])

    recall = len(covered & truth_keys) / len(truth_keys) if truth_keys else None
    denominator = len(true_positives) + len(false_positives)
    precision = len(true_positives) / denominator if denominator else None

    # FPR: prefer replay "tested" hypotheses (true negatives), else fall back to
    # the false-discovery rate over reported findings and label the basis.
    negatives = []
    for event in replay_events:
        if normalize(event.get("kind")) not in ("tested", "hypothesis", "probe", "test"):
            continue
        identifiers = identifiers_from([event.get("type"), event.get("id"), event.get("cwe")])
        if not _match_keys(identifiers, index):
            negatives.append(identifiers)
    reported_identifiers = [item["identifiers"] for item in reported]
    if negatives:
        fp_negatives = sum(
            1 for identifiers in negatives
            if any(identifiers & candidate for candidate in reported_identifiers)
        )
        tn = len(negatives) - fp_negatives
        fpr = fp_negatives / (fp_negatives + tn) if (fp_negatives + tn) else None
        fpr_basis = "replay_tested_hypotheses"
    elif precision is not None:
        fpr = 1.0 - precision
        fpr_basis = "reported_findings_fdr_proxy"
    else:
        fpr = None
        fpr_basis = "unavailable"

    # Reproducibility: findings reproduced in every run and modal report hash.
    runs = defaultdict(lambda: {"findings": set(), "hashes": []})
    for event in replay_events:
        run_id = str(event.get("run_id") or "default")
        kind = normalize(event.get("kind"))
        if kind == "finding":
            identifiers = identifiers_from(
                [event.get("id"), event.get("type"), event.get("cwe")]
            )
            keys = _match_keys(identifiers, index)
            marker = "gt:" + ",".join(sorted(keys)) if keys else "raw:" + "|".join(sorted(identifiers))
            runs[run_id]["findings"].add(marker)
        elif kind == "report" and event.get("sha256"):
            runs[run_id]["hashes"].append(str(event["sha256"]))
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

    # Tokens per valid finding (API usage from replay; no len/4 estimates).
    total_tokens = 0
    for event in replay_events:
        if normalize(event.get("kind")) == "usage":
            try:
                total_tokens += int(event.get("prompt_tokens") or 0)
                total_tokens += int(event.get("completion_tokens") or 0)
            except (TypeError, ValueError):
                continue
    valid_findings = len(true_positives) if truth_keys else len(reported)
    tokens_per_finding = total_tokens / valid_findings if valid_findings else None

    return {
        "recall": recall,
        "precision": precision,
        "false_positive_rate": fpr,
        "false_positive_count": len(false_positives),
        "false_positive_basis": fpr_basis,
        "reproducibility": reproducibility,
        "reproducibility_findings": finding_repro,
        "reproducibility_report_hash": hash_repro,
        "runs_observed": run_count,
        "ground_truth_count": len(truth_keys),
        "reported_findings": len(reported),
        "true_positives": len(true_positives),
        "total_tokens": total_tokens,
        "valid_findings": valid_findings,
        "tokens_per_finding": tokens_per_finding,
        "metrics_available": {
            "recall": bool(truth_keys),
            "precision": bool(truth_keys),
            "false_positive_rate": fpr is not None,
            "reproducibility": run_count >= 2,
            "tokens_per_finding": any(
                normalize(event.get("kind")) == "usage" for event in replay_events
            ),
        },
    }


def _format(value):
    return "n/a" if value is None else ("%.3f" % value if isinstance(value, float) else str(value))


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
        "false_positive_count",
        "reproducibility",
        "reproducibility_findings",
        "reproducibility_report_hash",
        "tokens_per_finding",
    ):
        print("  %-28s %s" % (name, _format(metrics[name])))
    print("  %-28s %s" % ("false_positive_basis", metrics["false_positive_basis"]))
    print("  %-28s %s" % ("ground_truth", metrics["ground_truth_count"]))
    print("  %-28s %s" % ("reported_findings", metrics["reported_findings"]))
    for note in notes:
        print("  NOTE: %s" % note)
    print("\nNo benchmark results are asserted here. Record real results in eval/results/.")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("reports", nargs="*", help="Markdown report files")
    ap.add_argument("--dir", help="directory to scan recursively for .md reports")
    ap.add_argument("--json", action="store_true", help="emit JSON instead of text")
    ap.add_argument("--strict", action="store_true", help="exit 1 on report problems or threshold violations")
    ap.add_argument("--manifest", help="JSON ground-truth manifest (expected vulns)")
    ap.add_argument("--replay", help="JSONL replay log from an engagement")
    ap.add_argument("--min-recall", type=float, help="strict: require recall >= value")
    ap.add_argument("--min-precision", type=float, help="strict: require precision >= value")
    ap.add_argument("--max-fpr", type=float, help="strict: require FPR <= value")
    args = ap.parse_args()

    paths = list(args.reports)
    if args.dir:
        paths.extend(discover(args.dir))
    if not paths:
        ap.error("provide at least one report or --dir")

    notes = []
    ground_truth = []
    replay_events = []
    if args.manifest:
        try:
            ground_truth = load_manifest(args.manifest)
        except (OSError, ValueError, json.JSONDecodeError) as error:
            ap.error("cannot read manifest %s: %s" % (args.manifest, error))
    else:
        notes.append("no --manifest: recall/precision/FPR are not computed")
    if args.replay:
        try:
            replay_events, replay_warnings = load_replay(args.replay)
        except OSError as error:
            ap.error("cannot read replay %s: %s" % (args.replay, error))
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

    metrics = compute_metrics(results, ground_truth, replay_events)
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
