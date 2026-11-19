#!/usr/bin/env python3
"""Score AgentBug Markdown engagement reports. Standard library only.

Usage:
    python3 score.py report.md [report2.md ...]
    python3 score.py --dir eval/results [--json] [--strict]

Checks, per report:
  * required sections (Executive Summary, Scope & ROE, Methodology, Findings,
    Coverage, Timeline, Appendices)
  * findings counted by severity
  * CVSS v3.1 vector and CWE presence
  * per-finding required fields (steps, PoC, impact, remediation, evidence hash)
"""

import argparse
import json
import os
import re
import sys

REQUIRED_SECTIONS = [
    "Executive Summary",
    "Scope & ROE",
    "Methodology",
    "Findings",
    "Coverage",
    "Timeline",
    "Appendices",
]
SEVERITIES = ["Critical", "High", "Medium", "Low", "None"]
CVSS_RE = re.compile(r"CVSS:3\.1/AV:[NALP]/AC:[LHP]/PR:[NLH]/UI:[NR]/S:[UC]/C:[NLH]/I:[NLH]/A:[NLH]")
CWE_RE = re.compile(r"CWE-\d+")
HASH_RE = re.compile(r"\b[0-9a-fA-F]{64}\b")
FINDING_RE = re.compile(r"^###\s+F[-\d]+", re.MULTILINE)
SEVERITY_RE = re.compile(r"Severity:\s*(Critical|High|Medium|Low|None)", re.IGNORECASE)
BRACKET_SEVERITY_RE = re.compile(r"\[(Critical|High|Medium|Low|None)\]", re.IGNORECASE)

FIELD_PATTERNS = {
    "steps": re.compile(r"steps to reproduce", re.IGNORECASE),
    "poc": re.compile(r"proof of concept|PoC", re.IGNORECASE),
    "impact": re.compile(r"\*\*impact\*\*|impact:", re.IGNORECASE),
    "remediation": re.compile(r"remediation", re.IGNORECASE),
    "evidence_hash": HASH_RE,
}


def _heading_names(text):
    return [m.group(1).strip() for m in re.finditer(r"^##\s+(.+?)\s*$", text, re.MULTILINE)]


def _sections(text):
    parts = re.split(r"^##\s+(.+?)\s*$", text, flags=re.MULTILINE)
    result = {}
    for i in range(1, len(parts) - 1, 2):
        result[parts[i].strip()] = parts[i + 1]
    return result


def score_report(path):
    with open(path, encoding="utf-8", errors="replace") as fh:
        text = fh.read()
    sections = _sections(text)
    headings = _heading_names(text)
    missing_sections = [s for s in REQUIRED_SECTIONS if s not in headings]

    findings_text = sections.get("Findings", "")
    blocks = FINDING_RE.split(findings_text)
    findings = []
    for block in blocks[1:]:
        sev_match = SEVERITY_RE.search(block) or BRACKET_SEVERITY_RE.search(block)
        severity = sev_match.group(1).capitalize() if sev_match else "Unknown"
        missing_fields = [name for name, pat in FIELD_PATTERNS.items() if not pat.search(block)]
        findings.append({
            "severity": severity,
            "cvss_vector": bool(CVSS_RE.search(block)),
            "cwe": bool(CWE_RE.search(block)),
            "missing_fields": missing_fields,
        })

    counts = {s: 0 for s in SEVERITIES}
    counts["Unknown"] = 0
    for f in findings:
        counts[f["severity"] if f["severity"] in counts else "Unknown"] += 1

    problems = []
    if missing_sections:
        problems.append("missing sections: " + ", ".join(missing_sections))
    for i, f in enumerate(findings, 1):
        if not f["cvss_vector"]:
            problems.append("finding %d: missing CVSS v3.1 vector" % i)
        if not f["cwe"]:
            problems.append("finding %d: missing CWE" % i)
        if f["missing_fields"]:
            problems.append("finding %d: missing %s" % (i, ", ".join(f["missing_fields"])))

    return {
        "path": path,
        "findings": counts,
        "total_findings": len(findings),
        "missing_sections": missing_sections,
        "problems": problems,
    }


def discover(directory):
    out = []
    for root, _dirs, files in os.walk(directory):
        for name in files:
            if name.lower().endswith(".md") and name.lower() != "readme.md":
                out.append(os.path.join(root, name))
    return sorted(out)


def print_summary(results):
    for r in results:
        print("Report: %s" % r["path"])
        counts = ", ".join("%s=%d" % (s, r["findings"][s]) for s in SEVERITIES + ["Unknown"])
        print("  findings: %d (%s)" % (r["total_findings"], counts))
        if r["missing_sections"]:
            print("  MISSING SECTIONS: %s" % ", ".join(r["missing_sections"]))
        for p in r["problems"]:
            print("  - %s" % p)
        print()
    total = sum(r["total_findings"] for r in results)
    print("TOTAL reports=%d findings=%d problems=%d" % (
        len(results), total, sum(len(r["problems"]) for r in results)))


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("reports", nargs="*", help="Markdown report files")
    ap.add_argument("--dir", help="directory to scan recursively for .md reports")
    ap.add_argument("--json", action="store_true", help="emit JSON instead of text")
    ap.add_argument("--strict", action="store_true", help="exit 1 if any problems found")
    args = ap.parse_args()

    paths = list(args.reports)
    if args.dir:
        paths.extend(discover(args.dir))
    if not paths:
        ap.error("provide at least one report or --dir")

    results = [score_report(p) for p in paths]
    if args.json:
        print(json.dumps(results, indent=2))
    else:
        print_summary(results)
    if args.strict and any(r["problems"] for r in results):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
