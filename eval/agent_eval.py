#!/usr/bin/env python3
"""BugFound V3 agent-quality evaluation harness (design: docs/architecture/06).

Reads exported traces (investigation audit JSONL), the investigation state and
the local report, then computes the metrics that can be computed from those
artifacts. Everything else is reported as ``not_measured`` — a synthetic
example must never be presented as an effectiveness result.

Usage:
    python eval/agent_eval.py --events <audit.jsonl> [--state <state.json>]
                              [--report <report.md>] [--out <metrics.json>]
    python eval/agent_eval.py --self-test
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any

REQUIRED_EVENT_FIELDS = ("id", "kind", "actor", "step_id", "call_id", "hash")
# Preimage fields of the store's investigation_event chain (store/lib.rs D11).
LEGACY_HASH_FIELDS = (
    "prev_hash", "run_id", "step_id", "call_id", "kind", "actor", "payload_json",
)
HASH_FIELDS_V2 = LEGACY_HASH_FIELDS[:1] + (
    "id", "engagement_id",
) + LEGACY_HASH_FIELDS[1:] + ("created_at", "hash_version_marker")
HASH_MARKER = "v2"


def _field(event: dict[str, Any], name: str) -> str:
    value = event.get(name)
    return "" if value is None else str(value)


def _sha256(preimage: str) -> str:
    return hashlib.sha256(preimage.encode("utf-8")).hexdigest()


def _chained_events(pairs: list[tuple[str, str]]) -> list[dict[str, Any]]:
    """Build a valid v2 store-style chain for self-tests."""
    previous = ""
    events: list[dict[str, Any]] = []
    for index, (kind, payload) in enumerate(pairs):
        event: dict[str, Any] = {
            "id": "e%d" % index,
            "kind": kind,
            "actor": "harness",
            "run_id": "run-1",
            "engagement_id": "eng-1",
            "step_id": str(index),
            "call_id": "c1",
            "created_at": "2026-11-28T00:00:%02dZ" % index,
            "prev_hash": previous,
            "payload_json": payload,
            "hash_version": 2,
        }
        fields = [name for name in HASH_FIELDS_V2 if name != "hash_version_marker"]
        event["hash"] = _sha256(
            "|".join(_field(event, name) for name in fields) + "|" + HASH_MARKER
        )
        previous = event["hash"]
        events.append(event)
    return events


def load_events(path: Path, warnings: list[str] | None = None) -> list[dict[str, Any]]:
    """Parse line by line: one malformed line must not discard the whole run."""
    events: list[dict[str, Any]] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as error:
            if warnings is not None:
                warnings.append("line %d: invalid JSON (%s)" % (line_number, error.msg))
            continue
        if isinstance(row, dict):
            events.append(row)
        elif warnings is not None:
            warnings.append("line %d: expected an object" % line_number)
    return events


def verify_hash_chain(events: list[dict[str, Any]]) -> dict[str, Any]:
    """Recompute the investigation_event chain; v1 and v2 preimages are both legal.

    store/lib.rs v1: prev_hash|run_id|step_id|call_id|kind|actor|payload_json
    v2 adds id/engagement_id/created_at and the ``v2`` marker (D11/R12). Legacy
    rows (hash_version < 2) are never rewritten, so both formulas are accepted.
    """
    expected_prev = ""
    broken: list[int] = []
    verified = 0
    for index, event in enumerate(events):
        if not all(name in event for name in (
            "prev_hash", "hash", "run_id", "step_id", "call_id",
            "kind", "actor", "payload_json", "id", "engagement_id", "created_at",
        )):
            broken.append(index)
            expected_prev = _field(event, "hash")
            continue
        if _field(event, "prev_hash") != expected_prev:
            broken.append(index)
            expected_prev = _field(event, "hash")
            continue
        legacy = _sha256("|".join(_field(event, name) for name in LEGACY_HASH_FIELDS))
        current_fields = [name for name in HASH_FIELDS_V2 if name != "hash_version_marker"]
        current = _sha256(
            "|".join(_field(event, name) for name in current_fields) + "|" + HASH_MARKER
        )
        try:
            version = int(event.get("hash_version", 1))
        except (TypeError, ValueError):
            version = 1
        valid = (
            _field(event, "hash") == current
            if version >= 2
            else _field(event, "hash") in (legacy, current)
        )
        if valid:
            verified += 1
        else:
            broken.append(index)
        expected_prev = _field(event, "hash")
    return {
        "ok": not broken,
        "verified": verified,
        "events": len(events),
        "broken_indexes": broken[:20],
        "reason": "" if not broken else "hash or prev_hash mismatch / missing chain fields",
    }


def audit_completeness(events: list[dict[str, Any]]) -> dict[str, Any]:
    missing = [
        index
        for index, event in enumerate(events)
        if any(field not in event for field in REQUIRED_EVENT_FIELDS)
    ]
    return {
        "events": len(events),
        "complete": len(events) - len(missing),
        "missing_indexes": missing[:20],
        "ok": not missing,
    }


def _ratio(numerator: int, denominator: int) -> float:
    """Ratios are bounded to [0, 1]; a count anomaly cannot report >100%."""
    if denominator <= 0:
        return 0.0
    return round(min(1.0, max(0.0, numerator / denominator)), 3)


def replan_proxy(events: list[dict[str, Any]]) -> dict[str, Any]:
    plans = sum(1 for event in events if event.get("kind") == "plan_generated")
    transitions = sum(1 for event in events if event.get("kind") == "state_transition")
    if plans == 0:
        return {"value": "not_measured", "reason": "no plan_generated events"}
    return {
        "value": _ratio(transitions, plans),
        "plan_events": plans,
        "state_transitions": transitions,
        "note": "proxy only; fixture ground truth required for M2",
    }


def stop_quality(events: list[dict[str, Any]]) -> dict[str, Any]:
    stops = [event for event in events if event.get("kind") == "stop_reason"]
    if not stops:
        return {"value": "not_measured", "reason": "no stop_reason events"}
    return {
        "value": dict(Counter(str(event.get("payload_json", "")) for event in stops)),
        "note": "counts only; goal-satisfied classification needs fixture truth",
    }


def efficiency(events: list[dict[str, Any]]) -> dict[str, Any]:
    kinds = Counter(str(event.get("kind", "")) for event in events)
    return {
        "tool_invoked": kinds.get("tool_invoked", 0),
        "policy_decisions": kinds.get("policy_decision", 0),
        "denials": sum(
            1
            for event in events
            if event.get("kind") == "policy_decision"
            and "deny" in str(event.get("payload_json", "")).lower()
        ),
        "tokens": "not_measured",
        "cost_usd": "not_measured",
    }


def reproducibility(runs: int) -> dict[str, Any]:
    if runs < 2:
        return {"value": "not_measured", "reason": "fewer than 2 recorded runs"}
    return {"value": "not_measured", "reason": "verifier comparison not yet wired"}


def evaluate(
    events: list[dict[str, Any]],
    state: dict[str, Any] | None,
    report: str | None,
    runs: int,
) -> dict[str, Any]:
    coverage_rows = (
        len(state["coverage"])
        if isinstance(state, dict) and isinstance(state.get("coverage"), list)
        else 0
    )
    metrics: dict[str, Any] = {
        "M1_useful_next_step": {
            "value": "not_measured",
            "reason": "requires fixture ground truth",
        },
        "M2_replan_coherence": replan_proxy(events),
        "M3_hypothesis_quality": {
            "value": "not_measured",
            "reason": "requires fixture labels",
        },
        "M4_coverage": (
            {"value": coverage_rows, "rows": coverage_rows}
            if state and isinstance(state.get("coverage"), list)
            else {
                "value": "not_measured",
                "rows": "not_measured",
                "reason": "no coverage rows in state",
            }
        ),
        "M5_reproducibility": reproducibility(runs),
        "M6_efficiency": efficiency(events),
        "M7_scope_compliance": {
            "value": "not_measured",
            "reason": "adversarial suite not yet recorded",
        },
        "M8_injection_resistance": {
            "value": "not_measured",
            "reason": "adversarial suite not yet recorded",
        },
        "M9_resume_consistency": {"value": "not_measured", "reason": "needs interrupted runs"},
        "M10_consistency": {"value": "not_measured", "reason": "needs multiple runs"},
        "M11_stop_quality": stop_quality(events),
        "M12_audit_completeness": audit_completeness(events),
        "hash_chain": verify_hash_chain(events),
        "report_sections": (
            sorted(
                section
                for section in (
                    "Executive Summary",
                    "Scope",
                    "Methodology",
                    "Findings",
                    "Coverage",
                    "Timeline",
                    "Appendices",
                )
                if report and section in report
            )
            if report
            else []
        ),
        "claim": "No effectiveness claim is made by this harness.",
    }
    return metrics


def self_test() -> int:
    events = _chained_events([
        ("plan_generated", '{"steps": 2}'),
        ("tool_invoked", '{"tool": "http_request"}'),
        ("state_transition", '{"revision": 2}'),
        ("stop_reason", "goal_satisfied"),
    ])
    state = {"coverage": [{"target": "example.test"}]}
    metrics = evaluate(events, state, "## Findings\n\n_no findings_", runs=1)
    assert metrics["M12_audit_completeness"]["ok"] is True
    assert metrics["M2_replan_coherence"]["value"] == 1.0
    assert metrics["M4_coverage"]["rows"] == 1
    assert metrics["M4_coverage"]["value"] == 1
    assert metrics["M5_reproducibility"]["value"] == "not_measured"
    assert metrics["M11_stop_quality"]["value"] != "not_measured"
    assert metrics["hash_chain"]["ok"] is True

    bad = [{"id": "x", "kind": "plan_generated"}]
    assert evaluate(bad, None, None, 1)["M12_audit_completeness"]["ok"] is False

    # Tampering with a payload breaks the recomputed hash chain.
    tampered = [dict(event) for event in events]
    tampered[2]["payload_json"] = '{"revision": 999}'
    chain = verify_hash_chain(tampered)
    assert chain["ok"] is False and 2 in chain["broken_indexes"]
    # Legacy v1 rows remain valid and are never rewritten (R12/D11).
    legacy = dict(events[0])
    legacy["hash_version"] = 1
    legacy["hash"] = _sha256("|".join(_field(legacy, name) for name in LEGACY_HASH_FIELDS))
    assert verify_hash_chain([legacy])["ok"] is True

    # Ratio metrics cannot exceed 1 even if transitions outnumber plans.
    many = _chained_events(
        [("plan_generated", "{}")] + [("state_transition", "{}") for _ in range(3)]
    )
    assert evaluate(many, None, None, 1)["M2_replan_coherence"]["value"] == 1.0

    # One malformed or non-object line must not abort the whole run.
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "audit.jsonl"
        path.write_text(
            "\n".join([
                json.dumps(events[0]), "{not json}", "[1, 2]", json.dumps(events[1]),
            ]) + "\n",
            encoding="utf-8",
        )
        warnings: list[str] = []
        parsed = load_events(path, warnings)
        assert len(parsed) == 2 and len(warnings) == 2
        assert evaluate(parsed, state, None, 1)["hash_chain"]["ok"] is True

    print("agent_eval self-test: ok")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--events", type=Path, help="investigation audit JSONL")
    parser.add_argument("--state", type=Path, help="investigation state JSON")
    parser.add_argument("--report", type=Path, help="local report markdown")
    parser.add_argument("--runs", type=int, default=1, help="number of recorded runs")
    parser.add_argument("--out", type=Path, help="write metrics JSON to this path")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        return self_test()
    if args.events is None:
        parser.error("--events is required unless --self-test is used")

    warnings: list[str] = []
    events = load_events(args.events, warnings)
    for warning in warnings:
        print("agent_eval: skipped %s" % warning, file=sys.stderr)
    state = json.loads(args.state.read_text(encoding="utf-8")) if args.state else None
    report = args.report.read_text(encoding="utf-8") if args.report else None
    metrics = evaluate(events, state, report, args.runs)
    payload = json.dumps(metrics, indent=2, sort_keys=True)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(payload + "\n", encoding="utf-8")
    print(payload)
    return 0


if __name__ == "__main__":
    sys.exit(main())
