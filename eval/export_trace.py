#!/usr/bin/env python3
"""Export SQLite trace_events into the score.py replay JSONL format.

Standard library only. Reads the authoritative engagement trace table

    trace_events(id, engagement_id, run_id, kind, payload_json, created_at)

and emits one JSON object per line with a ``kind`` field that ``score.py``
understands. The DB is opened read-only (``mode=ro``). When ``--merge`` is
supplied, the engagement's own ``workspace/replay-<id>.jsonl`` is joined too:
events are deduplicated by stable identity (finding id / tested type, etc.),
the trace values win on conflicts, and evidence fields from the engagement log
(evidence, capture, hashes, request/response, ...) are merged rather than
silently dropped. Brief/plan/error/lifecycle context is still retained.

Usage:
    python eval/export_trace.py engagement.db replay.jsonl
    python eval/export_trace.py engagement.db replay.jsonl \
        --merge workspace/replay-<id>.jsonl
"""

import argparse
import json
import os
import sqlite3
import sys
import tempfile
from pathlib import Path
from urllib.parse import quote

# Event spellings seen in trace_events and in the engagement replay log.
KIND_ALIASES = {
    "started": "run_start",
    "engagement.start": "run_start",
    "run.start": "run_start",
    "finding.saved": "finding",
    "engagement.finding": "finding",
    "token_usage": "usage",
    "tokens": "usage",
    "token": "usage",
    "verify": "verifier",
    "poc.verified": "verifier",
    "verifier.result": "verifier",
    "report.ready": "report",
    "report_ready": "report",
    "report.exported": "report",
}

# Stable identities used to dedupe across sources. The tuple selects the first
# available field; unrelated/context events fall back to their full JSON shape.
IDENTITY_FIELDS = {
    "run_start": ("run_id",),
    "finding": ("id", "finding_id"),
    "verifier": ("finding_id", "candidate", "id"),
    "tested": ("id", "type", "cwe"),
    "usage": ("run_id",),
    "report": ("sha256", "run_id"),
    "action": ("call_id", "id", "tool"),
}
# Evidence carried by engagement logs must survive a merge with trace events.
EVIDENCE_FIELDS = (
    "evidence", "evidence_hash", "capture", "request", "response", "artifact",
    "sha256", "oracle", "details", "raw", "notes", "target", "url",
)


def normalize_kind(value):
    text = str(value or "").strip().lower()
    return KIND_ALIASES.get(text, text)


def _token_value(payload, *names):
    usage = payload.get("usage")
    if isinstance(usage, dict):
        for name in names:
            if name in usage:
                return usage[name]
    for name in names:
        if name in payload:
            return payload[name]
    return 0


def normalize_tokens(payload):
    """Return (prompt_tokens, completion_tokens) from any common spelling."""
    prompt = _token_value(payload, "prompt_tokens", "input_tokens", "prompt")
    completion = _token_value(payload, "completion_tokens", "output_tokens", "completion")
    if not prompt and not completion:
        total = _token_value(payload, "total_tokens", "tokens")
        if total:
            completion = total
    try:
        return int(prompt or 0), int(completion or 0)
    except (TypeError, ValueError):
        return 0, 0


def _explicit_bool(payload, *names):
    """Return a real boolean from named fields only; never coerce strings.

    Verification evidence must be explicit. A string such as "result":
    "completed" must not become ``verified: true`` in the exported replay.
    """
    for name in names:
        value = payload.get(name)
        if isinstance(value, bool):
            return value
    return None


def _verdict(payload):
    """Loose success parsing for tool actions only, never for verification."""
    for name in ("verified", "verdict", "ok", "success", "result"):
        if name in payload:
            value = payload[name]
            if isinstance(value, bool):
                return value
            return str(value).strip().lower() not in ("false", "0", "no", "rejected", "failed")
    return None


def event_from_row(row):
    """Turn one trace_events row into a score.py-compatible event."""
    try:
        payload = json.loads(row["payload_json"] or "{}")
    except (TypeError, ValueError):
        payload = {"raw": row["payload_json"]}
    if not isinstance(payload, dict):
        payload = {"value": payload}

    kind = normalize_kind(row["kind"])
    # F10: payload keys go in first; authoritative DB columns are written last
    # so a forged payload cannot impersonate kind/run_id/engagement_id/time.
    event = {}
    event.update(payload)
    event["kind"] = kind
    event["run_id"] = row["run_id"] or row["engagement_id"] or "default"
    event["engagement_id"] = row["engagement_id"]
    event["created_at"] = row["created_at"]

    if kind == "finding":
        if not event.get("id"):
            event["id"] = payload.get("finding_id") or payload.get("finding")
        if not event.get("type"):
            event["type"] = payload.get("vuln_type") or payload.get("class")
        verdict = _explicit_bool(payload, "verified", "verdict")
        if verdict is not None:
            event["verified"] = verdict

    if kind == "usage":
        event["prompt_tokens"], event["completion_tokens"] = normalize_tokens(payload)

    if kind == "verifier":
        # The engagement verifier emits `candidate`; older replays may use
        # `finding_id`. Keep both additive mappings so score.py sees the verdict.
        event["candidate"] = payload.get("candidate") or payload.get("finding_id") or ""
        event["finding_id"] = payload.get("finding_id") or payload.get("candidate") or event.get("id")
        verdict = _explicit_bool(payload, "verified", "verdict")
        if verdict is not None:
            event["verified"] = verdict

    if kind == "action":
        verdict = _verdict(payload)
        if verdict is not None:
            event["ok"] = verdict
        if not event.get("type"):
            event["type"] = payload.get("hypothesis") or payload.get("vuln_type")

    if kind == "report" and not event.get("sha256"):
        event["sha256"] = payload.get("sha256", "")

    # Additive provenance keys; ignored by older scorers, available to R6 metrics.
    for key in ("type", "cwe", "oracle_type", "target_id", "tier", "lane", "verdict"):
        if key in payload and key not in event:
            event[key] = payload[key]
    return event


def load_trace(db_path):
    # A URI read-only connection cannot create or mutate the evidence DB.
    if not os.path.isfile(db_path):
        raise OSError("database file not found: %s" % db_path)
    uri = "file:" + quote(Path(db_path).resolve().as_posix(), safe="/") + "?mode=ro"
    connection = sqlite3.connect(uri, uri=True)
    connection.row_factory = sqlite3.Row
    try:
        rows = connection.execute(
            "SELECT engagement_id, run_id, kind, payload_json, created_at "
            "FROM trace_events ORDER BY rowid"
        ).fetchall()
    finally:
        connection.close()
    events = [event_from_row(row) for row in rows]

    # A run boundary is hard to infer from payloads alone; emit one explicit
    # run_start per run_id so score.py can compute reproducibility (N>=2 runs).
    seen_runs = {str(event.get("run_id")) for event in events if event["kind"] == "run_start"}
    inferred = []
    for event in events:
        run_id = str(event.get("run_id") or "default")
        if run_id in seen_runs:
            continue
        seen_runs.add(run_id)
        inferred.append({
            "kind": "run_start",
            "run_id": run_id,
            "engagement_id": event.get("engagement_id"),
        })
    return inferred + events


def load_engagement_replay(path):
    events = []
    with open(path, encoding="utf-8", errors="replace") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(event, dict):
                continue
            if "kind" not in event and "event" in event:
                event["kind"] = normalize_kind(event["event"])
            elif "kind" in event:
                event["kind"] = normalize_kind(event["kind"])
            events.append(event)
    return events


def event_identity(event):
    """Stable identity for dedupe, independent of JSON key order."""
    kind = str(event.get("kind") or "")
    for name in IDENTITY_FIELDS.get(kind, ()):
        value = event.get(name)
        if value not in (None, "", 0):
            return (kind, str(value))
    return (kind, json.dumps(event, sort_keys=True, ensure_ascii=False, default=str))


def merge_events(primary, secondary):
    """Merge evidence from ``secondary`` into authoritative ``primary``."""
    merged = dict(secondary)
    merged.update(primary)
    for key in EVIDENCE_FIELDS:
        if key not in secondary:
            continue
        if key not in primary or primary[key] in (None, "", [], {}):
            merged[key] = secondary[key]
        elif isinstance(primary[key], dict) and isinstance(secondary[key], dict):
            combined = dict(secondary[key])
            combined.update(primary[key])
            merged[key] = combined
    return merged


def dedupe_events(events):
    """One event per stable identity; duplicate evidence is merged, not lost."""
    positions = {}
    unique = []
    for event in events:
        key = event_identity(event)
        if key in positions:
            unique[positions[key]] = merge_events(unique[positions[key]], event)
        else:
            positions[key] = len(unique)
            unique.append(dict(event))
    return unique


def merged_replay(trace_events, engagement_events):
    # Trace rows are authoritative, but engagement finding/tested events with
    # the same identity contribute their evidence instead of being dropped.
    return dedupe_events(list(trace_events) + list(engagement_events))


def write_jsonl(path, events):
    written = 0
    with open(path, "w", encoding="utf-8") as handle:
        for event in dedupe_events(events):
            handle.write(json.dumps(event, ensure_ascii=False, sort_keys=True) + "\n")
            written += 1
    return written


def self_test():
    checks = []

    def check(name, condition):
        checks.append((name, bool(condition)))

    payload = {
        "kind": "run_start",
        "run_id": "forged-run",
        "engagement_id": "forged-engagement",
        "created_at": "1999-01-01T00:00:00Z",
        "id": "F-1",
        "type": "reflected XSS",
        "evidence": {"source": "payload"},
    }
    row = {
        "kind": "finding.saved",
        "run_id": "r1",
        "engagement_id": "e1",
        "created_at": "2026-11-28T00:00:00Z",
        "payload_json": json.dumps(payload),
    }
    event = event_from_row(row)
    check("payload cannot override authoritative kind", event["kind"] == "finding")
    check("payload cannot override authoritative run_id", event["run_id"] == "r1")
    check("payload cannot override authoritative engagement_id", event["engagement_id"] == "e1")
    check("payload cannot override authoritative created_at",
          event["created_at"] == "2026-11-28T00:00:00Z")
    check("non-authoritative payload fields survive", event.get("evidence") == {"source": "payload"})

    trace = [{"kind": "finding", "id": "F-1", "type": "reflected XSS",
              "verified": True, "run_id": "r1"}]
    engagement = [
        {"kind": "finding", "id": "F-1", "type": "reflected XSS", "verified": True,
         "run_id": "r1", "evidence": {"capture": "raw"}, "evidence_hash": "abc123"},
        {"kind": "tested", "type": "open redirect", "verdict": "rejected",
         "run_id": "r1", "evidence": {"note": "x"}},
        {"kind": "tested", "type": "open redirect", "verdict": "rejected",
         "run_id": "r1", "evidence": {"note": "x"}},
    ]
    merged = merged_replay(trace, engagement)
    finding = next(item for item in merged if item["kind"] == "finding")
    check("engagement finding evidence merged", finding.get("evidence") == {"capture": "raw"})
    check("engagement evidence_hash merged", finding.get("evidence_hash") == "abc123")
    check("duplicate tested events deduped by identity",
          sum(1 for item in merged if item["kind"] == "tested") == 1)

    with tempfile.TemporaryDirectory() as directory:
        db_path = os.path.join(directory, "trace.db")
        try:
            load_trace(db_path)
            check("missing DB is rejected cleanly", False)
        except OSError:
            check("missing DB is rejected cleanly", True)
        check("read-only connect did not create a DB", not os.path.exists(db_path))
        connection = sqlite3.connect(db_path)
        connection.execute(
            "CREATE TABLE trace_events(id TEXT, engagement_id TEXT, run_id TEXT, "
            "kind TEXT, payload_json TEXT, created_at TEXT)"
        )
        connection.execute(
            "INSERT INTO trace_events VALUES(?,?,?,?,?,?)",
            ("1", "e1", "r1", "finding.saved",
             json.dumps({"id": "F-1", "type": "reflected XSS", "verified": True}),
             "2026-11-28T00:00:00Z"),
        )
        connection.commit()
        connection.close()
        loaded = load_trace(db_path)
        check("read-only URI still reads existing DB",
              any(item["kind"] == "finding" for item in loaded))
        out = os.path.join(directory, "replay.jsonl")
        count = write_jsonl(out, merged_replay(loaded, engagement))
        written = load_engagement_replay(out)
        findings = [item for item in written if item["kind"] == "finding"]
        check("dedupe keeps exactly one finding", len(findings) == 1 and count == len(written))
        check("dedupe preserves engagement evidence", findings[0].get("evidence") == {"capture": "raw"})

    for name, passed in checks:
        print("[%s] %s" % ("PASS" if passed else "FAIL", name))
    failed = sum(1 for _, passed in checks if not passed)
    print("export_trace self-test: %d/%d passed" % (len(checks) - failed, len(checks)))
    return 1 if failed else 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true", help="run offline regression cases")
    parser.add_argument("db", help="engagement SQLite DB (trace_events table)", nargs="?")
    parser.add_argument("out", help="output replay JSONL path", nargs="?")
    parser.add_argument("--merge", help="engagement replay-<id>.jsonl to join")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    if not args.db or not args.out:
        parser.error("db and out are required unless --self-test is used")

    try:
        events = load_trace(args.db)
    except (OSError, sqlite3.Error) as error:
        print("export_trace: cannot read %s: %s" % (args.db, error), file=sys.stderr)
        return 1
    if args.merge:
        try:
            events = merged_replay(events, load_engagement_replay(args.merge))
        except OSError as error:
            print("export_trace: cannot read replay %s: %s" % (args.merge, error), file=sys.stderr)
            return 1
    try:
        count = write_jsonl(args.out, events)
    except OSError as error:
        print("export_trace: cannot write %s: %s" % (args.out, error), file=sys.stderr)
        return 1
    print("export_trace: wrote %d events to %s" % (count, args.out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
