#!/usr/bin/env python3
"""Export SQLite trace_events into the score.py replay JSONL format.

Standard library only. Reads the authoritative engagement trace table

    trace_events(id, engagement_id, run_id, kind, payload_json, created_at)

and emits one JSON object per line with a ``kind`` field that ``score.py``
understands. When ``--merge`` is supplied, the engagement's own
``workspace/replay-<id>.jsonl`` is joined too; trace events win for every kind
both sources provide, and the engagement log only contributes context the trace
does not carry (brief/plan/error/lifecycle). This keeps usage/finding counts
from being double-counted.

Usage:
    python eval/export_trace.py engagement.db replay.jsonl
    python eval/export_trace.py engagement.db replay.jsonl \
        --merge workspace/replay-<id>.jsonl
"""

import argparse
import json
import sqlite3
import sys

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

# Kinds the trace DB is authoritative for when merging two replay sources.
AUTHORITATIVE_KINDS = {
    "run_start", "action", "finding", "usage", "verifier", "report", "tested",
}


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
    event = {
        "kind": kind,
        "run_id": row["run_id"] or row["engagement_id"] or "default",
        "engagement_id": row["engagement_id"],
        "created_at": row["created_at"],
    }
    event.update(payload)
    event["kind"] = kind

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
    connection = sqlite3.connect(db_path)
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


def merged_replay(trace_events, engagement_events):
    trace_kinds = {event["kind"] for event in trace_events}
    result = list(trace_events)
    for event in engagement_events:
        # Prefer the DB for kinds it actually recorded; keep unrelated context.
        if event.get("kind") in AUTHORITATIVE_KINDS and event["kind"] in trace_kinds:
            continue
        result.append(event)
    return result


def write_jsonl(path, events):
    seen = set()
    written = 0
    with open(path, "w", encoding="utf-8") as handle:
        for event in events:
            line = json.dumps(event, ensure_ascii=False, sort_keys=True)
            if line in seen:
                continue
            seen.add(line)
            handle.write(line + "\n")
            written += 1
    return written


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("db", help="engagement SQLite DB (trace_events table)")
    parser.add_argument("out", help="output replay JSONL path")
    parser.add_argument("--merge", help="engagement replay-<id>.jsonl to join")
    args = parser.parse_args(argv)

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
