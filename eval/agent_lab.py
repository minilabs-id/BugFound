#!/usr/bin/env python3
"""Local, authorised fixture lab for BugFound V3 agent metrics.

Runs the real CLI against a loopback-only fixture brief N times, exports the
resulting investigation audit events and report, and feeds them to
``agent_eval.py``. All artifacts stay under ``eval/work/agent-lab`` (gitignored).

This is FIXTURE VERIFICATION, not an effectiveness benchmark. Metrics without
recorded evidence remain ``not_measured``. No public target is contacted.

Usage:
    python eval/agent_lab.py --runs 3
    python eval/agent_lab.py --runs 3 --binary /path/to/bugfound
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import socket
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

from agent_eval import evaluate

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "eval" / "fixtures" / "agent"
WORK = ROOT / "eval" / "work" / "agent-lab"

# Ambient provider credentials must never leak into fixture subprocesses.
SECRET_ENV_KEYS = (
    "BUGFOUND_API_KEY",
    "OPENAI_API_KEY",
    "BUGFOUND_BASE_URL",
    "BUGFOUND_MODEL",
    "ANTHROPIC_API_KEY",
)
ENV_ALLOWLIST = ("PATH", "SystemRoot", "TEMP", "TMP", "HOME", "USERPROFILE")
REQUIRED_TABLES = (
    "engagements",
    "sessions",
    "investigation_events",
    "investigation_state",
    "trace_events",
    "finding_provenance",
)


def minimal_env() -> dict[str, str]:
    """Pass only transport/OS keys, with provider credentials explicitly dropped."""
    env = {key: os.environ[key] for key in ENV_ALLOWLIST if key in os.environ}
    for key in SECRET_ENV_KEYS:
        env.pop(key, None)
    return env


def default_binary() -> Path:
    for name in ("bugfound.exe", "bugfound"):
        candidate = ROOT / "target" / "debug" / name
        if candidate.exists():
            return candidate
    return Path("bugfound")


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def write_config(
    path: Path, fixture: dict, adaptive: bool, llm_base: str | None = None
) -> None:
    in_scope = ", ".join(f'"{item}"' for item in fixture["scope"]["in"])
    out_scope = ", ".join(f'"{item}"' for item in fixture["scope"]["out"])
    path.write_text(
        "\n".join(
            [
                "[llm]",
                f'base_url = "{llm_base or "http://127.0.0.1:1/v1"}"',
                'api_key = "lab-key"' if llm_base else 'api_key = ""',
                'default_model = "mock"' if llm_base else "",
                "",
                "[agent]",
                'mode = "full_auto"',
                "max_steps = 6",
                f"llm_planning = {'true' if adaptive else 'false'}",
                "",
                "[network]",
                'trusted_local_targets = ["127.0.0.1"]' if llm_base else "",
                "",
                "[scope]",
                f"in_scope = [{in_scope}]",
                f"out_of_scope = [{out_scope}]",
                "",
            ]
        ),
        encoding="utf-8",
    )


def table_exists(conn: sqlite3.Connection, name: str) -> bool:
    return (
        conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)
        ).fetchone()
        is not None
    )


def assert_run_ok(completed: subprocess.CompletedProcess, db: Path) -> None:
    """Fail closed: a crashed CLI or half-initialised DB is not a green run."""
    if completed.returncode != 0:
        raise AssertionError(
            f"CLI exited with {completed.returncode} (db={db}); see stdout.log/stderr.log"
        )
    if not db.exists():
        raise AssertionError(f"CLI database missing: {db}")
    conn = sqlite3.connect(db)
    try:
        missing = [name for name in REQUIRED_TABLES if not table_exists(conn, name)]
        if missing:
            raise AssertionError(f"CLI database missing tables: {', '.join(missing)} ({db})")
        # An engagement run persists investigation-level state, not runner
        # sessions: `sessions` is legitimately empty for `engage`. Require rows
        # only in tables the engagement path actually writes.
        for name in (
            "engagements",
            "investigation_events",
            "investigation_state",
            "trace_events",
            "reports",
        ):
            count = conn.execute(f"SELECT COUNT(*) FROM {name}").fetchone()[0]
            if not count:
                raise AssertionError(f"CLI database table {name} has no rows ({db})")
    finally:
        conn.close()


def export_events(db: Path, out: Path) -> int:
    if not db.exists():
        out.write_text("", encoding="utf-8")
        return 0
    conn = sqlite3.connect(db)
    try:
        if not table_exists(conn, "investigation_events"):
            out.write_text("", encoding="utf-8")
            return 0
        rows = conn.execute(
            "SELECT id,kind,actor,step_id,call_id,payload_json,prev_hash,hash,created_at "
            "FROM investigation_events ORDER BY rowid ASC"
        ).fetchall()
        keys = (
            "id",
            "kind",
            "actor",
            "step_id",
            "call_id",
            "payload_json",
            "prev_hash",
            "hash",
            "created_at",
        )
        out.write_text(
            "".join(json.dumps(dict(zip(keys, row))) + "\n" for row in rows),
            encoding="utf-8",
        )
        return len(rows)
    finally:
        conn.close()


def export_state(db: Path, out: Path) -> bool:
    if not db.exists():
        return False
    conn = sqlite3.connect(db)
    try:
        if not table_exists(conn, "investigation_state"):
            return False
        row = conn.execute(
            "SELECT state_json FROM investigation_state ORDER BY rowid DESC LIMIT 1"
        ).fetchone()
        if not row:
            return False
        out.write_text(row[0], encoding="utf-8")
        return True
    finally:
        conn.close()


def export_provenance(db: Path) -> list[dict]:
    if not db.exists():
        return []
    conn = sqlite3.connect(db)
    try:
        if not table_exists(conn, "finding_provenance"):
            return []
        rows = conn.execute(
            "SELECT finding_id,catalog_version,tlp_label,verdict,confidence,oracle "
            "FROM finding_provenance"
        ).fetchall()
        keys = ("finding_id", "catalog_version", "tlp_label", "verdict", "confidence", "oracle")
        return [dict(zip(keys, row)) for row in rows]
    finally:
        conn.close()


def run_one(
    binary: Path,
    run_index: int,
    fixture: dict,
    adaptive: bool,
    llm_base: str | None = None,
) -> dict:
    run_dir = WORK / f"run-{run_index:02d}"
    run_dir.mkdir(parents=True, exist_ok=True)
    db = run_dir / "engagement.db"
    config = run_dir / "bugfound.toml"
    briefing = run_dir / "brief.txt"
    briefing.write_text((FIXTURE / "brief.txt").read_text(encoding="utf-8"), encoding="utf-8")
    write_config(config, fixture, adaptive, llm_base)

    command = [
        str(binary),
        "--config",
        str(config),
        "engage",
        "--brief-file",
        str(briefing),
        "--cwd",
        str(run_dir),
        "--db",
        str(db),
    ]
    environment = minimal_env()
    if llm_base:
        # Deliberate loopback-only mock provider values, never ambient credentials.
        environment.update(
            {
                "BUGFOUND_API_KEY": "lab-key",
                "BUGFOUND_BASE_URL": llm_base,
                "BUGFOUND_MODEL": "mock",
            }
        )
    completed = subprocess.run(
        command, capture_output=True, text=True, timeout=300, env=environment
    )
    (run_dir / "stdout.log").write_text(completed.stdout, encoding="utf-8")
    (run_dir / "stderr.log").write_text(completed.stderr, encoding="utf-8")
    assert_run_ok(completed, db)

    events_path = run_dir / "audit.jsonl"
    state_path = run_dir / "state.json"
    event_count = export_events(db, events_path)
    has_state = export_state(db, state_path)
    state = json.loads(state_path.read_text(encoding="utf-8")) if has_state else None

    report = next(iter(sorted(run_dir.glob("report*.md"))), None)
    report_text = report.read_text(encoding="utf-8") if report else None
    return {
        "run": run_index,
        "exit_code": completed.returncode,
        "events": event_count,
        "state_exported": has_state,
        "report": str(report) if report else None,
        "events_path": str(events_path),
        "state": state,
        "report_text": report_text,
        "provenance": export_provenance(db),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--binary", type=Path, default=default_binary())
    parser.add_argument(
        "--adaptive",
        action="store_true",
        help="enable the config-only adaptive/LLM planning path in the lab",
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help="start loopback mock LLM + target servers for real tool calls",
    )
    args = parser.parse_args()

    fixture = json.loads((FIXTURE / "fixture.json").read_text(encoding="utf-8"))
    shutil.rmtree(WORK, ignore_errors=True)
    WORK.mkdir(parents=True, exist_ok=True)

    llm_base = None
    servers: list[subprocess.Popen] = []
    try:
        if args.live:
            target_port = free_port()
            llm_port = free_port()
            target_url = f"http://127.0.0.1:{target_port}/?q=probe"
            servers.append(
                subprocess.Popen(
                    [
                        sys.executable,
                        str(ROOT / "eval" / "fixture_server.py"),
                        "--port",
                        str(target_port),
                    ],
                    env=minimal_env(),
                )
            )
            servers.append(
                subprocess.Popen(
                    [
                        sys.executable,
                        str(ROOT / "eval" / "mock_llm.py"),
                        "--port",
                        str(llm_port),
                        "--target-url",
                        target_url,
                    ],
                    env=minimal_env(),
                )
            )
            time.sleep(1)
            llm_base = f"http://127.0.0.1:{llm_port}"

        runs = [
            run_one(args.binary, index, fixture, args.adaptive, llm_base)
            for index in range(1, args.runs + 1)
        ]
    finally:
        for process in servers:
            process.terminate()

    events = []
    for run in runs:
        path = Path(run["events_path"])
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                events.append(json.loads(line))

    # M1 needs fixture ground truth about which steps were useful. The offline
    # fixture produces no adaptive plan events, so this stays not_measured.
    metrics = evaluate(
        events,
        runs[0]["state"],
        runs[0]["report_text"],
        runs=len(runs),
    )
    if args.live:
        expected_techniques = {"wstg-info", "wstg-config", "wstg-authz", "wstg-injection"}
        plan_events = [event for event in events if event.get("kind") == "plan_generated"]
        useful = 0
        for event in plan_events:
            try:
                payload = json.loads(event.get("payload_json", "{}"))
            except json.JSONDecodeError:
                continue
            techniques = payload.get("techniques", [])
            if techniques and any(item in expected_techniques for item in techniques):
                useful += 1
        metrics["M1_useful_next_step"] = {
            "value": round(useful / len(plan_events), 3) if plan_events else "not_measured",
            "useful_plans": useful,
            "plan_events": len(plan_events),
            "basis": "fixture expected technique ids",
        }

        all_provenance = [item for run in runs for item in run["provenance"]]
        proven = [item for item in all_provenance if item["verdict"] == "proven"]
        expected_facts = len(fixture["hidden_facts"])
        metrics["M3_hypothesis_quality"] = {
            "value": round(len(proven) / (expected_facts * len(runs)), 3)
            if expected_facts and runs
            else "not_measured",
            "proven": len(proven),
            "expected_per_run": expected_facts,
            "basis": "verifier provenance vs fixture hidden facts",
        }

        verdict_sets = [
            tuple(sorted(item["verdict"] for item in run["provenance"])) for run in runs
        ]
        if len(verdict_sets) >= 2:
            stable = sum(1 for item in verdict_sets[1:] if item == verdict_sets[0])
            metrics["M5_reproducibility"] = {
                "value": round(stable / (len(verdict_sets) - 1), 3),
                "runs": len(verdict_sets),
                "basis": "identical verifier verdict sets across runs",
            }

    metrics["fixture"] = {
        "id": fixture["id"],
        "version": fixture["version"],
        "content_hash": __import__("hashlib").sha256(
            (FIXTURE / "fixture.json").read_bytes()
        ).hexdigest(),
        "runs": [
            {
                "run": run["run"],
                "exit_code": run["exit_code"],
                "events": run["events"],
                "report": run["report"],
            }
            for run in runs
        ],
    }
    metrics["label"] = "fixture verification — not an effectiveness claim"

    out = WORK / "metrics.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(metrics, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"metrics": str(out), "runs": len(runs), "events": len(events)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
