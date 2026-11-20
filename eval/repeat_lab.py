"""Offline repeat driver for evaluation wiring records.

Runs the loopback lab fixture N>=3 times, records real probe artifacts with
hashes and timings, and writes a manifest. This is harness wiring evidence,
NOT a benchmark result: no agent effectiveness claim is computed here.

Usage:
    python eval/repeat_lab.py --repeat 3
    python eval/repeat_lab.py --repeat 3 --record
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import time
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lab.local_reflect_server import start_lab_server  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
GOLDEN = ROOT / "eval" / "lab" / "golden.local.json"
WORK = ROOT / "eval" / "work" / "lab"
RESULTS = ROOT / "eval" / "results" / "local-reflect-lab"
CLAIM = "harness wiring record; not a benchmark result"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def probe(base_url: str, path: str, marker: str) -> dict:
    started = time.perf_counter()
    with urllib.request.urlopen(base_url + path + "?q=" + marker, timeout=5) as response:
        status = response.status
        body = response.read().decode("utf-8", "replace")
    return {
        "path": path,
        "status": status,
        "body": body,
        "duration_ms": round((time.perf_counter() - started) * 1000, 3),
        "canary_reflected": marker in body,
    }


def run_once(base_url: str, lane: str, index: int, destination: Path) -> dict:
    run_id = f"local-reflect-lab:{lane}:run-{index}"
    run_dir = destination / lane / f"run-{index}"
    run_dir.mkdir(parents=True, exist_ok=True)
    started = datetime.now(timezone.utc).isoformat()
    clock = time.perf_counter()

    marker = "agentbug-lab-" + uuid.uuid4().hex[:16]
    reflected = probe(base_url, "/reflect", marker)
    negative = probe(base_url, "/safe", marker)

    events = [
        {"kind": "run_start", "run_id": run_id, "lane": lane},
        {
            "kind": "tested",
            "run_id": run_id,
            "target_id": "local-reflect-lab",
            "endpoint": "/reflect",
            "oracle_type": "canary_echo",
            "tier": "A",
            "verdict": "observed" if reflected["canary_reflected"] else "rejected",
            "duration_ms": reflected["duration_ms"],
        },
        {
            "kind": "tested",
            "run_id": run_id,
            "target_id": "local-reflect-lab",
            "endpoint": "/safe",
            "oracle_type": "canary_absent",
            "tier": "A",
            "verdict": "rejected" if not negative["canary_reflected"] else "observed",
            "duration_ms": negative["duration_ms"],
        },
    ]
    replay = run_dir / "replay.jsonl"
    with replay.open("w", encoding="utf-8") as handle:
        for event in events:
            handle.write(json.dumps(event, sort_keys=True) + "\n")

    probe_doc = {
        "run_id": run_id,
        "started_at": started,
        "reflected": reflected,
        "negative_control": negative,
        "claim": CLAIM,
    }
    probe_path = run_dir / "lab-probe.json"
    probe_path.write_text(json.dumps(probe_doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    return {
        "run_id": run_id,
        "started_at": started,
        "finished_at": datetime.now(timezone.utc).isoformat(),
        "duration_ms": round((time.perf_counter() - clock) * 1000, 3),
        "probe_sha256": sha256_file(probe_path),
        "replay_sha256": sha256_file(replay),
        "canary_reflected": reflected["canary_reflected"],
        "negative_control_clean": not negative["canary_reflected"],
    }


def write_baseline_not_run(destination: Path, reason: str) -> None:
    baseline = destination / "baseline"
    baseline.mkdir(parents=True, exist_ok=True)
    (baseline / "not-run.json").write_text(
        json.dumps(
            {
                "baseline_type": "not_run",
                "reason": reason,
                "claim": "no baseline comparison measured; wiring record only",
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repeat", type=int, default=3)
    parser.add_argument("--record", action="store_true")
    parser.add_argument("--baseline-cmd", default="")
    args = parser.parse_args()
    if args.repeat < 3:
        parser.error("--repeat must be >= 3 for a repeatability wiring record")

    destination = RESULTS if args.record else WORK
    destination.mkdir(parents=True, exist_ok=True)
    base_url, shutdown = start_lab_server()
    manifest = {
        "schema_version": 1,
        "target_id": "local-reflect-lab",
        "lane": "lab-wiring",
        "repeats": args.repeat,
        "golden_sha256": sha256_file(GOLDEN),
        "runs": [],
        "claim": CLAIM,
    }
    try:
        for index in range(1, args.repeat + 1):
            manifest["runs"].append(run_once(base_url, "lab", index, destination))
        if args.baseline_cmd:
            subprocess.run(args.baseline_cmd, shell=True, check=False, cwd=str(ROOT))
            write_baseline_not_run(destination, "operator-supplied baseline command executed; not scored")
        else:
            write_baseline_not_run(destination, "no plain-agent baseline supplied")
    finally:
        shutdown()

    manifest_path = destination / "run-manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps({"manifest": str(manifest_path), "claim": CLAIM}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
