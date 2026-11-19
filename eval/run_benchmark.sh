#!/usr/bin/env bash
# MiniBug benchmark driver. DRY RUN BY DEFAULT.
# Preview commands with no flags; actually execute with --execute.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGETS_FILE="$SCRIPT_DIR/targets.yml"
if [[ ! -f "$TARGETS_FILE" ]]; then
  TARGETS_FILE="$SCRIPT_DIR/targets.example.yml"
fi
RESULTS_DIR="$SCRIPT_DIR/results"
MINIBUG="${MINIBUG:-minibug}"
EXECUTE=0
ALLOW_REMOTE=0

usage() {
  cat <<'EOF'
Usage: run_benchmark.sh [options]

Options:
  --execute          Actually run the engagements (default: dry run only).
  --targets FILE     Target inventory YAML (default: eval/targets.yml, then example).
  --results DIR      Output directory (default: eval/results).
  --minibug BIN      MiniBug binary (default: minibug from PATH).
  --allow-remote     Permit non-loopback/non-private URLs (unsafe; benchmark use only).
  -h, --help         Show this help.

Dry run prints the commands it would run and writes nothing. Nothing is submitted
to any external platform; only local reports are produced.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --execute) EXECUTE=1; shift ;;
    --allow-remote) ALLOW_REMOTE=1; shift ;;
    --targets) TARGETS_FILE="${2:?--targets needs a file}"; shift 2 ;;
    --results) RESULTS_DIR="${2:?--results needs a directory}"; shift 2 ;;
    --minibug) MINIBUG="${2:?--minibug needs a binary}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

[[ -f "$TARGETS_FILE" ]] || { echo "targets file not found: $TARGETS_FILE" >&2; exit 1; }
command -v python3 >/dev/null || { echo "python3 is required to parse targets" >&2; exit 1; }

# Parse the small YAML subset into TSV: id, url, cwd. No external Python deps.
parse_targets() {
  python3 - "$TARGETS_FILE" <<'PY'
import re, sys
path = sys.argv[1]
current = {}
def flush():
    if current.get("id") and current.get("url"):
        print("%s\t%s\t%s" % (current["id"], current["url"], current.get("cwd", "")))
    current.clear()
with open(path, encoding="utf-8") as fh:
    for line in fh:
        line = line.rstrip("\n")
        m = re.match(r"^\s*-\s*id:\s*(\S+)\s*$", line)
        if m:
            flush()
            current["id"] = m.group(1)
            continue
        if not current:
            continue
        m = re.match(r"^\s+(url|cwd):\s*(\S+)\s*$", line)
        if m:
            current[m.group(1)] = m.group(2)
flush()
PY
}

# Refuse obviously non-local targets unless explicitly overridden.
is_local_url() {
  python3 - "$1" <<'PY'
import sys
from urllib.parse import urlparse
u = urlparse(sys.argv[1])
h = (u.hostname or "").lower()
if h in ("localhost", "127.0.0.1", "::1") or h.endswith(".local"):
    sys.exit(0)
parts = h.split(".")
if len(parts) == 4 and all(p.isdigit() for p in parts):
    a, b = int(parts[0]), int(parts[1])
    if a == 10 or (a == 192 and b == 168) or (a == 172 and 16 <= b <= 31):
        sys.exit(0)
sys.exit(1)
PY
}

mapfile -t ROWS < <(parse_targets)
if [[ ${#ROWS[@]} -eq 0 ]]; then
  echo "no targets found in $TARGETS_FILE" >&2
  exit 1
fi

declare -a SUMMARY=()
for row in "${ROWS[@]}"; do
  IFS=$'\t' read -r id url cwd <<<"$row"
  [[ -n "$id" && -n "$url" ]] || continue
  safe_id="$(printf '%s' "$id" | tr -c 'A-Za-z0-9._-' '_')"
  target_dir="$RESULTS_DIR/$safe_id"
  report="$target_dir/report.md"
  log="$target_dir/run.log"

  if [[ $ALLOW_REMOTE -eq 0 ]] && ! is_local_url "$url"; then
    echo "REFUSED (non-local URL; use --allow-remote only in an isolated lab): $id -> $url" >&2
    SUMMARY+=("$id|refused|$report")
    continue
  fi

  cmd=("$MINIBUG" engage --url "$url" --cwd "$cwd")
  echo "[$id] ${cmd[*]}"
  echo "        report -> $report   log -> $log"

  if [[ $EXECUTE -eq 0 ]]; then
    SUMMARY+=("$id|dry-run|$report")
    continue
  fi

  mkdir -p "$target_dir" "$cwd"
  if "${cmd[@]}" >"$log" 2>&1; then
    # The engagement writes its report under --cwd; copy the newest Markdown report.
    newest="$(find "$cwd" -maxdepth 2 -type f -name '*.md' -printf '%T@ %p\n' 2>/dev/null \
      | sort -rn | head -n 1 | cut -d' ' -f2-)"
    status="ok"
    if [[ -n "$newest" ]]; then
      cp "$newest" "$report"
    else
      echo "warning: no report found under $cwd" >&2
      status="no-report"
    fi
  else
    status="failed"
    echo "[$id] engagement failed; see $log" >&2
  fi
  SUMMARY+=("$id|$status|$report")
done

printf '\n===== Summary =====\n'
printf '%-24s %-12s %s\n' "TARGET" "STATUS" "REPORT"
for s in "${SUMMARY[@]}"; do
  IFS='|' read -r id status report <<<"$s"
  printf '%-24s %-12s %s\n' "$id" "$status" "$report"
done

if [[ $EXECUTE -eq 0 ]]; then
  printf '\nDry run only — nothing executed. Re-run with --execute to actually benchmark.\n'
fi
