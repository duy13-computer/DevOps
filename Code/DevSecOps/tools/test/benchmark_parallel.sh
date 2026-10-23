#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
REPOSITORY_ROOT="$(cd "$PROJECT_ROOT/../.." && pwd)"
SCAN_PROJECT_ROOT="$PROJECT_ROOT"
OUTPUT="$PROJECT_ROOT/tests/results/metrics/parallel_vs_seq.csv"
PHASE=""
RUNS=3

usage() {
  cat <<'EOF'
Usage: benchmark_parallel.sh (--baseline|--after-fix) [--runs N] [--output CSV]
Runs Semgrep, Gitleaks, Trivy FS, and Checkov sequentially and with GNU Parallel.
At least three paired measurements are required.
EOF
}

while (($#)); do
  case "$1" in
    --baseline|--after-fix)
      if [[ -n "$PHASE" ]]; then echo "Choose only one phase." >&2; exit 2; fi
      PHASE="${1#--}"
      shift
      ;;
    --runs)
      RUNS="${2:-}"
      shift 2
      ;;
    --output)
      OUTPUT="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ -z "$PHASE" || ! "$RUNS" =~ ^[0-9]+$ || "$RUNS" -lt 3 ]]; then
  usage >&2
  exit 2
fi
if ! command -v parallel >/dev/null 2>&1; then
  echo "GNU Parallel is required for this benchmark." >&2
  exit 127
fi

for tool in semgrep gitleaks trivy checkov; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "Required scanner is missing: $tool" >&2
    exit 127
  fi
done

run_scanner() {
  local tool="$1"
  mkdir -p "$REPORT_DIR"
  case "$tool" in
    semgrep)
      semgrep scan --metrics=off --config "$SCAN_PROJECT_ROOT/rules/semgrep" --json \
        --output "$REPORT_DIR/semgrep.json" "$SCAN_PROJECT_ROOT/src"
      ;;
    gitleaks)
      gitleaks dir "$SCAN_PROJECT_ROOT" --config "$SCAN_PROJECT_ROOT/.gitleaks.toml" \
        --report-format json --report-path "$REPORT_DIR/gitleaks.json" --exit-code 0
      ;;
    trivy-fs)
      trivy fs --scanners vuln,misconfig,secret --format json \
        --skip-dirs "$SCAN_PROJECT_ROOT/ground_truth/patches" \
        --skip-dirs "$SCAN_PROJECT_ROOT/tests/results" --skip-dirs "$SCAN_PROJECT_ROOT/reports" \
        --skip-dirs "$SCAN_PROJECT_ROOT/.venv" --skip-dirs "$SCAN_PROJECT_ROOT/__pycache__" \
        --skip-files "$SCAN_PROJECT_ROOT/lab/docker/Dockerfile.vuln" \
        --output "$REPORT_DIR/trivy-fs.json" --exit-code 0 "$SCAN_PROJECT_ROOT"
      ;;
    checkov)
      checkov -d "$SCAN_PROJECT_ROOT/infra" -o json \
        --output-file-path "$REPORT_DIR" --soft-fail
      ;;
    *)
      echo "Unknown scanner: $tool" >&2
      return 2
      ;;
  esac
}
export -f run_scanner
export PROJECT_ROOT SCAN_PROJECT_ROOT
export SHELL="${SHELL:-/bin/bash}"

elapsed_seconds() {
  awk -v start="$1" -v end="$2" 'BEGIN { printf "%.6f", (end - start) / 1000000000 }'
}

measure_sequential() {
  local directory="$1" tool status=0
  REPORT_DIR="$directory"
  export REPORT_DIR
  for tool in semgrep gitleaks trivy-fs checkov; do
    if run_scanner "$tool"; then :; else status=1; fi
  done
  return "$status"
}

measure_parallel() {
  REPORT_DIR="$1"
  export REPORT_DIR
  parallel --jobs 4 run_scanner ::: semgrep gitleaks trivy-fs checkov
}

STAMP="$(date -u +%Y%m%dT%H%M%S%N)"
RUN_ID="${PHASE}-${STAMP}"
COMMIT_SHA="$(git -C "$REPOSITORY_ROOT" rev-parse HEAD 2>/dev/null || printf 'unknown')"
TEMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/devsecops-benchmark.XXXXXX")"
trap 'rm -rf -- "$TEMP_ROOT"' EXIT
FAILED=0

if [[ "$PHASE" == "baseline" ]]; then
  BASELINE_ROOT="$TEMP_ROOT/repository"
  if ! python3 - "$PROJECT_ROOT" "$BASELINE_ROOT/Code/DevSecOps" "$BASELINE_ROOT" <<'PY'
import shutil
import subprocess
import sys
from pathlib import Path

source, destination, repository = (Path(value).resolve() for value in sys.argv[1:4])
patches = [Path("Code/DevSecOps/ground_truth/patches") / name for name in (
    "fix_sast.patch", "fix_secret.patch", "fix_docker.patch", "fix_infra.patch"
)]

def ignore(path, names):
    relative = Path(path).resolve().relative_to(source)
    ignored = {name for name in names if name in {".git", ".venv", "__pycache__", ".pytest_cache"}}
    if relative == Path("tests/results"):
        ignored.update(name for name in names if name in {"raw", "metrics", "experiments", "triage"})
    if relative == Path("."):
        ignored.update(name for name in names if name == "reports")
    return ignored

destination.parent.mkdir(parents=True, exist_ok=True)
shutil.copytree(source, destination, ignore=ignore)
subprocess.run(["git", "-C", str(repository), "init", "--quiet"], check=True)
for patch in patches:
    copied = repository / patch
    subprocess.run(["git", "-C", str(repository), "apply", "--reverse", "--check", str(copied)], check=True)
for patch in patches:
    copied = repository / patch
    subprocess.run(["git", "-C", str(repository), "apply", "--reverse", str(copied)], check=True)
PY
  then
    echo "Failed to reconstruct baseline in the temporary benchmark directory." >&2
    exit 1
  fi
  SCAN_PROJECT_ROOT="$BASELINE_ROOT/Code/DevSecOps"
  export SCAN_PROJECT_ROOT
fi

mkdir -p "$(dirname "$OUTPUT")"
python3 - "$OUTPUT" <<'PY'
import csv
import sys
from pathlib import Path

path = Path(sys.argv[1])
fields = ["phase", "run_id", "commit_sha", "n_runs", "run_index",
          "sequential_wall_time_s", "parallel_wall_time_s", "speedup",
          "sequential_exit", "parallel_exit", "successful_pair", "measurement_status"]
rows = []
if path.exists():
    with path.open(newline="", encoding="utf-8-sig") as stream:
        rows = list(csv.DictReader(stream))
    for row in rows:
        sequential, parallel = row.get("sequential_exit", ""), row.get("parallel_exit", "")
        valid = sequential == "0" and parallel == "0"
        row.setdefault("successful_pair", "1" if valid else "0")
        row.setdefault("measurement_status", "valid" if valid else "invalid")
with path.open("w", newline="", encoding="utf-8") as stream:
    writer = csv.DictWriter(stream, fieldnames=fields)
    writer.writeheader()
    writer.writerows(rows)
PY

for ((index = 1; index <= RUNS; index++)); do
  SEQ_DIR="$TEMP_ROOT/$index/sequential"
  PAR_DIR="$TEMP_ROOT/$index/parallel"
  mkdir -p "$SEQ_DIR" "$PAR_DIR"
  if ((index % 2 == 1)); then
    SEQ_START="$(date +%s%N)"
    if measure_sequential "$SEQ_DIR"; then SEQ_EXIT=0; else SEQ_EXIT=$?; FAILED=1; fi
    SEQ_END="$(date +%s%N)"
    PAR_START="$(date +%s%N)"
    if measure_parallel "$PAR_DIR"; then PAR_EXIT=0; else PAR_EXIT=$?; FAILED=1; fi
    PAR_END="$(date +%s%N)"
  else
    PAR_START="$(date +%s%N)"
    if measure_parallel "$PAR_DIR"; then PAR_EXIT=0; else PAR_EXIT=$?; FAILED=1; fi
    PAR_END="$(date +%s%N)"
    SEQ_START="$(date +%s%N)"
    if measure_sequential "$SEQ_DIR"; then SEQ_EXIT=0; else SEQ_EXIT=$?; FAILED=1; fi
    SEQ_END="$(date +%s%N)"
  fi
  SEQ_TIME="$(elapsed_seconds "$SEQ_START" "$SEQ_END")"
  PAR_TIME="$(elapsed_seconds "$PAR_START" "$PAR_END")"
  SPEEDUP="$(awk -v seq="$SEQ_TIME" -v par="$PAR_TIME" 'BEGIN { if (par > 0) printf "%.6f", seq / par; else print "0.000000" }')"
  PAIR_SUCCESS=0
  PAIR_STATUS=invalid
  if ((SEQ_EXIT == 0 && PAR_EXIT == 0)); then PAIR_SUCCESS=1; PAIR_STATUS=valid; else FAILED=1; fi
  printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
    "$PHASE" "$RUN_ID" "$COMMIT_SHA" "$RUNS" "$index" \
    "$SEQ_TIME" "$PAR_TIME" "$SPEEDUP" "$SEQ_EXIT" "$PAR_EXIT" "$PAIR_SUCCESS" "$PAIR_STATUS" >> "$OUTPUT"
  printf 'run %s/%s: sequential=%ss parallel=%ss speedup=%sx\n' \
    "$index" "$RUNS" "$SEQ_TIME" "$PAR_TIME" "$SPEEDUP"
done

echo "Appended $RUNS paired run(s) to $OUTPUT"
if ((FAILED)); then
  echo "One or more scanner commands failed; timing rows were still recorded." >&2
  exit 1
fi
