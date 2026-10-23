#!/usr/bin/env bash
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RAW="$ROOT/tests/results/raw"
METRICS="$ROOT/tests/results/metrics/timing.json"
REPORTS="$ROOT/reports"
IMAGE="devsecops-demo:local"
EXCEPTION_DATA=()
if [[ -f "$ROOT/policy/exceptions.json" ]]; then
  EXCEPTION_DATA=(--data "$ROOT/policy/exceptions.json")
fi
mkdir -p "$RAW" "$REPORTS" "$(dirname "$METRICS")"
clear_checkov_output() {
  if [[ -d "$RAW/checkov.json" && ! -L "$RAW/checkov.json" ]]; then
    rm -f -- "$RAW/checkov.json/results_json.json"
    rmdir -- "$RAW/checkov.json" || {
      echo "Refusing to remove non-empty legacy Checkov output directory: $RAW/checkov.json" >&2
      return 1
    }
  else
    rm -f -- "$RAW/checkov.json"
  fi
  rm -f -- "$RAW/results_json.json"
}
clear_checkov_output || exit 1
rm -f "$RAW/semgrep.json" "$RAW/gitleaks.json" "$RAW/trivy-fs.json" \
  "$RAW/trivy-image.json" "$RAW/findings.json" "$RAW/sbom.cyclonedx.json"
declare -A ELAPSED=()
FAILURES=()

run_step() {
  local name="$1"; shift
  local start end status=0
  start="$(date +%s)"
  "$@" || status=$?
  end="$(date +%s)"
  ELAPSED["$name"]=$((end - start))
  if (( status != 0 )); then FAILURES+=("$name (exit $status)"); fi
  printf '%-22s %4ss (exit %s)\n' "$name" "${ELAPSED[$name]}" "$status"
  return 0
}

run_checkov() {
  local status=0
  rm -f "$RAW/results_json.json"
  checkov -d "$ROOT/infra" -o json --output-file-path "$RAW" --soft-fail || status=$?
  if [[ -f "$RAW/results_json.json" ]]; then
    mv "$RAW/results_json.json" "$RAW/checkov.json" || return $?
  fi
  return "$status"
}

run_step docker_build docker build -f "$ROOT/lab/docker/Dockerfile" -t "$IMAGE" "$ROOT"
run_step exception_validation python3 "$ROOT/tools/check_exceptions.py"
run_step semgrep semgrep scan --config "$ROOT/rules/semgrep" --json --output "$RAW/semgrep.json" "$ROOT/src"
run_step gitleaks gitleaks dir "$ROOT" --config "$ROOT/.gitleaks.toml" --report-format json --report-path "$RAW/gitleaks.json" --exit-code 0
run_step trivy_fs trivy fs --scanners vuln,misconfig,secret --format json --exit-code 0 --output "$RAW/trivy-fs.json" --ignorefile "$ROOT/.trivyignore" "$ROOT"
run_step trivy_image trivy image --format json --exit-code 0 --output "$RAW/trivy-image.json" --ignorefile "$ROOT/.trivyignore" "$IMAGE"
run_step checkov run_checkov
run_step syft syft "$IMAGE" -o cyclonedx-json="$RAW/sbom.cyclonedx.json"
run_step normalize python3 "$ROOT/tools/normalize_results.py" --results "$RAW" --output "$RAW/findings.json"
run_step summarize python3 "$ROOT/tools/test/summarize.py" --results "$RAW" --output-dir "$REPORTS" \
  --exceptions "$ROOT/policy/exceptions.json" --require semgrep,gitleaks,trivy-fs,checkov \
  --run-id "${GITHUB_RUN_ID:-local}" --commit-sha "$(git -C "$ROOT/../.." rev-parse HEAD 2>/dev/null || echo unknown)"

if command -v conftest >/dev/null 2>&1; then
  run_step policy_g0 conftest test "$REPORTS/summary.json" --policy "$ROOT/policy/g0" --all-namespaces
  run_step policy_g1 conftest test "$REPORTS/summary.json" --policy "$ROOT/policy/g1" --policy "$ROOT/rules/conftest" "${EXCEPTION_DATA[@]}" --all-namespaces
  run_step policy_g2 conftest test "$REPORTS/summary.json" --policy "$ROOT/policy/g2" --policy "$ROOT/rules/conftest" "${EXCEPTION_DATA[@]}" --all-namespaces
else
  FAILURES+=("conftest (not installed)")
fi

TIMING_ARGS=()
for name in "${!ELAPSED[@]}"; do TIMING_ARGS+=("$name=${ELAPSED[$name]}"); done
python3 - "$METRICS" "${TIMING_ARGS[@]}" <<'PY'
import json, os, sys, time
path = sys.argv[1]
items = {}
for item in sys.argv[2:]:
    key, value = item.split("=", 1)
    items[key] = int(value)
with open(path, "w", encoding="utf-8") as out:
    json.dump({"unit": "seconds", "recorded_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "steps": items}, out, indent=2)
    out.write("\n")
PY

if ((${#FAILURES[@]})); then
  printf '\nPipeline failed: %s\n' "${FAILURES[*]}" >&2
  exit 1
fi
printf '\nAll local steps passed. Timing written to %s\n' "$METRICS"
