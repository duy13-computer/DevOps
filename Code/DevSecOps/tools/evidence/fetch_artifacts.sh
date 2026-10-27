#!/usr/bin/env bash
# Download retained GitHub Actions artefacts into tests/results/experiments and
# write a SHA-256 manifest so the appendix generator can prove provenance.
#
# Requirements: GitHub CLI (gh) authenticated with read access to the repo.
#   gh auth login
#   gh run list --repo duy13-computer/DevOps --workflow 'Ground truth before-after experiment'
#
# Usage:
#   bash tools/evidence/fetch_artifacts.sh --run-id 40346069403 \
#     --repo duy13-computer/DevOps [--run-main 40346092023]
set -euo pipefail

REPO="duy13-computer/DevOps"
RUN_ID=""
MAIN_RUN_ID=""
OUT=""

usage() {
  sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'
}

while (($#)); do
  case "$1" in
    --run-id) RUN_ID="${2:-}"; shift 2 ;;
    --run-main) MAIN_RUN_ID="${2:-}"; shift 2 ;;
    --repo) REPO="${2:-}"; shift 2 ;;
    --out) OUT="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ -z "$RUN_ID" ]]; then
  echo "--run-id is required" >&2
  usage >&2
  exit 2
fi
if ! command -v gh >/dev/null 2>&1; then
  echo "GitHub CLI (gh) is required. Install it and run: gh auth login" >&2
  exit 127
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
OUT="${OUT:-$PROJECT_ROOT/tests/results/experiments}"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/devsecops-artifacts.XXXXXX")"
trap 'rm -rf -- "$TMP"' EXIT

fetch_one() {
  local run="$1" name="$2"
  local dir="$TMP/$name"
  mkdir -p "$dir"
  echo "→ tải artefact $name (run $run)…"
  gh run download "$run" --repo "$REPO" --name "$name" --dir "$dir"
  # Artefacts upload theo path Code/DevSecOps/tests/results/..., nên bóc lớp đầu.
  local nested
  nested="$(find "$dir" -maxdepth 2 -type d -path '*tests/results/experiments' -print -quit)"
  if [[ -n "$nested" ]]; then
    mkdir -p "$OUT"
    cp -r "$nested/." "$OUT/"
  else
    echo "  ! không tìm thấy cấu trúc tests/results/experiments trong $name" >&2
  fi
}

mkdir -p "$OUT"
fetch_one "$RUN_ID" "ground-truth-baseline-$RUN_ID"
fetch_one "$RUN_ID" "ground-truth-after-fix-$RUN_ID"

if [[ -n "$MAIN_RUN_ID" ]]; then
  MAIN_DIR="$TMP/main"
  mkdir -p "$MAIN_DIR"
  echo "→ tải artefact main-security-scan-evidence (run $MAIN_RUN_ID)…"
  gh run download "$MAIN_RUN_ID" --repo "$REPO" --name "main-security-scan-evidence" --dir "$MAIN_DIR"
  MAIN_DEST="$PROJECT_ROOT/tests/results/deploy"
  mkdir -p "$MAIN_DEST"
  cp -r "$MAIN_DIR/." "$MAIN_DEST/" 2>/dev/null || true
fi

MANIFEST="$OUT/manifest-$RUN_ID.json"
python3 - "$OUT" "$RUN_ID" "$REPO" "$MANIFEST" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

out, run_id, repo, manifest = sys.argv[1:5]
root = Path(out).resolve()

def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()

files = []
for path in sorted(root.rglob("*")):
    if path.is_file() and path.name != "manifest-%s.json" % run_id:
        files.append({
            "path": path.relative_to(root).as_posix(),
            "bytes": path.stat().st_size,
            "sha256": digest(path),
        })

data = {
    "run_id": run_id,
    "repo": repo,
    "downloaded_via": "gh run download",
    "files": files,
}
Path(manifest).write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
print(f"Manifest: {len(files)} file → {manifest}")
PY

echo ""
echo "Hoàn tất. Chạy sinh phụ lục:"
echo "  python3 Code/DevSecOps/tools/evidence/build_appendix.py --source-label 'GitHub run $RUN_ID ($REPO)'"
