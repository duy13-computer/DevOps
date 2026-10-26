#!/usr/bin/env python3
"""Compare normalized findings with the declared seeded ground truth."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


CSV_FIELDS = [
    "phase", "metric_kind", "run_id", "commit_sha", "n_runs", "tool", "tp", "fp", "fn",
    "precision", "recall", "f1", "detected_seed_ids", "missed_seed_ids",
    "remaining_seed_ids", "residual_seed_count", "unmatched_findings",
]
TRIAGE_FIELDS = [
    "phase", "run_id", "commit_sha", "report", "tool", "finding_key", "category",
    "severity", "rule_id", "cve", "package", "installed_version", "file",
    "line_start", "title", "observed_count", "report_paths", "classification",
    "reviewer", "reviewed_at", "rationale",
]


def scalar(value: str) -> Any:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    if value.lower() in {"true", "false"}:
        return value.lower() == "true"
    if re.fullmatch(r"-?\d+", value):
        return int(value)
    if value.lower() in {"null", "~"}:
        return None
    return value


def load_seeds(path: Path) -> list[dict[str, Any]]:
    """Read the simple list-of-mappings YAML subset used by seeds.yaml."""
    seeds: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("- "):
            if current is not None:
                seeds.append(current)
            current = {}
            line = line[2:].strip()
        elif current is None or not raw.startswith("  "):
            raise ValueError(f"unsupported YAML structure on line {number}")
        if ":" not in line:
            raise ValueError(f"expected key: value on line {number}")
        key, value = line.split(":", 1)
        current[key.strip()] = scalar(value)
    if current is not None:
        seeds.append(current)
    if not seeds:
        raise ValueError(f"no seed entries found in {path}")
    return seeds


def norm_path(value: Any) -> str:
    return str(value or "").replace("\\", "/").lstrip("./")


def matches(seed: dict[str, Any], finding: dict[str, Any]) -> bool:
    for field in ("tool", "category", "rule_id", "cve"):
        if field in seed and seed[field] is not None:
            actual = str(finding.get(field, ""))
            expected = str(seed[field])
            if field in {"cve", "rule_id"}:
                actual, expected = actual.upper(), expected.upper()
            if actual != expected:
                return False
    if seed.get("rule_id_regex") and not re.fullmatch(
        str(seed["rule_id_regex"]), str(finding.get("rule_id", ""))
    ):
        return False
    expected_file = norm_path(seed.get("file"))
    actual_file = norm_path(finding.get("file"))
    if expected_file:
        candidates = {expected_file}
        project_prefix = "Code/DevSecOps/"
        if expected_file.startswith(project_prefix):
            candidates.add(expected_file[len(project_prefix):])
        if not any(actual_file == candidate or actual_file.endswith("/" + candidate)
                   for candidate in candidates):
            return False
    if seed.get("package"):
        if str(finding.get("package", "")).casefold() != str(seed["package"]).casefold():
            return False
    expected_version = str(seed.get("version", ""))
    actual_version = str(finding.get("installed_version") or finding.get("version") or "")
    if expected_version and actual_version and actual_version != expected_version:
        return False
    return True


def score_run(findings: list[dict[str, Any]], seeds: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    measured = [seed for seed in seeds if seed.get("measured", True)]
    tools = {str(seed["tool"]) for seed in measured}
    scores: dict[str, dict[str, Any]] = {}
    for tool in sorted(tools):
        expected = [seed for seed in measured if seed.get("tool") == tool]
        candidates = [item for item in findings if item.get("tool") == tool]
        detected: set[str] = set()
        unmatched_findings: list[dict[str, Any]] = []
        for finding in candidates:
            match = next((seed for seed in expected
                          if seed["id"] not in detected and matches(seed, finding)), None)
            if match:
                detected.add(str(match["id"]))
            else:
                unmatched_findings.append(finding)
        missed = {str(seed["id"]) for seed in expected} - detected
        tp = len(detected)
        # Unmatched findings are not automatically false positives: they may be
        # real findings missing from the seed manifest. Keep them for human triage.
        fp = len(unmatched_findings)
        fn = len(missed)
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        scores[tool] = {
            "tp": tp, "fp": fp, "fn": fn, "precision": precision,
            "recall": recall, "f1": f1, "detected": detected, "missed": missed,
            "unmatched_findings": unmatched_findings,
        }
    return scores


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    phase = parser.add_mutually_exclusive_group()
    phase.add_argument("--baseline", action="store_true", help="label this as the vulnerable baseline run")
    phase.add_argument("--after-fix", action="store_true", help="label this as the remediation run")
    project = Path("Code/DevSecOps") if Path("Code/DevSecOps/ground_truth/seeds.yaml").is_file() else Path(".")
    parser.add_argument("--findings", type=Path, nargs="+", help="one or more normalized summary.json files; multiple inputs are averaged")
    parser.add_argument("--seeds", type=Path, default=project / "ground_truth/seeds.yaml")
    parser.add_argument("--output", type=Path, default=project / "tests/results/metrics/detection_rate.csv")
    parser.add_argument("--triage-dir", type=Path, default=project / "tests/results/triage")
    parser.add_argument("--run-id", default="")
    parser.add_argument("--commit-sha", default="")
    parser.add_argument("--overwrite", action="store_true", help="replace the metrics CSV instead of appending rows")
    args = parser.parse_args()

    paths = args.findings or [project / "reports/summary.json"]
    if len(paths) < 1:
        parser.error("at least one findings report is required")
    seeds = load_seeds(args.seeds)
    phase_name = "after-fix" if args.after_fix else "baseline"
    run_scores: list[dict[str, dict[str, Any]]] = []
    triage_rows: list[dict[str, Any]] = []
    report_ids: list[str] = []
    commit_ids: list[str] = []
    scan_errors: list[str] = []
    for path in paths:
        data = json.loads(path.read_text(encoding="utf-8"))
        scores = score_run(data.get("findings", []), seeds)
        run_scores.append(scores)
        report_run_id = str(data.get("run_id", ""))
        report_commit = str(data.get("commit_sha", ""))
        for tool, score in scores.items():
            for finding in score["unmatched_findings"]:
                finding_key = str(
                    finding.get("fingerprint")
                    or finding.get("finding_id")
                    or hashlib.sha256(
                        json.dumps(finding, sort_keys=True, ensure_ascii=False).encode("utf-8")
                    ).hexdigest()[:20]
                )
                triage_rows.append({
                    "phase": phase_name,
                    "run_id": report_run_id or args.run_id,
                    "commit_sha": report_commit or args.commit_sha,
                    "report": path.as_posix(),
                    "tool": tool,
                    "finding_key": finding_key,
                    "category": finding.get("category", ""),
                    "severity": finding.get("severity", ""),
                    "rule_id": finding.get("rule_id", ""),
                    "cve": finding.get("cve", ""),
                    "package": finding.get("package", ""),
                    "installed_version": finding.get("installed_version", finding.get("version", "")),
                    "file": finding.get("file", ""),
                    "line_start": finding.get("line_start", ""),
                    "title": finding.get("title", ""),
                    "classification": "PENDING_REVIEW",
                    "reviewer": "",
                    "reviewed_at": "",
                    "rationale": "",
                })
        if data.get("run_id"):
            report_ids.append(str(data["run_id"]))
        if data.get("commit_sha"):
            commit_ids.append(str(data["commit_sha"]))
        scan_errors.extend(str(error) for error in data.get("scan_errors", []))

    run_id = args.run_id or (",".join(dict.fromkeys(report_ids)) if report_ids else datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"))
    commit_sha = args.commit_sha or os.getenv("GITHUB_SHA") or (commit_ids[0] if len(set(commit_ids)) == 1 and commit_ids else "mixed-or-unknown")
    all_tools = sorted({tool for scores in run_scores for tool in scores})
    rows: list[dict[str, Any]] = []
    for tool in all_tools:
        samples = [scores.get(tool, {"tp": 0, "fp": 0, "fn": 0, "precision": 0.0,
                                     "recall": 0.0, "f1": 0.0, "detected": set(), "missed": set()})
                   for scores in run_scores]
        remaining_ids = set.union(*(item["detected"] for item in samples))
        unmatched = sum(item["fp"] for item in samples)
        row = {
            "phase": phase_name,
            "metric_kind": "remediation" if args.after_fix else "detection",
            "run_id": run_id,
            "commit_sha": commit_sha,
            "n_runs": len(paths),
            "tool": tool,
            "tp": "N/A" if args.after_fix else sum(item["tp"] for item in samples),
            "fp": "N/A" if args.after_fix else sum(item["fp"] for item in samples),
            "fn": "N/A" if args.after_fix else sum(item["fn"] for item in samples),
            "precision": "N/A" if args.after_fix else sum(item["precision"] for item in samples) / len(samples),
            "recall": "N/A" if args.after_fix else sum(item["recall"] for item in samples) / len(samples),
            "f1": "N/A" if args.after_fix else sum(item["f1"] for item in samples) / len(samples),
            "detected_seed_ids": ";".join(sorted(remaining_ids)),
            "missed_seed_ids": "" if args.after_fix else ";".join(sorted(set.union(*(item["missed"] for item in samples)))),
            "remaining_seed_ids": ";".join(sorted(remaining_ids)) if args.after_fix else "",
            "residual_seed_count": len(remaining_ids) if args.after_fix else "N/A",
            "unmatched_findings": unmatched,
        }
        rows.append(row)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    existing: list[dict[str, Any]] = []
    if args.output.exists() and not args.overwrite:
        with args.output.open(newline="", encoding="utf-8-sig") as handle:
            existing = list(csv.DictReader(handle))
        for old in existing:
            old.setdefault("metric_kind", "remediation" if old.get("phase") == "after-fix" else "detection")
            old.setdefault("remaining_seed_ids", "")
            old.setdefault("residual_seed_count", "")
            old.setdefault("unmatched_findings", old.get("fp", ""))
    with args.output.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_FIELDS)
        writer.writeheader()
        writer.writerows(existing)
        writer.writerows(rows)
    for row in rows:
        if args.after_fix:
            print(f"{row['tool']}: residual seeded findings={row['residual_seed_count']} unmatched findings={row['unmatched_findings']} (n={row['n_runs']})")
        else:
            print(
                f"{row['tool']}: seed_precision_proxy={row['precision']:.3f} "
                f"seed_recall={row['recall']:.3f} seed_f1_proxy={row['f1']:.3f} "
                f"detected={row['detected_seed_ids'] or '-'} "
                f"missed={row['missed_seed_ids'] or '-'} "
                f"unmatched_pending_review={row['unmatched_findings']} (n={row['n_runs']})"
            )
    print(f"Appended {len(rows)} tool row(s) to {args.output}")
    args.triage_dir.mkdir(parents=True, exist_ok=True)
    safe_run_id = re.sub(r"[^A-Za-z0-9._-]", "_", run_id)
    triage_path = args.triage_dir / f"unmatched_findings_{phase_name}_{safe_run_id}.csv"
    triage_by_identity: dict[tuple[str, str], dict[str, Any]] = {}
    for row in triage_rows:
        identity = (row["tool"], row["finding_key"])
        if identity not in triage_by_identity:
            triage_by_identity[identity] = {
                **row,
                "observed_count": 1,
                "report_paths": row["report"],
            }
            continue
        existing_row = triage_by_identity[identity]
        existing_row["observed_count"] += 1
        if row["report"] not in existing_row["report_paths"].split(";"):
            existing_row["report_paths"] += ";" + row["report"]
    unique_triage_rows = list(triage_by_identity.values())
    with triage_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=TRIAGE_FIELDS)
        writer.writeheader()
        writer.writerows(unique_triage_rows)
    print(
        f"Wrote {len(unique_triage_rows)} unique unmatched finding(s) "
        f"from {len(triage_rows)} observations for manual triage to {triage_path}"
    )
    if scan_errors:
        print("Input reports include scanner errors; metrics may be incomplete:", file=sys.stderr)
        for error in scan_errors:
            print(f"- {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
