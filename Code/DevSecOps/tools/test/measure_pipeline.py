#!/usr/bin/env python3
"""Measure local scanner wall and child CPU time over repeated runs."""

from __future__ import annotations

import argparse
import csv
import os
import subprocess
import sys
import tempfile
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[2]
REPOSITORY_ROOT = PROJECT_ROOT.parents[1]
CSV_FIELDS = [
    "phase", "run_id", "commit_sha", "n_runs", "step", "wall_time_s",
    "cpu_time_s", "exit_codes",
]


def commit_sha() -> str:
    try:
        result = subprocess.run(
            ["git", "-C", str(REPOSITORY_ROOT), "rev-parse", "HEAD"],
            capture_output=True, text=True, check=False,
        )
    except OSError:
        return os.getenv("GITHUB_SHA", "unknown")
    return result.stdout.strip() if result.returncode == 0 else os.getenv("GITHUB_SHA", "unknown")


def scanner_commands(raw: Path, include_image: bool, phase: str, image: str) -> list[tuple[str, list[str]]]:
    commands = [
        ("semgrep", [
            "semgrep", "scan", "--metrics=off", "--config", str(PROJECT_ROOT / "rules/semgrep"),
            "--json", "--output", str(raw / "semgrep.json"), str(PROJECT_ROOT / "src"),
        ]),
        ("gitleaks", [
            "gitleaks", "dir", str(PROJECT_ROOT), "--config", str(PROJECT_ROOT / ".gitleaks.toml"),
            "--report-format", "json", "--report-path", str(raw / "gitleaks.json"), "--exit-code", "0",
        ]),
        ("trivy-fs", [
            "trivy", "fs", "--scanners", "vuln,misconfig,secret", "--format", "json",
            "--output", str(raw / "trivy-fs.json"), "--exit-code", "0", str(PROJECT_ROOT),
        ]),
        ("checkov", [
            "checkov", "-d", str(PROJECT_ROOT / "infra"), "-o", "json",
            "--output-file-path", str(raw), "--soft-fail",
        ]),
    ]
    if include_image:
        dockerfile = "lab/docker/Dockerfile.vuln" if phase == "baseline" else "lab/docker/Dockerfile.fixed"
        commands.extend([
            ("docker-build", [
                "docker", "build", "--file", str(PROJECT_ROOT / dockerfile),
                "--tag", image, str(PROJECT_ROOT),
            ]),
            ("trivy-image", [
                "trivy", "image", "--format", "json", "--output", str(raw / "trivy-image.json"),
                "--exit-code", "0", image,
            ]),
        ])
    return commands


def run_command(command: list[str]) -> tuple[float, float, int, str]:
    child_before = os.times()
    started = time.perf_counter()
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=False)
        status = result.returncode
        output = result.stdout + result.stderr
    except FileNotFoundError as exc:
        status = 127
        output = str(exc)
    wall_time = time.perf_counter() - started
    child_after = os.times()
    cpu_time = max(
        0.0,
        child_after.children_user + child_after.children_system
        - child_before.children_user - child_before.children_system,
    )
    return wall_time, cpu_time, status, output


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    phase = parser.add_mutually_exclusive_group(required=True)
    phase.add_argument("--baseline", action="store_true", help="measure the seeded vulnerable state")
    phase.add_argument("--after-fix", action="store_true", help="measure after applying the remediation patches")
    parser.add_argument("--runs", type=int, default=3, help="repetitions; minimum is three")
    parser.add_argument("--include-image", action="store_true", help="also build and scan the phase-specific Docker image")
    parser.add_argument("--output", type=Path, default=PROJECT_ROOT / "tests/results/metrics/pipeline_time.csv")
    parser.add_argument("--run-id", default="")
    parser.add_argument("--commit-sha", default="")
    args = parser.parse_args()
    if args.runs < 3:
        parser.error("--runs must be at least 3")

    phase_name = "after-fix" if args.after_fix else "baseline"
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    run_id = args.run_id or f"{phase_name}-{stamp}"
    sha = args.commit_sha or commit_sha()
    image = f"devsecops-seeded-lab:{phase_name}-{stamp.lower()}"
    samples: dict[str, list[tuple[float, float, int]]] = defaultdict(list)
    failures: list[str] = []

    for run_index in range(1, args.runs + 1):
        with tempfile.TemporaryDirectory(prefix="devsecops-measure-") as directory:
            raw = Path(directory)
            for step, command in scanner_commands(raw, args.include_image, phase_name, image):
                wall, cpu, status, output = run_command(command)
                samples[step].append((wall, cpu, status))
                print(f"run {run_index}/{args.runs} {step}: wall={wall:.3f}s cpu={cpu:.3f}s exit={status}")
                if status != 0:
                    failures.append(f"{step} run {run_index}: exit {status}")
                    if output.strip():
                        print(output[-1600:], file=sys.stderr)

    rows: list[dict[str, Any]] = []
    for step, values in sorted(samples.items()):
        rows.append({
            "phase": phase_name,
            "run_id": run_id,
            "commit_sha": sha,
            "n_runs": args.runs,
            "step": step,
            "wall_time_s": f"{sum(item[0] for item in values) / len(values):.6f}",
            "cpu_time_s": f"{sum(item[1] for item in values) / len(values):.6f}",
            "exit_codes": ";".join(str(item[2]) for item in values),
        })

    args.output.parent.mkdir(parents=True, exist_ok=True)
    mode = "a" if args.output.exists() else "w"
    with args.output.open(mode, newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_FIELDS)
        if mode == "w":
            writer.writeheader()
        writer.writerows(rows)
    print(f"Wrote {len(rows)} averaged step(s) to {args.output}")
    if failures:
        print("One or more scanner commands failed:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
