#!/usr/bin/env python3
"""Measure repeatable baseline and remediation scans, retaining each raw report."""

from __future__ import annotations

import argparse
import csv
import json
import os
import shutil
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
PROJECT_REL = Path("Code/DevSecOps")
PATCHES = [
    PROJECT_REL / "ground_truth/patches/fix_sast.patch",
    PROJECT_REL / "ground_truth/patches/fix_secret.patch",
    PROJECT_REL / "ground_truth/patches/fix_docker.patch",
    PROJECT_REL / "ground_truth/patches/fix_infra.patch",
]
CSV_FIELDS = [
    "phase", "run_id", "commit_sha", "n_runs", "step", "wall_time_s",
    "cpu_time_s", "successful_runs", "measurement_status", "exit_codes",
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


def copy_ignore(path: str, names: list[str]) -> set[str]:
    current = Path(path)
    relative = current.relative_to(PROJECT_ROOT)
    ignored = {name for name in names if name in {".git", ".venv", "__pycache__", ".pytest_cache"}}
    if relative == Path("tests/results"):
        ignored.update(name for name in names if name in {"raw", "metrics", "experiments", "triage"})
    if relative == Path("."):
        ignored.update(name for name in names if name == "reports")
    return ignored


def prepare_baseline(directory: Path) -> Path:
    baseline_root = directory / "repository"
    baseline_project = baseline_root / PROJECT_REL
    baseline_project.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(PROJECT_ROOT, baseline_project, ignore=copy_ignore)
    initialized = subprocess.run(
        ["git", "-C", str(baseline_root), "init", "--quiet"],
        capture_output=True, text=True, check=False,
    )
    if initialized.returncode != 0:
        raise RuntimeError(f"Could not initialize temporary baseline workspace: {initialized.stderr.strip()}")
    patch_paths = [baseline_root / item for item in PATCHES]
    for patch in patch_paths:
        check = subprocess.run(
            ["git", "-C", str(baseline_root), "apply", "--reverse", "--check", str(patch)],
            capture_output=True, text=True, check=False,
        )
        if check.returncode != 0:
            raise RuntimeError(f"Cannot reconstruct vulnerable baseline with {patch.name}: {check.stderr.strip()}")
    for patch in patch_paths:
        applied = subprocess.run(
            ["git", "-C", str(baseline_root), "apply", "--reverse", str(patch)],
            capture_output=True, text=True, check=False,
        )
        if applied.returncode != 0:
            raise RuntimeError(f"Could not reverse {patch.name}: {applied.stderr.strip()}")
    return baseline_root


def scanner_commands(raw: Path, include_image: bool, image: str) -> list[tuple[str, list[str]]]:
    project = PROJECT_REL.as_posix()
    output = raw.resolve().as_posix()
    commands = [
        ("semgrep", [
            "semgrep", "scan", "--metrics=off", "--config", f"{project}/rules/semgrep",
            "--json", "--output", f"{output}/semgrep.json", f"{project}/src",
        ]),
        ("gitleaks", [
            "gitleaks", "dir", project, "--config", f"{project}/.gitleaks.toml",
            "--report-format", "json", "--report-path", f"{output}/gitleaks.json", "--exit-code", "0",
        ]),
        ("trivy-fs", [
            "trivy", "fs", "--scanners", "vuln,misconfig,secret",
            "--skip-dirs", f"{project}/ground_truth/patches",
            "--skip-dirs", f"{project}/tests/results",
            "--skip-dirs", f"{project}/reports",
            "--skip-dirs", f"{project}/.venv",
            "--skip-dirs", f"{project}/__pycache__",
            "--skip-files", f"{project}/lab/docker/Dockerfile.vuln",
            "--format", "json", "--output", f"{output}/trivy-fs.json", "--exit-code", "0",
            "--severity", "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL", project,
        ]),
        ("checkov", [
            "checkov", "-d", f"{project}/infra", "-o", "json",
            "--output-file-path", output, "--soft-fail",
        ]),
    ]
    if include_image:
        dockerfile = f"{project}/lab/docker/Dockerfile"
        commands.extend([
            ("docker-build", ["docker", "build", "--file", dockerfile, "--tag", image, project]),
            ("trivy-image", [
                "trivy", "image", "--format", "json", "--output", f"{output}/trivy-image.json",
                "--exit-code", "0", "--severity", "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL", image,
            ]),
            ("syft-sbom", ["syft", image, "-o", f"cyclonedx-json={output}/sbom.cyclonedx.json"]),
        ])
    return commands


def run_command(command: list[str], cwd: Path) -> tuple[float, float, int, str]:
    child_before = os.times()
    started = time.perf_counter()
    try:
        result = subprocess.run(command, cwd=cwd, capture_output=True, text=True, check=False)
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


def append_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    existing: list[dict[str, Any]] = []
    if path.exists():
        with path.open(newline="", encoding="utf-8") as handle:
            existing = list(csv.DictReader(handle))
        for row in existing:
            codes = [int(code) for code in row.get("exit_codes", "").split(";") if code]
            row.setdefault("successful_runs", str(sum(code == 0 for code in codes)))
            row.setdefault("measurement_status", "valid" if codes and all(code == 0 for code in codes) else "invalid")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_FIELDS)
        writer.writeheader()
        writer.writerows(existing)
        writer.writerows(rows)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    phase = parser.add_mutually_exclusive_group(required=True)
    phase.add_argument("--baseline", action="store_true", help="rebuild the vulnerable state by reversing remediation patches")
    phase.add_argument("--after-fix", action="store_true", help="measure the checked-out remediation state")
    parser.add_argument("--runs", type=int, default=3, help="repetitions; minimum is three")
    parser.add_argument("--include-image", action="store_true", help="build/scan the phase image and write a CycloneDX SBOM")
    parser.add_argument("--output", type=Path, default=PROJECT_ROOT / "tests/results/metrics/pipeline_time.csv")
    parser.add_argument("--run-id", default="")
    parser.add_argument("--commit-sha", default="")
    args = parser.parse_args()
    if args.runs < 3:
        parser.error("--runs must be at least 3")

    phase_name = "after-fix" if args.after_fix else "baseline"
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    run_id = args.run_id or f"{phase_name}-{stamp}"
    safe_run_id = "".join(char if char.isalnum() or char in "._-" else "_" for char in run_id)
    sha = args.commit_sha or commit_sha()
    evidence_root = PROJECT_ROOT / "tests/results/experiments" / safe_run_id / phase_name
    evidence_root.mkdir(parents=True, exist_ok=True)
    samples: dict[str, list[tuple[float, float, int]]] = defaultdict(list)
    summaries: list[Path] = []
    failures: list[str] = []
    required = "semgrep,gitleaks,trivy-fs,checkov" + (",trivy-image" if args.include_image else "")

    try:
        with tempfile.TemporaryDirectory(prefix="devsecops-baseline-") as temporary:
            scan_root = prepare_baseline(Path(temporary)) if args.baseline else REPOSITORY_ROOT
            for run_index in range(1, args.runs + 1):
                run_dir = evidence_root / f"run-{run_index:02d}"
                raw = run_dir / "raw"
                summary_dir = run_dir / "summary"
                raw.mkdir(parents=True, exist_ok=True)
                image = f"devsecops-seeded-lab:{safe_run_id}-{phase_name}-{run_index}".lower()
                for step, command in scanner_commands(raw, args.include_image, image):
                    wall, cpu, status, output = run_command(command, scan_root)
                    if step == "checkov":
                        generated = raw / "results_json.json"
                        if generated.is_file():
                            generated.replace(raw / "checkov.json")
                    samples[step].append((wall, cpu, status))
                    print(f"run {run_index}/{args.runs} {step}: wall={wall:.3f}s cpu={cpu:.3f}s exit={status}")
                    if status != 0:
                        failures.append(f"{step} run {run_index}: exit {status}")
                        if output.strip():
                            print(output[-1600:], file=sys.stderr)
                summary_command = [
                    sys.executable, f"{PROJECT_REL.as_posix()}/tools/test/summarize.py",
                    "--results", str(raw), "--output-dir", str(summary_dir),
                    "--exceptions", f"{PROJECT_REL.as_posix()}/policy/exceptions.json",
                    "--require", required, "--run-id", f"{run_id}-{phase_name}-{run_index}", "--commit-sha", sha,
                ]
                wall, cpu, status, output = run_command(summary_command, REPOSITORY_ROOT)
                samples["normalize"].append((wall, cpu, status))
                print(f"run {run_index}/{args.runs} normalize: wall={wall:.3f}s exit={status}")
                if status != 0:
                    failures.append(f"normalize run {run_index}: exit {status}")
                    if output.strip():
                        print(output[-2400:], file=sys.stderr)
                summaries.append(summary_dir / "summary.json")

        metrics_status = "not-run"
        if all(path.is_file() for path in summaries):
            verify_command = [
                sys.executable, f"{PROJECT_REL.as_posix()}/tools/test/verify_ground_truth.py",
                "--findings", *[str(path) for path in summaries],
                "--baseline" if args.baseline else "--after-fix",
                "--run-id", run_id, "--commit-sha", sha,
            ]
            wall, cpu, status, output = run_command(verify_command, REPOSITORY_ROOT)
            samples["ground-truth-metrics"].append((wall, cpu, status))
            metrics_status = "valid" if status == 0 else "invalid"
            print(output.strip())
            if status != 0:
                failures.append(f"ground-truth metrics: exit {status}")
        else:
            failures.append("one or more normalized summaries were not created")

        rows: list[dict[str, Any]] = []
        for step, values in sorted(samples.items()):
            codes = [item[2] for item in values]
            successful = sum(code == 0 for code in codes)
            expected_runs = 1 if step == "ground-truth-metrics" else args.runs
            rows.append({
                "phase": phase_name,
                "run_id": run_id,
                "commit_sha": sha,
                "n_runs": args.runs,
                "step": step,
                "wall_time_s": f"{sum(item[0] for item in values) / len(values):.6f}",
                "cpu_time_s": f"{sum(item[1] for item in values) / len(values):.6f}",
                "successful_runs": successful,
                "measurement_status": "valid" if len(codes) == expected_runs and successful == expected_runs else "invalid",
                "exit_codes": ";".join(str(code) for code in codes),
            })
        append_csv(args.output, rows)
        experiment = {
            "phase": phase_name,
            "run_id": run_id,
            "commit_sha": sha,
            "requested_runs": args.runs,
            "include_image": args.include_image,
            "status": "valid" if not failures else "invalid",
            "ground_truth_metrics_status": metrics_status,
            "summaries": [path.relative_to(PROJECT_ROOT).as_posix() for path in summaries],
            "measurements": {
                step: [
                    {
                        "run_index": index,
                        "wall_time_s": round(value[0], 6),
                        "cpu_time_s": round(value[1], 6),
                        "exit_code": value[2],
                    }
                    for index, value in enumerate(values, 1)
                ]
                for step, values in samples.items()
            },
            "errors": failures,
        }
        (evidence_root / "experiment.json").write_text(json.dumps(experiment, indent=2) + "\n", encoding="utf-8")
        print(f"Wrote {len(rows)} measurement rows to {args.output}")
        print(f"Evidence retained at {evidence_root}")
    except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
        print(f"Experiment setup failed: {exc}", file=sys.stderr)
        return 1

    if failures:
        print("Experiment invalid or incomplete:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
