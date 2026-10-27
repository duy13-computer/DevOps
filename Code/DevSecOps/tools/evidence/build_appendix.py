#!/usr/bin/env python3
"""Build a defect-free evidence appendix from measured artefacts.

The generator only reports values it can read from files. Anything absent is
listed as MISSING so an appendix can never silently claim unmeasured results.
It also emits a machine-readable index and a list of claims that are currently
supported versus not supported by the retained evidence.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import statistics
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

PHASES = ("baseline", "after-fix")
SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN", "INFO")
SCANNER_STEPS = ("semgrep", "gitleaks", "trivy-fs", "trivy-image", "checkov", "docker-build", "syft-sbom")
MISSING = "**THIẾU**"


def read_json(path: Path) -> dict[str, Any] | None:
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError):
        return None


def read_csv(path: Path) -> list[dict[str, str]]:
    if not path.is_file():
        return []
    with path.open(newline="", encoding="utf-8-sig") as handle:
        return [row for row in csv.DictReader(handle)]


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def median(values: Iterable[float]) -> float | None:
    items = [value for value in values]
    return statistics.median(items) if items else None


def fmt(value: Any, digits: int = 3) -> str:
    if value is None:
        return MISSING
    if isinstance(value, float):
        return f"{value:.{digits}f}"
    return str(value)


def relpath(path: Path, base: Path) -> str:
    try:
        return path.relative_to(base).as_posix()
    except ValueError:
        return path.as_posix()


def find_project_root(start: Path) -> Path:
    for candidate in [start, *start.parents]:
        if (candidate / "ground_truth/seeds.yaml").is_file():
            return candidate
        if (candidate / "Code/DevSecOps/ground_truth/seeds.yaml").is_file():
            return candidate / "Code/DevSecOps"
    raise SystemExit("Cannot locate Code/DevSecOps/ground_truth/seeds.yaml")


def experiment_roots(project: Path) -> list[tuple[str, str, Path]]:
    """Return (run_id, phase, directory) for every retained experiment phase."""
    found: list[tuple[str, str, Path]] = []
    base = project / "tests/results/experiments"
    if not base.is_dir():
        return found
    for run_dir in sorted(path for path in base.iterdir() if path.is_dir()):
        for phase in PHASES:
            phase_dir = run_dir / phase
            if phase_dir.is_dir():
                found.append((run_dir.name, phase, phase_dir))
    return found


def timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def summarise_phase(project: Path, run_id: str, phase: str, phase_dir: Path) -> dict[str, Any]:
    environment = read_json(phase_dir / "environment.json")
    experiment = read_json(phase_dir / "experiment.json")
    summaries = sorted(phase_dir.glob("run-*/summary/summary.json"))
    raws = sorted(phase_dir.glob("run-*/raw"))

    runs: list[dict[str, Any]] = []
    measurements: dict[str, list[dict[str, Any]]] = (experiment or {}).get("measurements", {})
    for index, raw_dir in enumerate(raws, 1):
        summary_path = raw_dir.parent / "summary/summary.json"
        summary = read_json(summary_path) or {}
        findings = summary.get("findings", []) or []
        severity = Counter(str(item.get("severity", "UNKNOWN")).upper() for item in findings)
        tools = Counter(str(item.get("tool", "unknown")) for item in findings)
        exit_codes = {
            step: [entry.get("exit_code") for entry in values if entry.get("run_index") == index]
            for step, values in measurements.items()
            if step not in {"normalize", "ground-truth-metrics"}
        }
        runs.append({
            "run_index": index,
            "summary_path": summary_path,
            "summary_present": summary_path.is_file(),
            "findings": len(findings),
            "severity": dict(severity),
            "tools": dict(tools),
            "scan_errors": summary.get("scan_errors", []),
            "exit_codes": {step: codes[0] if codes else None for step, codes in exit_codes.items()},
            "raw_reports": sorted(path.name for path in raw_dir.iterdir() if path.is_file()) if raw_dir.is_dir() else [],
        })

    gate_text = ""
    gate_path = phase_dir / "gate-results.txt"
    if gate_path.is_file():
        gate_text = gate_path.read_text(encoding="utf-8", errors="replace")
    gate_blocked = sorted(set(re.findall(r"(\w+) blocked", gate_text)))
    gate_passed_phases = "passed g1 and g2" in gate_text
    gate_failures = [line.strip() for line in gate_text.splitlines() if line.strip().startswith("FAIL:")]

    deploy = read_json(phase_dir / "deploy/deployment.json")
    sbom_present = sum(1 for raw in raws if (raw / "sbom.cyclonedx.json").is_file())

    return {
        "run_id": run_id,
        "phase": phase,
        "directory": phase_dir,
        "environment": environment,
        "experiment": experiment,
        "runs": runs,
        "summary_count": len(summaries),
        "gate": {
            "file_present": gate_path.is_file(),
            "blocked_gates": gate_blocked,
            "after_fix_passed": gate_passed_phases,
            "failures": gate_failures,
            "text": gate_text,
        },
        "deploy": deploy,
        "sbom_runs": sbom_present,
    }


def metrics(project: Path) -> dict[str, Any]:
    timing_rows = read_csv(project / "tests/results/metrics/pipeline_time.csv")
    detection_rows = read_csv(project / "tests/results/metrics/detection_rate.csv")
    parallel_rows = read_csv(project / "tests/results/metrics/parallel_vs_seq.csv")
    triage_rows: list[dict[str, str]] = []
    triage_dir = project / "tests/results/triage"
    if triage_dir.is_dir():
        for path in sorted(triage_dir.glob("*.csv")):
            triage_rows.extend(read_csv(path))
    return {
        "timing": timing_rows,
        "timing_valid": [row for row in timing_rows if row.get("measurement_status") == "valid"],
        "timing_invalid": [row for row in timing_rows if row.get("measurement_status") != "valid"],
        "detection": detection_rows,
        "parallel": parallel_rows,
        "parallel_valid": [row for row in parallel_rows if row.get("measurement_status") == "valid"],
        "triage": triage_rows,
    }


def report_table(rows: list[list[str]], header: list[str]) -> list[str]:
    lines = ["| " + " | ".join(header) + " |", "|" + "|".join("---" for _ in header) + "|"]
    for row in rows:
        lines.append("| " + " | ".join(row) + " |")
    return lines


def build(project: Path, source_label: str | None) -> tuple[str, dict[str, Any]]:
    phases = [summarise_phase(project, *item) for item in experiment_roots(project)]
    data = metrics(project)
    seeds_measured = 0
    seeds_total = 0
    seeds_path = project / "ground_truth/seeds.yaml"
    if seeds_path.is_file():
        for line in seeds_path.read_text(encoding="utf-8").splitlines():
            if line.strip().startswith("- id:"):
                seeds_total += 1
            if line.strip().startswith("measured: true"):
                seeds_measured += 1

    index: dict[str, Any] = {
        "generated_at_utc": timestamp(),
        "project": project.as_posix(),
        "source_label": source_label or "auto",
        "phases": [],
        "seed_manifest": {"declared": seeds_total, "measured": seeds_measured},
    }

    out: list[str] = []
    out.append("# Phụ lục bằng chứng thực nghiệm (tự sinh)")
    out.append("")
    out.append(f"- Sinh lúc: `{index['generated_at_utc']}`")
    out.append(f"- Nguồn dữ liệu: `{source_label or 'tự nhận diện từ tests/results/experiments'}`")
    out.append("")
    out.append("> Quy ước: mọi ô **THIẾU** nghĩa là không có file/số liệu tương ứng trong workspace.")
    out.append("> Báo cáo này không nội suy, không thay thế, không làm tròn để lấp chỗ trống.")
    out.append("")

    # 1. Provenance
    out.append("## 1. Xuất xứ từng lần chạy")
    out.append("")
    if not phases:
        out.append(f"Không có thư mục `tests/results/experiments/<run-id>/<phase>/` nào. {MISSING}")
        out.append("")
    else:
        rows: list[list[str]] = []
        for item in phases:
            env = item["environment"] or {}
            versions = env.get("tool_versions", {}) or {}
            rendered = ", ".join(
                f"{name}={((entry or {}).get('output') or ['?'])[0]}" for name, entry in sorted(versions.items())
            )
            runner = " ".join(filter(None, [env.get("runner_os"), env.get("runner_arch")])) or MISSING
            rows.append([
                f"`{item['run_id']}`",
                item["phase"],
                (env.get("commit_sha") or (item["experiment"] or {}).get("commit_sha") or MISSING)[:12],
                runner if env else MISSING,
                env.get("cache_policy") or MISSING,
                rendered or MISSING,
            ])
            index["phases"].append({
                "run_id": item["run_id"],
                "phase": item["phase"],
                "environment_present": item["environment"] is not None,
                "experiment_present": item["experiment"] is not None,
                "summary_count": item["summary_count"],
                "gate_file_present": item["gate"]["file_present"],
                "sbom_runs": item["sbom_runs"],
            })
        out.extend(report_table(rows, ["run_id", "phase", "commit", "runner", "cache", "phiên bản công cụ"]))
        out.append("")
        missing_env = [item["run_id"] + "/" + item["phase"] for item in phases if item["environment"] is None]
        if missing_env:
            out.append(f"{MISSING} `environment.json` cho: " + ", ".join(f"`{name}`" for name in missing_env))
            out.append("")

    # 2. Per-run scanner outcome
    out.append("## 2. Kết quả từng lượt quét")
    out.append("")
    if not phases:
        out.append(f"Không có lượt quét nào. {MISSING}")
    else:
        rows = []
        for item in phases:
            for run in item["runs"]:
                codes = ", ".join(
                    f"{step}={code}" for step, code in sorted(run["exit_codes"].items()) if code is not None
                )
                severity = ", ".join(
                    f"{name}={run['severity'].get(name, 0)}" for name in SEVERITY_ORDER if run["severity"].get(name)
                )
                rows.append([
                    f"`{item['run_id']}`",
                    item["phase"],
                    f"run-{run['run_index']:02d}",
                    "có" if run["summary_present"] else MISSING,
                    str(run["findings"]),
                    severity or "0",
                    str(len(run["scan_errors"])),
                    codes or MISSING,
                    ", ".join(run["raw_reports"]) or MISSING,
                ])
        out.extend(report_table(
            rows,
            ["run_id", "phase", "run", "summary", "findings", "severity", "scan_errors", "exit codes", "raw"],
        ))
        out.append("")
        errored = [
            f"`{item['run_id']}`/`{item['phase']}` run-{run['run_index']:02d}: " + "; ".join(run["scan_errors"])
            for item in phases for run in item["runs"] if run["scan_errors"]
        ]
        if errored:
            out.append("**Lượt có lỗi scanner (không dùng để kết luận):**")
            out.extend(f"- {entry}" for entry in errored)
            out.append("")

    # 3. Gate evidence
    out.append("## 3. Bằng chứng gate")
    out.append("")
    if not phases:
        out.append(f"Không có `gate-results.txt`. {MISSING}")
    else:
        rows = []
        for item in phases:
            gate = item["gate"]
            verdict = MISSING
            if gate["failures"]:
                verdict = "FAIL: " + "; ".join(gate["failures"])
            elif item["phase"] == "baseline" and gate["blocked_gates"]:
                verdict = "bị chặn bởi " + ", ".join(gate["blocked_gates"])
            elif item["phase"] == "after-fix" and gate["after_fix_passed"]:
                verdict = "g1 và g2 PASS"
            elif gate["file_present"]:
                verdict = "không kết luận được (thiếu dòng PASS/blocked)"
            rows.append([
                f"`{item['run_id']}`",
                item["phase"],
                "có" if gate["file_present"] else MISSING,
                verdict,
            ])
        out.extend(report_table(rows, ["run_id", "phase", "gate-results.txt", "kết luận"]))
        out.append("")

    # 4. Detection / remediation metrics
    out.append("## 4. Tỷ lệ phát hiện theo seed và tồn dư sau sửa")
    out.append("")
    detection = data["detection"]
    if not detection:
        out.append(f"`tests/results/metrics/detection_rate.csv` không có dòng nào. {MISSING}")
    else:
        rows = []
        for row in detection:
            kind = row.get("metric_kind") or ("remediation" if row.get("phase") == "after-fix" else "detection")
            if kind == "remediation":
                rows.append([
                    row.get("phase", ""), row.get("tool", ""), kind,
                    row.get("residual_seed_count", "N/A"),
                    row.get("remaining_seed_ids", "") or "-",
                    row.get("unmatched_findings", ""),
                ])
            else:
                rows.append([
                    row.get("phase", ""), row.get("tool", ""), kind,
                    f"TP={row.get('tp','')} FP'={row.get('fp','')} FN={row.get('fn','')}",
                    f"P'={row.get('precision','')} R={row.get('recall','')} F1'={row.get('f1','')}",
                    row.get("missed_seed_ids", "") or "-",
                ])
        out.extend(report_table(rows, ["phase", "tool", "kind", "đếm", "chỉ số", "seed bỏ sót / còn lại"]))
        out.append("")
        out.append("> `P'` và `FP'` là chỉ số **tương đối với seed đã khai báo**, không phải precision/FPR được chuyên gia gán nhãn.")
        out.append("")

    # 5. Timing
    out.append("## 5. Thời gian từng scanner")
    out.append("")
    valid = data["timing_valid"]
    invalid = data["timing_invalid"]
    if not valid:
        out.append(f"Không có dòng `pipeline_time.csv` hợp lệ nào. {MISSING}")
        if invalid:
            out.append(f"- Có {len(invalid)} dòng bị đánh dấu `invalid` (giữ làm lịch sử, **không** dùng để kết luận).")
        out.append("")
    else:
        grouped: dict[tuple[str, str], list[dict[str, str]]] = defaultdict(list)
        for row in valid:
            grouped[(row.get("phase", ""), row.get("step", ""))].append(row)
        rows = []
        for (phase, step), values in sorted(grouped.items()):
            walls = [float(value["wall_time_s"]) for value in values if value.get("wall_time_s")]
            cpus = [float(value["cpu_time_s"]) for value in values if value.get("cpu_time_s")]
            rows.append([
                phase, step, str(len(values)),
                fmt(median(walls), 6), fmt(median(cpus), 6),
                ", ".join(value.get("run_id", "") for value in values[:1]),
            ])
        out.extend(report_table(rows, ["phase", "step", "n", "wall median (s)", "cpu median (s)", "run_id"]))
        out.append("")
        if invalid:
            out.append(f"- {len(invalid)} dòng `measurement_status=invalid` đã bị loại khỏi bảng trên.")
            out.append("")

    # 6. Benchmark
    out.append("## 6. Tuần tự so với song song")
    out.append("")
    pairs = data["parallel_valid"]
    if not pairs:
        out.append(f"`parallel_vs_seq.csv` không có cặp hợp lệ nào. {MISSING}")
        out.append("")
    else:
        speedups = [float(row["speedup"]) for row in pairs if row.get("speedup")]
        rows = [
            [row.get("phase", ""), row.get("run_index", ""), fmt(float(row["sequential_wall_time_s"]), 6),
             fmt(float(row["parallel_wall_time_s"]), 6), fmt(float(row["speedup"]), 3), row.get("measurement_status", "")]
            for row in pairs
        ]
        out.extend(report_table(rows, ["phase", "pair", "sequential (s)", "parallel (s)", "speedup", "status"]))
        out.append("")
        out.append(f"- Số cặp hợp lệ: **{len(pairs)}**; speedup trung vị: **{fmt(median(speedups), 3)}x**.")
        out.append("")

    # 7. Deploy
    out.append("## 7. Bằng chứng chạy thử sau gate")
    out.append("")
    deploys = [item for item in phases if item["deploy"]]
    if not deploys:
        out.append(f"Không có `deploy/deployment.json` trong workspace. {MISSING}")
        out.append("")
    else:
        rows = []
        for item in deploys:
            deploy = item["deploy"] or {}
            rows.append([
                f"`{item['run_id']}`", item["phase"], str(deploy.get("status", MISSING)),
                str(deploy.get("health_endpoint", MISSING)), str(deploy.get("duration_s", MISSING)),
                str(deploy.get("image_digest", MISSING))[:19], str(deploy.get("deployment_scope", MISSING)),
            ])
        out.extend(report_table(rows, ["run_id", "phase", "status", "endpoint", "duration (s)", "digest", "phạm vi"]))
        out.append("")

    # 8. SBOM
    out.append("## 8. SBOM")
    out.append("")
    sbom_counts = {f"`{item['run_id']}`/{item['phase']}": item["sbom_runs"] for item in phases}
    if not sbom_counts:
        out.append(f"Không có SBOM. {MISSING}")
    else:
        out.append(", ".join(f"{name}: {count} run" for name, count in sbom_counts.items()))
    out.append("")

    # 9. Triage
    out.append("## 9. Triage finding chưa khớp seed")
    out.append("")
    triage = data["triage"]
    if not triage:
        out.append(f"Không có file triage nào. {MISSING}")
        out.append("")
    else:
        classifications = Counter(row.get("classification", "") or "TRỐNG" for row in triage)
        reviewed = sum(1 for row in triage if (row.get("reviewer") or "").strip() and (row.get("reviewed_at") or "").strip())
        rows = [[name, str(count)] for name, count in sorted(classifications.items())]
        out.extend(report_table(rows, ["classification", "số finding"]))
        out.append("")
        out.append(f"- Đã ký duyệt (có reviewer và reviewed_at): **{reviewed}/{len(triage)}**")
        pending = len(triage) - reviewed
        if pending:
            out.append(f"- Còn **{pending}** finding chưa có người xác nhận → chưa được phép công bố FPR.")
        out.append("")

    # 10. Seed manifest
    out.append("## 10. Manifest seed")
    out.append("")
    out.append(f"- Tổng seed khai báo: **{seeds_total}**; seed dùng để đo (`measured: true`): **{seeds_measured}**.")
    out.append("")

    # 11. Claims guard
    out.append("## 11. Tuyên bố được phép và không được phép")
    out.append("")
    valid_pairs = len(pairs)
    all_triage_reviewed = bool(triage) and all(
        (row.get("reviewer") or "").strip() for row in triage
    )
    deploy_ok = any((item["deploy"] or {}).get("status") == "passed" for item in phases)
    has_baseline_gate = any(item["phase"] == "baseline" and item["gate"]["blocked_gates"] for item in phases)
    has_after_gate = any(item["phase"] == "after-fix" and item["gate"]["after_fix_passed"] for item in phases)
    has_sbom = any(item["sbom_runs"] for item in phases)
    claims = [
        ("Baseline bị g1/g2 chặn", has_baseline_gate),
        ("After-fix vượt g1 và g2", has_after_gate),
        ("Có SBOM CycloneDX cho image", has_sbom),
        ("Có số liệu thời gian hợp lệ", bool(valid)),
        ("Có ≥3 cặp benchmark hợp lệ để nói về speedup", valid_pairs >= 3),
        ("Có bằng chứng chạy thử /health sau gate", deploy_ok),
        ("Có triage do người đánh giá ký duyệt (được nói FPR)", all_triage_reviewed),
    ]
    rows = [["Được phép" if ok else "KHÔNG được phép", claim] for claim, ok in claims]
    out.extend(report_table(rows, ["trạng thái", "tuyên bố"]))
    out.append("")

    # 12. Integrity
    out.append("## 12. Vân tay tệp bằng chứng")
    out.append("")
    entries: list[list[str]] = []
    for item in phases:
        for candidate in sorted(item["directory"].rglob("*")):
            if candidate.is_file() and candidate.suffix in {".json", ".txt", ".csv"}:
                entries.append([
                    candidate.relative_to(project).as_posix(),
                    str(candidate.stat().st_size),
                    sha256_of(candidate)[:16],
                ])
    if entries:
        out.extend(report_table(entries[:80], ["tệp", "bytes", "sha256[:16]"]))
        if len(entries) > 80:
            out.append("")
            out.append(f"- (lược {len(entries) - 80} tệp; xem `reports/evidence-index.json`)")
    else:
        out.append(f"Không có tệp bằng chứng nào để băm. {MISSING}")
    out.append("")

    index["metrics"] = {
        "timing_valid_rows": len(valid),
        "timing_invalid_rows": len(invalid),
        "parallel_valid_pairs": valid_pairs,
        "detection_rows": len(detection),
        "triage_rows": len(triage),
        "triage_reviewed_rows": sum(
            1 for row in triage if (row.get("reviewer") or "").strip() and (row.get("reviewed_at") or "").strip()
        ),
    }
    index["claims"] = {claim: ok for claim, ok in claims}
    index["hashes"] = {row[0]: row[2] for row in entries}

    out.append("---")
    out.append("")
    out.append("Sinh bởi `Code/DevSecOps/tools/evidence/build_appendix.py`. Không chỉnh sửa tay phần số liệu.")
    out.append("")
    return "\n".join(out), index


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", type=Path, default=None)
    parser.add_argument("--output", type=Path, default=None)
    parser.add_argument("--json-output", type=Path, default=None)
    parser.add_argument("--source-label", default=None,
                        help="nhãn xuất xứ, ví dụ 'GitHub run 40346069403' hoặc 'máy lab WSL'")
    parser.add_argument("--strict", action="store_true",
                        help="trả mã lỗi nếu thiếu bằng chứng gate hoặc thiếu phase")
    args = parser.parse_args()

    project = (args.project_root or find_project_root(Path(__file__).resolve().parent)).resolve()
    markdown, index = build(project, args.source_label)

    output = args.output or project / "reports/evidence-appendix.md"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(markdown, encoding="utf-8")

    json_output = args.json_output or project / "reports/evidence-index.json"
    json_output.write_text(json.dumps(index, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    print(f"Wrote {relpath(output, project)}")
    print(f"Wrote {relpath(json_output, project)}")
    unsupported = [claim for claim, ok in index["claims"].items() if not ok]
    if unsupported:
        print("Chưa đủ bằng chứng cho các tuyên bố sau:", file=sys.stderr)
        for claim in unsupported:
            print(f"- {claim}", file=sys.stderr)

    if args.strict:
        profile = index["claims"]
        if not profile.get("Baseline bị g1/g2 chặn") or not profile.get("After-fix vượt g1 và g2"):
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
