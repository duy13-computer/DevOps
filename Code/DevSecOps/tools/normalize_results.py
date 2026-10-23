#!/usr/bin/env python3
"""Normalize Semgrep, Gitleaks, Trivy, and Checkov JSON for Conftest."""
import argparse
import json
from pathlib import Path


def load(path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except (json.JSONDecodeError, OSError) as exc:
        raise ValueError(f"cannot parse {path}: {exc}") from exc


def add(findings, tool, severity, category, title, file, rule_id, **extra):
    severity = (severity or "UNKNOWN").upper()
    if severity not in {"UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"}:
        severity = "UNKNOWN"
    findings.append({"tool": tool, "severity": severity, "category": category,
                     "title": title or rule_id or "finding", "file": file or "<unknown>",
                     "rule_id": str(rule_id or ""), **extra})


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--results", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = args.results
    findings = []
    errors = []

    semgrep = load(root / "semgrep.json")
    if semgrep:
        for item in semgrep.get("results", []):
            extra = item.get("extra", {})
            semgrep_severity = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}.get(
                str(extra.get("severity", "")).upper(), extra.get("severity")
            )
            add(findings, "semgrep", semgrep_severity, "sast", extra.get("message"),
                item.get("path"), item.get("check_id"))

    gitleaks = load(root / "gitleaks.json")
    if gitleaks:
        for item in gitleaks if isinstance(gitleaks, list) else []:
            add(findings, "gitleaks", "HIGH", "secret", item.get("Description") or "Secret detected",
                item.get("File"), item.get("RuleID"))

    for report_name, category in (("trivy-fs.json", "sca"), ("trivy-image.json", "image")):
        report = load(root / report_name)
        if not report:
            continue
        for result in report.get("Results", []) or []:
            target = result.get("Target", "<unknown>")
            for item in result.get("Vulnerabilities", []) or []:
                add(findings, "trivy", item.get("Severity"), category,
                    item.get("Title") or item.get("VulnerabilityID"), target,
                    item.get("VulnerabilityID"), package=item.get("PkgName"))
            for item in result.get("Misconfigurations", []) or []:
                add(findings, "trivy", item.get("Severity"), "config",
                    item.get("Message") or item.get("Title"), target, item.get("ID"))

    checkov = load(root / "checkov.json")
    if checkov:
        checks = checkov if isinstance(checkov, list) else [checkov]
        for section in checks:
            for item in section.get("results", {}).get("failed_checks", []) or []:
                severity = item.get("severity") or "HIGH"
                add(findings, "checkov", severity, "iac", item.get("check_name"),
                    item.get("file_path"), item.get("check_id"))

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps({"findings": findings, "scan_errors": errors}, indent=2) + "\n",
                           encoding="utf-8")
    print(f"Normalized {len(findings)} finding(s) to {args.output}")


if __name__ == "__main__":
    main()
