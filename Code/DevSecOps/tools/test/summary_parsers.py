#!/usr/bin/env python3
"""Parsers for the scanner JSON formats used by the DevSecOps lab."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


SEVERITIES = {"UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"}


def read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None


def norm_severity(value: Any) -> str:
    text = str(value or "UNKNOWN").upper()
    if text in {"ERROR", "CRITICAL", "HIGH"}:
        return "HIGH" if text == "ERROR" else text
    if text in {"WARNING", "MEDIUM"}:
        return "MEDIUM"
    if text in {"INFO", "LOW"}:
        return "LOW"
    return text if text in SEVERITIES else "UNKNOWN"


def add(findings: list[dict[str, Any]], tool: str, severity: Any, category: str,
        title: Any, file: Any, rule_id: Any, **extra: Any) -> None:
    finding = {
        "tool": tool,
        "severity": norm_severity(severity),
        "category": category,
        "title": str(title or rule_id or "finding"),
        "file": str(file or "<unknown>"),
        "rule_id": str(rule_id or ""),
    }
    finding.update({key: value for key, value in extra.items() if value is not None and value != ""})
    findings.append(finding)


def parse_semgrep(report: Any, findings: list[dict[str, Any]]) -> None:
    if not isinstance(report, dict):
        return
    for item in report.get("results", []) or []:
        extra = item.get("extra") or {}
        metadata = extra.get("metadata") or {}
        rule_id = str(item.get("check_id") or "")
        for prefix in (
            "Code.DevSecOps.rules.semgrep.",
            "Code/DevSecOps/rules/semgrep/",
            "Code.DevSecOps.rules.",
        ):
            if rule_id.startswith(prefix):
                rule_id = rule_id[len(prefix):]
                break
        add(findings, "semgrep", extra.get("severity"), "sast", extra.get("message"),
            item.get("path"), rule_id,
            line=(item.get("start") or {}).get("line"),
            cwe=metadata.get("cwe"), remediation=metadata.get("fix"))


def parse_gitleaks(report: Any, findings: list[dict[str, Any]]) -> None:
    entries = report if isinstance(report, list) else []
    for item in entries:
        add(findings, "gitleaks", "HIGH", "secret", item.get("Description"), item.get("File"),
            item.get("RuleID"), line=item.get("StartLine"),
            remediation="Remove the secret and rotate the exposed credential.")


def cvss_score(item: dict[str, Any]) -> Any:
    scores = item.get("CVSS") or {}
    for version in ("nvd", "redhat", "ghsa"):
        score = scores.get(version) or {}
        if score.get("V3Score") is not None:
            return score["V3Score"]
        if score.get("V2Score") is not None:
            return score["V2Score"]
    return None


def parse_trivy(report: Any, findings: list[dict[str, Any]], image: bool) -> None:
    if not isinstance(report, dict):
        return
    tool = "trivy-image" if image else "trivy-fs"
    category = "image" if image else "sca"
    for result in report.get("Results", []) or []:
        target = result.get("Target", "<unknown>")
        for item in result.get("Vulnerabilities", []) or []:
            add(findings, tool, item.get("Severity"), category,
                item.get("Title") or item.get("VulnerabilityID"), target,
                item.get("VulnerabilityID"),
                cve=item.get("VulnerabilityID"), cvss=cvss_score(item),
                package=item.get("PkgName"), installed_version=item.get("InstalledVersion"),
                fixed_version=item.get("FixedVersion"),
                remediation=("Upgrade to " + item["FixedVersion"] if item.get("FixedVersion") else None))
        for item in result.get("Misconfigurations", []) or []:
            cause = item.get("CauseMetadata") or {}
            category = "iac" if str(target).lower().endswith((".tf", ".tf.json")) else "config"
            add(findings, tool, item.get("Severity"), category,
                item.get("Message") or item.get("Title"), target, item.get("ID"),
                line=cause.get("StartLine") or cause.get("start_line"),
                remediation=item.get("Resolution"))
        for item in result.get("Secrets", []) or []:
            add(findings, tool, item.get("Severity") or "HIGH", "secret",
                item.get("Title") or item.get("RuleID"), target, item.get("RuleID"),
                line=item.get("StartLine"), remediation="Remove the secret and rotate the exposed credential.")


def parse_checkov(report: Any, findings: list[dict[str, Any]]) -> None:
    sections = report if isinstance(report, list) else [report] if isinstance(report, dict) else []
    for section in sections:
        if not isinstance(section, dict):
            continue
        results = section.get("results") or {}
        for item in results.get("failed_checks", []) or []:
            line_range = item.get("file_line_range") or []
            line = line_range[0] if line_range else None
            file_path = str(item.get("file_path") or "<unknown>").replace("\\", "/")
            normalized_file = file_path.lstrip("/")
            if normalized_file == "main.tf":
                normalized_file = "Code/DevSecOps/infra/main.tf"
            elif normalized_file.startswith("infra/"):
                normalized_file = "Code/DevSecOps/" + normalized_file
            elif not normalized_file.startswith("Code/DevSecOps/") and "Code/DevSecOps/" not in normalized_file:
                normalized_file = "Code/DevSecOps/infra/" + normalized_file
            add(findings, "checkov", item.get("severity") or "HIGH", "iac",
                item.get("check_name"), normalized_file, item.get("check_id"),
                line=line, remediation=item.get("guideline") or item.get("guideline_url"),
                resource_type=item.get("resource") or item.get("resource_type"),
                resource=item.get("resource_address"))


