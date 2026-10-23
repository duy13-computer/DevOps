#!/usr/bin/env python3
"""Normalize scanner JSON, apply valid scoped exceptions, and write CI summaries."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


from summary_parsers import (
    parse_checkov,
    parse_gitleaks,
    parse_semgrep,
    parse_trivy,
    read_json,
)


def apply_exceptions(findings: list[dict[str, Any]], exceptions: Any) -> list[str]:
    entries = exceptions.get("exceptions", []) if isinstance(exceptions, dict) else []
    now = datetime.now(timezone.utc)
    notes: list[str] = []
    for exception in entries:
        if not isinstance(exception, dict):
            notes.append("- Invalid exception entry: each entry must be an object.")
            continue
        scope = exception.get("scope") or {}
        if not isinstance(scope, dict) or not scope:
            notes.append(f"- Invalid scope: {exception.get('id', '<missing id>')} (scope must be a non-empty object).")
            continue
        required_scope = {"tool", "category", "severity", "rule_id", "file"}
        if set(scope) != required_scope or any(
            not isinstance(value, str) or not value.strip() or value.strip() in {"*", "all", "ANY"}
            for value in scope.values()
        ):
            notes.append(
                f"- Invalid scope: {exception.get('id', '<missing id>')} (requires exact tool/category/severity/rule_id/file values)."
            )
            continue
        matches = [finding for finding in findings
                   if all(finding.get(key) == expected for key, expected in scope.items())]
        if not matches:
            notes.append(f"- No matching finding: {exception.get('id', '<missing id>')}.")
            continue
        protected = [finding for finding in matches
                     if finding.get("category") == "secret"
                     or (finding.get("category") == "iac" and finding.get("severity") == "CRITICAL")]
        if protected:
            notes.append(
                f"- Rejected {exception.get('id', '<missing id>')}: secrets and CRITICAL IaC findings cannot be excepted."
            )
            continue
        try:
            expires = datetime.fromisoformat(str(exception.get("expires", "")).replace("Z", "+00:00"))
            if expires.tzinfo is None:
                raise ValueError("expiry must include a timezone")
        except ValueError:
            notes.append(f"- Invalid expiry: {exception.get('id', '<missing id>')}.")
            continue
        if expires.astimezone(timezone.utc) <= now:
            notes.append(f"- Expired: {exception.get('id', '<missing id>')} (owner: {exception.get('owner', 'unknown')}).")
            continue
        if not exception.get("owner") or not exception.get("justification"):
            notes.append(f"- Invalid metadata: {exception.get('id', '<missing id>')} (owner and justification are required).")
            continue
        exception_id = str(exception.get("id", ""))
        for finding in matches:
            finding["exception_id"] = exception_id
        notes.append(f"- Applied {exception_id} to {len(matches)} finding(s); owner: {exception['owner']}; expires: {exception['expires']}.")
    return notes


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results", type=Path, default=Path("tests/results/raw"))
    parser.add_argument("--output-dir", type=Path, default=Path("reports"))
    parser.add_argument("--exceptions", type=Path, default=Path("policy/exceptions.json"))
    parser.add_argument("--run-id", default="")
    parser.add_argument("--commit-sha", default="")
    parser.add_argument("--require", default="", help="Comma-separated report stems required to exist")
    args = parser.parse_args()

    findings: list[dict[str, Any]] = []
    errors: list[str] = []
    report_specs = [
        ("semgrep.json", parse_semgrep, ()),
        ("gitleaks.json", parse_gitleaks, ()),
        ("trivy-fs.json", parse_trivy, (False,)),
        ("trivy-image.json", parse_trivy, (True,)),
        ("checkov.json", parse_checkov, ()),
    ]
    required = {item.strip() for item in args.require.split(",") if item.strip()}
    for filename, parser_fn, extra_args in report_specs:
        path = args.results / filename
        try:
            report = read_json(path)
        except (json.JSONDecodeError, OSError) as exc:
            errors.append(f"Could not read {filename}: {exc}")
            continue
        if report is None:
            if path.stem in required:
                errors.append(f"Required scanner report is missing: {filename}")
            continue
        try:
            parser_fn(report, findings, *extra_args)
        except (AttributeError, TypeError, ValueError) as exc:
            errors.append(f"Could not normalize {filename}: {exc}")

    for status_file in sorted(args.results.glob("status-*.json")):
        try:
            status = json.loads(status_file.read_text(encoding="utf-8"))
            if status.get("outcome") != "success":
                errors.append(f"Scanner {status.get('scanner', status_file.stem[7:])} ended with {status.get('outcome', 'unknown')}")
        except (json.JSONDecodeError, OSError) as exc:
            errors.append(f"Could not read {status_file.name}: {exc}")

    try:
        exceptions_data = read_json(args.exceptions) if args.exceptions.exists() else {"exceptions": []}
    except (json.JSONDecodeError, OSError) as exc:
        errors.append(f"Could not read exception data {args.exceptions}: {exc}")
        exceptions_data = {"exceptions": []}
    exception_notes = apply_exceptions(findings, exceptions_data)
    summary = {
        "run_id": args.run_id,
        "commit_sha": args.commit_sha,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "findings": findings,
        "scan_errors": errors,
    }

    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    counts = {severity: sum(1 for item in findings if item["severity"] == severity)
              for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")}
    rows = [
        "# DevSecOps scan summary",
        "",
        f"- Run: {args.run_id or 'local'}",
        f"- Commit: {args.commit_sha or 'unknown'}",
        f"- Findings: {len(findings)} (Critical {counts['CRITICAL']}, High {counts['HIGH']}, Medium {counts['MEDIUM']}, Low {counts['LOW']}, Unknown {counts['UNKNOWN']})",
        f"- Scan errors: {len(errors)}",
        "",
        "## Findings",
        "",
        "| Severity | Tool | Rule | File | Line | Title |",
        "|---|---|---|---|---:|---|",
    ]
    for item in findings:
        title = item["title"].replace("|", "\\|").replace("\n", " ")
        rows.append(f"| {item['severity']} | {item['tool']} | {item['rule_id']} | {item['file']} | {item.get('line', '')} | {title} |")
    if not findings:
        rows.append("| — | — | — | — | — | No findings |")
    if errors:
        rows.extend(["", "## Scanner errors", ""] + [f"- {error}" for error in errors])
    (args.output_dir / "pr-summary.md").write_text("\n".join(rows) + "\n", encoding="utf-8")
    exception_lines = ["# Applied exceptions", ""] + exception_notes
    if not exception_notes:
        exception_lines.append("- No exceptions configured or matched.")
    (args.output_dir / "exceptions_applied.md").write_text("\n".join(exception_lines) + "\n", encoding="utf-8")
    print(f"Wrote {len(findings)} findings to {args.output_dir / 'summary.json'}")
    if errors:
        print("Scanner errors detected; failing closed:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
