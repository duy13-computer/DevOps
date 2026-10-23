#!/usr/bin/env python3
"""Validate narrowly scoped, owner-approved, time-bounded finding exceptions."""

from __future__ import annotations

import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PATH = PROJECT_ROOT / "policy/exceptions.json"
REQUIRED_SCOPE = {"tool", "category", "severity", "rule_id", "file"}
ALLOWED_SEVERITIES = {"UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
ALLOWED_TOOLS = {"semgrep", "gitleaks", "trivy-fs", "trivy-image", "checkov"}
ALLOWED_CATEGORIES = {"sast", "sca", "secret", "iac", "image", "config"}


def validate(data: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(data, dict) or not isinstance(data.get("exceptions"), list):
        return ["top-level JSON must contain an exceptions array"]
    seen_ids: set[str] = set()
    now = datetime.now(timezone.utc)
    for index, item in enumerate(data["exceptions"], 1):
        label = f"exceptions[{index}]"
        if not isinstance(item, dict):
            errors.append(f"{label} must be an object")
            continue
        exception_id = item.get("id")
        if not isinstance(exception_id, str) or not exception_id.strip():
            errors.append(f"{label}.id must be a non-empty string")
        elif exception_id != exception_id.strip():
            errors.append(f"{label}.id cannot have leading or trailing whitespace")
        elif exception_id in seen_ids:
            errors.append(f"duplicate exception id: {exception_id}")
        else:
            seen_ids.add(exception_id)
        for field in ("owner", "justification"):
            if not isinstance(item.get(field), str) or not item[field].strip():
                errors.append(f"{label}.{field} must be a non-empty string")
        raw_expiry = item.get("expires")
        try:
            expiry_text = str(raw_expiry)
            if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})", expiry_text):
                raise ValueError("timestamp must be RFC3339")
            expiry = datetime.fromisoformat(expiry_text.replace("Z", "+00:00"))
            if expiry.tzinfo is None:
                raise ValueError("timezone is required")
            if expiry.astimezone(timezone.utc) <= now:
                errors.append(f"{label}.expires is expired")
        except ValueError:
            errors.append(f"{label}.expires must be a future RFC3339 timestamp with timezone")

        scope = item.get("scope")
        if not isinstance(scope, dict):
            errors.append(f"{label}.scope must be an object")
            continue
        missing = REQUIRED_SCOPE - set(scope)
        extra = set(scope) - REQUIRED_SCOPE
        if missing:
            errors.append(f"{label}.scope is missing: {', '.join(sorted(missing))}")
        if extra:
            errors.append(f"{label}.scope has unsupported fields: {', '.join(sorted(extra))}")
        for field in REQUIRED_SCOPE & set(scope):
            value = scope[field]
            if not isinstance(value, str) or not value.strip():
                errors.append(f"{label}.scope.{field} must be a non-empty string")
            elif value.strip() in {"*", "all", "ANY"}:
                errors.append(f"{label}.scope.{field} cannot be a wildcard")
        severity = str(scope.get("severity", ""))
        if severity and severity not in ALLOWED_SEVERITIES:
            errors.append(f"{label}.scope.severity is not recognized")
        scope_tool = scope.get("tool")
        scope_category = scope.get("category")
        if isinstance(scope_tool, str) and scope_tool and scope_tool not in ALLOWED_TOOLS:
            errors.append(f"{label}.scope.tool is not a supported scanner")
        if isinstance(scope_category, str) and scope_category and scope_category not in ALLOWED_CATEGORIES:
            errors.append(f"{label}.scope.category is not recognized")
        if scope.get("category") == "secret":
            errors.append(f"{label} cannot suppress secrets")
        if scope.get("category") == "iac" and severity == "CRITICAL":
            errors.append(f"{label} cannot suppress CRITICAL IaC findings")
    return errors


def main() -> int:
    path = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else DEFAULT_PATH
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"Could not read exception policy {path}: {exc}", file=sys.stderr)
        return 1
    errors = validate(data)
    if errors:
        print("Invalid exception policy:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1
    count = len(data["exceptions"])
    print(f"Exception policy valid: {count} narrowly scoped exception(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
