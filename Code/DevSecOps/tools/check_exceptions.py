#!/usr/bin/env python3
"""Validate owner/expiry metadata for each active ID in .trivyignore."""
from datetime import date
from pathlib import Path
import re
import sys

path = Path(__file__).resolve().parents[1] / ".trivyignore"
lines = path.read_text(encoding="utf-8").splitlines()
errors = []
for i, line in enumerate(lines):
    value = line.strip()
    if not value or value.startswith("#"):
        continue
    comments = []
    j = i - 1
    while j >= 0 and lines[j].lstrip().startswith("#"):
        comments.append(lines[j].lstrip()[1:].strip())
        j -= 1
    text = "\n".join(comments)
    owner = re.search(r"owner:\s*([^\s]+)", text, re.I)
    expires = re.search(r"expires:\s*(\d{4}-\d{2}-\d{2})", text, re.I)
    if not owner or not expires:
        errors.append(f"line {i + 1} {value}: requires adjacent owner and expires metadata")
        continue
    try:
        if date.fromisoformat(expires.group(1)) < date.today():
            errors.append(f"line {i + 1} {value}: exception expired on {expires.group(1)}")
    except ValueError:
        errors.append(f"line {i + 1} {value}: invalid expiry date")
if errors:
    print("\n".join(errors), file=sys.stderr)
    sys.exit(1)
print("All Trivy exceptions have a named owner and a future expiry date.")
