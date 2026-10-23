package main

import rego.v1

# g0 records MEDIUM, LOW, and unscored findings for triage while allowing the pipeline to continue.
warn contains message if {
  finding := input.findings[_]
  finding.severity in {"MEDIUM", "LOW", "UNKNOWN"}
  message := sprintf(
    "g0 warning: %s %s (%s) at %s",
    [finding.severity, finding.rule_id, finding.tool, finding.file],
  )
}
