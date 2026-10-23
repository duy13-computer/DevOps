package main

import rego.v1

# g0 reports MEDIUM and LOW findings while allowing the pipeline to continue.
warn contains message if {
  finding := input.findings[_]
  finding.severity in {"MEDIUM", "LOW"}
  message := sprintf(
    "g0 warning: %s %s (%s) at %s",
    [finding.severity, finding.rule_id, finding.tool, finding.file],
  )
}
