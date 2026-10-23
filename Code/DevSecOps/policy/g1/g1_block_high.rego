package main

import rego.v1
import data.devsecops.exceptions

# g1 blocks HIGH and CRITICAL findings unless an unexpired scoped exception applies.
deny contains message if {
  finding := input.findings[_]
  finding.severity in {"HIGH", "CRITICAL"}
  not exceptions.valid_exception(finding)
  message := sprintf(
    "g1 blocked %s finding: %s (%s) at %s",
    [finding.severity, finding.rule_id, finding.tool, finding.file],
  )
}
