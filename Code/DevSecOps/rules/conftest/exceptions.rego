package devsecops.exceptions

import rego.v1
import data.exceptions

# Load with: conftest test --data policy/exceptions.json ...
# The report carries exception_id; every scoped field must match the finding.
protected_finding(finding) if {
  finding.category == "secret"
}

protected_finding(finding) if {
  finding.category == "iac"
  finding.severity == "CRITICAL"
}

valid_exception(finding) := exception if {
  finding.exception_id != ""
  not protected_finding(finding)
  exception := exceptions.exceptions[_]
  exception.id == finding.exception_id
  exception.owner != ""
  exception.justification != ""
  scope_matches(exception.scope, finding)
  expiry_ns := time.parse_rfc3339_ns(exception.expires)
  time.now_ns() < expiry_ns
}

scope_matches(scope, finding) if {
  is_object(scope)
  count(scope) == 5
  scope.tool != ""
  scope.category != ""
  scope.severity != ""
  scope.rule_id != ""
  scope.file != ""
  scope.tool != "*"
  scope.category != "*"
  scope.severity != "*"
  scope.rule_id != "*"
  scope.file != "*"
  every key, expected in scope {
    finding[key] == expected
  }
}
