package main

import rego.v1
import data.devsecops.exceptions

blocked_iac_rule_ids := {
  "CKV_AWS_1",
  "CKV_AWS_19",
  "CKV_AWS_20",
  "CKV_AWS_24",
  "CKV_AWS_25",
  "CKV_AWS_49",
  "CKV_AWS_51",
  "CKV_AWS_55",
  "CKV_AWS_57",
  "CKV_AWS_58",
  "CKV_AWS_106",
  "CKV_AWS_109",
  "CKV_AWS_110",
  "CKV_AWS_136",
  "SEEDED-IAC-01",
  "SEEDED-IAC-02",
  "SEEDED-IAC-03",
  "SEEDED-IAC-04",
  "SEEDED-IAC-05",
  "SEEDED-IAC-06",
}

# Never let an unlisted CRITICAL IaC rule bypass the release gate.
deny contains message if {
  finding := input.findings[_]
  finding.category == "iac"
  finding.severity == "CRITICAL"
  not exceptions.valid_exception(finding)
  message := sprintf("g2 blocked CRITICAL IaC finding %s at %s", [finding.rule_id, finding.file])
}

# g2 blocks known public-network, public-bucket, wildcard-IAM, and weak-ECR checks.
deny contains message if {
  finding := input.findings[_]
  finding.rule_id in blocked_iac_rule_ids
  not exceptions.valid_exception(finding)
  message := sprintf(
    "g2 blocked IaC control %s at %s",
    [finding.rule_id, finding.file],
  )
}

# Also block weak IaC findings from tools that emit resource metadata.
deny contains message if {
  finding := input.findings[_]
  finding.resource_type == "aws_security_group"
  finding.cidr_blocks[_] == "0.0.0.0/0"
  finding.from_port in {22, 3389}
  not exceptions.valid_exception(finding)
  message := sprintf("g2 blocked public management port in %s", [finding.file])
}

deny contains message if {
  finding := input.findings[_]
  finding.resource_type == "aws_s3_bucket_acl"
  finding.acl == "public-read"
  not exceptions.valid_exception(finding)
  message := sprintf("g2 blocked public S3 ACL in %s", [finding.file])
}

deny contains message if {
  finding := input.findings[_]
  finding.resource_type in {"aws_iam_policy", "aws_iam_role_policy"}
  finding.actions[_] == "*"
  finding.resources[_] == "*"
  not exceptions.valid_exception(finding)
  message := sprintf("g2 blocked wildcard IAM policy in %s", [finding.file])
}

# The gate blocks HIGH/CRITICAL image findings.
deny contains message if {
  finding := input.findings[_]
  finding.tool in {"trivy-image", "trivy_image"}
  finding.severity in {"HIGH", "CRITICAL"}
  not exceptions.valid_exception(finding)
  message := sprintf(
    "g2 blocked %s image finding %s",
    [finding.severity, finding.rule_id],
  )
}

deny contains message if {
  finding := input.findings[_]
  finding.category == "secret"
  not exceptions.valid_exception(finding)
  message := sprintf("g2 blocked secret finding at %s", [finding.file])
}
