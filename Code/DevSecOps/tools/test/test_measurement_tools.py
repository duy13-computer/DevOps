from __future__ import annotations

import csv
import json
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

TOOLS_DIR = Path(__file__).resolve().parents[1]
WORKSPACE_ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(TOOLS_DIR))
sys.path.insert(0, str(TOOLS_DIR / "test"))

import check_exceptions  # noqa: E402
import measure_pipeline  # noqa: E402
import summary_parsers  # noqa: E402
import verify_ground_truth  # noqa: E402


class GroundTruthTests(unittest.TestCase):
    def test_semgrep_parser_removes_config_path_from_rule_id(self) -> None:
        findings: list[dict[str, object]] = []
        summary_parsers.parse_semgrep({
            "results": [{
                "check_id": "Code.DevSecOps.rules.semgrep.python.lang.security.audit.eval",
                "path": "Code/DevSecOps/src/app/app.py",
                "start": {"line": 40},
                "extra": {"severity": "ERROR", "message": "unsafe eval"},
            }],
        }, findings)
        self.assertEqual(findings[0]["rule_id"], "python.lang.security.audit.eval")

    def test_baseline_reconstruction_reverses_remediation_patches(self) -> None:
        with tempfile.TemporaryDirectory(dir=WORKSPACE_ROOT) as temporary:
            baseline = measure_pipeline.prepare_baseline(Path(temporary))
            dockerfile = baseline / "Code/DevSecOps/lab/docker/Dockerfile"
            requirements = baseline / "Code/DevSecOps/src/app/requirements.txt"
            baseline_dockerfile = dockerfile.read_text(encoding="utf-8")
            self.assertIn("FROM python:3.12-slim", baseline_dockerfile)
            self.assertIn("USER root", baseline_dockerfile)
            self.assertIn("requests==2.19.0", baseline_dockerfile)
            self.assertIn("requests==2.19.0", requirements.read_text(encoding="utf-8"))

    def test_seed_matches_project_relative_finding_path(self) -> None:
        seed = {
            "tool": "semgrep",
            "category": "sast",
            "rule_id": "RULE-1",
            "file": "Code/DevSecOps/src/app.py",
        }
        finding = {
            "tool": "semgrep",
            "category": "sast",
            "rule_id": "RULE-1",
            "file": "src/app.py",
        }
        self.assertTrue(verify_ground_truth.matches(seed, finding))

    def test_live_rule_ids_match_declared_checkov_and_docker_seeds(self) -> None:
        seeds = verify_ground_truth.load_seeds(
            TOOLS_DIR.parent / "ground_truth" / "seeds.yaml"
        )
        cases = {
            "SEEDED-IAC-03": {
                "tool": "checkov", "category": "iac", "rule_id": "CKV_AWS_145",
                "file": "Code/DevSecOps/infra/main.tf",
            },
            "SEEDED-IAC-05": {
                "tool": "checkov", "category": "iac", "rule_id": "CKV_AWS_274",
                "file": "Code/DevSecOps/infra/main.tf",
            },
            "SEEDED-DOCKER-02": {
                "tool": "trivy-fs", "category": "config", "rule_id": "DS-0002",
                "file": "Code/DevSecOps/lab/docker/Dockerfile",
            },
        }
        for seed_id, finding in cases.items():
            with self.subTest(seed=seed_id):
                seed = next(item for item in seeds if item["id"] == seed_id)
                self.assertTrue(verify_ground_truth.matches(seed, finding))

    def test_score_separates_seeded_matches_from_unmatched_findings(self) -> None:
        seeds = [
            {"id": "S1", "tool": "semgrep", "category": "sast", "rule_id": "RULE-1", "measured": True},
            {"id": "S2", "tool": "semgrep", "category": "sast", "rule_id": "RULE-2", "measured": True},
        ]
        findings = [
            {"tool": "semgrep", "category": "sast", "rule_id": "RULE-1"},
            {"tool": "semgrep", "category": "sast", "rule_id": "UNSEEDED"},
        ]
        score = verify_ground_truth.score_run(findings, seeds)["semgrep"]
        self.assertEqual(score["tp"], 1)
        self.assertEqual(score["fn"], 1)
        self.assertEqual(score["fp"], 1)  # Stored as unmatched pending human review.
        self.assertEqual(score["unmatched_findings"][0]["rule_id"], "UNSEEDED")

    def test_measurement_writes_pending_triage_rows(self) -> None:
        with tempfile.TemporaryDirectory(dir=WORKSPACE_ROOT) as temporary:
            root = Path(temporary)
            seeds = root / "seeds.yaml"
            seeds.write_text(
                "- id: S1\n  tool: semgrep\n  category: sast\n  rule_id: RULE-1\n  measured: true\n",
                encoding="utf-8",
            )
            report = root / "summary.json"
            report.write_text(json.dumps({
                "run_id": "unit-run",
                "commit_sha": "deadbeef",
                "findings": [
                    {"tool": "semgrep", "category": "sast", "rule_id": "RULE-1", "file": "app.py"},
                    {"tool": "semgrep", "category": "sast", "rule_id": "UNSEEDED", "file": "app.py"},
                ],
                "scan_errors": [],
            }), encoding="utf-8")
            output = root / "metrics.csv"
            triage_dir = root / "triage"
            script = TOOLS_DIR / "test" / "verify_ground_truth.py"
            result = subprocess.run([
                sys.executable, str(script), "--findings", str(report), "--baseline",
                "--seeds", str(seeds), "--output", str(output), "--triage-dir", str(triage_dir),
                "--run-id", "unit-run", "--commit-sha", "deadbeef",
            ], check=False, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            with output.open(newline="", encoding="utf-8") as stream:
                metric = next(csv.DictReader(stream))
            self.assertEqual(metric["tp"], "1")
            self.assertEqual(metric["unmatched_findings"], "1")
            triage_files = list(triage_dir.glob("*.csv"))
            self.assertEqual(len(triage_files), 1)
            with triage_files[0].open(newline="", encoding="utf-8") as stream:
                triage = next(csv.DictReader(stream))
            self.assertEqual(triage["classification"], "PENDING_REVIEW")
            self.assertEqual(triage["rule_id"], "UNSEEDED")
            self.assertEqual(triage["observed_count"], "1")


class ExceptionPolicyTests(unittest.TestCase):
    def valid_exception(self) -> dict[str, object]:
        expiry = (datetime.now(timezone.utc) + timedelta(days=30)).replace(microsecond=0)
        return {
            "id": "EXC-UNIT-1",
            "owner": "security@example.test",
            "justification": "Temporary test exception",
            "expires": expiry.isoformat().replace("+00:00", "Z"),
            "scope": {
                "tool": "semgrep",
                "category": "sast",
                "severity": "MEDIUM",
                "rule_id": "RULE-1",
                "file": "src/app.py",
            },
        }

    def test_accepts_narrow_future_exception(self) -> None:
        self.assertEqual(check_exceptions.validate({"exceptions": [self.valid_exception()]}), [])

    def test_rejects_wildcard_and_secret_exception(self) -> None:
        exception = self.valid_exception()
        exception["scope"]["file"] = "*"  # type: ignore[index]
        exception["scope"]["category"] = "secret"  # type: ignore[index]
        errors = check_exceptions.validate({"exceptions": [exception]})
        self.assertTrue(any("wildcard" in error for error in errors))
        self.assertTrue(any("cannot suppress secrets" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
