# Ground truth

`seeds.yaml` is the source of truth for 23 intentionally seeded cases. Each case records its tool, rule or CVE, repository-relative path, source line, and severity. The `id` is the seed marker used in the source fixture. The verification script matches the normalized report on stable finding fields; line numbers are included for review and can change after edits.

The manifest marks 21 cases as measurable by the current workflows. The Python 3.6 end-of-life base image is documented but not measured because the release workflow builds the fixed image. The dummy file copied by the vulnerable Dockerfile is a clean non-secret control and must not be counted as a detection.

From the repository root, apply each patch to reproduce the remediation state:

```bash
git apply Code/DevSecOps/ground_truth/patches/fix_sast.patch
git apply Code/DevSecOps/ground_truth/patches/fix_secret.patch
git apply Code/DevSecOps/ground_truth/patches/fix_docker.patch
git apply Code/DevSecOps/ground_truth/patches/fix_infra.patch
```

Compare one normalized report:

```bash
python Code/DevSecOps/tools/test/verify_ground_truth.py --baseline
python Code/DevSecOps/tools/test/verify_ground_truth.py --after-fix
```

The default input resolves to `Code/DevSecOps/reports/summary.json` from either the repository root or the project directory. Pass multiple `--findings` files to average metrics over repeated scans. Rows append to `tests/results/metrics/detection_rate.csv`; use `--overwrite` to start a new experiment. Precision is relative to the measured seed set, so unlisted findings are unmatched findings, not necessarily scanner false positives.
