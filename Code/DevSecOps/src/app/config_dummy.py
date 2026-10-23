"""Fake credentials for secret-scanner demonstrations only."""

# SEEDED-SECRET-01: demo-only AWS key identifier; intentionally non-functional.
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"

# SEEDED-SECRET-02: demo-only GitHub token; all characters are zero.
GITHUB_TOKEN = "ghp_000000000000000000000000000000000000"

# SEEDED-SECRET-03: demo-only private-key marker; not valid PEM key material.
RSA_PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
THIS_IS_A_FAKE_NON_FUNCTIONAL_DEMO_VALUE
-----END RSA PRIVATE KEY-----"""
