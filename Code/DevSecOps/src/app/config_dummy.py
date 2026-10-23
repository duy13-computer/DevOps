"""Fake credentials are read from the environment in the remediation state."""
import os

AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID")
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
RSA_PRIVATE_KEY = os.getenv("RSA_PRIVATE_KEY")
