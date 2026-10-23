"""Compatibility entry point for the original lab instructions."""
from app import app


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
