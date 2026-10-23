"""Intentionally vulnerable Flask app for the DevSecOps seeded lab.

Run only in an isolated local lab. Never deploy this seeded application.
"""
import os
import subprocess

from flask import Flask, jsonify, request

app = Flask(__name__)


class FakeDatabase:
    """A tiny stand-in that records SQL without connecting to a real database."""

    def execute(self, query, params=None):
        return {"query": query, "params": params or (), "rows": [{"id": 1, "username": "demo"}]}


db = FakeDatabase()


@app.route("/", methods=["GET"])
def index():
    return jsonify(
        service="devsecops-seeded-lab",
        routes=["/health", "/evaluate", "/users", "/run"],
    )


@app.route("/health", methods=["GET"])
def health():
    return jsonify(status="ok", database="simulated")


@app.route("/evaluate", methods=["GET"])
def evaluate():
    expression = request.args.get("expression", "1 + 1")
    # Keep the submitted expression as data; never execute user input.
    return jsonify(expression=expression, evaluation="disabled")


@app.route("/users", methods=["GET"])
def get_user():
    user_id = request.args.get("id", "1")
    query = "SELECT id, username FROM users WHERE id = ?"
    return jsonify(db.execute(query, (user_id,)))


@app.route("/run", methods=["GET"])
def run_command():
    message = request.args.get("message", "hello")
    # Pass user data as an argument; do not invoke a shell.
    result = subprocess.run(
        ["printf", "%s\\n", message],
        shell=False,
        capture_output=True,
        text=True,
        timeout=3,
    )
    return jsonify(output=result.stdout)


if __name__ == "__main__":
    # Debug stays off; the dedicated Semgrep rule has a separate seeded fixture.
    app.run(
        host="0.0.0.0",
        port=int(os.getenv("PORT", "5000")),
        debug=False,
    )
