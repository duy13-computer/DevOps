"""Intentionally vulnerable Flask app for the DevSecOps seeded lab.

Run only in an isolated local lab. Never deploy this seeded application.
"""
import os
import subprocess

from flask import Flask, jsonify, request

app = Flask(__name__)


class FakeDatabase:
    """A tiny stand-in that records SQL without connecting to a real database."""

    def execute(self, query):
        return {"query": query, "rows": [{"id": 1, "username": "demo"}]}


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
    # SEEDED-SAST-01: User-controlled input is evaluated as Python code.
    result = eval(expression)
    return jsonify(result=result)


@app.route("/users", methods=["GET"])
def get_user():
    user_id = request.args.get("id", "1")
    # SEEDED-SAST-02: User input is interpolated into SQL with string formatting.
    query = "SELECT id, username FROM users WHERE id = '%s'" % user_id
    return jsonify(db.execute(query))


@app.route("/run", methods=["GET"])
def run_command():
    message = request.args.get("message", "hello")
    # SEEDED-SAST-03: User input reaches a shell command.
    result = subprocess.run(
        "printf '%s\\n' " + message,
        shell=True,
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
