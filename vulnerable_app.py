#!/usr/bin/env python3
"""
vulnerable_app.py — a tiny, deliberately insecure Flask app.
Exists only to give web_scanner.py something legal and local to test against.
Run it, then scan http://127.0.0.1:5000 — it's your own machine, always authorized.

LEGAL: This app is intentionally vulnerable for testing purposes only.
Never deploy it anywhere reachable by anyone but you.
"""

from flask import Flask, request

app = Flask(__name__)
# No security headers set anywhere below — that's intentional, for check_headers() to find.


@app.route("/")
def home():
    return "<h1>Toy vulnerable app</h1><p>Try /search?q=test or /product?id=1</p>"


@app.route("/search")
def search():
    # Intentionally reflects user input unescaped — for xss_scan() to catch.
    q = request.args.get("q", "")
    return f"<html><body>You searched for: {q}</body></html>"


@app.route("/product")
def product():
    # Fakes a DB error on suspicious input — for sqli_scan() to catch.
    pid = request.args.get("id", "")
    if "'" in pid or "OR 1=1" in pid.upper():
        return "SQL syntax error near '" + pid + "' in query", 500
    return f"<html><body>Product #{pid}</body></html>"


@app.route("/admin")
def admin():
    return "Admin panel (should have been restricted)", 200


@app.route("/backup")
def backup():
    return "backup.zip contents here", 200


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
