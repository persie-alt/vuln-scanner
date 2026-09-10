#!/usr/bin/env python3
"""
dashboard.py — simple web dashboard for the vulnerability scanner.
Enter a target in the browser, see port scan + banner + OS + CVE results.

Run: python3 dashboard.py
Then open http://127.0.0.1:5001

LEGAL: Only scan systems you own or have written permission to test.
"""

from flask import Flask, request, render_template_string

from main import run_scan
from reporter import _severity_color

app = Flask(__name__)

FORM_HTML = """
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Vuln Scanner Dashboard</title>
<style>
    body { font-family: Arial, sans-serif; max-width: 600px; margin: 4rem auto; background: #f7f7f7; color: #222; }
    h1 { color: #333; }
    input[type=text] { width: 100%; padding: 10px; margin: 8px 0; box-sizing: border-box; }
    button { padding: 10px 20px; background: #333; color: #fff; border: none; cursor: pointer; }
    .legal { color: #888; font-size: 0.85em; margin-top: 2rem; }
</style>
</head>
<body>
    <h1>Vulnerability Scanner</h1>
    <form method="POST" action="/scan">
        <label>Target (IP or hostname):</label>
        <input type="text" name="target" placeholder="scanme.nmap.org" required>
        <button type="submit">Scan</button>
    </form>
    <p class="legal">⚠ Only scan systems you own or have explicit written permission to test. A scan can take a minute or two.</p>
</body>
</html>
"""

RESULTS_HTML = """
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Scan Results - {{ target }}</title>
<style>
    body { font-family: Arial, sans-serif; margin: 2rem; background: #f7f7f7; color: #222; }
    h1 { color: #333; }
    table { border-collapse: collapse; width: 100%; background: #fff; margin-top: 1rem; }
    th, td { border: 1px solid #ddd; padding: 8px; text-align: left; vertical-align: top; }
    th { background: #333; color: #fff; }
    a.back { display: inline-block; margin-top: 1.5rem; }
    .legal { color: #888; font-size: 0.85em; margin-top: 2rem; }
</style>
</head>
<body>
    <h1>Scan Results - {{ target }}</h1>
    <p><strong>OS guess:</strong> {{ os_name }}{{ os_acc }}</p>
    <table>
        <tr><th>Port</th><th>Banner</th><th>CVEs</th></tr>
        {% for row in rows %}
        <tr><td>{{ row.port }}</td><td>{{ row.banner }}</td><td>{{ row.cve_html|safe }}</td></tr>
        {% endfor %}
        {% if not rows %}
        <tr><td colspan="3">No open ports found</td></tr>
        {% endif %}
    </table>
    <a class="back" href="/">&larr; New scan</a>
    <p class="legal">⚠ Only scan systems you own or have explicit written permission to test.</p>
</body>
</html>
"""


@app.route("/")
def index():
    return FORM_HTML


@app.route("/scan", methods=["POST"])
def scan():
    target = request.form.get("target", "").strip()
    if not target:
        return "No target provided", 400

    results = run_scan(target)

    rows = []
    for port in results.get("open_ports", []):
        banner = results.get("banners", {}).get(port, "")
        cves = results.get("cves", {}).get(port, [])
        if cves:
            cve_html = "<br>".join(
                f'<span style="color:{_severity_color(c["cvss"])}">'
                f'{c["id"]} (CVSS {c["cvss"] if c["cvss"] is not None else "N/A"})</span>'
                for c in cves
            )
        else:
            cve_html = "—"
        rows.append({"port": port, "banner": banner or "—", "cve_html": cve_html})

    os_info = results.get("os") or {}
    os_name = os_info.get("name", "Unknown")
    os_acc = f' ({os_info["accuracy"]}% confidence)' if "accuracy" in os_info else ""

    return render_template_string(
        RESULTS_HTML, target=target, os_name=os_name, os_acc=os_acc, rows=rows
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=False)
