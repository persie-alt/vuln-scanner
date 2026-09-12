#!/usr/bin/env python3
"""
dashboard_public.py — public-facing vulnerability scanner dashboard.
Accepts any authorized target with a confirmation checkbox.

Run locally:   python3 dashboard_public.py
Run in prod:   gunicorn dashboard_public:app

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
<title>Vulnerability Scanner</title>
<style>
    body { font-family: Arial, sans-serif; max-width: 600px; margin: 4rem auto; background: #f7f7f7; color: #222; padding: 0 1rem; }
    h1 { color: #333; }
    input[type=text] { width: 100%; padding: 10px; margin: 8px 0; box-sizing: border-box; font-size: 14px; }
    .auth-box { background: #fff3cd; border: 1px solid #ffc107; border-radius: 5px; padding: 12px; margin: 10px 0; }
    .auth-box label { display: flex; align-items: flex-start; gap: 10px; font-size: 13px; cursor: pointer; }
    .auth-box input[type=checkbox] { margin-top: 2px; flex-shrink: 0; }
    button { padding: 10px 20px; background: #333; color: #fff; border: none; cursor: pointer; margin-top: 8px; }
    .legal { color: #888; font-size: 0.82em; margin-top: 2rem; }
    .example { color: #555; font-size: 0.85em; margin: 4px 0 0 0; }
</style>
</head>
<body>
    <h1>Vulnerability Scanner</h1>
    <p>Enter any target you are authorized to scan. Source code on <a href="https://github.com/persie-alt/vuln-scanner" target="_blank">GitHub</a>.</p>
    <form method="POST" action="/scan" onsubmit="return validate()">
        <label><strong>Target (IP or hostname):</strong></label>
        <input type="text" name="target" id="target" placeholder="e.g. scanme.nmap.org or 192.168.1.1" required>
        <p class="example">Not sure? Use <strong>scanme.nmap.org</strong> — Nmap's official public test host, always authorized.</p>
        <div class="auth-box">
            <label>
                <input type="checkbox" id="authCheck" name="authorized" value="yes" required>
                I confirm I own this system or have explicit written authorization to scan it. Unauthorized scanning is illegal.
            </label>
        </div>
        <button type="submit" id="scanBtn">Scan</button>
    </form>
    <p class="legal">⚠ Scans common ports (1-500). Results take up to 60 seconds.</p>
    <script>
    function validate() {
        if (!document.getElementById('authCheck').checked) {
            alert('You must confirm authorization before scanning.');
            return false;
        }
        document.getElementById('scanBtn').disabled = true;
        document.getElementById('scanBtn').textContent = 'Scanning...';
        return true;
    }
    </script>
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
    authorized = request.form.get("authorized", "")
    if not target:
        return "No target provided.", 400
    if authorized != "yes":
        return "Authorization confirmation required.", 403

    results = run_scan(target, port_range="1-500")

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
    import os
    port = int(os.environ.get("PORT", 5001))
    app.run(host="0.0.0.0", port=port, debug=False)
