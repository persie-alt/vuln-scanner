#!/usr/bin/env python3
"""
dashboard_public.py — deployment-safe variant of the dashboard.
Unlike dashboard.py, the target is a fixed dropdown of pre-authorized
hosts, not free text — this is the version meant to be deployed publicly,
so a stranger on the internet can't point it at an arbitrary third party.

Run locally:   python3 dashboard_public.py
Run in prod:   gunicorn dashboard_public:app

LEGAL: Only scan systems you own or have written permission to test.
This app intentionally restricts targets to pre-authorized hosts for that reason.
"""

from flask import Flask, request, render_template_string

from main import run_scan
from reporter import _severity_color

app = Flask(__name__)

# Only add a host here if scanning it is explicitly authorized.
# scanme.nmap.org is the Nmap Project's official public test target.
ALLOWED_TARGETS = {
    "scanme.nmap.org": "scanme.nmap.org — Nmap Project's official public test host",
}

FORM_HTML = """
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Vuln Scanner - Live Demo</title>
<style>
    body { font-family: Arial, sans-serif; max-width: 600px; margin: 4rem auto; background: #f7f7f7; color: #222; }
    h1 { color: #333; }
    select { width: 100%; padding: 10px; margin: 8px 0; box-sizing: border-box; }
    button { padding: 10px 20px; background: #333; color: #fff; border: none; cursor: pointer; }
    .legal { color: #888; font-size: 0.85em; margin-top: 2rem; }
    .note { color: #555; font-size: 0.9em; }
</style>
</head>
<body>
    <h1>Vulnerability Scanner — Live Demo</h1>
    <p class="note">This public demo only scans pre-authorized test hosts. The full tool (any target you're authorized to test) is in the GitHub repo, run locally.</p>
    <form method="POST" action="/scan">
        <label>Target:</label>
        <select name="target" required>
            {% for host, desc in targets.items() %}
            <option value="{{ host }}">{{ desc }}</option>
            {% endfor %}
        </select>
        <button type="submit">Scan</button>
    </form>
    <p class="legal">⚠ Demo restricted to explicitly authorized targets. A scan can take a minute or two.</p>
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
    <p class="legal">⚠ Demo restricted to explicitly authorized targets.</p>
</body>
</html>
"""


@app.route("/")
def index():
    return render_template_string(FORM_HTML, targets=ALLOWED_TARGETS)


@app.route("/scan", methods=["POST"])
def scan():
    target = request.form.get("target", "").strip()
    if target not in ALLOWED_TARGETS:
        return "Target not in the authorized demo list.", 403

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
    import os
    port = int(os.environ.get("PORT", 5001))
    app.run(host="0.0.0.0", port=port, debug=False)
