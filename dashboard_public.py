#!/usr/bin/env python3
"""
dashboard_public.py — mobile-first vulnerability scanner dashboard.
Run locally:   python3 dashboard_public.py
Run in prod:   gunicorn dashboard_public:app
LEGAL: Only scan systems you own or have written permission to test.
"""

from flask import Flask, request, render_template_string
from main import run_scan
from remediation import generate_remediation
from reporter import _severity_color

app = Flask(__name__)

BASE_STYLE = """
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
       background:#0d1117;color:#e6edf3;min-height:100vh;padding:0}
  .topbar{background:#161b22;border-bottom:1px solid #30363d;
          padding:14px 20px;display:flex;align-items:center;gap:10px}
  .topbar .logo{font-size:18px;font-weight:700;letter-spacing:.03em;color:#58a6ff}
  .topbar .sub{font-size:12px;color:#8b949e;margin-left:auto}
  .card{background:#161b22;border:1px solid #30363d;border-radius:10px;
        margin:20px 16px;padding:20px}
  label{display:block;font-size:13px;color:#8b949e;margin-bottom:6px;font-weight:500}
  input[type=text]{width:100%;background:#0d1117;border:1px solid #30363d;
    border-radius:7px;color:#e6edf3;font-size:15px;padding:12px 14px;outline:none}
  input[type=text]:focus{border-color:#58a6ff}
  .hint{font-size:12px;color:#6e7681;margin-top:6px}
  .auth-box{background:#1c2128;border:1px solid #ffa657;border-radius:7px;
            padding:14px;margin:16px 0}
  .auth-box label{display:flex;align-items:flex-start;gap:10px;
                  color:#e6edf3;font-size:13px;cursor:pointer;font-weight:400}
  .auth-box input[type=checkbox]{width:16px;height:16px;margin-top:1px;
                                  flex-shrink:0;accent-color:#58a6ff}
  .btn{display:block;width:100%;padding:14px;background:#238636;
       color:#fff;border:none;border-radius:7px;font-size:16px;
       font-weight:600;cursor:pointer;margin-top:4px;letter-spacing:.02em}
  .btn:disabled{background:#21262d;color:#6e7681;cursor:default}
  .legal{font-size:11px;color:#6e7681;text-align:center;
         padding:0 16px 24px;line-height:1.5}
  a{color:#58a6ff;text-decoration:none}

  /* results */
  .result-card{background:#161b22;border:1px solid #30363d;
               border-radius:10px;margin:12px 16px;padding:16px}
  .port-row{display:flex;align-items:center;gap:10px;margin-bottom:8px}
  .port-badge{background:#1f6feb;color:#fff;font-size:13px;font-weight:700;
              padding:4px 10px;border-radius:5px;font-family:monospace;
              white-space:nowrap}
  .banner{font-size:12px;color:#8b949e;font-family:monospace;
          word-break:break-all;line-height:1.5;margin-bottom:8px}
  .cve-list{display:flex;flex-direction:column;gap:5px}
  .cve-chip{font-size:12px;padding:5px 10px;border-radius:5px;
            font-weight:600;font-family:monospace}
  .cve-crit{background:#3d0000;color:#ff7b72;border:1px solid #ff7b72}
  .cve-high{background:#3d1a00;color:#ffa657;border:1px solid #ffa657}
  .cve-med{background:#2d2200;color:#e3b341;border:1px solid #e3b341}
  .cve-low{background:#0d2a0d;color:#3fb950;border:1px solid #3fb950}
  .cve-none{color:#6e7681;font-size:12px}
  .meta{font-size:12px;color:#8b949e;margin:16px 16px 8px}
  .back-btn{display:block;margin:8px 16px 24px;padding:12px;
            background:#21262d;color:#e6edf3;border:none;border-radius:7px;
            font-size:14px;cursor:pointer;text-align:center;text-decoration:none}
  .os-badge{display:inline-block;background:#1c2128;border:1px solid #30363d;
            border-radius:5px;padding:4px 10px;font-size:12px;color:#8b949e;
            margin-bottom:4px}
  .rem-card{background:#0d1f12;border:1px solid #238636;border-radius:10px;
            margin:12px 16px;padding:16px}
  .rem-title{font-size:13px;font-weight:600;color:#3fb950;margin-bottom:10px;
             display:flex;align-items:center;gap:6px}
  .rem-item{margin-bottom:12px;padding-bottom:12px;
            border-bottom:1px solid #1a3a1e}
  .rem-item:last-child{margin-bottom:0;padding-bottom:0;border-bottom:none}
  .rem-sev{font-size:11px;font-weight:700;padding:2px 7px;border-radius:4px;
           display:inline-block;margin-bottom:4px}
  .rem-sev.crit{background:#3d000022;color:#ff7b72;border:1px solid #ff7b72}
  .rem-sev.high{background:#3d1a0022;color:#ffa657;border:1px solid #ffa657}
  .rem-sev.med{background:#2d220022;color:#e3b341;border:1px solid #e3b341}
  .rem-action{font-size:13px;color:#e6edf3;margin:4px 0}
  .rem-cmd{background:#0d1117;border:1px solid #30363d;border-radius:5px;
           padding:8px 10px;font-family:monospace;font-size:11px;
           color:#8b949e;margin-top:6px;word-break:break-all;
           white-space:pre-wrap}
  .rem-detail{font-size:11px;color:#6e7681;margin-top:4px}
  .section-title{font-size:13px;font-weight:600;color:#8b949e;
                 padding:0 16px;margin:16px 0 4px;
                 text-transform:uppercase;letter-spacing:.05em}
</style>
"""

FORM_HTML = """<!DOCTYPE html>
<html lang="en">
<head>""" + BASE_STYLE + """
<title>Vuln Scanner</title>
</head>
<body>
  <div class="topbar">
    <span class="logo">&#x1F50D; vuln-scanner</span>
    <span class="sub">by <a href="https://github.com/persie-alt/vuln-scanner" target="_blank">persie-alt</a></span>
  </div>

  <div class="card">
    <label>Target — IP address or hostname</label>
    <input type="text" id="target" name="target"
           placeholder="scanme.nmap.org or 192.168.1.1" autocomplete="off" autocapitalize="none">
    <p class="hint">No target? Use <strong>scanme.nmap.org</strong> — always authorized for scanning practice.</p>

    <div class="auth-box">
      <label>
        <input type="checkbox" id="authCheck">
        I confirm I own this system or have explicit written authorization to scan it.
        Unauthorized scanning is illegal.
      </label>
    </div>

    <button class="btn" id="scanBtn" onclick="startScan()">Run Scan</button>
  </div>

  <p class="legal">Scans ports 1–500 &bull; Results take up to 60 seconds<br>
  <a href="https://github.com/persie-alt/vuln-scanner" target="_blank">View source on GitHub</a></p>

  <form id="scanForm" method="POST" action="/scan" style="display:none">
    <input type="hidden" name="target" id="formTarget">
    <input type="hidden" name="authorized" value="yes">
  </form>

  <script>
  function startScan(){
    var target = document.getElementById('target').value.trim();
    var auth = document.getElementById('authCheck').checked;
    if(!target){ alert('Enter a target first.'); return; }
    if(!auth){ alert('Confirm authorization before scanning.'); return; }
    document.getElementById('scanBtn').disabled = true;
    document.getElementById('scanBtn').textContent = 'Scanning...';
    document.getElementById('formTarget').value = target;
    document.getElementById('scanForm').submit();
  }
  </script>
</body>
</html>"""


def _cve_chip(cve):
    score = cve.get("cvss")
    cid = cve.get("id", "")
    if score is None:
        css = "cve-low"
    elif score >= 9.0:
        css = "cve-crit"
    elif score >= 7.0:
        css = "cve-high"
    elif score >= 4.0:
        css = "cve-med"
    else:
        css = "cve-low"
    label = f"{cid} &bull; CVSS {score if score is not None else 'N/A'}"
    return f'<div class="cve-chip {css}">{label}</div>'


RESULTS_HTML = """<!DOCTYPE html>
<html lang="en">
<head>""" + BASE_STYLE + """
<title>Results &mdash; {{ target }}</title>
</head>
<body>
  <div class="topbar">
    <span class="logo">&#x1F50D; vuln-scanner</span>
    <span class="sub">results</span>
  </div>

  <div class="meta">
    <strong style="color:#e6edf3">{{ target }}</strong><br>
    <span class="os-badge">OS: {{ os_name }}{{ os_acc }}</span>
  </div>

  {% if not rows %}
  <div class="result-card"><p class="no-ports">No open ports found on this target.</p></div>
  {% endif %}

  {% for row in rows %}
  <div class="result-card">
    <div class="port-row">
      <span class="port-badge">:{{ row.port }}</span>
    </div>
    {% if row.banner != '&mdash;' %}
    <div class="banner">{{ row.banner }}</div>
    {% endif %}
    <div class="cve-list">
      {{ row.cve_html|safe }}
    </div>
  </div>
  {% endfor %}

  {% if rem_items %}
  <div class="section-title">&#x1F527; Remediation Steps</div>
  <div class="rem-card">
    <div class="rem-title">&#x2705; What to fix — generated automatically from scan results</div>
    {% for fix in rem_items %}
    <div class="rem-item">
      <span class="rem-sev {{ fix.css }}">{{ fix.severity }}</span>
      {% if fix.cve_id %}<span style="font-size:11px;color:#6e7681;margin-left:6px">{{ fix.cve_id }}</span>{% endif %}
      <div class="rem-action">{{ fix.action }}</div>
      {% if fix.cmd %}
      <div class="rem-cmd">{{ fix.cmd }}</div>
      {% endif %}
      <div class="rem-detail">{{ fix.detail }}</div>
    </div>
    {% endfor %}
  </div>
  {% endif %}

  <a class="back-btn" href="/">&larr; New Scan</a>
  <p class="legal">&#9888; Only scan systems you own or have explicit written permission to test.</p>
</body>
</html>"""


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
            cve_html = "\n".join(_cve_chip(c) for c in cves)
        else:
            cve_html = '<span class="cve-none">No known CVEs found</span>'
        rows.append({"port": port, "banner": banner or "&mdash;", "cve_html": cve_html})

    os_info = results.get("os") or {}
    os_name = os_info.get("name", "Unknown")
    os_acc = f' ({os_info["accuracy"]}% confidence)' if "accuracy" in os_info else ""

    # Auto-generate remediation
    rem = generate_remediation(results)
    sev_css = {"CRITICAL": "crit", "HIGH": "high", "MEDIUM": "med", "LOW": "low"}
    rem_items = []
    for fix in rem.get("cve_fixes", []):
        cmd = fix.get("linux_cmd") or fix.get("windows_cmd", "")
        rem_items.append({
            "cve_id": fix.get("cve_id", ""),
            "severity": fix.get("severity", "MEDIUM"),
            "css": sev_css.get(fix.get("severity", "MEDIUM"), "med"),
            "action": fix.get("action", ""),
            "cmd": cmd[:200] if cmd else "",
            "detail": fix.get("detail", ""),
        })
    # Add header/TLS remediations if present
    if rem.get("headers_config"):
        rem_items.append({
            "cve_id": "",
            "severity": "MEDIUM",
            "css": "med",
            "action": "Add missing security headers to your web server config",
            "cmd": "# Add to nginx:\nadd_header X-Frame-Options SAMEORIGIN;\nadd_header X-Content-Type-Options nosniff;\nadd_header Content-Security-Policy \"default-src 'self'\";",
            "detail": "Missing headers allow clickjacking, MIME-type attacks, and XSS.",
        })
    if rem.get("tls_config"):
        rem_items.append({
            "cve_id": "",
            "severity": "HIGH",
            "css": "high",
            "action": "Disable TLS 1.0 and 1.1 — allow TLS 1.2+ only",
            "cmd": "# nginx: ssl_protocols TLSv1.2 TLSv1.3;\n# apache: SSLProtocol all -SSLv2 -SSLv3 -TLSv1 -TLSv1.1",
            "detail": "Outdated TLS versions are vulnerable to POODLE, BEAST, and CRIME attacks.",
        })

    return render_template_string(
        RESULTS_HTML, target=target, os_name=os_name,
        os_acc=os_acc, rows=rows, rem_items=rem_items
    )


if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 5001))
    app.run(host="0.0.0.0", port=port, debug=False)
