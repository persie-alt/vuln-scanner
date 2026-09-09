#!/usr/bin/env python3
"""
reporter.py — Day 4: JSON + HTML report generation
Takes a scan results dict and writes a timestamped JSON file and a
standalone HTML report with color-coded CVE severity.
"""

import json
import os
from datetime import datetime

OUTPUT_DIR = "output"


def _ensure_output_dir(output_dir: str = OUTPUT_DIR) -> str:
    os.makedirs(output_dir, exist_ok=True)
    return output_dir


def save_json(results: dict, output_dir: str = OUTPUT_DIR) -> str:
    """Save scan results as a timestamped JSON file. Returns the filepath ('' on failure)."""
    _ensure_output_dir(output_dir)
    target_safe = str(results.get("target", "scan")).replace(".", "_").replace(":", "_")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filepath = os.path.join(output_dir, f"{target_safe}_{timestamp}.json")

    try:
        with open(filepath, "w") as f:
            json.dump(results, f, indent=2, default=str)
        return filepath
    except OSError as e:
        print(f"[!] Failed to save JSON: {e}")
        return ""


def _severity_color(cvss) -> str:
    """CVSS >= 7.0 red, 4-6.9 yellow, <4 green, unknown gray."""
    if cvss is None:
        return "#888888"
    if cvss >= 7.0:
        return "#d9534f"
    if cvss >= 4.0:
        return "#f0ad4e"
    return "#5cb85c"


def generate_html(results: dict, output_dir: str = OUTPUT_DIR) -> str:
    """Render scan results as a standalone HTML report. Returns the filepath ('' on failure)."""
    _ensure_output_dir(output_dir)
    target = results.get("target", "unknown")
    timestamp = results.get("timestamp", "")
    open_ports = results.get("open_ports", [])
    banners = results.get("banners", {})
    os_info = results.get("os", {}) or {}
    cves = results.get("cves", {})

    rows = []
    for port in open_ports:
        banner = banners.get(port, banners.get(str(port), ""))
        port_cves = cves.get(port, cves.get(str(port), []))
        if port_cves:
            cve_html = "<br>".join(
                f'<span style="color:{_severity_color(c["cvss"])}">'
                f'{c["id"]} (CVSS {c["cvss"] if c["cvss"] is not None else "N/A"})</span>'
                for c in port_cves
            )
        else:
            cve_html = "—"
        rows.append(
            f"<tr><td>{port}</td><td>{banner or '—'}</td><td>{cve_html}</td></tr>"
        )

    os_name = os_info.get("name", "Unknown")
    os_acc = f' ({os_info["accuracy"]}% confidence)' if "accuracy" in os_info else ""

    html = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Scan Report - {target}</title>
<style>
    body {{ font-family: Arial, sans-serif; margin: 2rem; background: #f7f7f7; color: #222; }}
    h1 {{ color: #333; }}
    table {{ border-collapse: collapse; width: 100%; background: #fff; }}
    th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; vertical-align: top; }}
    th {{ background: #333; color: #fff; }}
    .meta {{ margin-bottom: 1.5rem; color: #555; }}
</style>
</head>
<body>
    <h1>Vulnerability Scan Report</h1>
    <div class="meta">
        <p><strong>Target:</strong> {target}</p>
        <p><strong>Scan time:</strong> {timestamp}</p>
        <p><strong>OS guess:</strong> {os_name}{os_acc}</p>
    </div>
    <table>
        <tr><th>Port</th><th>Banner</th><th>CVEs</th></tr>
        {"".join(rows) if rows else "<tr><td colspan='3'>No open ports found</td></tr>"}
    </table>
</body>
</html>"""

    target_safe = str(target).replace(".", "_").replace(":", "_")
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    filepath = os.path.join(output_dir, f"{target_safe}_{ts}.html")

    try:
        with open(filepath, "w") as f:
            f.write(html)
        return filepath
    except OSError as e:
        print(f"[!] Failed to save HTML report: {e}")
        return ""
