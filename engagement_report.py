#!/usr/bin/env python3
"""
engagement_report.py — professional engagement report generator.

Takes your scanner JSON output + post-exploitation evidence JSON and
produces a client-ready HTML report with executive summary, findings,
proof of compromise, and remediation steps.

Usage:
    python3 engagement_report.py --scan output/scan.json --evidence evidence/evidence.json
    python3 engagement_report.py --scan output/scan.json  # scan-only report

LEGAL: Only use for systems you own or have explicit written authorization to test.
"""

import argparse
import json
import os
from datetime import datetime

SEVERITY_COLOR = {
    "CRITICAL": "#ff7b72",
    "HIGH":     "#ffa657",
    "MEDIUM":   "#e3b341",
    "LOW":      "#3fb950",
    "NONE":     "#8b949e",
}

REMEDIATION = {
    "CVE-2011-2523": "Upgrade vsftpd immediately. This backdoor allows instant root access.",
    "CVE-2017-0143": "Apply MS17-010 patch immediately. Disable SMBv1. This is the EternalBlue/WannaCry vector.",
    "CVE-2017-0144": "Apply MS17-010 patch immediately. Disable SMBv1.",
    "CVE-2014-6271": "Update bash to a patched version. Review all CGI scripts.",
    "CVE-2021-44228": "Update Log4j to 2.17.1+. This is Log4Shell — critical priority.",
    "CVE-2021-41773": "Upgrade Apache to 2.4.51+. Disable mod_cgi if not needed.",
    "CVE-2019-0708": "Apply MS19-0708 patch. Disable RDP if not required. Enable NLA.",
    "CVE-2007-2447": "Upgrade Samba. Disable username map script.",
}

DEFAULT_REMEDIATION = "Update the affected software to the latest stable version. Review vendor security advisories."


def load_json(path: str) -> dict:
    with open(path) as f:
        return json.load(f)


def severity_label(cvss) -> str:
    if cvss is None:
        return "NONE"
    if cvss >= 9.0:
        return "CRITICAL"
    if cvss >= 7.0:
        return "HIGH"
    if cvss >= 4.0:
        return "MEDIUM"
    return "LOW"


def generate_report(scan: dict, evidence: dict = None, output_dir: str = "output") -> str:
    target = scan.get("target", "unknown")
    scan_time = scan.get("timestamp", "")
    open_ports = scan.get("open_ports", [])
    banners = scan.get("banners", {})
    cves_by_port = scan.get("cves", {})
    os_info = scan.get("os", {}) or {}

    # flatten all CVEs for risk summary
    all_cves = []
    for port_cves in cves_by_port.values():
        all_cves.extend(port_cves)

    critical = [c for c in all_cves if (c.get("cvss") or 0) >= 9.0]
    high = [c for c in all_cves if 7.0 <= (c.get("cvss") or 0) < 9.0]
    medium = [c for c in all_cves if 4.0 <= (c.get("cvss") or 0) < 7.0]
    low = [c for c in all_cves if 0 < (c.get("cvss") or 0) < 4.0]

    overall_risk = "CRITICAL" if critical else "HIGH" if high else "MEDIUM" if medium else "LOW" if low else "INFORMATIONAL"
    overall_color = SEVERITY_COLOR.get(overall_risk, "#8b949e")

    # build findings rows
    findings_html = ""
    for port in open_ports:
        banner = banners.get(port, banners.get(str(port), "—"))
        port_cves = cves_by_port.get(port, cves_by_port.get(str(port), []))
        if port_cves:
            for cve in port_cves:
                sev = severity_label(cve.get("cvss"))
                color = SEVERITY_COLOR.get(sev, "#8b949e")
                msf = cve.get("msf")
                msf_html = (
                    f'<div style="margin-top:4px;font-size:11px;color:#58a6ff;font-family:monospace">'
                    f'Metasploit: {msf["module"]}</div>'
                ) if msf else ""
                remediation = REMEDIATION.get(cve.get("id", ""), DEFAULT_REMEDIATION)
                findings_html += f"""
                <tr>
                  <td style="font-family:monospace;color:#58a6ff">{port}</td>
                  <td style="font-size:12px;font-family:monospace;color:#8b949e">{banner[:60] if banner else '—'}</td>
                  <td style="font-family:monospace">{cve.get('id','')}</td>
                  <td><span style="background:{color}22;color:{color};padding:2px 8px;border-radius:4px;font-size:12px;font-weight:600">{sev} {cve.get('cvss','')}</span></td>
                  <td style="font-size:12px">{cve.get('description','')[:100]}...{msf_html}</td>
                  <td style="font-size:12px;color:#e6edf3">{remediation}</td>
                </tr>"""
        else:
            findings_html += f"""
            <tr>
              <td style="font-family:monospace;color:#58a6ff">{port}</td>
              <td style="font-size:12px;font-family:monospace;color:#8b949e">{banner[:60] if banner else '—'}</td>
              <td colspan="4" style="color:#6e7681;font-size:12px">No known CVEs — verify manually</td>
            </tr>"""

    # post-exploitation section
    poc_html = ""
    if evidence:
        proof = evidence.get("proof", {})
        poc_html = f"""
        <h2 style="color:#e6edf3;margin:2rem 0 1rem">Proof of Compromise</h2>
        <p style="color:#8b949e;font-size:13px">The following evidence was collected from inside the target system, confirming successful access during the authorized engagement.</p>
        <div style="background:#0d1117;border:1px solid #30363d;border-radius:8px;padding:16px;margin-bottom:1rem">
          <table style="width:100%;border-collapse:collapse;font-size:13px">
            <tr><td style="color:#8b949e;padding:6px 0;width:160px">User account</td><td style="color:#e6edf3;font-family:monospace">{proof.get('whoami','—')}</td></tr>
            <tr><td style="color:#8b949e;padding:6px 0">User ID</td><td style="color:#e6edf3;font-family:monospace">{proof.get('current_user_id','—')}</td></tr>
            <tr><td style="color:#8b949e;padding:6px 0">Hostname</td><td style="color:#e6edf3;font-family:monospace">{proof.get('hostname','—')}</td></tr>
            <tr><td style="color:#8b949e;padding:6px 0">OS</td><td style="color:#e6edf3;font-family:monospace">{proof.get('os_info','—')[:120]}</td></tr>
          </table>
        </div>
        <h3 style="color:#e6edf3;margin:1rem 0 .5rem">Internal network position</h3>
        <pre style="background:#0d1117;border:1px solid #30363d;border-radius:6px;padding:14px;font-size:11px;color:#8b949e;overflow-x:auto;white-space:pre-wrap">{proof.get('internal_ips','—')[:600]}</pre>
        <h3 style="color:#e6edf3;margin:1rem 0 .5rem">Sensitive files located</h3>
        <pre style="background:#0d1117;border:1px solid #30363d;border-radius:6px;padding:14px;font-size:11px;color:#8b949e;overflow-x:auto;white-space:pre-wrap">{proof.get('interesting_files','none found')}</pre>
        """

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Penetration Test Report — {target}</title>
<style>
  body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0d1117;color:#e6edf3;margin:0;padding:2rem}}
  .header{{border-bottom:1px solid #30363d;padding-bottom:1.5rem;margin-bottom:2rem}}
  .badge{{display:inline-block;background:{overall_color}22;color:{overall_color};padding:4px 14px;border-radius:5px;font-weight:700;font-size:14px}}
  table{{width:100%;border-collapse:collapse;background:#161b22;border-radius:8px;overflow:hidden;margin-bottom:2rem}}
  th{{background:#21262d;color:#8b949e;padding:10px 12px;text-align:left;font-size:12px;font-weight:600;text-transform:uppercase;letter-spacing:.05em}}
  td{{padding:10px 12px;border-top:1px solid #30363d;vertical-align:top}}
  .stat{{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:14px 18px;display:inline-block;margin-right:12px;margin-bottom:12px;min-width:80px;text-align:center}}
  .stat-n{{font-size:28px;font-weight:700}}
  .stat-l{{font-size:11px;color:#8b949e;margin-top:2px}}
  h1{{font-size:22px;margin:0 0 8px}}
  h2{{font-size:17px;color:#e6edf3;margin:2rem 0 1rem}}
  .meta{{color:#8b949e;font-size:13px}}
  .legal{{color:#6e7681;font-size:11px;text-align:center;margin-top:3rem;border-top:1px solid #21262d;padding-top:1rem}}
</style>
</head>
<body>
  <div class="header">
    <h1>Penetration Test Report</h1>
    <div class="meta">Target: <strong style="color:#e6edf3">{target}</strong> &bull; Scan date: {scan_time[:10]} &bull; OS: {os_info.get('name','Unknown')}</div>
    <div style="margin-top:12px"><span class="badge">Overall Risk: {overall_risk}</span></div>
  </div>

  <h2>Executive Summary</h2>
  <p style="color:#8b949e;font-size:14px;line-height:1.7">
    A penetration test was conducted against <strong style="color:#e6edf3">{target}</strong> on {scan_time[:10]}.
    The assessment identified <strong style="color:#e6edf3">{len(open_ports)}</strong> open ports and
    <strong style="color:#e6edf3">{len(all_cves)}</strong> known vulnerabilities.
    The overall risk rating is <strong style="color:{overall_color}">{overall_risk}</strong>.
    {'Proof of compromise was obtained and is documented below.' if evidence else 'Network-level reconnaissance completed. Manual exploitation testing required to confirm exploitability.'}
  </p>

  <div>
    <div class="stat"><div class="stat-n" style="color:#ff7b72">{len(critical)}</div><div class="stat-l">Critical</div></div>
    <div class="stat"><div class="stat-n" style="color:#ffa657">{len(high)}</div><div class="stat-l">High</div></div>
    <div class="stat"><div class="stat-n" style="color:#e3b341">{len(medium)}</div><div class="stat-l">Medium</div></div>
    <div class="stat"><div class="stat-n" style="color:#3fb950">{len(low)}</div><div class="stat-l">Low</div></div>
    <div class="stat"><div class="stat-n" style="color:#58a6ff">{len(open_ports)}</div><div class="stat-l">Open Ports</div></div>
  </div>

  <h2>Findings</h2>
  <table>
    <tr>
      <th>Port</th><th>Service</th><th>CVE</th><th>Severity</th><th>Description</th><th>Remediation</th>
    </tr>
    {findings_html}
  </table>

  {poc_html}

  <div class="legal">
    ⚠ This report is confidential and prepared for authorized security testing purposes only.
    Produced by vuln-scanner — github.com/persie-alt/vuln-scanner
  </div>
</body>
</html>"""

    os.makedirs(output_dir, exist_ok=True)
    target_safe = target.replace(".", "_").replace(":", "_")
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(output_dir, f"engagement_{target_safe}_{ts}.html")
    with open(path, "w") as f:
        f.write(html)
    print(f"[+] Engagement report saved: {path}")
    return path


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate a client engagement report.")
    parser.add_argument("--scan", required=True, help="Path to scanner JSON output")
    parser.add_argument("--evidence", default=None, help="Path to post-exploit evidence JSON")
    parser.add_argument("--output", default="output", help="Output directory")
    args = parser.parse_args()

    scan = load_json(args.scan)
    evidence = load_json(args.evidence) if args.evidence else None
    generate_report(scan, evidence, args.output)
