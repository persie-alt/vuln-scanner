#!/usr/bin/env python3
"""
remediation.py — automated remediation script generator.

Reads scanner JSON output and generates:
1. A firewall hardening script (iptables/ufw) to close unnecessary ports
2. Web server config snippets to add missing security headers
3. TLS hardening config to disable weak versions
4. Package update commands for CVE-affected software
5. A before/after comparison report

Usage:
    python3 remediation.py --scan output/scan.json --os linux
    python3 remediation.py --scan output/scan.json --os windows

LEGAL: Only run against systems you own or have explicit written authorization.
Always review generated scripts before running them on production systems.
A script that closes the wrong port could lock you out of a server.
"""

import argparse
import json
import os
from datetime import datetime

# Ports that are commonly legitimate — don't recommend closing these by default
COMMONLY_NEEDED_PORTS = {
    22: "SSH — remote admin access",
    80: "HTTP — web traffic",
    443: "HTTPS — secure web traffic",
    25: "SMTP — email sending",
    53: "DNS — domain resolution",
    3306: "MySQL — database (only if web app needs it locally)",
    5432: "PostgreSQL — database",
}

# CVE → specific fix command
CVE_FIXES = {
    "CVE-2011-2523": {
        "action": "Uninstall or upgrade vsftpd immediately",
        "linux_cmd": "sudo apt-get remove vsftpd -y || sudo yum remove vsftpd -y",
        "severity": "CRITICAL",
        "detail": "This is a deliberate backdoor — the server must be removed or replaced immediately.",
    },
    "CVE-2017-0143": {
        "action": "Disable SMBv1 and apply MS17-010 patch",
        "linux_cmd": "sudo sed -i 's/\\[global\\]/\\[global\\]\\n\\tmin protocol = SMB2/' /etc/samba/smb.conf && sudo systemctl restart smbd",
        "windows_cmd": "Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force",
        "severity": "CRITICAL",
        "detail": "EternalBlue — used by WannaCry. Disable SMBv1 immediately.",
    },
    "CVE-2017-0144": {
        "action": "Disable SMBv1 and apply MS17-010 patch",
        "linux_cmd": "sudo sed -i 's/\\[global\\]/\\[global\\]\\n\\tmin protocol = SMB2/' /etc/samba/smb.conf && sudo systemctl restart smbd",
        "windows_cmd": "Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force",
        "severity": "CRITICAL",
        "detail": "EternalBlue variant — same fix as CVE-2017-0143.",
    },
    "CVE-2014-6271": {
        "action": "Update bash to a patched version",
        "linux_cmd": "sudo apt-get update && sudo apt-get install --only-upgrade bash -y",
        "severity": "CRITICAL",
        "detail": "Shellshock — update bash immediately. Also disable CGI scripts if not needed.",
    },
    "CVE-2021-44228": {
        "action": "Update Log4j to 2.17.1 or later",
        "linux_cmd": "# Find Log4j jars: find / -name 'log4j*.jar' 2>/dev/null\n# Update your application's dependency to log4j 2.17.1+",
        "severity": "CRITICAL",
        "detail": "Log4Shell — most critical Java vulnerability in years. Update immediately.",
    },
    "CVE-2021-41773": {
        "action": "Upgrade Apache to 2.4.51 or later",
        "linux_cmd": "sudo apt-get update && sudo apt-get install --only-upgrade apache2 -y",
        "severity": "CRITICAL",
        "detail": "Path traversal + RCE in Apache 2.4.49. Upgrade immediately.",
    },
    "CVE-2007-2447": {
        "action": "Upgrade Samba and disable username map script",
        "linux_cmd": "sudo apt-get update && sudo apt-get install --only-upgrade samba -y\nsudo sed -i '/username map script/d' /etc/samba/smb.conf\nsudo systemctl restart smbd",
        "severity": "HIGH",
        "detail": "Remove the username map script directive from smb.conf.",
    },
    "CVE-2019-0708": {
        "action": "Apply BlueKeep patch and enable NLA on RDP",
        "windows_cmd": "# Apply KB4499175 patch\n# Enable NLA: System Properties > Remote > Require NLA",
        "severity": "CRITICAL",
        "detail": "BlueKeep RDP pre-auth RCE. Patch immediately. Disable RDP if not needed.",
    },
}

# Security headers to add
SECURITY_HEADERS_CONFIG = {
    "nginx": """# Add to your nginx server block:
add_header Content-Security-Policy "default-src 'self'" always;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "no-referrer-when-downgrade" always;""",

    "apache": """# Add to your Apache VirtualHost or .htaccess:
Header always set Content-Security-Policy "default-src 'self'"
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
Header always set X-Frame-Options "SAMEORIGIN"
Header always set X-Content-Type-Options "nosniff"
Header always set Referrer-Policy "no-referrer-when-downgrade"
# Enable: sudo a2enmod headers && sudo systemctl restart apache2""",
}

TLS_HARDENING = {
    "nginx": """# Add to your nginx ssl configuration:
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers HIGH:!aNULL:!MD5:!3DES;
ssl_prefer_server_ciphers on;
ssl_session_cache shared:SSL:10m;""",

    "apache": """# Add to your Apache SSL VirtualHost:
SSLProtocol all -SSLv2 -SSLv3 -TLSv1 -TLSv1.1
SSLCipherSuite HIGH:!aNULL:!MD5:!3DES
SSLHonorCipherOrder on""",
}


def generate_remediation(scan: dict, target_os: str = "linux") -> dict:
    """
    Generate all remediation content from a scan results dict.
    Returns a dict with firewall_script, headers_config, tls_config,
    cve_fixes, and summary.
    """
    open_ports = scan.get("open_ports", [])
    cves_by_port = scan.get("cves", {})
    web_findings = scan.get("web", {})
    missing_headers = web_findings.get("headers", {}).get("missing", []) if web_findings else []
    ssl_info = web_findings.get("ssl", {}) if web_findings else {}

    remediation = {
        "target": scan.get("target", "unknown"),
        "generated": datetime.now().isoformat(),
        "firewall_script": "",
        "headers_config": {},
        "tls_config": {},
        "cve_fixes": [],
        "summary": [],
    }

    # --- Firewall rules ---
    fw_lines = [
        "#!/bin/bash",
        "# Firewall hardening script — generated by vuln-scanner",
        "# REVIEW BEFORE RUNNING — wrong rules can lock you out",
        "# Run as root/sudo on the target system",
        "",
    ]

    if target_os == "linux":
        fw_lines += [
            "# Flush existing rules (careful on production servers)",
            "# sudo iptables -F",
            "",
            "# Allow established connections",
            "sudo iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
            "",
            "# Allow loopback",
            "sudo iptables -A INPUT -i lo -j ACCEPT",
            "",
        ]
        for port in open_ports:
            if port in COMMONLY_NEEDED_PORTS:
                fw_lines.append(f"# KEEP: Port {port} — {COMMONLY_NEEDED_PORTS[port]}")
                fw_lines.append(f"sudo iptables -A INPUT -p tcp --dport {port} -j ACCEPT")
            else:
                fw_lines.append(f"# CLOSE: Port {port} — no known legitimate use identified")
                fw_lines.append(f"sudo iptables -A INPUT -p tcp --dport {port} -j DROP")
            fw_lines.append("")

        fw_lines += [
            "# Drop everything else",
            "sudo iptables -A INPUT -j DROP",
            "",
            "# Save rules (Debian/Ubuntu)",
            "# sudo iptables-save > /etc/iptables/rules.v4",
        ]

    elif target_os == "windows":
        fw_lines = [
            "# Windows Firewall hardening (run in PowerShell as Administrator)",
            "",
        ]
        for port in open_ports:
            if port in COMMONLY_NEEDED_PORTS:
                fw_lines.append(f"# KEEP: Port {port} — {COMMONLY_NEEDED_PORTS[port]}")
            else:
                fw_lines.append(f"# CLOSE: Port {port}")
                fw_lines.append(
                    f'New-NetFirewallRule -DisplayName "Block port {port}" '
                    f'-Direction Inbound -LocalPort {port} -Protocol TCP -Action Block'
                )
            fw_lines.append("")

    remediation["firewall_script"] = "\n".join(fw_lines)

    # --- CVE fixes ---
    all_cves = []
    for port_cves in cves_by_port.values():
        all_cves.extend(port_cves)

    for cve in all_cves:
        cve_id = cve.get("id", "")
        if cve_id in CVE_FIXES:
            fix = CVE_FIXES[cve_id].copy()
            fix["cve_id"] = cve_id
            fix["cvss"] = cve.get("cvss")
            remediation["cve_fixes"].append(fix)
            remediation["summary"].append(
                f"[{fix['severity']}] {cve_id}: {fix['action']}"
            )
        else:
            remediation["cve_fixes"].append({
                "cve_id": cve_id,
                "action": "Update affected software to latest stable version",
                "linux_cmd": "sudo apt-get update && sudo apt-get upgrade -y",
                "severity": "MEDIUM",
                "detail": "Check vendor advisory for specific patch instructions.",
            })

    # --- Security headers ---
    if missing_headers:
        remediation["headers_config"] = SECURITY_HEADERS_CONFIG
        remediation["summary"].append(
            f"Add {len(missing_headers)} missing security headers (nginx/Apache config included)"
        )

    # --- TLS hardening ---
    if ssl_info.get("risky_tls"):
        remediation["tls_config"] = TLS_HARDENING
        remediation["summary"].append(
            f"Disable {ssl_info.get('tls_version')} — only TLS 1.2+ should be allowed"
        )

    return remediation


def save_remediation(remediation: dict, output_dir: str = "output") -> dict:
    """Save firewall script and return saved paths."""
    os.makedirs(output_dir, exist_ok=True)
    target_safe = remediation["target"].replace(".", "_").replace(":", "_")
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    paths = {}

    # Save firewall script
    fw_path = os.path.join(output_dir, f"firewall_hardening_{target_safe}_{ts}.sh")
    with open(fw_path, "w") as f:
        f.write(remediation["firewall_script"])
    os.chmod(fw_path, 0o755)
    paths["firewall"] = fw_path
    print(f"[+] Firewall script saved: {fw_path}")

    # Save full remediation as JSON
    json_path = os.path.join(output_dir, f"remediation_{target_safe}_{ts}.json")
    with open(json_path, "w") as f:
        json.dump(remediation, f, indent=2)
    paths["json"] = json_path
    print(f"[+] Remediation JSON saved: {json_path}")

    return paths


def print_summary(remediation: dict) -> None:
    print("\n" + "="*60)
    print("REMEDIATION SUMMARY")
    print(f"Target: {remediation['target']}")
    print("="*60)
    for item in remediation["summary"]:
        print(f"  • {item}")
    if not remediation["summary"]:
        print("  No critical remediations identified from this scan.")
    print("="*60)
    print("\nCVE FIXES:")
    for fix in remediation["cve_fixes"]:
        print(f"\n  [{fix['severity']}] {fix['cve_id']}")
        print(f"  Action: {fix['action']}")
        cmd = fix.get("linux_cmd") or fix.get("windows_cmd", "")
        if cmd:
            print(f"  Command:\n    {cmd.replace(chr(10), chr(10)+'    ')}")
        print(f"  Detail: {fix['detail']}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Generate remediation scripts from scanner output."
    )
    parser.add_argument("--scan", required=True, help="Path to scanner JSON output")
    parser.add_argument("--os", default="linux",
                        choices=["linux", "windows"],
                        help="Target OS for firewall script (default: linux)")
    parser.add_argument("--output", default="output", help="Output directory")
    args = parser.parse_args()

    with open(args.scan) as f:
        scan = json.load(f)

    remediation = generate_remediation(scan, args.os)
    print_summary(remediation)
    save_remediation(remediation, args.output)
    print("\n[*] Use engagement_report.py to include remediation in your client report.")
