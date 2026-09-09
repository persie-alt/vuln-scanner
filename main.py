#!/usr/bin/env python3
"""
main.py — Day 4: single entry point
Runs port scan -> banner grab -> OS detect -> CVE lookup -> JSON + HTML report.

Usage: python3 main.py <target_ip>

LEGAL: Only scan systems you own or have written permission to test.
"""

import sys
from datetime import datetime

from scanner import raw_socket_scan, banner_scan, os_detect
from cve_lookup import banner_to_cves
from reporter import save_json, generate_html


def run_scan(target: str) -> dict:
    """Run the full scan pipeline against target and return a results dict."""
    results = {
        "target": target,
        "timestamp": datetime.now().isoformat(),
    }

    print(f"[*] Port scanning {target}...")
    results["open_ports"] = raw_socket_scan(target)

    print(f"\n[*] Grabbing banners...")
    results["banners"] = banner_scan(target)

    print(f"\n[*] OS detection...")
    results["os"] = os_detect(target)

    print(f"\n[*] CVE lookup per banner...")
    cve_results = {}
    for port, banner in results["banners"].items():
        cves = banner_to_cves(banner)
        if cves:
            cve_results[port] = cves
    results["cves"] = cve_results

    return results


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 main.py <target_ip>")
        sys.exit(1)

    target = sys.argv[1]
    results = run_scan(target)

    json_path = save_json(results)
    html_path = generate_html(results)

    print(f"\n[+] JSON saved:  {json_path}")
    print(f"[+] HTML report: {html_path}")
