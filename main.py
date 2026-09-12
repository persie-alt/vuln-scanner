#!/usr/bin/env python3
"""
main.py — single entry point for the full scan pipeline.
Port scan -> banner grab -> OS detect -> CVE lookup -> JSON + HTML report,
plus optional web app scanning.

Usage:
    python3 main.py --target <ip> [--ports 1-1024] [--output output]
                     [--web <url>] [--threads 50]

Examples:
    python3 main.py --target scanme.nmap.org
    python3 main.py --target scanme.nmap.org --ports 1-100 --threads 100
    python3 main.py --target 127.0.0.1 --web "http://127.0.0.1:5000/product?id=1"

LEGAL: Only scan systems you own or have written permission to test.
"""

import argparse
from datetime import datetime
from urllib.parse import urlparse

from scanner import threaded_port_scan, banner_scan, os_detect
from cve_lookup import banner_to_cves, cve_to_metasploit
from reporter import save_json, generate_html


def run_scan(target: str, port_range: str = "1-1024", threads: int = 50) -> dict:
    """
    Run the full network scan pipeline against target and return a results dict.
    port_range/threads have safe defaults so existing callers (e.g. dashboard.py)
    that only pass target keep working unchanged.
    """
    try:
        start_port, end_port = (int(x) for x in port_range.split("-"))
    except ValueError:
        print(f"[!] Invalid port range '{port_range}', defaulting to 1-1024")
        start_port, end_port = 1, 1024

    results = {
        "target": target,
        "timestamp": datetime.now().isoformat(),
    }

    print(f"[*] Port scanning {target} (ports {start_port}-{end_port}, {threads} threads)...")
    results["open_ports"] = threaded_port_scan(target, start_port, end_port, max_workers=threads)

    print(f"\n[*] Grabbing banners...")
    results["banners"] = banner_scan(target)

    print(f"\n[*] OS detection...")
    results["os"] = os_detect(target)

    print(f"\n[*] CVE lookup per banner...")
    cve_results = {}
    for port, banner in results["banners"].items():
        cves = banner_to_cves(banner)
        cves = cve_to_metasploit(cves)
        if cves:
            cve_results[port] = cves
    results["cves"] = cve_results

    return results


def run_web_scan(url: str, fallback_host: str) -> dict:
    """Run header + SSL checks against url. Import kept local so main.py
    doesn't require web_scanner's deps unless --web is actually used."""
    from web_scanner import check_headers, check_ssl

    host = urlparse(url).hostname or fallback_host
    print(f"\n[*] Web scan on {url}")
    return {
        "headers": check_headers(url),
        "ssl": check_ssl(host),
    }


def parse_args():
    parser = argparse.ArgumentParser(
        description="Python vulnerability scanner — port scan, CVE lookup, and web checks."
    )
    parser.add_argument("--target", required=True, help="Target IP or hostname")
    parser.add_argument("--ports", default="1-1024", help="Port range, e.g. 1-1024 (default: 1-1024)")
    parser.add_argument("--output", default="output", help="Output directory for JSON/HTML reports")
    parser.add_argument("--web", default=None, help="URL to also run web app scanning against")
    parser.add_argument("--threads", type=int, default=50, help="Threads for port scanning (default: 50)")
    parser.add_argument("--remediate", action="store_true", help="Generate remediation scripts after scan")
    parser.add_argument("--target-os", default="linux", choices=["linux","windows"], help="Target OS for remediation scripts")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()

    results = run_scan(args.target, args.ports, args.threads)

    if args.web:
        results["web"] = run_web_scan(args.web, args.target)

    json_path = save_json(results, args.output)
    html_path = generate_html(results, args.output)

    print(f"\n[+] JSON saved:  {json_path}")
    print(f"[+] HTML report: {html_path}")

    if args.remediate:
        from remediation import generate_remediation, save_remediation, print_summary
        print(f"\n[*] Generating remediation scripts...")
        rem = generate_remediation(results, args.target_os)
        print_summary(rem)
        save_remediation(rem, args.output)
