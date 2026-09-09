#!/usr/bin/env python3
"""
cve_lookup.py — Day 2: NVD CVE lookup
Queries the NVD REST API 2.0 for CVEs matching a service/version keyword.

Rate limits: 5 req/30s without an API key, 50 req/30s with one.
Get a free key at https://nvd.nist.gov/developers/request-an-api-key
Set it as an env var so it never lands in your repo:
    export NVD_API_KEY="your-key-here"
"""

import os
import time
import requests
from colorama import Fore, Style, init as colorama_init

colorama_init(autoreset=True)

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def risk_color(cvss) -> str:
    """Map a CVSS score to a colorama color. None/unknown -> white."""
    if cvss is None:
        return Fore.WHITE
    if cvss >= 7.0:
        return Fore.RED
    if cvss >= 4.0:
        return Fore.YELLOW
    return Fore.GREEN


def print_cves(cves: list[dict], port: int = None) -> None:
    """Print a list of CVE dicts (from query_cve) with color-coded severity."""
    label = f" for port {port}" if port is not None else ""
    if not cves:
        print(f"[-] No CVEs found{label}")
        return

    for c in cves:
        color = risk_color(c["cvss"])
        score = c["cvss"] if c["cvss"] is not None else "N/A"
        sev = c["severity"] or "UNKNOWN"
        print(f"{color}[{sev}] {c['id']}  CVSS {score}{Style.RESET_ALL}{label}")
        print(f"    {c['description']}")


def query_cve(keyword: str, max_results: int = 10, timeout: float = 10.0) -> list[dict]:
    """
    Search NVD by keyword (e.g. 'vsftpd 2.3.4').
    Returns a list of dicts: {id, cvss, severity, description}.
    Empty list on no matches or on error (errors are printed, not raised).
    """
    api_key = os.environ.get("NVD_API_KEY")
    headers = {"Accept": "application/json"}
    if api_key:
        headers["apiKey"] = api_key

    params = {
        "keywordSearch": keyword,
        "resultsPerPage": max_results,
    }

    try:
        resp = requests.get(NVD_API_URL, headers=headers, params=params, timeout=timeout)

        if resp.status_code == 403 or resp.status_code == 429:
            print(f"[!] NVD rate limit hit — wait 30s and retry (get an API key to raise the limit)")
            return []
        resp.raise_for_status()

        data = resp.json()
        results = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id", "UNKNOWN")

            # prefer CVSS v3.1, fall back to v3.0, then v2
            metrics = cve.get("metrics", {})
            cvss, severity = None, None
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if key in metrics:
                    m = metrics[key][0]["cvssData"]
                    cvss = m.get("baseScore")
                    severity = metrics[key][0].get("baseSeverity", m.get("baseSeverity"))
                    break

            descriptions = cve.get("descriptions", [])
            desc_text = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")

            results.append({
                "id": cve_id,
                "cvss": cvss,
                "severity": severity,
                "description": desc_text[:200],
            })

        return results

    except requests.exceptions.Timeout:
        print(f"[!] NVD request timed out for '{keyword}'")
        return []
    except requests.exceptions.RequestException as e:
        print(f"[!] NVD request failed for '{keyword}': {e}")
        return []
    except (KeyError, ValueError) as e:
        print(f"[!] Unexpected NVD response format: {e}")
        return []


def banner_to_cves(banner: str, max_results: int = 5) -> list[dict]:
    """
    Convenience wrapper: take a raw banner string (e.g. '220 vsftpd 2.3.4 ready')
    and use it directly as a keyword search. Strips common noise chars.
    """
    cleaned = banner.replace("\r", " ").replace("\n", " ").strip()
    if not cleaned:
        return []
    return query_cve(cleaned, max_results=max_results)


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python cve_lookup.py '<service keyword, e.g. vsftpd 2.3.4>'")
        sys.exit(1)

    keyword = " ".join(sys.argv[1:])
    print(f"[*] Querying NVD for: {keyword}")
    cves = query_cve(keyword)
    print_cves(cves)

    time.sleep(1)  # be polite to the API between manual runs
