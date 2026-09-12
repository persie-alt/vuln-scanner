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
    Extract a clean keyword from a banner and search NVD.
    e.g. 'SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13' -> 'OpenSSH 6.6.1'
    """
    import re
    cleaned = banner.replace("\r", " ").replace("\n", " ").strip()
    if not cleaned:
        return []

    # Try to extract 'product version' pattern from the banner
    # e.g. OpenSSH_6.6.1p1 -> "OpenSSH 6.6.1"
    match = re.search(r'([A-Za-z][A-Za-z0-9\-]+)[_/\s]v?(\d+\.\d+[\.\d]*)', cleaned)
    if match:
        product = match.group(1).replace("_", " ")
        version = match.group(2)
        keyword = f"{product} {version}"
    else:
        # Fall back to first 40 chars of cleaned banner
        keyword = cleaned[:40]

    return query_cve(keyword, max_results=max_results)


# CVE → Metasploit module mapping
# Source: well-known public Metasploit modules, manually curated
# Add more as you encounter them in practice
CVE_TO_MSF = {
    "CVE-2011-2523": {
        "module": "exploit/unix/ftp/vsftpd_234_backdoor",
        "description": "vsftpd 2.3.4 backdoor — opens shell on port 6200",
        "reliability": "Excellent",
    },
    "CVE-2004-2687": {
        "module": "exploit/unix/misc/distcc_exec",
        "description": "DistCC daemon command execution",
        "reliability": "Excellent",
    },
    "CVE-2007-2447": {
        "module": "exploit/multi/samba/usermap_script",
        "description": "Samba username map script — remote code execution",
        "reliability": "Excellent",
    },
    "CVE-2009-3103": {
        "module": "exploit/windows/smb/ms09_050_smb2_negotiate_func_index",
        "description": "MS09-050 SMBv2 negotiate — Windows BSOD/RCE",
        "reliability": "Average",
    },
    "CVE-2017-0143": {
        "module": "exploit/windows/smb/ms17_010_eternalblue",
        "description": "EternalBlue SMBv1 — WannaCry vector, SYSTEM shell",
        "reliability": "Average",
    },
    "CVE-2017-0144": {
        "module": "exploit/windows/smb/ms17_010_eternalblue",
        "description": "EternalBlue SMBv1 — WannaCry vector, SYSTEM shell",
        "reliability": "Average",
    },
    "CVE-2014-6271": {
        "module": "exploit/multi/http/apache_mod_cgi_bash_env_exec",
        "description": "Shellshock — bash environment variable injection",
        "reliability": "Excellent",
    },
    "CVE-2021-41773": {
        "module": "exploit/multi/http/apache_normalize_path_rce",
        "description": "Apache 2.4.49 path traversal + RCE",
        "reliability": "Excellent",
    },
    "CVE-2021-42013": {
        "module": "exploit/multi/http/apache_normalize_path_rce",
        "description": "Apache 2.4.50 path traversal + RCE (bypass of 41773 fix)",
        "reliability": "Excellent",
    },
    "CVE-2021-44228": {
        "module": "exploit/multi/misc/log4shell_header_injection",
        "description": "Log4Shell — Log4j JNDI injection, remote code execution",
        "reliability": "Excellent",
    },
    "CVE-2019-0708": {
        "module": "exploit/windows/rdp/cve_2019_0708_bluekeep_rce",
        "description": "BlueKeep — RDP pre-auth RCE on Windows 7/2008",
        "reliability": "Average",
    },
    "CVE-2016-0777": {
        "module": "auxiliary/scanner/ssh/ssh_enumusers",
        "description": "OpenSSH info leak — use for user enumeration first",
        "reliability": "Normal",
    },
}


def cve_to_metasploit(cves: list[dict]) -> list[dict]:
    """
    Takes a list of CVE dicts (from query_cve) and annotates each one
    with its Metasploit module if a known mapping exists.
    Returns the same list with a 'msf' key added where applicable.
    """
    for cve in cves:
        cve_id = cve.get("id", "")
        if cve_id in CVE_TO_MSF:
            cve["msf"] = CVE_TO_MSF[cve_id]
            msf = CVE_TO_MSF[cve_id]
            print(f"{Fore.CYAN}[MSF] {cve_id} → {msf['module']}")
            print(f"      {msf['description']} (reliability: {msf['reliability']})")
        else:
            cve["msf"] = None
    return cves


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python cve_lookup.py '<service keyword, e.g. vsftpd 2.3.4>'")
        sys.exit(1)

    keyword = " ".join(sys.argv[1:])
    print(f"[*] Querying NVD for: {keyword}")
    cves = query_cve(keyword)
    print_cves(cves)
    print(f"\n[*] Checking for Metasploit modules...")
    cve_to_metasploit(cves)

    time.sleep(1)
