#!/usr/bin/env python3
"""
web_scanner.py — Day 5: web application scanning
- HTTP security header check
- SSL/TLS version + cert expiry check
- Directory brute-force against a wordlist

LEGAL: Only scan web apps you own or have written permission to test.
"""

import socket
import ssl
from datetime import datetime, timezone

import requests

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
]


def check_headers(url: str, timeout: float = 5.0) -> dict:
    """
    GET the URL and check for missing security headers.
    Returns {'present': [...], 'missing': [...], 'status_code': int}, or {} on request failure.
    """
    try:
        resp = requests.get(url, timeout=timeout, allow_redirects=True)
    except requests.exceptions.RequestException as e:
        print(f"[!] Request failed for {url}: {e}")
        return {}

    present, missing = [], []
    for header in SECURITY_HEADERS:
        (present if header in resp.headers else missing).append(header)

    for h in missing:
        print(f"[!] Missing header: {h}")
    for h in present:
        print(f"[+] Present header: {h}")

    return {"present": present, "missing": missing, "status_code": resp.status_code}


def check_ssl(target: str, port: int = 443, timeout: float = 5.0) -> dict:
    """
    Connect via TLS, check negotiated version and cert expiry.
    Flags TLS 1.0/1.1 as high risk. Returns {} on connection failure.
    """
    context = ssl.create_default_context()
    try:
        with socket.create_connection((target, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=target) as ssock:
                cert = ssock.getpeercert()
                tls_version = ssock.version()
                risky_tls = tls_version in ("TLSv1", "TLSv1.1")

                expiry, days_left = None, None
                not_after = cert.get("notAfter") if cert else None
                if not_after:
                    expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    days_left = (expiry.replace(tzinfo=timezone.utc) - datetime.now(timezone.utc)).days

                tag = " — HIGH RISK (outdated)" if risky_tls else ""
                print(f"[+] TLS version: {tls_version}{tag}")
                if days_left is not None:
                    status = "EXPIRED" if days_left < 0 else f"{days_left} days left"
                    print(f"[+] Cert expiry: {expiry} ({status})")

                return {
                    "tls_version": tls_version,
                    "risky_tls": risky_tls,
                    "cert_expiry": str(expiry) if expiry else None,
                    "days_left": days_left,
                }
    except ssl.SSLError as e:
        print(f"[!] SSL error connecting to {target}:{port}: {e}")
        return {}
    except (socket.timeout, ConnectionRefusedError, socket.gaierror) as e:
        print(f"[!] Could not connect to {target}:{port}: {e}")
        return {}


def dir_bruteforce(base_url: str, wordlist_path: str, timeout: float = 3.0, max_words: int = 500) -> list:
    """
    GET each word in wordlist_path against base_url. Flags status 200/403.
    max_words caps the run so a big list doesn't hang for hours.
    Returns a list of {'path': str, 'status': int}.
    """
    found = []
    try:
        with open(wordlist_path, "r", errors="ignore") as f:
            words = [line.strip() for line in f if line.strip()][:max_words]
    except OSError as e:
        print(f"[!] Could not read wordlist {wordlist_path}: {e}")
        return found

    base_url = base_url.rstrip("/")
    for word in words:
        url = f"{base_url}/{word}"
        try:
            resp = requests.get(url, timeout=timeout, allow_redirects=False)
            if resp.status_code in (200, 403):
                print(f"[+] {resp.status_code} {url}")
                found.append({"path": word, "status": resp.status_code})
        except requests.exceptions.RequestException:
            continue  # unreachable/timeout on this one path — skip, don't kill the run

    return found


if __name__ == "__main__":
    import sys
    from urllib.parse import urlparse

    if len(sys.argv) < 2:
        print("Usage: python3 web_scanner.py <url>")
        sys.exit(1)

    url = sys.argv[1]
    host = urlparse(url).hostname or url

    print(f"[*] Checking headers for {url}")
    check_headers(url)

    print(f"\n[*] Checking SSL/TLS for {host}")
    check_ssl(host)

    wordlist = "/usr/share/wordlists/dirb/common.txt"
    print(f"\n[*] Directory brute-force on {url} (wordlist: {wordlist})")
    dir_bruteforce(url, wordlist)
