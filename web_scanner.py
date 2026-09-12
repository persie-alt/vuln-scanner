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
import re
from datetime import datetime, timezone
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse

import requests

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
]

SERVER_SIGNATURES = [
    (r"nginx[/\s]?([\d.]+)?", "Nginx"),
    (r"apache[/\s]?([\d.]+)?", "Apache"),
    (r"openresty[/\s]?([\d.]+)?", "OpenResty"),
    (r"microsoft-iis[/\s]?([\d.]+)?", "IIS"),
    (r"litespeed", "LiteSpeed"),
    (r"cloudflare", "Cloudflare"),
    (r"gunicorn[/\s]?([\d.]+)?", "Gunicorn/Python"),
    (r"werkzeug[/\s]?([\d.]+)?", "Flask/Python"),
    (r"express", "Express/Node"),
    (r"php[/\s]?([\d.]+)?", "PHP"),
    (r"tomcat[/\s]?([\d.]+)?", "Tomcat/Java"),
    (r"jetty[/\s]?([\d.]+)?", "Jetty/Java"),
]

LEAK_HEADERS = [
    "Server", "X-Powered-By", "X-Generator", "X-AspNet-Version",
    "X-AspNetMvc-Version", "Via", "X-Backend-Server", "X-Runtime",
    "X-Served-By", "X-Drupal-Cache", "X-Varnish",
]


def _match_signatures(text: str) -> list:
    text_lower = text.lower()
    found = []
    for pattern, label in SERVER_SIGNATURES:
        m = re.search(pattern, text_lower)
        if m:
            version = m.group(1) if m.lastindex and m.group(1) else ""
            found.append(f"{label} {version}".strip())
    return found


def fingerprint(url: str, timeout: float = 6.0) -> dict:
    """
    Multi-technique HTTP fingerprinting to identify silent servers.
    Technique 1: Leak headers (Server, X-Powered-By, X-Generator etc.)
    Technique 2: 404 error page content
    Technique 3: Invalid HTTP method response
    Technique 4: Session cookie names
    """
    result = {"leak_headers": {}, "identified": [], "raw_clues": []}
    parsed = urlparse(url)
    host = parsed.hostname or url
    resp = None

    # Technique 1: leak headers + cookies
    try:
        resp = requests.get(url, timeout=timeout, allow_redirects=True)
        for h in LEAK_HEADERS:
            val = resp.headers.get(h)
            if val:
                result["leak_headers"][h] = val
                print(f"[+] {h}: {val}")
                result["identified"] += _match_signatures(val)
        for cookie in resp.cookies:
            name_lower = cookie.name.lower()
            if "phpsessid" in name_lower:
                result["identified"].append("PHP")
                print(f"[+] PHP detected via cookie: {cookie.name}")
            elif "jsessionid" in name_lower:
                result["identified"].append("Java")
                print(f"[+] Java detected via cookie: {cookie.name}")
            elif "asp.net_sessionid" in name_lower:
                result["identified"].append("ASP.NET")
                print(f"[+] ASP.NET detected via cookie: {cookie.name}")
    except requests.exceptions.RequestException as e:
        print(f"[!] Fingerprint GET failed: {e}")

    # Technique 2: 404 error page
    try:
        r404 = requests.get(
            f"{parsed.scheme}://{host}/vuln-scanner-probe-xq7z9k",
            timeout=timeout, allow_redirects=True
        )
        hits = _match_signatures(r404.text)
        if hits:
            result["identified"] += hits
            print(f"[+] Error page reveals: {', '.join(hits)}")
        result["raw_clues"].append(f"404 body: {len(r404.text)} bytes")
    except requests.exceptions.RequestException:
        pass

    # Technique 3: invalid HTTP method
    try:
        rinv = requests.request("INVALID", url, timeout=timeout, allow_redirects=False)
        hits = _match_signatures(rinv.text)
        if hits:
            result["identified"] += hits
            print(f"[+] Invalid method response reveals: {', '.join(hits)}")
        result["raw_clues"].append(f"Invalid method → HTTP {rinv.status_code}")
    except requests.exceptions.RequestException:
        pass

    # Technique 4: HEAD vs GET header delta
    try:
        head = requests.head(url, timeout=timeout, allow_redirects=True)
        extra = set(head.headers.keys()) - set(resp.headers.keys() if resp else [])
        if extra:
            result["raw_clues"].append(f"HEAD-only headers: {', '.join(extra)}")
    except requests.exceptions.RequestException:
        pass

    result["identified"] = list(dict.fromkeys(result["identified"]))

    if result["identified"]:
        print(f"[+] Stack identified: {', '.join(result['identified'])}")
    elif not result["leak_headers"]:
        print("[-] Server suppressing all identification — "
              "try WhatWeb for deeper analysis")
    return result


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


SQLI_PAYLOADS = ["'", "' OR 1=1 --"]
SQLI_ERROR_SIGNATURES = [
    "sql syntax", "mysql_fetch", "syntax error", "unclosed quotation",
    "sqlstate", "odbc sql", "pg_query", "warning: mysql",
]


def sqli_scan(url: str, timeout: float = 5.0) -> list:
    """
    Inject SQLi payloads into each query parameter of url.
    Flags a param if the response shows a DB error signature, or its length
    changes drastically vs a clean baseline request. Returns a list of findings.
    """
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    if not params:
        print(f"[-] No query parameters found in {url} — nothing to test")
        return []

    try:
        baseline = requests.get(url, timeout=timeout)
        baseline_len = len(baseline.text)
    except requests.exceptions.RequestException as e:
        print(f"[!] Baseline request failed: {e}")
        return []

    findings = []
    for param in params:
        for payload in SQLI_PAYLOADS:
            test_params = {k: v[0] for k, v in params.items()}
            test_params[param] = payload
            test_url = urlunparse(parsed._replace(query=urlencode(test_params)))
            try:
                resp = requests.get(test_url, timeout=timeout)
            except requests.exceptions.RequestException:
                continue

            body_lower = resp.text.lower()
            error_hit = next((sig for sig in SQLI_ERROR_SIGNATURES if sig in body_lower), None)
            length_diff = abs(len(resp.text) - baseline_len)

            if error_hit:
                print(f"[!] Possible SQLi on '{param}' — DB error signature: '{error_hit}'")
                findings.append({"param": param, "payload": payload, "reason": f"error signature: {error_hit}"})
            elif baseline_len and length_diff > baseline_len * 0.5:
                print(f"[!] Possible SQLi on '{param}' — response length changed significantly")
                findings.append({"param": param, "payload": payload, "reason": "response length changed"})

    if not findings:
        print(f"[-] No SQLi indicators found on {url}")
    return findings


XSS_PAYLOAD = "<script>alert(1)</script>"


def xss_scan(url: str, timeout: float = 5.0) -> list:
    """
    Inject a reflected XSS payload into each query parameter.
    Flags a param if the payload appears unescaped in the response body.
    """
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    if not params:
        print(f"[-] No query parameters found in {url} — nothing to test")
        return []

    findings = []
    for param in params:
        test_params = {k: v[0] for k, v in params.items()}
        test_params[param] = XSS_PAYLOAD
        test_url = urlunparse(parsed._replace(query=urlencode(test_params)))
        try:
            resp = requests.get(test_url, timeout=timeout)
        except requests.exceptions.RequestException:
            continue

        if XSS_PAYLOAD in resp.text:
            print(f"[!] Reflected XSS on '{param}' — payload appears unescaped")
            findings.append({"param": param, "payload": XSS_PAYLOAD})

    if not findings:
        print("[-] No reflected XSS found")
    return findings


if __name__ == "__main__":
    import sys
    from urllib.parse import urlparse

    if len(sys.argv) < 2:
        print("Usage: python3 web_scanner.py <url>")
        sys.exit(1)

    url = sys.argv[1]
    host = urlparse(url).hostname or url

    print(f"[*] Fingerprinting {url}")
    fingerprint(url)

    print(f"\n[*] Checking security headers for {url}")
    check_headers(url)

    print(f"\n[*] Checking SSL/TLS for {host}")
    check_ssl(host)

    wordlist = "/usr/share/wordlists/dirb/common.txt"
    print(f"\n[*] Directory brute-force on {url} (wordlist: {wordlist})")
    dir_bruteforce(url, wordlist)

    if parse_qs(urlparse(url).query):
        print(f"\n[*] SQLi probing on {url}")
        sqli_scan(url)

        print(f"\n[*] Reflected XSS probing on {url}")
        xss_scan(url)
    else:
        print("\n[-] URL has no query parameters — skipping SQLi/XSS probes "
              "(pass a URL like http://host/page?id=1)")
