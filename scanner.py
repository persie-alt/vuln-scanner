#!/usr/bin/env python3
"""
scanner.py — Day 1: TCP port scanner
Raw-socket implementation + python-nmap wrapper (service/version detection).

LEGAL: Only scan systems you own or have written permission to test.
"""

import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False


def scan_port(target: str, port: int, timeout: float = 1.0) -> bool:
    """Attempt a TCP connect to target:port. Return True if open."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            return sock.connect_ex((target, port)) == 0
    except socket.error as e:
        print(f"[!] Socket error on port {port}: {e}")
        return False


def raw_socket_scan(target: str, start_port: int = 1, end_port: int = 1024,
                     timeout: float = 1.0) -> list[int]:
    """Scan a port range with raw sockets, no third-party libs. Returns open ports."""
    open_ports = []
    try:
        socket.gethostbyname(target)  # fail fast if host doesn't resolve
    except socket.gaierror:
        print(f"[!] Could not resolve target: {target}")
        return open_ports

    for port in range(start_port, end_port + 1):
        if scan_port(target, port, timeout):
            print(f"[+] Port {port} open")
            open_ports.append(port)
    return open_ports


def threaded_port_scan(target: str, start_port: int = 1, end_port: int = 1024,
                        timeout: float = 1.0, max_workers: int = 50) -> list[int]:
    """
    Multi-threaded version of raw_socket_scan — same logic, run concurrently.
    max_workers caps how many ports are checked in parallel at once.
    """
    open_ports = []
    try:
        socket.gethostbyname(target)
    except socket.gaierror:
        print(f"[!] Could not resolve target: {target}")
        return open_ports

    ports = range(start_port, end_port + 1)
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_port = {executor.submit(scan_port, target, port, timeout): port for port in ports}
        for future in as_completed(future_to_port):
            port = future_to_port[future]
            try:
                if future.result():
                    print(f"[+] Port {port} open")
                    open_ports.append(port)
            except Exception as e:
                print(f"[!] Error scanning port {port}: {e}")

    return sorted(open_ports)


def nmap_scan(target: str, port_range: str = "1-1024") -> dict:
    """Scan with python-nmap using -sV. Returns {port: {service, product, version}}."""
    if not NMAP_AVAILABLE:
        print("[!] python-nmap not installed. Run: pip install python-nmap")
        return {}

    results = {}
    try:
        scanner = nmap.PortScanner()
        scanner.scan(target, port_range, arguments="-sV")
        if target not in scanner.all_hosts():
            print(f"[!] Host {target} did not respond")
            return results
        for proto in scanner[target].all_protocols():
            for port, info in scanner[target][proto].items():
                if info["state"] == "open":
                    results[port] = {
                        "service": info.get("name", "unknown"),
                        "product": info.get("product", ""),
                        "version": info.get("version", ""),
                    }
                    print(f"[+] {port}/{proto} open — "
                          f"{info.get('product','')} {info.get('version','')}")
    except nmap.PortScannerError as e:
        print(f"[!] Nmap error: {e}")
    except Exception as e:
        print(f"[!] Unexpected error: {e}")
    return results


def grab_banner(target: str, port: int, timeout: float = 2.0) -> str:
    """
    Connect to target:port and read whatever banner the service sends.
    Falls back to a minimal HTTP probe for ports that don't greet first (e.g. 80).
    Returns the banner text, or '' if nothing was received/connect failed.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((target, port))
            try:
                banner = sock.recv(1024)
            except socket.timeout:
                banner = b""

            if not banner:
                # service didn't greet on connect (typical for HTTP) — probe it
                try:
                    sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                    banner = sock.recv(1024)
                except (socket.timeout, socket.error):
                    banner = b""

            return banner.decode(errors="ignore").strip()
    except socket.timeout:
        return ""
    except ConnectionRefusedError:
        return ""
    except socket.error as e:
        print(f"[!] Banner grab error on port {port}: {e}")
        return ""


def banner_scan(target: str, ports: list[int] = (21, 22, 80), timeout: float = 2.0) -> dict[int, str]:
    """Grab banners from a list of ports. Returns {port: banner_text}."""
    banners = {}
    for port in ports:
        banner = grab_banner(target, port, timeout)
        if banner:
            first_line = banner.splitlines()[0] if banner else ""
            print(f"[+] Port {port} banner: {first_line}")
            banners[port] = banner
        else:
            print(f"[-] Port {port}: no banner / closed")
    return banners


def os_detect(target: str) -> dict:
    """
    OS fingerprint via Nmap -O. Requires root/sudo — Nmap needs raw socket
    access for OS detection. Returns {} with a printed reason on failure.
    """
    if not NMAP_AVAILABLE:
        print("[!] python-nmap not installed. Run: pip install python-nmap")
        return {}

    try:
        scanner = nmap.PortScanner()
        scanner.scan(target, arguments="-O")
        if target not in scanner.all_hosts():
            print(f"[!] Host {target} did not respond to OS scan")
            return {}

        osmatches = scanner[target].get("osmatch", [])
        if not osmatches:
            print("[-] No OS match found (target may be filtering probes)")
            return {}

        best = osmatches[0]
        print(f"[+] OS guess: {best['name']} ({best['accuracy']}% confidence)")
        return {"name": best["name"], "accuracy": best["accuracy"]}

    except nmap.PortScannerError as e:
        print(f"[!] Nmap error (try running with sudo): {e}")
        return {}
    except Exception as e:
        print(f"[!] Unexpected OS detection error: {e}")
        return {}


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python scanner.py <target_ip>")
        sys.exit(1)

    target = sys.argv[1]

    print(f"[*] Raw socket scan of {target} (ports 1-1024)")
    raw_socket_scan(target)

    if NMAP_AVAILABLE:
        print(f"\n[*] Nmap -sV scan of {target}")
        nmap_scan(target)

    print(f"\n[*] Banner grab on {target} (ports 21, 22, 80)")
    banners = banner_scan(target)

    print(f"\n[*] OS detection on {target} (requires sudo)")
    os_detect(target)

    # Day 3: wire each banner straight into an NVD lookup, color-coded by risk
    try:
        from cve_lookup import banner_to_cves, print_cves
        for port, banner in banners.items():
            print(f"\n[*] CVE lookup for port {port} banner")
            cves = banner_to_cves(banner)
            print_cves(cves, port=port)
    except ImportError:
        print("[!] cve_lookup.py not found in this directory — skipping CVE lookup")
