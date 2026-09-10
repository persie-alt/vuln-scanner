# vuln-scanner

⚠ **Legal**: Only scan systems you own or have explicit written permission to test. Unauthorized scanning is illegal in most jurisdictions.

A Python vulnerability scanner built as a portfolio project targeting SOC Analyst / Junior Penetration Tester roles. Combines network scanning, live CVE lookup, and web application checks with both a CLI and a browser dashboard.

## Features

- TCP port scanning (raw socket + multithreaded)
- Service banner grabbing (FTP, SSH, HTTP)
- OS fingerprinting (Nmap `-O`)
- Live CVE lookup via the NVD API 2.0, color-coded by CVSS severity
- Web app scanning: missing security headers, SSL/TLS version + cert expiry, directory brute-force, SQLi and reflected XSS probing
- JSON + HTML report generation
- Browser dashboard: enter a target, see results rendered live

## Setup

```bash
pip install -r requirements.txt
export NVD_API_KEY="your-key-here"   # https://nvd.nist.gov/developers/request-an-api-key
```

## Usage

**CLI:**
```bash
python3 main.py --target scanme.nmap.org
python3 main.py --target scanme.nmap.org --ports 1-100 --threads 100
python3 main.py --target 127.0.0.1 --web "http://127.0.0.1:5000/product?id=1"
```

| Flag | Description | Default |
|---|---|---|
| `--target` | IP or hostname to scan (required) | — |
| `--ports` | Port range | `1-1024` |
| `--output` | Report output directory | `output` |
| `--web` | URL to also run web app scanning against | none |
| `--threads` | Threads for port scanning | `50` |

**Dashboard:**
```bash
python3 dashboard.py
```
Open the forwarded port in your browser, enter a target, view results.

**Web scanner standalone:**
```bash
python3 web_scanner.py "http://target/page?id=1"
```

**Legal test target included:** `vulnerable_app.py` is a small intentionally-insecure Flask app for testing the web scanner safely against your own machine:
```bash
python3 vulnerable_app.py &
python3 web_scanner.py "http://127.0.0.1:5000/product?id=1"
```

## Progress

- [x] TCP port scanner (raw socket + threaded)
- [x] Banner grabbing
- [x] NVD CVE lookup with risk scoring
- [x] OS detection
- [x] JSON + HTML reporting
- [x] Web app scanning (headers, SSL/TLS, directory brute-force, SQLi, XSS)
- [x] CLI with argparse
- [x] Multithreaded scanning
- [x] Browser dashboard

## Files

- `scanner.py` — port scanning, banner grabbing, OS detection
- `cve_lookup.py` — NVD CVE lookup + risk-color formatting
- `web_scanner.py` — headers, SSL/TLS, directory brute-force, SQLi/XSS
- `reporter.py` — JSON + HTML report generation
- `main.py` — CLI entry point
- `dashboard.py` — browser UI
- `vulnerable_app.py` — safe local test target for web scanning

⚠ **Legal**: Only run this scanner against systems you own or have explicit written permission to test.
