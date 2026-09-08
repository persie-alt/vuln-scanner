# vuln-scanner

⚠ **Legal**: Only scan systems you own or have explicit written permission to test. Unauthorized scanning is illegal in most jurisdictions.

A Python vulnerability scanner built as a portfolio project targeting SOC Analyst / Junior Penetration Tester roles.

## Progress

- [x] TCP port scanner (raw socket + python-nmap)
- [x] Banner grabbing (ports 21/22/80)
- [x] NVD CVE lookup (API 2.0)
- [ ] Web application scanning (headers, SSL/TLS, SQLi, XSS)
- [ ] HTML reporting
- [ ] CLI polish (argparse, threading)

## Usage

```bash
pip install -r requirements.txt
python3 scanner.py <target_ip>
python3 cve_lookup.py "vsftpd 2.3.4"
```

Set your NVD API key as an environment variable before running lookups:
```bash
export NVD_API_KEY="your-key-here"
```

## Files

- `scanner.py` — TCP port scanning, banner grabbing
- `cve_lookup.py` — NVD CVE lookup by keyword

⚠ **Legal**: Only run this scanner against systems you own or have explicit written permission to test.
