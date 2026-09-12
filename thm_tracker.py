#!/usr/bin/env python3
"""
thm_tracker.py — TryHackMe room tracker.

Takes your scanner JSON output and maps each CVE found to the exact
TryHackMe room where you can practice exploiting that vulnerability
in a legal, authorized lab environment.

Usage:
    python3 thm_tracker.py --scan output/scan.json
    python3 thm_tracker.py --cve CVE-2017-0143
"""

import argparse
import json

# CVE → TryHackMe room mapping
# Format: CVE-ID → {room, url, description, skill}
CVE_TO_THM = {
    # EternalBlue / SMB
    "CVE-2017-0143": {
        "room": "Blue",
        "url": "https://tryhackme.com/room/blue",
        "description": "Exploit EternalBlue (MS17-010) on a Windows machine end to end",
        "skill": "SMB exploitation, Metasploit, privilege escalation",
    },
    "CVE-2017-0144": {
        "room": "Blue",
        "url": "https://tryhackme.com/room/blue",
        "description": "Exploit EternalBlue (MS17-010) on a Windows machine end to end",
        "skill": "SMB exploitation, Metasploit, privilege escalation",
    },
    # vsftpd backdoor
    "CVE-2011-2523": {
        "room": "Metasploitable",
        "url": "https://tryhackme.com/room/metasploitable",
        "description": "vsftpd 2.3.4 backdoor — classic intro to Metasploit exploitation",
        "skill": "FTP exploitation, Metasploit basics",
    },
    # Shellshock
    "CVE-2014-6271": {
        "room": "Shellshock",
        "url": "https://tryhackme.com/room/shellshock",
        "description": "Exploit the Shellshock bash vulnerability via CGI",
        "skill": "Web exploitation, bash injection",
    },
    # Log4Shell
    "CVE-2021-44228": {
        "room": "Solar",
        "url": "https://tryhackme.com/room/solar",
        "description": "Log4Shell — exploit Log4j JNDI injection from scratch",
        "skill": "Java exploitation, JNDI, RCE",
    },
    # BlueKeep RDP
    "CVE-2019-0708": {
        "room": "Blaster",
        "url": "https://tryhackme.com/room/blaster",
        "description": "Windows RDP exploitation and post-exploitation",
        "skill": "RDP exploitation, Windows privilege escalation",
    },
    # Apache path traversal
    "CVE-2021-41773": {
        "room": "Vulnerability Capstone",
        "url": "https://tryhackme.com/room/vulnerabilitycapstone",
        "description": "Practice Apache 2.4.49 path traversal and RCE",
        "skill": "Web exploitation, path traversal",
    },
    # Samba
    "CVE-2007-2447": {
        "room": "Metasploitable",
        "url": "https://tryhackme.com/room/metasploitable",
        "description": "Samba usermap script — remote code execution via SMB",
        "skill": "SMB exploitation, Metasploit",
    },
    # OpenSSH
    "CVE-2016-0777": {
        "room": "Jr Penetration Tester",
        "url": "https://tryhackme.com/path/outline/jrpenetrationtester",
        "description": "SSH enumeration and exploitation techniques",
        "skill": "SSH exploitation, user enumeration",
    },
    # General web
    "CVE-2019-9053": {
        "room": "OWASP Top 10",
        "url": "https://tryhackme.com/room/owasptop10",
        "description": "CMS Made Simple SQLi — practice SQL injection",
        "skill": "SQL injection, web exploitation",
    },
}

# General skill → room mapping (used when CVE has no direct match)
SKILL_ROOMS = {
    "metasploit": {
        "room": "Metasploit",
        "url": "https://tryhackme.com/module/metasploit",
        "description": "Full Metasploit module — from basics to post-exploitation",
    },
    "nmap": {
        "room": "Nmap",
        "url": "https://tryhackme.com/room/furthernmap",
        "description": "Advanced Nmap scanning techniques",
    },
    "web": {
        "room": "OWASP Top 10",
        "url": "https://tryhackme.com/room/owasptop10",
        "description": "Full OWASP Top 10 walkthrough with hands-on labs",
    },
    "privilege_escalation_linux": {
        "room": "Linux PrivEsc",
        "url": "https://tryhackme.com/room/linuxprivesc",
        "description": "Linux privilege escalation techniques end to end",
    },
    "privilege_escalation_windows": {
        "room": "Windows PrivEsc",
        "url": "https://tryhackme.com/room/windows10privesc",
        "description": "Windows privilege escalation techniques end to end",
    },
    "ejpt_prep": {
        "room": "Jr Penetration Tester Path",
        "url": "https://tryhackme.com/path/outline/jrpenetrationtester",
        "description": "Full path covering everything needed for eJPT certification",
    },
}


def map_cves_to_rooms(cves: list) -> list:
    """Map a list of CVE dicts to TryHackMe rooms."""
    results = []
    seen_rooms = set()
    for cve in cves:
        cve_id = cve.get("id", "")
        if cve_id in CVE_TO_THM:
            room = CVE_TO_THM[cve_id]
            if room["room"] not in seen_rooms:
                results.append({"cve": cve_id, **room})
                seen_rooms.add(room["room"])
    return results


def print_tracker(rooms: list, scan_target: str = None) -> None:
    print("\n" + "="*60)
    print("TRYHACKME PRACTICE ROOMS — based on your scan")
    if scan_target:
        print(f"Target scanned: {scan_target}")
    print("="*60)

    if not rooms:
        print("\nNo direct CVE matches found.")
        print("Start with the Jr Penetration Tester path:")
        print("  https://tryhackme.com/path/outline/jrpenetrationtester")
        return

    for i, r in enumerate(rooms, 1):
        print(f"\n{i}. [{r['cve']}] → {r['room']}")
        print(f"   {r['description']}")
        print(f"   Skill: {r.get('skill','')}")
        print(f"   URL:   {r['url']}")

    print("\n" + "="*60)
    print("ALWAYS START HERE (eJPT prep):")
    ep = SKILL_ROOMS["ejpt_prep"]
    print(f"  {ep['room']} — {ep['url']}")
    print("="*60)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Map scanner CVEs to TryHackMe practice rooms."
    )
    parser.add_argument("--scan", default=None, help="Path to scanner JSON output")
    parser.add_argument("--cve", default=None, help="Look up a single CVE e.g. CVE-2017-0143")
    args = parser.parse_args()

    if args.cve:
        cve_id = args.cve.upper()
        if cve_id in CVE_TO_THM:
            r = CVE_TO_THM[cve_id]
            print(f"\n{cve_id} → {r['room']}")
            print(f"  {r['description']}")
            print(f"  Skill: {r.get('skill','')}")
            print(f"  URL:   {r['url']}")
        else:
            print(f"{cve_id} not in tracker yet.")
            print("Start with Jr Penetration Tester path:")
            print("  https://tryhackme.com/path/outline/jrpenetrationtester")

    elif args.scan:
        with open(args.scan) as f:
            scan = json.load(f)
        all_cves = []
        for port_cves in scan.get("cves", {}).values():
            all_cves.extend(port_cves)
        rooms = map_cves_to_rooms(all_cves)
        print_tracker(rooms, scan.get("target"))

    else:
        print("Usage: python3 thm_tracker.py --scan output/scan.json")
        print("       python3 thm_tracker.py --cve CVE-2017-0143")
