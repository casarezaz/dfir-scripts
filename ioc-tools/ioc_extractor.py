#!/usr/bin/env python3
"""
ioc_extractor.py - Extract, defang/refang, dedupe, and optionally enrich IOCs.

Extracts IPv4/IPv6, domains, URLs, emails, and MD5/SHA1/SHA256 hashes from
any text file (reports, emails, log excerpts). Handles common defanging
(hxxp, [.], (.), [at]). Optional enrichment via VirusTotal and AbuseIPDB
if API keys are set in the environment (VT_API_KEY, ABUSEIPDB_API_KEY).

Usage:
  python ioc_extractor.py report.txt
  python ioc_extractor.py report.txt -o iocs.csv --defang
  python ioc_extractor.py report.txt --enrich --json
  cat *.txt | python ioc_extractor.py -
"""

import argparse
import csv
import ipaddress
import json
import os
import re
import sys
import urllib.request

REFANG = [
    (re.compile(r"(?i)hxxps?"), lambda m: m.group(0).lower().replace("xx", "tt")),
    (re.compile(r"\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)", re.I), lambda m: "."),
    (re.compile(r"\[at\]|\(at\)", re.I), lambda m: "@"),
    (re.compile(r"\[:\]|\[://\]"), lambda m: m.group(0).strip("[]")),
]

RE_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
RE_IPV6 = re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b")
RE_URL = re.compile(r"\bhttps?://[^\s\"'<>)\]}]+", re.I)
RE_EMAIL = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")
RE_DOMAIN = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b", re.I)
RE_MD5 = re.compile(r"\b[a-fA-F0-9]{32}\b")
RE_SHA1 = re.compile(r"\b[a-fA-F0-9]{40}\b")
RE_SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")

# Common false-positive domains/TLD-lookalikes to drop
NOISE_DOMAINS = {"schemas.microsoft.com", "www.w3.org", "example.com",
                 "localhost.localdomain"}
NOISE_SUFFIXES = (".py", ".ps1", ".exe", ".dll", ".txt", ".log", ".json",
                  ".csv", ".yml", ".yaml", ".md", ".sh", ".bat", ".tmp")


def refang(text):
    for pattern, repl in REFANG:
        text = pattern.sub(repl, text)
    return text


def defang(ioc, kind):
    if kind in ("ipv4", "ipv6", "domain"):
        return ioc.replace(".", "[.]")
    if kind == "url":
        return ioc.replace("http", "hxxp").replace(".", "[.]")
    if kind == "email":
        return ioc.replace("@", "[at]").replace(".", "[.]")
    return ioc


def valid_ip(s):
    try:
        ip = ipaddress.ip_address(s)
        return not (ip.is_loopback or ip.is_unspecified)
    except ValueError:
        return False


def extract(text):
    text = refang(text)
    iocs = {}

    def add(kind, value):
        iocs.setdefault((kind, value), 0)
        iocs[(kind, value)] += 1

    for m in RE_URL.findall(text):
        add("url", m.rstrip(".,;"))
    for m in RE_IPV4.findall(text):
        if valid_ip(m):
            add("ipv4", m)
    for m in RE_IPV6.findall(text):
        if valid_ip(m):
            add("ipv6", m)
    for m in RE_EMAIL.findall(text):
        add("email", m.lower())
    for m in RE_SHA256.findall(text):
        add("sha256", m.lower())
    for m in RE_SHA1.findall(text):
        add("sha1", m.lower())
    for m in RE_MD5.findall(text):
        add("md5", m.lower())

    hashes = {v for (k, v) in iocs if k in ("md5", "sha1", "sha256")}
    urls = " ".join(v for (k, v) in iocs if k == "url")
    emails = " ".join(v for (k, v) in iocs if k == "email")
    for m in RE_DOMAIN.findall(text):
        d = m.lower()
        if (d in NOISE_DOMAINS or d.endswith(NOISE_SUFFIXES) or d in hashes
                or RE_IPV4.fullmatch(d) or d in urls or d in emails):
            continue
        add("domain", d)

    return [{"type": k, "value": v, "count": n}
            for (k, v), n in sorted(iocs.items())]


def http_get_json(url, headers):
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read().decode())
    except Exception as exc:  # noqa: BLE001 - report and continue
        return {"error": str(exc)}


def enrich(iocs):
    vt_key = os.environ.get("VT_API_KEY")
    abuse_key = os.environ.get("ABUSEIPDB_API_KEY")
    if not vt_key and not abuse_key:
        print("[!] no VT_API_KEY / ABUSEIPDB_API_KEY set; skipping enrichment",
              file=sys.stderr)
        return iocs

    for ioc in iocs:
        kind, value = ioc["type"], ioc["value"]
        if vt_key and kind in ("md5", "sha1", "sha256"):
            data = http_get_json(
                f"https://www.virustotal.com/api/v3/files/{value}",
                {"x-apikey": vt_key})
            stats = (data.get("data", {}).get("attributes", {})
                     .get("last_analysis_stats", {}))
            if stats:
                ioc["vt_malicious"] = stats.get("malicious", 0)
                ioc["vt_total"] = sum(stats.values())
        elif vt_key and kind == "domain":
            data = http_get_json(
                f"https://www.virustotal.com/api/v3/domains/{value}",
                {"x-apikey": vt_key})
            stats = (data.get("data", {}).get("attributes", {})
                     .get("last_analysis_stats", {}))
            if stats:
                ioc["vt_malicious"] = stats.get("malicious", 0)
        elif abuse_key and kind == "ipv4":
            data = http_get_json(
                f"https://api.abuseipdb.com/api/v2/check?ipAddress={value}",
                {"Key": abuse_key, "Accept": "application/json"})
            d = data.get("data", {})
            if d:
                ioc["abuse_score"] = d.get("abuseConfidenceScore")
                ioc["abuse_country"] = d.get("countryCode")
    return iocs


def main():
    ap = argparse.ArgumentParser(description="Extract IOCs from text")
    ap.add_argument("input", help="text file or '-' for stdin")
    ap.add_argument("-o", "--output", help="write CSV here")
    ap.add_argument("--json", action="store_true", help="JSON output")
    ap.add_argument("--defang", action="store_true",
                    help="defang IOCs in output (safe for sharing)")
    ap.add_argument("--enrich", action="store_true",
                    help="enrich via VT/AbuseIPDB (needs API keys in env)")
    args = ap.parse_args()

    text = (sys.stdin.read() if args.input == "-" else
            open(args.input, "r", encoding="utf-8", errors="replace").read())
    iocs = extract(text)
    if args.enrich:
        iocs = enrich(iocs)
    if args.defang:
        for ioc in iocs:
            ioc["value"] = defang(ioc["value"], ioc["type"])

    if args.output:
        fields = sorted({k for ioc in iocs for k in ioc})
        with open(args.output, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=fields)
            writer.writeheader()
            writer.writerows(iocs)
        print(f"[+] {len(iocs)} IOCs -> {args.output}")
    elif args.json:
        print(json.dumps(iocs, indent=2))
    else:
        for ioc in iocs:
            extra = {k: v for k, v in ioc.items()
                     if k not in ("type", "value", "count")}
            print(f"{ioc['type']:8} {ioc['value']}"
                  + (f"  {extra}" if extra else ""))
        print(f"\n[+] {len(iocs)} unique IOCs", file=sys.stderr)


if __name__ == "__main__":
    main()
