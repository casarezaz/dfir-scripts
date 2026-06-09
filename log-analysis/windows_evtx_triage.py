#!/usr/bin/env python3
"""
windows_evtx_triage.py - Triage Windows event logs for suspicious activity.

Accepts:
  - .evtx files (requires: pip install python-evtx)
  - JSONL exports (one JSON event per line, e.g. from evtx_dump or Hayabusa)

Flags high-value DFIR events: failed/odd logons, account creation, service
installs, scheduled tasks, log clearing, PowerShell script blocks, and
suspicious process creation command lines.

Usage:
  python windows_evtx_triage.py Security.evtx
  python windows_evtx_triage.py export.jsonl -o findings.csv
  python windows_evtx_triage.py Security.evtx --json
"""

import argparse
import csv
import json
import re
import sys
from pathlib import Path

# Event IDs of interest -> (description, severity)
INTERESTING_EVENTS = {
    "1102": ("Audit log cleared", "HIGH"),
    "4624": ("Successful logon", "INFO"),
    "4625": ("Failed logon", "MEDIUM"),
    "4648": ("Logon with explicit credentials", "MEDIUM"),
    "4672": ("Special privileges assigned to new logon", "INFO"),
    "4688": ("Process creation", "INFO"),
    "4697": ("Service installed (Security)", "HIGH"),
    "4698": ("Scheduled task created", "HIGH"),
    "4702": ("Scheduled task updated", "MEDIUM"),
    "4720": ("User account created", "HIGH"),
    "4722": ("User account enabled", "MEDIUM"),
    "4724": ("Password reset attempt", "MEDIUM"),
    "4728": ("Member added to security-enabled global group", "HIGH"),
    "4732": ("Member added to security-enabled local group", "HIGH"),
    "4756": ("Member added to security-enabled universal group", "HIGH"),
    "4768": ("Kerberos TGT requested", "INFO"),
    "4769": ("Kerberos service ticket requested", "INFO"),
    "4776": ("NTLM credential validation", "INFO"),
    "5140": ("Network share accessed", "INFO"),
    "5145": ("Network share object checked", "INFO"),
    "7045": ("Service installed (System)", "HIGH"),
    "4104": ("PowerShell script block logged", "MEDIUM"),
}

# Regexes that make a 4688/4104 event suspicious
SUSPICIOUS_PATTERNS = [
    (r"(?i)-enc(odedcommand)?\s+[A-Za-z0-9+/=]{20,}", "Encoded PowerShell command"),
    (r"(?i)downloadstring|downloadfile|invoke-webrequest|iwr\s|curl\s+http", "Download cradle"),
    (r"(?i)iex\s*\(|invoke-expression", "Invoke-Expression"),
    (r"(?i)bypass\s+-nop|-nop\s+-w\s+hidden|executionpolicy\s+bypass", "PowerShell evasion flags"),
    (r"(?i)mimikatz|sekurlsa|lsadump|kerberoast", "Credential theft tooling"),
    (r"(?i)vssadmin\s+delete\s+shadows|wbadmin\s+delete", "Shadow copy deletion"),
    (r"(?i)bcdedit\s+/set|wevtutil\s+cl", "Recovery tampering / log clearing"),
    (r"(?i)reg(\.exe)?\s+(add|save).*(sam|system|security)", "Registry hive dumping"),
    (r"(?i)rundll32.*comsvcs.*minidump", "LSASS dump via comsvcs"),
    (r"(?i)certutil.*-urlcache|certutil.*-decode", "Certutil abuse"),
    (r"(?i)bitsadmin\s+/transfer", "BITS job abuse"),
    (r"(?i)schtasks\s+/create", "Scheduled task creation via CLI"),
    (r"(?i)net\s+user\s+\S+\s+\S+\s+/add", "User added via net.exe"),
    (r"(?i)wmic.*process\s+call\s+create", "WMIC remote process creation"),
    (r"(?i)\\\\.\\pipe\\|psexec", "PsExec / named pipe usage"),
    (r"(?i)(cmd|powershell)[^\n]{0,100}(\.\.[\\/]){2,}", "Path traversal in command"),
]

LOGON_TYPE_NOTES = {"3": "network", "10": "RDP", "9": "runas /netonly"}


def iter_evtx(path):
    try:
        import Evtx.Evtx as evtx  # type: ignore
    except ImportError:
        sys.exit("python-evtx required for .evtx files: pip install python-evtx")
    import xml.etree.ElementTree as ET

    ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
    with evtx.Evtx(str(path)) as log:
        for record in log.records():
            try:
                root = ET.fromstring(record.xml())
            except ET.ParseError:
                continue
            eid = root.findtext(".//e:EventID", default="", namespaces=ns)
            ts_el = root.find(".//e:TimeCreated", ns)
            ts = ts_el.get("SystemTime", "") if ts_el is not None else ""
            data = {
                d.get("Name", ""): (d.text or "")
                for d in root.findall(".//e:EventData/e:Data", ns)
            }
            yield {"EventID": str(eid), "TimeCreated": ts, "Data": data}


def iter_jsonl(path):
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue
            # Tolerate common shapes: evtx_dump, Hayabusa, winlogbeat
            sysinfo = ev.get("Event", {}).get("System", {}) if "Event" in ev else ev
            eid = sysinfo.get("EventID")
            if isinstance(eid, dict):
                eid = eid.get("#text") or eid.get("Value")
            ts = ""
            tc = sysinfo.get("TimeCreated", {})
            if isinstance(tc, dict):
                ts = tc.get("#attributes", {}).get("SystemTime") or tc.get("SystemTime", "")
            data = ev.get("Event", {}).get("EventData", {}) if "Event" in ev else ev.get("EventData", {})
            if not isinstance(data, dict):
                data = {}
            yield {"EventID": str(eid or ""), "TimeCreated": ts, "Data": data}


def analyze(events):
    findings = []
    for ev in events:
        eid = ev["EventID"]
        if eid not in INTERESTING_EVENTS:
            continue
        desc, severity = INTERESTING_EVENTS[eid]
        data = ev["Data"]
        notes = []

        blob = " ".join(str(v) for v in data.values())
        for pattern, label in SUSPICIOUS_PATTERNS:
            if re.search(pattern, blob):
                notes.append(label)
                severity = "HIGH"

        if eid == "4624":
            lt = str(data.get("LogonType", ""))
            if lt in LOGON_TYPE_NOTES:
                notes.append(f"logon type {lt} ({LOGON_TYPE_NOTES[lt]})")
            elif not notes:
                continue  # skip noisy benign interactive logons
        if eid in ("4688", "4104") and not notes:
            continue  # only keep process/script events that matched a pattern

        findings.append({
            "TimeCreated": ev["TimeCreated"],
            "EventID": eid,
            "Description": desc,
            "Severity": severity,
            "User": data.get("TargetUserName") or data.get("SubjectUserName", ""),
            "SourceIP": data.get("IpAddress", ""),
            "Detail": "; ".join(notes) or blob[:300],
        })
    return findings


def main():
    ap = argparse.ArgumentParser(description="Triage Windows event logs")
    ap.add_argument("logfile", help=".evtx or .jsonl input")
    ap.add_argument("-o", "--output", help="write findings CSV here")
    ap.add_argument("--json", action="store_true", help="print JSON instead of table")
    args = ap.parse_args()

    path = Path(args.logfile)
    if not path.exists():
        sys.exit(f"not found: {path}")

    events = iter_evtx(path) if path.suffix.lower() == ".evtx" else iter_jsonl(path)
    findings = analyze(events)
    findings.sort(key=lambda f: ({"HIGH": 0, "MEDIUM": 1, "INFO": 2}[f["Severity"]], f["TimeCreated"]))

    if args.output:
        with open(args.output, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=list(findings[0].keys()) if findings else
                                    ["TimeCreated", "EventID", "Description", "Severity", "User", "SourceIP", "Detail"])
            writer.writeheader()
            writer.writerows(findings)
        print(f"[+] {len(findings)} findings -> {args.output}")
    elif args.json:
        print(json.dumps(findings, indent=2))
    else:
        for f in findings:
            print(f"[{f['Severity']:6}] {f['TimeCreated']} EID {f['EventID']} "
                  f"{f['Description']} | {f['User']} {f['SourceIP']} | {f['Detail'][:120]}")
        print(f"\n[+] {len(findings)} findings")


if __name__ == "__main__":
    main()
