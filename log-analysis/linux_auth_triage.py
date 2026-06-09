#!/usr/bin/env python3
"""
linux_auth_triage.py - Triage Linux auth logs (auth.log / secure) for
brute force, account changes, privilege use, and odd SSH activity.

Usage:
  python linux_auth_triage.py /var/log/auth.log
  python linux_auth_triage.py auth.log --threshold 5 -o report.json
  zcat auth.log.1.gz | python linux_auth_triage.py -
"""

import argparse
import json
import re
import sys
from collections import Counter, defaultdict

PATTERNS = {
    "failed_password": re.compile(
        r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+)"),
    "invalid_user": re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>\S+)"),
    "accepted": re.compile(
        r"Accepted (?P<method>\w+) for (?P<user>\S+) from (?P<ip>\S+)"),
    "sudo": re.compile(
        r"sudo:\s+(?P<user>\S+) : .*COMMAND=(?P<cmd>.+)$"),
    "user_added": re.compile(r"useradd.*new user.*name=(?P<user>[^,]+)"),
    "user_mod": re.compile(r"usermod\[\d+\]: (?P<detail>.+)$"),
    "group_added": re.compile(r"groupadd.*new group.*name=(?P<group>[^,]+)"),
    "ssh_key_added": re.compile(r"Accepted publickey for (?P<user>\S+) from (?P<ip>\S+)"),
    "session_root": re.compile(r"session opened for user root"),
    "auth_failure_su": re.compile(r"su\[\d+\].*authentication failure"),
}

TIMESTAMP = re.compile(
    r"^(?P<ts>(?:\w{3}\s+\d+\s[\d:]{8})|(?:\d{4}-\d{2}-\d{2}T[\d:.+-]+))")


def parse(stream, threshold):
    failed_by_ip = Counter()
    failed_users_by_ip = defaultdict(set)
    accepted = []
    sudo_cmds = []
    account_changes = []
    root_sessions = 0
    success_after_fail = []
    first_ts = last_ts = ""

    for line in stream:
        m = TIMESTAMP.match(line)
        ts = m.group("ts") if m else ""
        if ts:
            first_ts = first_ts or ts
            last_ts = ts

        if (m := PATTERNS["failed_password"].search(line)) or \
           (m := PATTERNS["invalid_user"].search(line)):
            ip = m.group("ip")
            failed_by_ip[ip] += 1
            failed_users_by_ip[ip].add(m.group("user"))
        elif m := PATTERNS["accepted"].search(line):
            entry = {"ts": ts, "user": m.group("user"), "ip": m.group("ip"),
                     "method": m.group("method")}
            accepted.append(entry)
            if failed_by_ip.get(m.group("ip"), 0) >= threshold:
                success_after_fail.append(entry)
        elif m := PATTERNS["sudo"].search(line):
            sudo_cmds.append({"ts": ts, "user": m.group("user"),
                              "cmd": m.group("cmd").strip()})
        elif m := PATTERNS["user_added"].search(line):
            account_changes.append({"ts": ts, "type": "useradd",
                                    "detail": m.group("user")})
        elif m := PATTERNS["group_added"].search(line):
            account_changes.append({"ts": ts, "type": "groupadd",
                                    "detail": m.group("group")})
        elif m := PATTERNS["user_mod"].search(line):
            account_changes.append({"ts": ts, "type": "usermod",
                                    "detail": m.group("detail")[:200]})
        elif PATTERNS["session_root"].search(line):
            root_sessions += 1

    brute_force = [
        {"ip": ip, "failures": n, "distinct_users": len(failed_users_by_ip[ip]),
         "spray": len(failed_users_by_ip[ip]) >= threshold}
        for ip, n in failed_by_ip.most_common() if n >= threshold
    ]

    return {
        "window": {"first": first_ts, "last": last_ts},
        "summary": {
            "total_failed_sources": len(failed_by_ip),
            "brute_force_sources": len(brute_force),
            "successful_logins": len(accepted),
            "logins_after_bruteforce": len(success_after_fail),
            "sudo_commands": len(sudo_cmds),
            "account_changes": len(account_changes),
            "root_sessions": root_sessions,
        },
        "alerts": {
            "login_after_bruteforce": success_after_fail,  # highest priority
            "brute_force_sources": brute_force,
            "account_changes": account_changes,
        },
        "successful_logins": accepted[-50:],
        "sudo_commands": sudo_cmds[-50:],
    }


def main():
    ap = argparse.ArgumentParser(description="Triage Linux auth logs")
    ap.add_argument("logfile", help="auth.log / secure path, or '-' for stdin")
    ap.add_argument("--threshold", type=int, default=10,
                    help="failed attempts per IP to flag (default 10)")
    ap.add_argument("-o", "--output", help="write JSON report here")
    args = ap.parse_args()

    stream = sys.stdin if args.logfile == "-" else open(
        args.logfile, "r", encoding="utf-8", errors="replace")
    try:
        report = parse(stream, args.threshold)
    finally:
        if stream is not sys.stdin:
            stream.close()

    out = json.dumps(report, indent=2, default=str)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(out)
        print(f"[+] report -> {args.output}")
    else:
        print(out)

    s = report["summary"]
    print(f"\n[+] {s['brute_force_sources']} brute-force source(s), "
          f"{s['logins_after_bruteforce']} login(s) after brute force, "
          f"{s['account_changes']} account change(s)", file=sys.stderr)


if __name__ == "__main__":
    main()
