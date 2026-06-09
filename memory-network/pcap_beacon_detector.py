#!/usr/bin/env python3
"""
pcap_beacon_detector.py - Detect C2-style beaconing in network captures.

Looks for src->dst:port conversations with highly regular intervals and
consistent payload sizes - classic beacon behavior. Accepts:
  - .pcap/.pcapng (requires: pip install scapy)
  - Zeek conn.log (TSV or JSON)

Scoring combines interval regularity (coefficient of variation), size
consistency, and session count. Higher score = more beacon-like.

Usage:
  python pcap_beacon_detector.py capture.pcap
  python pcap_beacon_detector.py conn.log --min-sessions 8 -o beacons.csv
"""

import argparse
import csv
import json
import statistics
import sys
from collections import defaultdict
from pathlib import Path


def iter_pcap(path):
    try:
        from scapy.all import PcapReader, IP, TCP, UDP  # type: ignore
    except ImportError:
        sys.exit("scapy required for pcap input: pip install scapy")
    with PcapReader(str(path)) as reader:
        for pkt in reader:
            if IP not in pkt:
                continue
            layer = TCP if TCP in pkt else (UDP if UDP in pkt else None)
            if layer is None:
                continue
            yield {
                "ts": float(pkt.time),
                "src": pkt[IP].src,
                "dst": pkt[IP].dst,
                "dport": pkt[layer].dport,
                "size": len(pkt),
            }


def iter_zeek(path):
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        first = fh.readline()
        fh.seek(0)
        if first.lstrip().startswith("{"):  # JSON lines
            for line in fh:
                try:
                    r = json.loads(line)
                except json.JSONDecodeError:
                    continue
                yield {
                    "ts": float(r.get("ts", 0)),
                    "src": r.get("id.orig_h", ""),
                    "dst": r.get("id.resp_h", ""),
                    "dport": int(r.get("id.resp_p", 0)),
                    "size": int(r.get("orig_bytes") or 0),
                }
        else:  # Zeek TSV
            fields = []
            for line in fh:
                if line.startswith("#fields"):
                    fields = line.strip().split("\t")[1:]
                    continue
                if line.startswith("#") or not fields:
                    continue
                vals = dict(zip(fields, line.rstrip("\n").split("\t")))
                try:
                    yield {
                        "ts": float(vals.get("ts", 0)),
                        "src": vals.get("id.orig_h", ""),
                        "dst": vals.get("id.resp_h", ""),
                        "dport": int(vals.get("id.resp_p", 0)),
                        "size": int(vals.get("orig_bytes") or 0)
                        if vals.get("orig_bytes", "-") != "-" else 0,
                    }
                except ValueError:
                    continue


def analyze(records, min_sessions):
    convos = defaultdict(list)
    for r in records:
        convos[(r["src"], r["dst"], r["dport"])].append((r["ts"], r["size"]))

    results = []
    for (src, dst, dport), events in convos.items():
        if len(events) < min_sessions:
            continue
        events.sort()
        times = [t for t, _ in events]
        sizes = [s for _, s in events]
        intervals = [b - a for a, b in zip(times, times[1:])]
        if not intervals:
            continue
        mean_iv = statistics.mean(intervals)
        if mean_iv < 1:  # sub-second chatter, not beaconing
            continue
        iv_cv = (statistics.stdev(intervals) / mean_iv
                 if len(intervals) > 1 and mean_iv else 1.0)
        mean_sz = statistics.mean(sizes)
        sz_cv = (statistics.stdev(sizes) / mean_sz
                 if len(sizes) > 1 and mean_sz else 0.0)

        # Score: regular intervals dominate, consistent size helps,
        # more sessions = more confidence. Range ~0-100.
        score = max(0.0, (1 - min(iv_cv, 1)) * 60
                    + (1 - min(sz_cv, 1)) * 25
                    + min(len(events) / 50, 1) * 15)
        results.append({
            "src": src, "dst": dst, "dport": dport,
            "sessions": len(events),
            "mean_interval_s": round(mean_iv, 1),
            "interval_cv": round(iv_cv, 3),
            "mean_size": round(mean_sz, 1),
            "size_cv": round(sz_cv, 3),
            "score": round(score, 1),
            "duration_min": round((times[-1] - times[0]) / 60, 1),
        })
    results.sort(key=lambda r: -r["score"])
    return results


def main():
    ap = argparse.ArgumentParser(description="Detect beaconing in pcap/Zeek logs")
    ap.add_argument("input", help=".pcap/.pcapng or Zeek conn.log")
    ap.add_argument("--min-sessions", type=int, default=6,
                    help="min connections per conversation (default 6)")
    ap.add_argument("--min-score", type=float, default=65.0,
                    help="only report scores >= this (default 65)")
    ap.add_argument("-o", "--output", help="write CSV here")
    args = ap.parse_args()

    path = Path(args.input)
    if not path.exists():
        sys.exit(f"not found: {path}")
    records = (iter_pcap(path) if path.suffix.lower() in (".pcap", ".pcapng", ".cap")
               else iter_zeek(path))
    results = [r for r in analyze(records, args.min_sessions)
               if r["score"] >= args.min_score]

    if args.output:
        with open(args.output, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=list(results[0].keys()) if results else
                                    ["src", "dst", "dport", "sessions", "mean_interval_s",
                                     "interval_cv", "mean_size", "size_cv", "score", "duration_min"])
            writer.writeheader()
            writer.writerows(results)
        print(f"[+] {len(results)} beacon candidates -> {args.output}")
    else:
        for r in results:
            print(f"score {r['score']:5}  {r['src']} -> {r['dst']}:{r['dport']}  "
                  f"{r['sessions']} sessions every ~{r['mean_interval_s']}s "
                  f"(cv={r['interval_cv']}) over {r['duration_min']}min")
        print(f"\n[+] {len(results)} beacon candidates (score >= {args.min_score})")


if __name__ == "__main__":
    main()
