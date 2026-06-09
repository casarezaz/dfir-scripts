#!/usr/bin/env python3
"""
vol3_triage.py - Run a standard Volatility 3 triage pass over a memory image.

Wraps `vol` (Volatility 3) to run a curated plugin set, save each output,
and produce a quick-look summary of common red flags (unlinked processes,
suspicious parents, injected code regions, odd network listeners).

Requires Volatility 3 on PATH: pip install volatility3

Usage:
  python vol3_triage.py memory.raw -d vol_output/
  python vol3_triage.py memory.raw --os linux -d out/
  python vol3_triage.py memory.raw --plugins windows.pslist,windows.netscan
"""

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

PLUGIN_SETS = {
    "windows": [
        "windows.info",
        "windows.pslist",
        "windows.pstree",
        "windows.psscan",       # finds unlinked/hidden processes vs pslist
        "windows.cmdline",
        "windows.netscan",
        "windows.netstat",
        "windows.malfind",      # injected code regions
        "windows.dlllist",
        "windows.svcscan",
        "windows.registry.hivelist",
        "windows.sessions",
    ],
    "linux": [
        "linux.pslist",
        "linux.pstree",
        "linux.psaux",
        "linux.sockstat",
        "linux.malfind",
        "linux.lsmod",
        "linux.bash",
    ],
    "mac": [
        "mac.pslist",
        "mac.pstree",
        "mac.netstat",
        "mac.malfind",
        "mac.bash",
    ],
}

# Parent->child pairs that are suspicious on Windows
ODD_PARENTS = {
    ("winword.exe", "cmd.exe"), ("winword.exe", "powershell.exe"),
    ("excel.exe", "cmd.exe"), ("excel.exe", "powershell.exe"),
    ("outlook.exe", "powershell.exe"), ("explorer.exe", "rundll32.exe"),
    ("svchost.exe", "cmd.exe"), ("lsass.exe", "cmd.exe"),
    ("wmiprvse.exe", "powershell.exe"), ("mshta.exe", "powershell.exe"),
}


def run_plugin(vol_bin, image, plugin, outdir):
    outfile = outdir / f"{plugin.replace('.', '_')}.txt"
    cmd = [vol_bin, "-q", "-f", str(image), plugin]
    print(f"[*] {plugin} ...", flush=True)
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
    except subprocess.TimeoutExpired:
        outfile.write_text("TIMEOUT\n")
        return None
    outfile.write_text(proc.stdout + ("\n--- stderr ---\n" + proc.stderr
                                      if proc.returncode else ""))
    return proc.stdout if proc.returncode == 0 else None


def summarize(outputs, outdir):
    notes = []

    pslist = outputs.get("windows.pslist", "") or ""
    psscan = outputs.get("windows.psscan", "") or ""
    if pslist and psscan:
        def pids(text):
            out = set()
            for line in text.splitlines():
                parts = line.split()
                if parts and parts[0].isdigit():
                    out.add(parts[0])
            return out
        hidden = pids(psscan) - pids(pslist)
        if hidden:
            notes.append(f"PIDs in psscan but not pslist (possibly hidden): "
                         f"{', '.join(sorted(hidden)[:20])}")

    pstree = outputs.get("windows.pstree", "") or ""
    lowered = pstree.lower()
    for parent, child in ODD_PARENTS:
        if parent in lowered and child in lowered:
            notes.append(f"check pstree: both {parent} and {child} present - "
                         f"verify parent/child relationship")

    malfind = outputs.get("windows.malfind") or outputs.get("linux.malfind") \
        or outputs.get("mac.malfind") or ""
    hits = [ln for ln in malfind.splitlines()
            if "PAGE_EXECUTE_READWRITE" in ln or "VadS" in ln]
    if hits:
        notes.append(f"malfind: {len(hits)} executable+writable region line(s) "
                     f"- review malfind output")

    netscan = outputs.get("windows.netscan", "") or ""
    odd_ports = [ln for ln in netscan.splitlines()
                 if any(f":{p} " in ln for p in (4444, 1337, 31337, 8081, 9001))]
    if odd_ports:
        notes.append(f"netscan: {len(odd_ports)} connection(s) on commonly "
                     f"abused ports")

    summary = outdir / "TRIAGE_SUMMARY.txt"
    with open(summary, "w", encoding="utf-8") as fh:
        if notes:
            fh.write("RED FLAGS\n=========\n")
            for n in notes:
                fh.write(f"- {n}\n")
        else:
            fh.write("No automatic red flags. Review plugin outputs manually.\n")
    print(f"\n[+] summary -> {summary}")
    for n in notes:
        print(f"    ! {n}")


def main():
    ap = argparse.ArgumentParser(description="Volatility 3 triage wrapper")
    ap.add_argument("image", help="memory image path")
    ap.add_argument("--os", choices=("windows", "linux", "mac"),
                    default="windows", dest="osname")
    ap.add_argument("--plugins", help="comma-separated override list")
    ap.add_argument("-d", "--outdir", default="vol3_triage_output")
    args = ap.parse_args()

    vol_bin = shutil.which("vol") or shutil.which("vol3") or shutil.which("volatility3")
    if not vol_bin:
        sys.exit("Volatility 3 not found on PATH: pip install volatility3")
    image = Path(args.image)
    if not image.exists():
        sys.exit(f"not found: {image}")

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    plugins = (args.plugins.split(",") if args.plugins
               else PLUGIN_SETS[args.osname])
    outputs = {}
    for plugin in plugins:
        outputs[plugin.strip()] = run_plugin(vol_bin, image, plugin.strip(), outdir)

    summarize(outputs, outdir)
    print(f"[+] raw outputs in {outdir}/")


if __name__ == "__main__":
    main()
