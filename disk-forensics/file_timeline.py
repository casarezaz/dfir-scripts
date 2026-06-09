#!/usr/bin/env python3
"""
file_timeline.py - Hash files and build a filesystem timeline for triage.

Walks a directory tree, hashes files (SHA256 + optional MD5), records
MAC(B) timestamps, and flags items of interest: executables in temp/user
dirs, double extensions, recently modified binaries, and hidden files.
Output is CSV (sortable timeline) or mactime-style bodyfile.

Usage:
  python file_timeline.py /evidence/mount -o timeline.csv
  python file_timeline.py C:\\Users\\victim --days 7 --flagged-only
  python file_timeline.py /mnt/image --bodyfile -o body.txt
"""

import argparse
import csv
import hashlib
import os
import stat
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

EXEC_EXTS = {".exe", ".dll", ".sys", ".scr", ".com", ".pif", ".bat", ".cmd",
             ".ps1", ".vbs", ".js", ".jse", ".wsf", ".hta", ".msi", ".jar",
             ".sh", ".elf", ".bin"}
DOC_EXTS = {".doc", ".docx", ".xls", ".xlsx", ".pdf", ".rtf", ".ppt", ".pptx",
            ".txt", ".jpg", ".png", ".gif", ".zip"}
SUSPICIOUS_DIRS = ("temp", "tmp", "appdata\\local\\temp", "downloads",
                   "public", "programdata", "perflogs", "$recycle.bin",
                   "/tmp", "/var/tmp", "/dev/shm")
MAX_HASH_SIZE = 200 * 1024 * 1024  # skip hashing files >200MB


def iso(ts):
    try:
        return datetime.fromtimestamp(ts, tz=timezone.utc).strftime(
            "%Y-%m-%d %H:%M:%S")
    except (OSError, OverflowError, ValueError):
        return ""


def hash_file(path, want_md5):
    sha = hashlib.sha256()
    md5 = hashlib.md5() if want_md5 else None
    try:
        with open(path, "rb") as fh:
            while chunk := fh.read(1024 * 1024):
                sha.update(chunk)
                if md5:
                    md5.update(chunk)
    except (OSError, PermissionError):
        return "", ""
    return sha.hexdigest(), (md5.hexdigest() if md5 else "")


def flags_for(path, st, cutoff):
    p = str(path).lower()
    name = path.name.lower()
    ext = path.suffix.lower()
    flags = []

    if ext in EXEC_EXTS:
        if any(d in p for d in SUSPICIOUS_DIRS):
            flags.append("exec-in-susp-dir")
        if st.st_mtime >= cutoff:
            flags.append("recent-exec")
    parts = name.split(".")
    if len(parts) >= 3 and f".{parts[-1]}" in EXEC_EXTS \
            and f".{parts[-2]}" in DOC_EXTS:
        flags.append("double-extension")
    if name.startswith(".") and ext in EXEC_EXTS:
        flags.append("hidden-exec")
    if st.st_size == 0 and ext in EXEC_EXTS:
        flags.append("zero-byte-exec")
    if os.name != "nt" and stat.S_ISREG(st.st_mode) and \
            (st.st_mode & (stat.S_ISUID | stat.S_ISGID)):
        flags.append("setuid-setgid")
    return sorted(set(flags))


def walk(root, args):
    cutoff = time.time() - args.days * 86400
    for dirpath, dirnames, filenames in os.walk(root, onerror=lambda e: None):
        # don't descend into other filesystems' mountpoints accidentally
        for fname in filenames:
            fpath = Path(dirpath) / fname
            try:
                st = fpath.lstat()
            except OSError:
                continue
            if not stat.S_ISREG(st.st_mode):
                continue
            flags = flags_for(fpath, st, cutoff)
            if args.flagged_only and not flags:
                continue
            sha256 = md5 = ""
            if not args.no_hash and st.st_size <= MAX_HASH_SIZE:
                sha256, md5 = hash_file(fpath, args.md5)
            yield {
                "path": str(fpath),
                "size": st.st_size,
                "modified": iso(st.st_mtime),
                "accessed": iso(st.st_atime),
                "changed": iso(st.st_ctime),
                "sha256": sha256,
                "md5": md5,
                "flags": ",".join(flags),
                "_st": st,
            }


def main():
    ap = argparse.ArgumentParser(description="File hashing + timeline triage")
    ap.add_argument("root", help="directory to walk")
    ap.add_argument("-o", "--output", help="output file (CSV or bodyfile)")
    ap.add_argument("--days", type=int, default=14,
                    help="window for 'recent' flag (default 14)")
    ap.add_argument("--md5", action="store_true", help="also compute MD5")
    ap.add_argument("--no-hash", action="store_true", help="skip hashing")
    ap.add_argument("--flagged-only", action="store_true",
                    help="only output flagged files")
    ap.add_argument("--bodyfile", action="store_true",
                    help="mactime bodyfile format instead of CSV")
    args = ap.parse_args()

    root = Path(args.root)
    if not root.is_dir():
        sys.exit(f"not a directory: {root}")

    out = open(args.output, "w", newline="", encoding="utf-8") \
        if args.output else sys.stdout
    count = flagged = 0
    try:
        if args.bodyfile:
            for row in walk(root, args):
                st = row["_st"]
                # md5|name|inode|mode|uid|gid|size|atime|mtime|ctime|crtime
                out.write("|".join(str(x) for x in (
                    row["md5"] or row["sha256"] or "0", row["path"],
                    st.st_ino, oct(st.st_mode), st.st_uid, st.st_gid,
                    st.st_size, int(st.st_atime), int(st.st_mtime),
                    int(st.st_ctime), 0)) + "\n")
                count += 1
                flagged += bool(row["flags"])
        else:
            writer = csv.DictWriter(out, fieldnames=[
                "modified", "accessed", "changed", "size", "sha256", "md5",
                "flags", "path"], extrasaction="ignore")
            writer.writeheader()
            for row in walk(root, args):
                writer.writerow(row)
                count += 1
                flagged += bool(row["flags"])
    finally:
        if out is not sys.stdout:
            out.close()

    print(f"[+] {count} files processed, {flagged} flagged", file=sys.stderr)


if __name__ == "__main__":
    main()
