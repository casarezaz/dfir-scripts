# dfir-scripts

A collection of digital forensics and incident response (DFIR) triage scripts. Python scripts are cross-platform and dependency-light; PowerShell scripts target live Windows hosts and are strictly read-only.

## Layout

```
log-analysis/      Event log and auth log triage
ioc-tools/         IOC extraction and enrichment
disk-forensics/    File hashing, timelines, suspicious file hunting
memory-network/    Memory image triage, beacon detection, live response
```

## Scripts

### log-analysis

**windows_evtx_triage.py** — Parses `.evtx` files (needs `python-evtx`) or JSONL exports and flags high-value events: log clearing (1102), account creation (4720), service installs (4697/7045), scheduled tasks (4698), group changes, and process creation / PowerShell script blocks matching suspicious patterns (encoded commands, download cradles, credential theft tooling, shadow copy deletion).

```
python windows_evtx_triage.py Security.evtx -o findings.csv
```

**linux_auth_triage.py** — Parses `auth.log`/`secure` for SSH brute force, password spraying, logins from brute-forcing IPs (highest-priority alert), sudo usage, and account/group changes.

```
python linux_auth_triage.py /var/log/auth.log --threshold 10
zcat auth.log.2.gz | python linux_auth_triage.py -
```

**Get-WinEventTriage.ps1** — Live equivalent of the evtx triage for Windows hosts. Queries Security/System/PowerShell logs over a lookback window, flags suspicious script blocks, and detects failed-logon bursts.

```powershell
.\Get-WinEventTriage.ps1 -Hours 72 -OutputPath triage.csv
```

### ioc-tools

**ioc_extractor.py** — Extracts IPs, domains, URLs, emails, and MD5/SHA1/SHA256 hashes from any text. Refangs defanged input (`hxxp`, `[.]`, `[at]`), dedupes, filters noise, and can re-defang output for safe sharing. Optional enrichment via VirusTotal (`VT_API_KEY`) and AbuseIPDB (`ABUSEIPDB_API_KEY`).

```
python ioc_extractor.py threat_report.txt --defang -o iocs.csv
python ioc_extractor.py report.txt --enrich --json
```

### disk-forensics

**file_timeline.py** — Walks a directory tree, hashes files (SHA256, optional MD5), and emits a CSV timeline or mactime bodyfile. Flags executables in staging dirs, double extensions, recently modified binaries, hidden executables, and setuid/setgid files.

```
python file_timeline.py /mnt/evidence -o timeline.csv --flagged-only
python file_timeline.py /mnt/evidence --bodyfile -o body.txt   # for mactime
```

**Find-SuspiciousFiles.ps1** — Live Windows sweep of common staging directories (Temp, Downloads, ProgramData, Public, Recycle Bin) for executables, double extensions, alternate data streams with content, and unsigned binaries.

```powershell
.\Find-SuspiciousFiles.ps1 -Days 30 -OutputPath sweep.csv
```

### memory-network

**vol3_triage.py** — Volatility 3 wrapper (needs `vol` on PATH) that runs a curated plugin set per OS, saves every output, and writes a `TRIAGE_SUMMARY.txt` of automatic red flags: PIDs visible to psscan but not pslist, malfind RWX regions, odd parent/child pairs, and connections on commonly abused ports.

```
python vol3_triage.py memory.raw -d vol_output/
python vol3_triage.py memory.lime --os linux -d out/
```

**pcap_beacon_detector.py** — Detects C2-style beaconing in `.pcap`/`.pcapng` (needs `scapy`) or Zeek `conn.log` (TSV or JSON). Scores conversations 0–100 on interval regularity, payload size consistency, and session count.

```
python pcap_beacon_detector.py capture.pcap
python pcap_beacon_detector.py conn.log --min-sessions 8 -o beacons.csv
```

**Invoke-LiveResponse.ps1** — Read-only volatile data collection from a live Windows host, ordered by volatility: network connections (with owning process), processes (with SHA256 + command lines), DNS cache, logon/SMB sessions, services, scheduled tasks, registry autoruns, startup folders, local users/admins, and PowerShell history. Output is zipped with a SHA256 manifest for chain of custody.

```powershell
.\Invoke-LiveResponse.ps1 -OutputRoot D:\collections
```

## Install

```
pip install -r requirements.txt   # optional deps: python-evtx, scapy, volatility3
```

Core functionality of every Python script works with the standard library alone; the optional packages enable `.evtx` parsing, pcap parsing, and memory analysis respectively.

## Notes

- PowerShell scripts are read-only and make no system changes. Run elevated for full coverage.
- These are triage tools meant to point investigators at what to look at first — not a replacement for full forensic analysis.
- Test in a lab before relying on output in a real engagement.

## License

MIT
