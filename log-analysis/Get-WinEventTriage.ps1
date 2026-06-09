<#
.SYNOPSIS
    Triage live Windows event logs for high-value DFIR events.

.DESCRIPTION
    Queries Security, System, and PowerShell operational logs for events
    commonly tied to intrusion activity (account creation, service installs,
    scheduled tasks, log clearing, suspicious logons) within a lookback window.

.PARAMETER Hours
    Lookback window in hours. Default 24.

.PARAMETER OutputPath
    Optional CSV output path.

.EXAMPLE
    .\Get-WinEventTriage.ps1 -Hours 72 -OutputPath triage.csv

.NOTES
    Run elevated for Security log access. Read-only; makes no system changes.
#>
[CmdletBinding()]
param(
    [int]$Hours = 24,
    [string]$OutputPath
)

$start = (Get-Date).AddHours(-$Hours)
$results = New-Object System.Collections.Generic.List[object]

$queries = @(
    @{ Log = 'Security'; Ids = 1102, 4625, 4648, 4672, 4697, 4698, 4702, 4720, 4722, 4724, 4728, 4732, 4756; Sev = @{
        1102 = 'HIGH'; 4697 = 'HIGH'; 4698 = 'HIGH'; 4720 = 'HIGH'; 4728 = 'HIGH'; 4732 = 'HIGH'; 4756 = 'HIGH'
        4625 = 'MEDIUM'; 4648 = 'MEDIUM'; 4702 = 'MEDIUM'; 4722 = 'MEDIUM'; 4724 = 'MEDIUM'; 4672 = 'INFO' } }
    @{ Log = 'System'; Ids = 7045, 7030, 6005, 6006; Sev = @{ 7045 = 'HIGH'; 7030 = 'MEDIUM'; 6005 = 'INFO'; 6006 = 'INFO' } }
    @{ Log = 'Microsoft-Windows-PowerShell/Operational'; Ids = 4104; Sev = @{ 4104 = 'MEDIUM' } }
)

$suspiciousScript = '-enc|downloadstring|iex\s*\(|invoke-expression|bypass|mimikatz|frombase64string'

foreach ($q in $queries) {
    try {
        $events = Get-WinEvent -FilterHashtable @{
            LogName = $q.Log; Id = $q.Ids; StartTime = $start
        } -ErrorAction Stop
    }
    catch [Exception] {
        if ($_.Exception.Message -match 'No events were found') { continue }
        Write-Warning "Cannot read $($q.Log): $($_.Exception.Message)"
        continue
    }

    foreach ($e in $events) {
        $sev = $q.Sev[$e.Id]
        $msg = ($e.Message -split "`n")[0].Trim()

        # PowerShell script blocks: only keep ones matching suspicious patterns
        if ($e.Id -eq 4104) {
            if ($e.Message -notmatch $suspiciousScript) { continue }
            $sev = 'HIGH'
            $msg = ($e.Message | Select-String -Pattern $suspiciousScript -AllMatches).Matches.Value -join ', '
            $msg = "Suspicious script block: $msg"
        }

        $results.Add([pscustomobject]@{
            TimeCreated = $e.TimeCreated
            Log         = $q.Log
            EventID     = $e.Id
            Severity    = $sev
            Computer    = $e.MachineName
            Summary     = $msg.Substring(0, [Math]::Min(200, $msg.Length))
        })
    }
}

# Failed logon burst detection (possible brute force)
$failed = $results | Where-Object EventID -eq 4625
if ($failed.Count -ge 10) {
    $results.Add([pscustomobject]@{
        TimeCreated = Get-Date
        Log         = 'Analysis'
        EventID     = 0
        Severity    = 'HIGH'
        Computer    = $env:COMPUTERNAME
        Summary     = "ALERT: $($failed.Count) failed logons in window - possible brute force"
    })
}

$sorted = $results | Sort-Object @{Expression = { switch ($_.Severity) { 'HIGH' { 0 } 'MEDIUM' { 1 } default { 2 } } } }, TimeCreated

if ($OutputPath) {
    $sorted | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
    Write-Host "[+] $($sorted.Count) findings -> $OutputPath"
}
else {
    $sorted | Format-Table -AutoSize -Wrap
    Write-Host "[+] $($sorted.Count) findings in last $Hours hour(s)"
}
