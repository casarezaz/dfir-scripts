<#
.SYNOPSIS
    Collect volatile triage data from a live Windows host.

.DESCRIPTION
    Read-only live response collection: processes (with hashes and command
    lines), network connections, services, scheduled tasks, autoruns (registry
    run keys + startup folders), local users/groups, logon sessions, DNS cache,
    SMB shares/sessions, and recent PowerShell history. Everything is written
    to a timestamped folder and zipped for transport.

.PARAMETER OutputRoot
    Where to create the collection folder. Default: current directory.

.EXAMPLE
    .\Invoke-LiveResponse.ps1 -OutputRoot D:\collections

.NOTES
    Run elevated. Read-only: collects data, changes nothing.
    Order follows volatility: network/process state first.
#>
[CmdletBinding()]
param(
    [string]$OutputRoot = (Get-Location).Path
)

$hostname = $env:COMPUTERNAME
$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$dir = Join-Path $OutputRoot "LR_${hostname}_${stamp}"
New-Item -ItemType Directory -Path $dir -Force | Out-Null

function Save {
    param([string]$Name, [scriptblock]$Block)
    Write-Host "[*] $Name"
    try {
        & $Block | Export-Csv -Path (Join-Path $dir "$Name.csv") -NoTypeInformation -Encoding UTF8
    }
    catch {
        ($_ | Out-String) | Set-Content -Path (Join-Path $dir "$Name.ERROR.txt")
        Write-Warning "  failed: $($_.Exception.Message)"
    }
}

# --- Most volatile first ---

Save 'network_connections' {
    Get-NetTCPConnection | ForEach-Object {
        $p = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
        [pscustomobject]@{
            State = $_.State; Local = "$($_.LocalAddress):$($_.LocalPort)"
            Remote = "$($_.RemoteAddress):$($_.RemotePort)"
            PID = $_.OwningProcess; Process = $p.Name; Path = $p.Path
        }
    }
}

Save 'udp_endpoints' {
    Get-NetUDPEndpoint | Select-Object LocalAddress, LocalPort, OwningProcess
}

Save 'processes' {
    Get-CimInstance Win32_Process | ForEach-Object {
        $hash = if ($_.ExecutablePath) {
            try { (Get-FileHash $_.ExecutablePath -Algorithm SHA256 -ErrorAction Stop).Hash } catch { '' }
        } else { '' }
        [pscustomobject]@{
            PID = $_.ProcessId; PPID = $_.ParentProcessId; Name = $_.Name
            Path = $_.ExecutablePath; CommandLine = $_.CommandLine
            Created = $_.CreationDate; SHA256 = $hash
        }
    }
}

Save 'dns_cache' { Get-DnsClientCache | Select-Object Entry, Name, Data, TimeToLive }

Save 'logon_sessions' {
    Get-CimInstance Win32_LogonSession | Select-Object LogonId, LogonType, StartTime, AuthenticationPackage
}

Save 'smb_sessions' { Get-SmbSession -ErrorAction SilentlyContinue | Select-Object ClientComputerName, ClientUserName, NumOpens }
Save 'smb_shares'   { Get-SmbShare | Select-Object Name, Path, Description }

# --- Persistence surfaces ---

Save 'services' {
    Get-CimInstance Win32_Service | Select-Object Name, DisplayName, State, StartMode, PathName, StartName
}

Save 'scheduled_tasks' {
    Get-ScheduledTask | ForEach-Object {
        [pscustomobject]@{
            TaskName = $_.TaskName; Path = $_.TaskPath; State = $_.State
            Author = $_.Author
            Action = ($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join '; '
        }
    }
}

Save 'autoruns_registry' {
    $keys = @(
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run'
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
        'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run'
    )
    foreach ($k in $keys) {
        if (Test-Path $k) {
            $props = Get-ItemProperty -Path $k
            $props.PSObject.Properties |
                Where-Object { $_.Name -notmatch '^PS(Path|ParentPath|ChildName|Provider|Drive)$' } |
                ForEach-Object { [pscustomobject]@{ Key = $k; Name = $_.Name; Value = $_.Value } }
        }
    }
}

Save 'startup_folder' {
    $paths = @(
        "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
    )
    Get-ChildItem -Path $paths -Force -ErrorAction SilentlyContinue |
        Select-Object FullName, CreationTime, LastWriteTime, Length
}

Save 'local_users' {
    Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordLastSet, SID
}

Save 'local_admins' {
    Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue |
        Select-Object Name, PrincipalSource, ObjectClass
}

# --- History / misc ---

Write-Host "[*] powershell_history"
$psHistory = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
if (Test-Path $psHistory) {
    Copy-Item $psHistory (Join-Path $dir 'powershell_history.txt')
}

Write-Host "[*] system_info"
@(
    "Hostname : $hostname"
    "Collected: $(Get-Date -Format o)"
    "User     : $env:USERNAME"
    "OS       : $((Get-CimInstance Win32_OperatingSystem).Caption)"
    "Boot     : $((Get-CimInstance Win32_OperatingSystem).LastBootUpTime)"
    "TimeZone : $((Get-TimeZone).Id)"
) | Set-Content (Join-Path $dir 'system_info.txt')

# --- Package up ---
$zip = "$dir.zip"
Compress-Archive -Path $dir -DestinationPath $zip -Force
$sha = (Get-FileHash $zip -Algorithm SHA256).Hash
"$sha  $(Split-Path $zip -Leaf)" | Set-Content "$zip.sha256"

Write-Host "`n[+] Collection complete: $zip"
Write-Host "[+] SHA256: $sha"
