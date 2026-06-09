<#
.SYNOPSIS
    Hunt for suspicious files on a live Windows system or mounted image.

.DESCRIPTION
    Read-only sweep that flags:
      - Executables in Temp/Downloads/ProgramData/Public/Recycle Bin
      - Double extensions (invoice.pdf.exe)
      - Alternate Data Streams with content
      - Unsigned executables in autostart-adjacent locations
      - Executables created within the lookback window

.PARAMETER Path
    Root path(s) to scan. Defaults to common user/system staging dirs.

.PARAMETER Days
    Creation-time lookback for "recent" flag. Default 14.

.PARAMETER OutputPath
    Optional CSV output path.

.EXAMPLE
    .\Find-SuspiciousFiles.ps1 -Days 30 -OutputPath sweep.csv

.NOTES
    Read-only; makes no system changes. Run elevated for full coverage.
#>
[CmdletBinding()]
param(
    [string[]]$Path,
    [int]$Days = 14,
    [string]$OutputPath
)

$execExt = '.exe', '.dll', '.scr', '.com', '.pif', '.bat', '.cmd', '.ps1',
           '.vbs', '.js', '.jse', '.wsf', '.hta', '.msi', '.jar'
$docExt = '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.txt', '.jpg', '.png', '.zip'
$cutoff = (Get-Date).AddDays(-$Days)

if (-not $Path) {
    $Path = @(
        "$env:SystemDrive\Users\*\AppData\Local\Temp"
        "$env:SystemDrive\Users\*\Downloads"
        "$env:SystemDrive\Users\Public"
        "$env:ProgramData"
        "$env:SystemRoot\Temp"
        "$env:SystemDrive\PerfLogs"
        "$env:SystemDrive\`$Recycle.Bin"
    ) | Where-Object { Test-Path $_ }
}

$findings = New-Object System.Collections.Generic.List[object]

function Add-Finding {
    param($File, $Reason, $Severity = 'MEDIUM')
    $hash = try { (Get-FileHash -Path $File.FullName -Algorithm SHA256 -ErrorAction Stop).Hash } catch { '' }
    $findings.Add([pscustomobject]@{
        Severity = $Severity
        Reason   = $Reason
        Path     = $File.FullName
        SizeKB   = [math]::Round($File.Length / 1KB, 1)
        Created  = $File.CreationTime
        Modified = $File.LastWriteTime
        SHA256   = $hash
    })
}

foreach ($root in $Path) {
    Write-Verbose "Scanning $root"
    $files = Get-ChildItem -Path $root -Recurse -File -Force -ErrorAction SilentlyContinue

    foreach ($f in $files) {
        $ext = $f.Extension.ToLower()
        $isExec = $execExt -contains $ext

        # Executable in staging directory
        if ($isExec) {
            $sev = if ($f.CreationTime -ge $cutoff) { 'HIGH' } else { 'MEDIUM' }
            Add-Finding $f 'Executable in staging directory' $sev
        }

        # Double extension
        $parts = $f.Name.ToLower().Split('.')
        if ($parts.Count -ge 3 -and $isExec -and $docExt -contains ".$($parts[-2])") {
            Add-Finding $f 'Double extension' 'HIGH'
        }

        # Alternate Data Streams (skip Zone.Identifier noise)
        $ads = Get-Item -Path $f.FullName -Stream * -ErrorAction SilentlyContinue |
            Where-Object { $_.Stream -notin ':$DATA', 'Zone.Identifier' -and $_.Length -gt 0 }
        foreach ($s in $ads) {
            Add-Finding $f "ADS with content: $($s.Stream) ($($s.Length) bytes)" 'HIGH'
        }
    }
}

# Signature check on flagged PE files (live systems only)
foreach ($fnd in $findings | Where-Object { $_.Path -match '\.(exe|dll|sys)$' }) {
    try {
        $sig = Get-AuthenticodeSignature -FilePath $fnd.Path -ErrorAction Stop
        if ($sig.Status -ne 'Valid') {
            $fnd.Reason += " | unsigned/invalid signature ($($sig.Status))"
            $fnd.Severity = 'HIGH'
        }
    } catch { }
}

$sorted = $findings | Sort-Object @{Expression = { if ($_.Severity -eq 'HIGH') { 0 } else { 1 } } }, Created -Descending

if ($OutputPath) {
    $sorted | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
    Write-Host "[+] $($sorted.Count) findings -> $OutputPath"
}
else {
    $sorted | Format-Table Severity, Reason, Path, Created -AutoSize -Wrap
    Write-Host "[+] $($sorted.Count) findings"
}
