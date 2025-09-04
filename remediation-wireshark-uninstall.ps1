<#
.SYNOPSIS
  Uninstall Wireshark on Windows 11 (optionally Npcap/USBPcap) with silent flags.

.DESCRIPTION
  - Scans HKLM/HKCU uninstall keys (32/64-bit views) for Wireshark, Npcap, USBPcap.
  - Stops running capture processes to avoid file/driver locks.
  - Prefers QuietUninstallString; falls back to UninstallString.
  - Adds appropriate silent flags (MSI: /qn /norestart; NSIS: /S; Inno Setup: /VERYSILENT /SUPPRESSMSGBOXES /NORESTART).
  - Optional: remove Npcap/USBPcap; purge user config/cache.

.PARAMETERS
  -IncludeNpcap     : Also remove Npcap/WinPcap (default: $false)
  -IncludeUSBPcap   : Also remove USBPcap (default: $false)
  -PurgeProfiles    : Delete %APPDATA%/%LOCALAPPDATA%/ProgramData Wireshark dirs (default: $false)
  -DryRun           : Show what would run without executing (default: $false)

.EXAMPLES
  .\Uninstall-Wireshark.ps1
  .\Uninstall-Wireshark.ps1 -IncludeNpcap -IncludeUSBPcap -PurgeProfiles
  .\Uninstall-Wireshark.ps1 -DryRun
#>

[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [switch]$IncludeNpcap,
    [switch]$IncludeUSBPcap,
    [switch]$PurgeProfiles,
    [switch]$DryRun
)

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-UninstallEntries {
    param(
        [Parameter(Mandatory)][string]$NamePattern # regex
    )
    $roots = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
    )
    foreach ($root in $roots) {
        if (Test-Path $root) {
            Get-ChildItem $root -ErrorAction SilentlyContinue | ForEach-Object {
                try {
                    $p = Get-ItemProperty $_.PsPath -ErrorAction Stop
                    if ($p.DisplayName -and ($p.DisplayName -match $NamePattern)) {
                        [PSCustomObject]@{
                            DisplayName        = $p.DisplayName
                            DisplayVersion     = $p.DisplayVersion
                            Publisher          = $p.Publisher
                            QuietUninstall     = $p.QuietUninstallString
                            UninstallString    = $p.UninstallString
                            InstallLocation    = $p.InstallLocation
                            PsPath             = $_.PsPath
                        }
                    }
                } catch { }
            }
        }
    }
}

function Stop-WiresharkProcesses {
    $names = @('Wireshark','tshark','dumpcap','capinfos','rawshark')
    foreach ($n in $names) {
        try { Get-Process -Name $n -ErrorAction Stop | Stop-Process -Force } catch {}
    }
    Start-Sleep -Milliseconds 300
}

function Split-Command {
    param([Parameter(Mandatory)][string]$CommandLine)
    $s = $CommandLine.Trim()
    if ($s.StartsWith('"')) {
        $end = $s.IndexOf('"',1)
        if ($end -gt 0) {
            return [PSCustomObject]@{
                Exe  = $s.Substring(1, $end-1)
                Args = $s.Substring($end+1).Trim()
            }
        }
    }
    $parts = $s -split '\s+', 2
    [PSCustomObject]@{
        Exe  = $parts[0]
        Args = if ($parts.Count -gt 1) { $parts[1].Trim() } else { '' }
    }
}

function Add-SilentFlags {
    param(
        [Parameter(Mandatory)][string]$Exe,
        [Parameter(Mandatory)][string]$Args
    )
    $exeName = [IO.Path]::GetFileName($Exe)

    # MSI
    if ($Exe -match '(?i)\\?msiexec(\.exe)?$') {
        if ($Args -notmatch '(?i)\s/q[nrby]?\b') { $Args += ' /qn' }
        if ($Args -notmatch '(?i)\s/norestart\b') { $Args += ' /norestart' }
        return $Args.Trim()
    }

    # Inno Setup typical unins*.exe
    if ($exeName -match '(?i)^unins.*\.exe$') {
        if ($Args -notmatch '(?i)\b/VERYSILENT\b') { $Args += ' /VERYSILENT' }
        if ($Args -notmatch '(?i)\b/SUPPRESSMSGBOXES\b') { $Args += ' /SUPPRESSMSGBOXES' }
        if ($Args -notmatch '(?i)\b/NORESTART\b') { $Args += ' /NORESTART' }
        return $Args.Trim()
    }

    # NSIS / generic EXE (Wireshark often uses NSIS-style uninstallers)
    if ($Args -notmatch '(^|[\s])(/S|-s|-silent)(\s|$)') { $Args += ' /S' }
    return $Args.Trim()
}

function Invoke-Uninstall {
    param(
        [Parameter(Mandatory)][string]$UninstallString,
        [switch]$DryRun
    )

    $cmd = Split-Command -CommandLine $UninstallString
    $exe = $cmd.Exe
    $args = $cmd.Args

    # Add silent flags if not already present
    $args = Add-SilentFlags -Exe $exe -Args $args

    if ($DryRun) {
        return [PSCustomObject]@{ Executable=$exe; Arguments=$args; ExitCode=$null; Started=$false }
    }

    $p = Start-Process -FilePath $exe -ArgumentList $args -Wait -PassThru -ErrorAction SilentlyContinue
    [PSCustomObject]@{ Executable=$exe; Arguments=$args; ExitCode=$p.ExitCode; Started=$true }
}

if (-not (Test-Admin)) {
    Write-Warning "Tip: Run PowerShell as Administrator. Driver removals (Npcap/USBPcap) require admin."
}

Write-Host "Scanning for Wireshark..." -ForegroundColor Cyan
$targets = @()

# Always target Wireshark
$targets += Get-UninstallEntries -NamePattern '^(?i)Wireshark'

# Optional drivers/tools
if ($IncludeNpcap)   { $targets += Get-UninstallEntries -NamePattern '^(?i)(Npcap|WinPcap|Npcap OEM)' }
if ($IncludeUSBPcap) { $targets += Get-UninstallEntries -NamePattern '^(?i)USBPcap' }

if (-not $targets) {
    Write-Host "No matching products found." -ForegroundColor Yellow
    return
}

# De-dupe by UninstallString
$targets = $targets | Sort-Object UninstallString -Unique

# Show plan
$targets | ForEach-Object {
    "{0}  (v{1})" -f $_.DisplayName, ($_.DisplayVersion ?? 'unknown')
} | Write-Output

# Stop Wireshark-related processes
Stop-WiresharkProcesses

# Uninstall loop
$results = @()
foreach ($t in $targets) {
    $cmdLine = $t.QuietUninstall
    if (-not $cmdLine) { $cmdLine = $t.UninstallString }
    if (-not $cmdLine) {
        $results += [PSCustomObject]@{
            DisplayName=$t.DisplayName; DisplayVersion=$t.DisplayVersion
            Method='No UninstallString'; Success=$false; ExitCode=$null; Detail=$t.PsPath
        }
        continue
    }

    if ($PSCmdlet.ShouldProcess($t.DisplayName, "Uninstall")) {
        $r = Invoke-Uninstall -UninstallString $cmdLine -DryRun:$DryRun
        $ok = ($r.Started -and ($r.ExitCode -eq 0 -or $null -eq $r.ExitCode)) -or $DryRun
        $results += [PSCustomObject]@{
            DisplayName=$t.DisplayName; DisplayVersion=$t.DisplayVersion
            Method=("$($r.Executable) $($r.Arguments)").Trim()
            Success=$ok; ExitCode=$r.ExitCode; Detail=$t.PsPath
        }
    }
}

# Optional profile/config purge
if ($PurgeProfiles) {
    Write-Host "Purging Wireshark profiles & config..." -ForegroundColor Cyan
    $paths = @(
        "$env:APPDATA\Wireshark",
        "$env:LOCALAPPDATA\Wireshark",
        "$env:ProgramData\Wireshark"
    ) | Where-Object { $_ -and (Test-Path $_) }

    foreach ($p in $paths) {
        if ($DryRun) {
            Write-Output "Would remove: $p"
        } else {
            try { Remove-Item -Path $p -Recurse -Force -ErrorAction Stop } catch { }
        }
    }
}

# Summary (table + objects for pipeline)
$results | Format-Table DisplayName, DisplayVersion, Success, ExitCode, Method -AutoSize
$results

## SHORT VERSION##

How to run

Save as Uninstall-Wireshark.ps1.

Open PowerShell as Administrator.

Execute: 

Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\Uninstall-Wireshark.ps1
