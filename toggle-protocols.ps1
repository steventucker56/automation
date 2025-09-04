<#
.SYNOPSIS
    Toggle cryptographic protocols (secure vs. insecure) on Windows 10 by setting SCHANNEL registry keys.
    In "secure" mode: disables SSL 2.0/3.0 and TLS 1.0/1.1, enables TLS 1.2. Run in an elevated PowerShell session.

.NOTES
    Author        : Steven Tucker
    Date Created  : 2025-09-04
    Last Modified : 2025-09-04
    Version       : 1.0

.TESTED ON
    Date(s) Tested  : 2025-09-04
    Tested By       : Steven Tucker
    Systems Tested  : Windows 10 Pro 22H2 (Build 19045)
    PowerShell Ver. : 5.1

.USAGE
    Set [$makeSecure = $true] to secure the system (recommended).
    Example:
      PS C:\> .\toggle-protocols.ps1
#>

# --- Configuration ---
# $true  = secure posture (disable SSL 2.0/3.0, TLS 1.0/1.1; enable TLS 1.2)
# $false = insecure posture (enable SSL 2.0/3.0, TLS 1.0/1.1; disable TLS 1.2)
$makeSecure = $true

# --- Admin check ---
function Check-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $pr = New-Object Security.Principal.WindowsPrincipal($id)
    return $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Check-Admin)) {
    Write-Error "Access Denied. Please run with Administrator privileges."
    exit 1
}

# --- Helper: ensure a path exists ---
function Ensure-Key {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }
}

# --- Helper: set Server/Client values for a protocol ---
function Set-ProtocolState {
    param(
        [Parameter(Mandatory)][string]$ProtocolName,
        [Parameter(Mandatory)][bool]$Enable # true = Enabled=1/DisabledByDefault=0 ; false = Enabled=0/DisabledByDefault=1
    )

    $server = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$ProtocolName\Server"
    $client = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$ProtocolName\Client"

    foreach ($p in @($server,$client)) {
        Ensure-Key -Path $p
        if ($Enable) {
            New-ItemProperty -Path $p -Name 'Enabled' -Value 1 -PropertyType DWord -Force | Out-Null
            New-ItemProperty -Path $p -Name 'DisabledByDefault' -Value 0 -PropertyType DWord -Force | Out-Null
        } else {
            New-ItemProperty -Path $p -Name 'Enabled' -Value 0 -PropertyType DWord -Force | Out-Null
            New-ItemProperty -Path $p -Name 'DisabledByDefault' -Value 1 -PropertyType DWord -Force | Out-Null
        }
    }
}

# --- Apply settings ---
if ($makeSecure) {
    Write-Host "Applying SECURE protocol configuration..." -ForegroundColor Cyan
    # Disable legacy/insecure
    Set-ProtocolState -ProtocolName 'SSL 2.0' -Enable:$false
    Write-Host "SSL 2.0 has been disabled."
    Set-ProtocolState -ProtocolName 'SSL 3.0' -Enable:$false
    Write-Host "SSL 3.0 has been disabled."
    Set-ProtocolState -ProtocolName 'TLS 1.0' -Enable:$false
    Write-Host "TLS 1.0 has been disabled."
    Set-ProtocolState -ProtocolName 'TLS 1.1' -Enable:$false
    Write-Host "TLS 1.1 has been disabled."

    # Enable modern
    Set-ProtocolState -ProtocolName 'TLS 1.2' -Enable:$true
    Write-Host "TLS 1.2 has been enabled."
} else {
    Write-Host "Applying INSECURE protocol configuration..." -ForegroundColor Yellow
    # Enable legacy/insecure
    Set-ProtocolState -ProtocolName 'SSL 2.0' -Enable:$true
    Write-Host "SSL 2.0 has been enabled."
    Set-ProtocolState -ProtocolName 'SSL 3.0' -Enable:$true
    Write-Host "SSL 3.0 has been enabled."
    Set-ProtocolState -ProtocolName 'TLS 1.0' -Enable:$true
    Write-Host "TLS 1.0 has been enabled."
    Set-ProtocolState -ProtocolName 'TLS 1.1' -Enable:$true
    Write-Host "TLS 1.1 has been enabled."

    # Disable modern
    Set-ProtocolState -ProtocolName 'TLS 1.2' -Enable:$false
    Write-Host "TLS 1.2 has been disabled."
}

Write-Host "Please reboot the system for settings to take effect." -ForegroundColor Green
