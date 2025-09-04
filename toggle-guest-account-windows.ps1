<#
.SYNOPSIS
    Toggle the built-in Guest local account (enable/disable) on Windows 10.
    Useful for hardening baselines and lab scenarios. Run in an elevated PowerShell session.

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
    Set [$enableGuestAccount = $false] to secure the system (disable Guest).
    Example:
      PS C:\> .\toggle-guest-account.ps1
#>

# --- Configuration ---
# Set to $true to ENABLE the Guest account, $false to DISABLE it (secure default).
$enableGuestAccount = $false
$guestAccount       = 'Guest'

# --- Helpers ---
function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $pr = New-Object Security.Principal.WindowsPrincipal($id)
    return $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Admin)) {
    Write-Error "Access denied. Please run PowerShell as Administrator."
    exit 1
}

# Ensure LocalAccounts cmdlets are available (Windows 10/Server 2016+)
try {
    Import-Module Microsoft.PowerShell.LocalAccounts -ErrorAction Stop
} catch {
    Write-Error "Required module 'Microsoft.PowerShell.LocalAccounts' not available."
    exit 1
}

# Verify the Guest account exists
try {
    $guest = Get-LocalUser -Name $guestAccount -ErrorAction Stop
} catch {
    Write-Error "Local account '$guestAccount' was not found."
    exit 1
}

function Toggle-GuestAccount {
    param(
        [Parameter(Mandatory)][string]$AccountName,
        [Parameter(Mandatory)][bool]$EnableAccount
    )

    $acct = Get-LocalUser -Name $AccountName
    if ($EnableAccount) {
        if (-not $acct.Enabled) {
            Enable-LocalUser -Name $AccountName
            Write-Output "Guest account has been successfully enabled."
        } else {
            Write-Output "Guest account is already enabled."
        }
    } else {
        if ($acct.Enabled) {
            Disable-LocalUser -Name $AccountName
            Write-Output "Guest account has been successfully disabled."
        } else {
            Write-Output "Guest account is already disabled."
        }
    }

    # Show final state
    ($null = $acct = Get-LocalUser -Name $AccountName)
    Write-Output ("Current state -> Name: {0} | Enabled: {1}" -f $acct.Name, $acct.Enabled)
}

# --- Execute ---
Toggle-GuestAccount -AccountName $guestAccount -EnableAccount $enableGuestAccount
