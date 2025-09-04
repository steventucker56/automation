<#
.SYNOPSIS
    Toggles guest account Administrators group membership (add vs remove) on the system (Windows 10).
    Please test thoroughly in a non-production environment before deploying widely.
    Run as Administrator.

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
    Set [$AddGuestToAdminGroup = $False] to secure the system
    Example syntax:
    PS C:\> .\toggle-guest-local-administrators.ps1
#>

# Define the variable to control the action: $True to add the guest account, $False to remove it
$AddGuestToAdminGroup = $False

# Define the local group and user account
$LocalAdminGroup = "Administrators"
$GuestAccount    = "Guest"

# Function to add the guest account to the Administrators group
function Add-GuestToAdminGroup {
    if (-not (Get-LocalGroupMember -Group $LocalAdminGroup -Member $GuestAccount -ErrorAction SilentlyContinue)) {
        Add-LocalGroupMember -Group $LocalAdminGroup -Member $GuestAccount
        Write-Output "Guest account has been added to the Administrators group."
    } else {
        Write-Output "Guest account is already a member of the Administrators group."
    }
}

# Function to remove the guest account from the Administrators group
function Remove-GuestFromAdminGroup {
    if (Get-LocalGroupMember -Group $LocalAdminGroup -Member $GuestAccount -ErrorAction SilentlyContinue) {
        Remove-LocalGroupMember -Group $LocalAdminGroup -Member $GuestAccount
        Write-Output "Guest account has been removed from the Administrators group."
    } else {
        Write-Output "Guest account is not a member of the Administrators group."
    }
}

# Check the variable and perform the appropriate action
if ($AddGuestToAdminGroup -eq $True) {
    Add-GuestToAdminGroup
} else {
    Remove-GuestFromAdminGroup
}
