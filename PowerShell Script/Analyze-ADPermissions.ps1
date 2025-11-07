<#
.SYNOPSIS
    Analyzes Active Directory for potential security misconfigurations related to computer objects
    and domain-join rights. This script is intended for analysis and reporting. Remediation
    should be performed manually by an administrator after careful review.

.DESCRIPTION
    This script performs three main security checks:

    1. Identifies principals (users or groups) with permissions to create computer objects
       in the default 'Computers' container. By default, 'Authenticated Users' can create
       a limited number of computer accounts. This check highlights non-default permissions.

    2. Scans all computer objects for dangerous permissions (e.g., FullControl, WriteDacl, WriteOwner)
       granted to principals other than well-known administrative groups. This can help identify
       over-permissioned computer objects.

    3. Searches for sensitive Access Control Entries (ACEs) on computer objects related to
       LAPS password access ('ms-Mcs-AdmPwd') and Resource-Based Constrained Delegation
       ('msDS-AllowedToActOnBehalfOfOtherIdentity').

.OUTPUTS
    Outputs custom PowerShell objects containing detailed information about each finding.
    Each finding includes a 'Recommendation' field with guidance for manual remediation.

.NOTES
    Author: Krishnaramanan
    Version: 1.0
    Run this script with domain administrator privileges for best results.
    This script requires the Active Directory module for PowerShell.
#>

#Requires -Module ActiveDirectory

[CmdletBinding()]
param()

function Get-ComputerCreationRights {
    Write-Host "[-] Checking for principals with rights to create computer objects..." -ForegroundColor Cyan
    $Domain = Get-ADDomain
    $ComputersContainer = "CN=Computers,$($Domain.DistinguishedName)"
    
    try {
        $Acl = Get-Acl -Path "AD:\$ComputersContainer"
        foreach ($Ace in $Acl.Access) {
            # Guid for 'Create Computer objects'
            $CreateComputerObjectGuid = [System.Guid]"bf967a86-0de6-11d0-a285-00aa003049e2"
            if (
                ($Ace.ActiveDirectoryRights -match "CreateChild") -and
                ($Ace.ObjectType -eq $CreateComputerObjectGuid) -and
                ($Ace.AccessControlType -eq "Allow")
            ) {
                $Principal = Get-ADObject -Identity $Ace.IdentityReference.Value -ErrorAction SilentlyContinue
                if ($Principal) {
                    [PSCustomObject]@{
                        Check           = "Computer Creation Rights"
                        Principal       = $Principal.Name
                        PrincipalType   = $Principal.ObjectClass
                        Container       = $ComputersContainer
                        Risk            = "This principal can create computer accounts in the default Computers container. If unintended, this could lead to unauthorized computer objects being joined to the domain."
                        Recommendation  = "Review the business need for this permission. If not required, remove the 'Create Computer objects' permission for '$($Principal.Name)' on the container '$ComputersContainer'."
                    }
                }
            }
        }
    }
    catch {
        Write-Warning "Could not access ACL for '$ComputersContainer'. Error: $($_.Exception.Message)"
    }
}

function Get-ExcessiveComputerPermissions {
    Write-Host "[-] Scanning computer objects for excessive permissions..." -ForegroundColor Cyan
    $WellKnownAdminSIDs = @(
        "S-1-5-32-544",  # Administrators
        "S-1-5-21-*-512", # Domain Admins (placeholder, will be resolved)
        "S-1-5-21-*-519"  # Enterprise Admins (placeholder, will be resolved)
    )
    
    $DomainSID = (Get-ADDomain).DomainSID.Value
    $ResolvedAdminSIDs = $WellKnownAdminSIDs.ForEach({ $_.Replace("*", $DomainSID) })
    
    $DangerousRights = "GenericAll", "WriteDacl", "WriteOwner"
    
    $Computers = Get-ADComputer -Filter * -Properties nTSecurityDescriptor
    foreach ($Computer in $Computers) {
        $Acl = $Computer.nTSecurityDescriptor
        foreach ($Ace in $Acl.Access) {
            if (
                ($Ace.AccessControlType -eq "Allow") -and
                ($DangerousRights -contains $Ace.ActiveDirectoryRights) -and
                ($ResolvedAdminSIDs -notcontains $Ace.IdentityReference.Value)
            ) {
                $Principal = Get-ADObject -Identity $Ace.IdentityReference.Value -ErrorAction SilentlyContinue
                if ($Principal) {
                    [PSCustomObject]@{
                        Check           = "Excessive Computer Permissions"
                        ComputerName    = $Computer.Name
                        Principal       = $Principal.Name
                        PrincipalType   = $Principal.ObjectClass
                        Permission      = $Ace.ActiveDirectoryRights
                        Risk            = "A non-administrative principal has dangerous rights on this computer object. This could allow the principal to take control of the computer account, change its permissions, or delete it."
                        Recommendation  = "Review the business need for this permission. If not required, remove the ACE granting '$($Ace.ActiveDirectoryRights)' to '$($Principal.Name)' on the computer object '$($Computer.Name)'."
                    }
                }
            }
        }
    }
}

function Get-SensitiveAclOnComputers {
    Write-Host "[-] Searching for sensitive ACEs on computer objects (LAPS, RBCD)..." -ForegroundColor Cyan
    # LAPS Password Read GUID
    $LapsReadGuid = [System.Guid]"1131f6aa-9c07-11d1-f79f-00c04fc2dcd2" # All extended rights
    $LapsPwdGuid = [System.Guid]"c7407360-20bf-11d2-8525-00c04f8faf8a" # ms-Mcs-AdmPwd

    # RBCD GUID
    $RbcdGuid = [System.Guid]"28630ebf-41d3-4121-942a-01a464e76b25" # msDS-AllowedToActOnBehalfOfOtherIdentity
    
    $Computers = Get-ADComputer -Filter * -Properties nTSecurityDescriptor
    foreach ($Computer in $Computers) {
        $Acl = $Computer.nTSecurityDescriptor
        foreach ($Ace in $Acl.Access) {
            if ($Ace.AccessControlType -eq "Allow") {
                $SensitivePermission = $null
                if (($Ace.ObjectType -eq $LapsReadGuid -or $Ace.ActiveDirectoryRights -match "ExtendedRight") -and ($Ace.InheritedObjectType -eq $LapsPwdGuid)) {
                    $SensitivePermission = "Read LAPS Password"
                }
                elseif ($Ace.ObjectType -eq $RbcdGuid) {
                    $SensitivePermission = "AllowedToActOnBehalfOfOtherIdentity (RBCD)"
                }

                if ($SensitivePermission) {
                    $Principal = Get-ADObject -Identity $Ace.IdentityReference.Value -ErrorAction SilentlyContinue
                    if ($Principal) {
                        [PSCustomObject]@{
                            Check           = "Sensitive ACE Detected"
                            ComputerName    = $Computer.Name
                            Principal       = $Principal.Name
                            PrincipalType   = $Principal.ObjectClass
                            Permission      = $SensitivePermission
                            Risk            = "A principal has been granted sensitive rights. '$SensitivePermission' can be abused to compromise the computer or other resources."
                            Recommendation  = "Ensure that '$($Principal.Name)' is authorized to have the '$SensitivePermission' right on '$($Computer.Name)'. If not, remove the permission."
                        }
                    }
                }
            }
        }
    }
}

# --- Main Execution ---
Write-Host "Starting Active Directory Security Analysis..." -ForegroundColor Green

$Findings = @()
$Findings += Get-ComputerCreationRights
$Findings += Get-ExcessiveComputerPermissions
$Findings += Get-SensitiveAclOnComputers

Write-Host "Analysis complete." -ForegroundColor Green

if ($Findings.Count -gt 0) {
    Write-Host ("{0} potential issues found." -f $Findings.Count) -ForegroundColor Yellow
    $Findings | Format-Table -AutoSize
}
else {
    Write-Host "No high-risk permission issues found based on the script's checks." -ForegroundColor Green
}
