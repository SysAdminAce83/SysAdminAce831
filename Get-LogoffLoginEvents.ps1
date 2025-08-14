<#
.SYNOPSIS
    Retrieves logon (EventID 4624) and logoff (EventID 4634) events from Security logs.
    Creates master reports and user-specific reports with caching and multi-user support.

.DESCRIPTION
    This script for Windows Server 2016/2019/2022 and Windows 10/11:
    1. Runs as Administrator (required for Security log access)
    2. Checks for existing recent reports (≤4 hours old) to avoid redundant event collection
    3. Collects logon/logoff events from last 7 days
    4. Processes event details (IP, LogonType, Domain, etc.)
    5. Generates:
        - Master report: All_Logon_Logoff_Events.csv
        - User-specific reports: Logon_Events_For_[USER].csv
    6. Supports multiple users in single execution
    7. Uses TEMP directory for better permissions handling

.EXAMPLE
    PS> .\Get-LogonLogoffEvents.ps1
    Collects events and prompts for usernames to generate reports

.NOTES
    Author: Krishnaramanan.S
    Modified: 2024-07-17
    Version: 2.0
    Requires: PowerShell 5.1+, Administrator privileges
#>

[CmdletBinding()]
param ()

#region Initialization and Admin Check
function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    return [Security.Principal.WindowsPrincipal]::new($id).IsInRole(
        [Security.Principal.WindowsBuiltinRole]::Administrator
    )
}

if (-not (Test-IsAdmin)) {
    Write-Error "Administrator privileges required. Please run PowerShell as Administrator."
    if ($Host.Name -eq 'ConsoleHost') {
        Write-Host "Press any key to exit..." -ForegroundColor Yellow
        $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | Out-Null
    }
    exit 1
}

$baseOutputPath = "$env:TEMP\SecurityLogs"
$allEventsFile = Join-Path $baseOutputPath "All_Logon_Logoff_Events.csv"
$reportRefreshed = $false
#endregion

#region Event Collection and Processing
try {
    # Create output directory if needed
    if (-not (Test-Path $baseOutputPath)) {
        New-Item -Path $baseOutputPath -ItemType Directory -Force | Out-Null
    }

    # Check for recent existing report
    $existingReport = Get-ChildItem $baseOutputPath -Filter "All_Logon_Logoff_Events.csv" -ErrorAction SilentlyContinue | 
        Where-Object { $_.LastWriteTime -ge (Get-Date).AddHours(-4) } | 
        Select-Object -First 1

    if ($existingReport) {
        Write-Host "Using existing report (modified within 4 hours)." -ForegroundColor Green
        $report = Import-Csv -Path $existingReport.FullName
    }
    else {
        # Rename old report if exists
        Get-ChildItem $baseOutputPath -Filter "All_Logon_Logoff_Events.csv" -ErrorAction SilentlyContinue | 
            Rename-Item -NewName {"LoginLogoff_Audit_Log_$($_.CreationTime.ToString('yyyyMMdd_HHmmss')).csv"} -Force

        # Set time range and get events
        $endTime = Get-Date
        $startTime = $endTime.AddDays(-7)
        Write-Host "Collecting events from $($startTime.ToShortDateString()) to $($endTime.ToShortDateString())..." -ForegroundColor Cyan
        
        $rawEvents = Get-WinEvent -FilterHashtable @{
            LogName   = 'Security'
            ID        = 4624, 4634
            StartTime = $startTime
            EndTime   = $endTime
        } -ErrorAction Stop

        if (-not $rawEvents) {
            Write-Warning "No logon/logoff events found in specified timeframe"
            exit
        }

        # Process events
        $report = [System.Collections.Generic.List[object]]::new()
        foreach ($event in $rawEvents) {
            $eventXml = [xml]$event.ToXml()
            $eventData = @{}
            $eventXml.Event.EventData.Data | ForEach-Object { 
                $eventData[$_.Name] = $_.'#text' 
            }

            $report.Add([PSCustomObject]@{
                TimeCreated   = $event.TimeCreated
                EventID       = $event.Id
                Status        = if ($event.Id -eq 4624) { "Logon" } else { "Logoff" }
                AccountName   = $eventData.TargetUserName
                AccountDomain = $eventData.TargetDomainName
                SID           = $eventData.TargetUserSid
                LogonType     = $eventData.LogonType
                SourceIP      = $eventData.IpAddress
            })
        }

        # Save master report
        $report | Export-Csv -Path $allEventsFile -NoTypeInformation
        Write-Host "Master report saved: $allEventsFile" -ForegroundColor Green
        $reportRefreshed = $true
    }
}
catch {
    Write-Error "ERROR: $($_.Exception.Message)"
    if ($Host.Name -eq 'ConsoleHost') {
        Write-Host "Press any key to exit..." -ForegroundColor Yellow
        $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | Out-Null
    }
    exit 1
}
#endregion

#region User Report Generation
if ($report) {
    $userCount = 0
    do {
        $userCount++
        $targetUser = Read-Host "`nEnter username for report #$userCount (or press Enter to exit)"
        if ([string]::IsNullOrWhiteSpace($targetUser)) { break }

        $userEvents = $report | Where-Object { 
            $_.AccountName -eq $targetUser -or
            $_.SID -eq $targetUser 
        }

        if ($userEvents) {
            $safeName = $targetUser -replace '[\\/:"*?<>|]', '_'
            $userFile = Join-Path $baseOutputPath "Logon_Events_For_$safeName.csv"
            $userEvents | Export-Csv $userFile -NoTypeInformation
            Write-Host "Created report: $userFile ($($userEvents.Count) events)" -ForegroundColor Green
        }
        else {
            Write-Warning "No events found for '$targetUser'"
        }

        # Prompt to continue after every 3 users
        if ($userCount % 3 -eq 0) {
            $choice = Read-Host "Process more users? (Y/N)"
            if ($choice -notmatch '^[yY]') { break }
        }
    } while ($true)
}
#endregion

# Final status
Write-Host "`nReports available at: $baseOutputPath" -ForegroundColor Cyan
if ($reportRefreshed) {
    Write-Host "Event data refreshed" -ForegroundColor Yellow
}
else {
    Write-Host "Using cached event data" -ForegroundColor Yellow
}

if ($Host.Name -eq 'ConsoleHost') {
    Write-Host "`nPress any key to exit..." -ForegroundColor Yellow
    $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | Out-Null
}