<#
.SYNOPSIS
    Cleanup-BitLockerKeys.ps1

.DESCRIPTION
    Reads a list of computer names from a text file, verifies they are running Windows 10 or 11,
    and removes old BitLocker Recovery Passwords from Active Directory for each valid computer, keeping only the newest key.
    All actions and errors are logged to a CSV file.

.PARAMETER ComputerListPath
    The full path to the input text file containing one computer name per line.

.PARAMETER CsvLogPath
    The full path where the output CSV log file will be saved.

.EXAMPLE
    .\Cleanup-BitLockerKeys.ps1 -ComputerListPath "C:\temp\computers.txt" -CsvLogPath "C:\temp\BitLockerCleanupLog.csv"
    This command will process the computers listed in computers.txt and save the results to BitLockerCleanupLog.csv.
#>
param (
    [Parameter(Mandatory = $true)]
    [string]$ComputerListPath,

    [Parameter(Mandatory = $true)]
    [string]$CsvLogPath
)

# --- Script Initialization ---
# Check if the input file exists before starting
if (-not (Test-Path -Path $ComputerListPath -PathType Leaf)) {
    Write-Error "Input file not found at path: $ComputerListPath"
    # Stop execution if the file doesn't exist
    return
}

# Get computer names from the provided text file
$computerNames = Get-Content -Path $ComputerListPath
# Array to store log objects for final CSV export
$logOutput = @()

Write-Host "Starting BitLocker key cleanup process..." -ForegroundColor Yellow

# --- Main Processing Loop ---
foreach ($name in $computerNames) {
    # Create a log object for each computer to track its status
    $logEntry = [PSCustomObject]@{ 
        ComputerName      = $name
        Timestamp         = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        Status            = ""
        Details           = ""
        OperatingSystem   = "Not Found"
        KeysRemovedCount  = 0
        KeysKeptCount     = 0
    }

    try {
        # Fetch the computer from Active Directory
        $computer = Get-ADComputer -Identity $name -Properties Name, DistinguishedName, OperatingSystem
        $logEntry.OperatingSystem = $computer.OperatingSystem

        # --- Requirement: Check for Windows 10 or Windows 11 ---
        if ($computer.OperatingSystem -like "Windows 10*" -or $computer.OperatingSystem -like "Windows 11*") {
            
            $params = @{
                Filter     = 'objectclass -eq "msFVE-RecoveryInformation"'
                SearchBase = $computer.DistinguishedName
                Properties = 'msFVE-RecoveryPassword', 'whencreated'
            }
            # Get BitLocker recovery information, sorted newest to oldest
            $bitlockerInfos = Get-ADObject @params | Sort-Object -Property WhenCreated -Descending

            if ($bitlockerInfos) {
                $logEntry.KeysKeptCount = 1
                # Check if there are multiple keys to process
                if ($bitlockerInfos.Count -gt 1) {
                    Write-Host "Found $($bitlockerInfos.Count) keys for $($computer.Name). Cleaning old keys..." -ForegroundColor Cyan
                    
                    # Loop through and remove all keys except the first one (the newest)
                    foreach ($info in $bitlockerInfos[1..($bitlockerInfos.Count - 1)]) {
                        try {
                            Remove-ADObject -Identity $info.DistinguishedName -Confirm:$false
                            $logEntry.KeysRemovedCount++
                            Write-Host "  - Removed old key for $($computer.Name) created on $($info.whencreated)" -ForegroundColor Green
                        }
                        catch {
                            # This catch handles errors during the removal of a single key
                            Write-Warning "Failed to remove a key for $($computer.Name) created on $($info.whencreated). Error: $_"
                        }
                    }
                    $logEntry.Status = "Success"
                    $logEntry.Details = "Removed $($logEntry.KeysRemovedCount) old key(s)."
                }
                else {
                    # Only one key exists
                    $logEntry.Status = "No Action Required"
                    $logEntry.Details = "Only one BitLocker Recovery key was found."
                    Write-Host "Only one key found for $($computer.Name). No action required." -ForegroundColor Cyan
                }
            }
            else {
                # No keys found for this computer
                $logEntry.Status = "No Keys Found"
                $logEntry.Details = "No BitLocker Recovery information was found in AD."
                $logEntry.KeysKeptCount = 0
                Write-Host "No BitLocker Recovery information found for $($computer.Name)" -ForegroundColor Cyan
            }
        }
        else {
            # --- Operating System did not match ---
            $logEntry.Status = "Skipped"
            $logEntry.Details = "Computer is not running Windows 10 or 11."
            Write-Warning "Skipping computer '$($name)' because its OS is '$($computer.OperatingSystem)'."
        }
    }
    catch {
        # --- This catch handles errors like 'computer not found in AD' ---
        $logEntry.Status = "Error"
        # Sanitize the error message for clean CSV output
        $errorMessage = ($_.Exception.Message).Replace("`r", " ").Replace("`n", " ")
        $logEntry.Details = "An error occurred: $errorMessage"
        Write-Error "Failed to process computer '$($name)'. Details: $errorMessage"
    }
    
    # Add the detailed log entry to our output array
    $logOutput += $logEntry
}

# --- Finalization ---
try {
    # Export the collected log data to the specified CSV file
    $logOutput | Export-Csv -Path $CsvLogPath -NoTypeInformation -Encoding UTF8
    Write-Host "Process complete. Log file has been saved to: $CsvLogPath" -ForegroundColor Green
}
catch {
    Write-Error "Failed to save the log file to '$CsvLogPath'. Error: $($_.Exception.Message)"
}
