<#
.SYNOPSIS
    Searches the Network Policy Server (NPS) event log for a specific MAC address.

.DESCRIPTION
    This script queries the 'Microsoft-Windows-NPS/Operational' event log, which corresponds to
    "Server Roles > Network Policy and Access Services" in Event Viewer. It filters events to find
    any that contain the specified MAC address in their message body.

    The script is designed to find the MAC address regardless of its formatting (e.g., 08-3F-21-25-CE-A7, 08:3F:21:25:CE:A7, or 083F2125CEA7).

.PARAMETER MacAddress
    The MAC address you want to search for. The default is the one from your request.

.EXAMPLE
    .\Search-NpsLogForMac.ps1

    # This will search for the default MAC address "08-3f-21-25-ce-a7".

.EXAMPLE
    .\Search-NpsLogForMac.ps1 -MacAddress "00-1A-2B-3C-4D-5E"

    # This will search for the specified MAC address "00-1A-2B-3C-4D-5E".
#>
param (
    [Parameter(Mandatory=$false)]
    [string]$MacAddress = "08-3f-21-25-ce-a7"
)

# --- Script Configuration ---

# The official log name for Network Policy and Access Services
$npsLogName = "Microsoft-Windows-NPS/Operational"

# Prepare the MAC address for a flexible search by removing all common separators.
$macToFindClean = $MacAddress -replace '[-:.]',''

Write-Host "Searching for MAC address '$MacAddress' in the '$npsLogName' log..."
Write-Host "This may take a moment on servers with large log files."

# --- Main Logic ---

try {
    # Get all events from the NPS log and then filter them.
    # The 'ErrorAction SilentlyContinue' will suppress errors if the log is empty or inaccessible for a moment.
    $matchingEvents = Get-WinEvent -LogName $npsLogName -ErrorAction SilentlyContinue | Where-Object {
        # Check if the message exists and then perform a flexible match
        $_.Message -and (($_.Message -replace '[-:.]','') -like "*$macToFindClean*")
    }

    # --- Output Results ---

    if ($matchingEvents) {
        Write-Host -ForegroundColor Green "Found one or more matching events."
        
        # Display the results in a readable format.
        # We select the time, the event ID (useful for diagnostics), and the full message.
        $matchingEvents | Select-Object TimeCreated, Id, LevelDisplayName, Message | Format-List
    }
    else {
        Write-Host -ForegroundColor Yellow "No events found matching the MAC address '$MacAddress'."
    }
}
catch {
    Write-Host -ForegroundColor Red "An error occurred while trying to access the event log."
    Write-Host -ForegroundColor Red "Error details: $($_.Exception.Message)"
    Write-Host "Please ensure you are running this script with administrator privileges and that the 'Network Policy and Access Services' role is installed."
}