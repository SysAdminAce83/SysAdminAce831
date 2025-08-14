$regPath = "HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters"
$regName = "RequireSecuritySignature"
$expectedValue = 1

try {
    $actualValue = Get-ItemPropertyValue -Path $regPath -Name $regName -ErrorAction Stop
    if ($actualValue -eq $expectedValue) {
        Write-Output "Registry entry exists and value is correct."
    } else {
        Write-Output "Registry entry exists but value is different: $actualValue"
    }
} catch {
    Write-Output "Registry entry or value not found."
}
