function Check-NBT-NSAndLLMNR {
    [CmdletBinding()]
    param (
        [string]$ComputerName = $env:COMPUTERNAME
    )

    $result = @{
        ItemNumber = "ADS036"
        UseCase = "NBT-NS & LLMNR Poisoning"
        WeightedScore = 5
        TechnicalInformation = "NBT-NS (NetBIOS Name Service) and LLMNR (Link-Local Multicast Name Resolution) are network protocols used for name resolution. If enabled, they can be exploited by attackers to perform spoofing attacks or intercept network traffic."
        Category = "Lateral Movement Analysis"
        TechnicalDetails = $null # will fulfill later 
        RemedediationSolution = "Disable NBT-NS and LLMNR protocols if not required. Use DNS for name resolution instead. Examine any records with the following Event IDs on your DNS servers: 8003, 4319, 1014, and 1015."
        MITREMapping = "[MITRE] T1203: Exploitation for Client Execution"
        Status = $null
        ErrorMsg = $null 
    }

    try {
        # Check if NBT-NS is enabled
        $nbtNSKey = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" -Name "EnableLmhosts" -ErrorAction SilentlyContinue
        $nbtNSStatus = if ($nbtNSKey -eq $null) { 0 } else { $nbtNSKey.EnableLmhosts }

        # Check if LLMNR is enabled
        $llmnrKey = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "EnableMulticast" -ErrorAction SilentlyContinue
        $llmnrStatus = if ($llmnrKey -eq $null) { 0 } else { $llmnrKey.EnableMulticast }

        # Add NBT-NS status to TechnicalDetails
        $result.TechnicalDetails = @(
            [PSCustomObject]@{
                Service = "NBT-NS (NetBIOS Name Service)"
                Status = if ($nbtNSStatus -eq 1) { "Enabled" } else { "Disabled" }
            },
            [PSCustomObject]@{
                Service = "LLMNR (Link-Local Multicast Name Resolution)"
                Status = if ($llmnrStatus -eq 1) { "Enabled" } else { "Disabled" }
            }
        )

        # Set overall status
        $result.Status = if ($nbtNSStatus -eq 1 -or $llmnrStatus -eq 1) { "Fail" } else { "Pass" }

        # Set ErrorMsg based on status
        $result.ErrorMsg = if ($result.Status -eq "Pass") {
            "NBT-NS and LLMNR are disabled."
        } else {
            "NBT-NS and/or LLMNR are enabled."
        }
    }
    catch {
        $result.Status = "Error"
        $result.ErrorMsg = "Error checking for NBT-NS and LLMNR: $_"
    }

    return $result
}

# Example usage
$ComputerName = "Vul-DC"
$result = Check-NBT-NSAndLLMNR -ComputerName $ComputerName
Write-Output $result | ConvertTo-Json -Depth 10