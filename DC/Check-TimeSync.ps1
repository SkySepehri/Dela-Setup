function Check-TimeSync {
    [CmdletBinding()]
    param()

    $result = @{
        ItemNumber = "ADS022"
        UseCase = "Ensure Server Time Synchronization with Reliable Source"
        WeightedScore = 5
        TechnicalInformation = "Accurate time synchronization is crucial for the proper functioning of network services, security protocols, and logging. It helps ensure that all systems in the network are operating on the same time, which is essential for coordination and troubleshooting. If time synchronization is misconfigured, attackers can exploit this to evade detection, manipulate logs, and disrupt security protocols."
        Category = "Authentication & Permission Policies"
        TechnicalDetails = $null # will fulfill later 
        RemedediationSolution = "Review and adjust the server's time synchronization settings to ensure it is synchronized with a reliable time source, such as time.windows.com."
        MITREMapping = "[MITRE] T1070.006: Indicator Removal on Host: Timestomp"
        Status = $null
        ErrorMsg = $null 
    }

    try {
        # Check if the server is synchronized with a reliable time source
        $timeSource = w32tm /query /status /verbose | Select-String "Source"

        if ($timeSource -match "time.windows.com") {
            $result.Status = "Pass"
            $result.TechnicalDetails = "Pass: Server is synchronized with a reliable time source."
        } else {
            $result.Status = "Fail"
            $result.TechnicalDetails = "Fail: Server is not synchronized with the expected time source."
        }

    } catch {
        $result.Status = "Error"
        $result.ErrorMsg = $_.Exception.Message
    }

    return $result
}

# Example usage
$result = Check-TimeSync
Write-Output $result | ConvertTo-Json -Depth 10