function Check-ObsoleteOS {
    param (
        [string]$Server
    )

    $result = @{
        ItemNumber = "ADS026"
        UseCase = "Obsolete OS"
        WeightedScore = 20
        TechnicalInformation = "Obsolete operating systems in Active Directory refer to outdated OS versions that no longer receive security updates or patches. These systems are vulnerable to exploitation, as attackers can target unpatched vulnerabilities."
        Category = "AD Domain & Domain Group Configuration"
        TechnicalDetails = $null # will fulfill later 
        RemedediationSolution = "Regularly checking for and decommissioning obsolete operating systems reduces the risk of security breaches within the network."
        MITREMapping = "[MITRE] T1203: Exploitation for Client Execution"
        Status = $null
        ErrorMsg = $null 
    }

    try {
        # Define a list of obsolete operating systems
        $obsoleteOSList = @("Windows XP", "Windows Vista", "Windows 7", "Windows 8", "Windows Server 2003", "Windows Server 2008", "Windows Server 2008 R2")

        # Get all computers in the domain
        $computers = Get-ADComputer -Server $Server -Filter * -Properties OperatingSystem

        # Check each computer for obsolete operating systems
        $obsoleteOSComputers = foreach ($computer in $computers) {
            $os = $computer.OperatingSystem
            if ($obsoleteOSList -contains $os) {
                [PSCustomObject]@{
                    ComputerName = $computer.Name
                    OperatingSystem = $os
                }
            }
        }

        if ($obsoleteOSComputers.Count -gt 0) {
            $result.Status = "Fail"
            $result.TechnicalDetails = "Obsolete operating systems found: " + ($obsoleteOSComputers | ConvertTo-Json -Compress)
        } else {
            $result.Status = "Pass"
            $result.TechnicalDetails = "No obsolete operating systems found."
        }

    } catch {
        $result.Status = "Error"
        $result.ErrorMsg = $_.Exception.Message
    }

    return $result
}

# # Example usage
$result = Check-ObsoleteOS -Server "lab.local"
Write-Output $result | ConvertTo-Json -Depth 10