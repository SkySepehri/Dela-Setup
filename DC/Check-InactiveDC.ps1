function Check-InactiveDC {
    [CmdletBinding()]
    param()

    $result = @{
        ItemNumber = "ADS028"
        UseCase = "Inactive Domain Controllers"
        WeightedScore = 5
        TechnicalInformation = "Domain Controllers are essential for managing security, authentication, and directory services. If a Domain Controller is inactive, it may indicate network issues, hardware failures, or misconfigurations. This use case retrieves information about all Domain Controllers and identifies any that are not actively communicating, allowing IT administrators to investigate and address any problems."
        Category = "AD Domain & Domain Group Configuration"
        TechnicalDetails = $null # will fulfill later 
        RemedediationSolution = "Investigate and address any issues preventing communication with the Domain Controllers, including verifying network connectivity, checking services, reviewing event logs, testing DNS configuration, checking replication status, and reviewing hardware health."
        MITREMapping = "[MITRE] T1078: Valid Accounts"
        Status = $null
        ErrorMsg = $null 
    }

    try {
        # Get information about all Domain Controllers
        $domainControllers = Get-ADDomainController -Filter *

        # Check each Domain Controller for inactivity
        $inactiveDCs = foreach ($dc in $domainControllers) {
            try {
                $repData = (Get-ADReplicationUpToDatenessVectorTable -Target $dc.HostName -Partition * | Measure-Object -Property LastReplicationAttempt)
                $lastReplication = $repData.Maximum
                $ntdsSettingsDN = "CN=NTDS Settings,$($dc.NTDSSettingsObjectDN)"
                $lastLogon = (Get-ADObject -Filter {DistinguishedName -eq $ntdsSettingsDN} -Server $dc.HostName -Properties LastLogon).LastLogon

                $inactiveThreshold = (Get-Date).AddDays(-30)  # Adjust the threshold as needed (e.g., 30 days)

                if ($lastReplication -lt $inactiveThreshold -or $lastLogon -lt $inactiveThreshold) {
                    $dc
                }
            } catch [Microsoft.ActiveDirectory.Management.ADServerDownException] {
                Write-Warning "Unable to contact server $($dc.HostName). Skipping this DC."
            } catch {
                Write-Warning "Error occurred while retrieving replication data for $($dc.HostName): $_"
            }
        }

        if ($inactiveDCs.Count -gt 0) {
            $result.Status = "Fail"
            $result.TechnicalDetails = "Inactive Domain Controllers found: " + ($inactiveDCs | ForEach-Object { $_.Name } | Out-String)
        } else {
            $result.Status = "Pass"
            $result.TechnicalDetails = "No inactive Domain Controllers found."
        }

    } catch {
        $result.Status = "Error"
        $result.ErrorMsg = $_.Exception.Message
    }

    return $result
}

# Example usage
$result = Check-InactiveDC
Write-Output $result | ConvertTo-Json -Depth 10