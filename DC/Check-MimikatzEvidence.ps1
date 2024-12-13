function Check-MimikatzEvidence {
    [CmdletBinding()]
    param(
        [string]$serverName = $env:COMPUTERNAME
    )

    # $result = @{
    #     Description            = "Checks for evidence of Mimikatz on the system."
    #     Severity               = "High"
    #     LikelihoodOfCompromise = "High"
    #     Findings               = $null
    #     FindingSummary         = $null
    #     Score                  = $null
    #     Remediation            = "Investigate and remediate any potential compromise."
    #     Status                 = $null
    # }

    $result = @{
        ItemNumber = "ADS031"
        UseCase = "Evidence of Mimikatz"
        WeightedScore = 5
        TechnicalInformation = "Mimikatz and its variants are tools used to extract sensitive information like plaintext passwords and Kerberos tickets from memory. Detecting evidence of these tools on a system is crucial, as they can indicate an attacker’s attempt to compromise credentials or escalate privileges."
        Category = "Forensic Analysis"
        TechnicalDetails = $null # will fullfill later 
        RemedediationSolution = 
        "Regularly checking for Mimikatz or its variants helps identify and address potential security breaches."
        MITREMapping = "[MITRE] T1003: OS Credential Dumping"
        Status = $null
        ErrorMsg = $null 
    }

    try {
        # Check for evidence of Mimikatz in event logs
        $mimikatzEvents = Get-WinEvent -ComputerName $serverName -FilterHashtable @{
            LogName    = 'Security'
            ProviderId = 'Security'
            Id         = 4662
        } -ErrorAction SilentlyContinue

        if ($null -eq $mimikatzEvents) {
            $result.Status = "Pass"
            $result.TechnicalDetails = "Pass: No security event logs were found."
        } elseif ($mimikatzEvents.Count -eq 0) {
            $result.Status = "Pass"
            $result.TechnicalDetails = "Pass: No evidence of Mimikatz found in Security event logs."
        } else {
            $result.Status = "Fail"
            $result.TechnicalDetails = "Fail: Evidence of Mimikatz found in Security event logs."
        }

        # Additional checks specific to Mimikatz evidence can be added here

    } catch {
        $errstr = $_.Exception.Message
        $result.Status = "Fail"
        $result.TechnicalDetails = "Error: $errstr"
    }

    return $result
}

# Example usage
$result = Check-MimikatzEvidence -serverName "AgentServerName"
Write-Output $result | ConvertTo-Json -Depth 10