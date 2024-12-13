function Check-AnonymousAccessToAD {
    [CmdletBinding()]
    param()

    $result = @{
        ItemNumber = "ADS020"
        UseCase = "Anonymous Access to Active Directory"
        WeightedScore = 5
        TechnicalInformation = "Anonymous access to Active Directory allows users or attackers to query the directory without authentication. This can expose sensitive information, such as user accounts and group memberships, which can be exploited for reconnaissance or privilege escalation."
        Category = "Authentication & Permission Policies"
        TechnicalDetails = $null # will fulfill later 
        RemedediationSolution = "Restrict anonymous access to Active Directory by configuring security settings to require authentication for directory queries. Review and update access controls and regularly audit directory access logs to ensure compliance with security policies."
        MITREMapping = "[MITRE] T1087:  Account Discovery"
        Status = $null
        ErrorMsg = $null 
    }

    try {
        # Check for anonymous access to Active Directory
        $anonymousAccess = (Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\NTDS\Parameters")."Anonymous Logon"

        if ($null -ne $anonymousAccess) {
            $result.Status = "Fail"
            $result.TechnicalDetails = "Anonymous access to Active Directory is enabled."
        } else {
            $result.Status = "Pass"
            $result.TechnicalDetails = "Anonymous access to Active Directory is not enabled."
        }

    } catch {
        $result.Status = "Error"
        $result.ErrorMsg = $_.Exception.Message
    }

    return $result
}

# Example usage
$result = Check-AnonymousAccessToAD
Write-Output $result| ConvertTo-Json -Depth 10