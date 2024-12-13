function Check-LDAPSigningDisabled {
    [CmdletBinding()]
    param (
        [string]$Server
    )

    $result = @{
        ItemNumber = "ADS018"
        UseCase = "LDAP Signing Misconfiguration"
        WeightedScore = 10
        TechnicalInformation = "LDAP signing is a security feature that ensures data integrity and authenticity for LDAP communications between domain controllers and clients. If LDAP signing is disabled, attackers can perform man-in-the-middle attacks or tamper with LDAP traffic, potentially leading to unauthorized access or data manipulation."
        Category = "Authentication & Permission Policies"
        TechnicalDetails = $null # will fulfill later 
        RemedediationSolution = "Ensure LDAP signing is enabled on all domain controllers to protect against data tampering and man-in-the-middle attacks. Review and update Group Policy settings to enforce LDAP signing requirements and regularly audit network traffic for compliance with security policies.

Open gpedit.msc and navigate to Computer Configuration > Administrative Templates > Network > DNS Client > Turn off multicast name resolution and set to Enabled"
        MITREMapping = "[MITRE] T1557: Adversary-in-the-Middle"
        Status = $null
        ErrorMsg = $null 
    }

    try {
        $ldapSigning = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -Name "LDAPServerIntegrity" -ErrorAction Stop

        if ($ldapSigning.LDAPServerIntegrity -eq 1) {
            $result.Status = "Pass"
            $result.TechnicalDetails = "LDAP signing is enabled on the server."
        } else {
            $result.Status = "Fail"
            $result.TechnicalDetails = "LDAP signing is disabled on the server."
        }
    } catch {
        $result.Status = "Error"
        $result.ErrorMsg = $_.Exception.Message
    }

    return $result
}

# Example usage
$Server = "your-server-name"
$result = Check-LDAPSigningDisabled -Server $Server
Write-Output $result| ConvertTo-Json -Depth 10