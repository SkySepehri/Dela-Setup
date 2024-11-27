function Check-EPAPermissions {
    [CmdletBinding()]
    param (
        [string]$DomainController
    )

    # try {
    #     $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration"

    #     # Check if the registry path exists
    #     if (Test-Path $regPath) {
    #         # Check if EPA permissions are set correctly
    #         $acl = Get-Acl -Path $regPath
    #         $epaRule = $acl.Access | Where-Object { $_.IdentityReference -like "*Enrollment Policy Agent*" }

    #         if ($epaRule) {
    #             $result = @{
    #                 ItemNumber =  "ADS033"
    #                 Description = "Check for Enrollment Policy Agent (EPA) permissions."
    #                 Severity = "Informational"
    #                 LikelihoodOfCompromise = "Low"
    #                 Findings = $null
    #                 FindingSummary = "EPA permissions check completed successfully."
    #                 Remediation = "No action required."
    #                 Status = "Pass"
    #             }
    #         } else {
    #             $result = @{
    #                 Description = "Check for Enrollment Policy Agent (EPA) permissions."
    #                 Severity = "High"
    #                 LikelihoodOfCompromise = "High"
    #                 Findings = $null
    #                 FindingSummary = "Error: EPA permissions not found."
    #                 Remediation = "Ensure correct permissions are set for Enrollment Policy Agent (EPA)."
    #                 Status = "Fail"
    #             }
    #         }
    #     } else {
    #         # If the registry path does not exist
    #         $result = @{
    #             Description = "Check for Enrollment Policy Agent (EPA) permissions."
    #             Severity = "High"
    #             LikelihoodOfCompromise = "High"
    #             Findings = $null
    #             FindingSummary = "Error: Registry path not found."
    #             Remediation = "Verify the installation of Certificate Services and the correct registry path."
    #             Status = "Fail"
    #         }
    #     }

    #     return $result
    # }
    # catch {
    #     # If an error occurs during the execution of the function
    #     $errorMessage = $_.Exception.Message
    #     $result = @{
    #         Description = "Error checking for Enrollment Policy Agent (EPA) permissions."
    #         Severity = "High"
    #         LikelihoodOfCompromise = "High"
    #         Findings = $null
    #         FindingSummary = "Error: $errorMessage"
    #         Remediation = "Investigate and resolve the issue."
    #         Status = "Fail"
    #     }

    #     Write-Error $result.FindingSummary
    #     return $result
    # }

    # $result = @{
    #     ItemNumber = "ADS004"
    #     UseCase = "Constrained Delegation"
    #     WeightedScore = 5
    #     TechnicalInformation = "Ensures no constrained delegations  transition are applied to Domain Controllers (DCs). This setup allows a delegate to impersonate users without proper service limitations, potentially enabling domain control by impersonating a domain admin and making unauthorized modifications via LDAP. The configuration is managed through the msDS-AllowedToDelegateTo attribute and a flag in userAccountControl."
    #     Category = "Object Privilege & Configuration"
    #     TechnicalDetails = $null # will fullfill later 
    #     RemedediationSolution = 
    #     "Constrained delegation with protocol transition or having constrained authentication delegationsto a domain controller service must not be allowed.Edit the msDS-AllowedToDelegateTo attribute for the accounts listed below to remove the SPNs associated with the domain controllers involved.This can be fixed with PowerShell too,the following command can be used to remove such a delegation on a target computer named COMPUTER: Set-ADComputer COMPUTER -PrincipalsAllowedToDelegateToAccount $Null"
    #     MITREMapping = "[MITRE] T1187: Forced Authentication"
    #     Status = $null
    #     ErrorMsg = $null 
    # }

    $result = @{
        ItemNumber =  "ADS033"
        UseCase = "Misconfigured EPA Permissions"
        WeightedScore = 5
        TechnicalInformation = "Enrollment Policy Agent (EPA) permissions control access to certificate enrollment processes in Active Directory Certificate Services (ADCS). Improperly configured EPA permissions can be exploited by attackers to enroll unauthorized certificates, potentially allowing them to impersonate users, escalate privileges, or gain unauthorized access to secure resources."    
        Category = "Object Privilege & Configuration"
        TechnicalDetails = $null # will fullfill later
        RemedediationSolution = "Verify the installation of Certificate Services and the correct registry path.
Instructions to Verify Certificate Services Installation
Open Services
Locate Certificate Services:
In the Services window, find Active Directory Certificate Services.
Ensure the status is Running. If not, right-click and select Start.
Open Registry Editor:
Navigate to Registry Path:
Go to the following registry path:
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc
Verify Key Values:
Check the values under this key to ensure they reflect the correct configuration for your Certificate Services.
Confirm CA Configuration:
In the same registry path, confirm that the Configuration key contains the correct settings for your Certification Authority."
        MITREMapping = "[MITRE] T1649: Steal or Forge Authentication Certificates"
        Status = $null
        ErrorMsg = $null 
    }

    try {
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration"

        if (Test-Path $regPath) {
            $acl = Get-Acl -Path $regPath
            $epaRule = $acl.Access | Where-Object { $_.IdentityReference -like "*Enrollment Policy Agent*" }

            if ($epaRule) {
                # Pass scenario
                $result.Status = "Pass"
                $result.TechnicalDetails = "EPA permissions are correctly set."
            } else {
                # Fail scenario
                $result.Status = "Fail"
                $result.TechnicalDetails = "EPA permissions not found. This could lead to security vulnerabilities."
            }
        } else {
            # Fail scenario (registry path not found)
            $result.Status = "Fail"
            $result.TechnicalDetails = "Registry path for Certificate Services configuration not found. This indicates potential issues with the Certificate Services installation."
        }
    }
    catch {
        # Error scenario
        $result.Status = "Error"
        $result.ErrorMsg = $_.Exception.Message
        $result.TechnicalDetails = "An error occurred while checking EPA permissions: $($result.ErrorMsg)"
    }

    return $result
}

# Example usage
$result = Check-EPAPermissions -DomainController "AgentDomainController"
Write-Output $result