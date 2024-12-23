﻿function Check-EPAPermissions {
    [CmdletBinding()]
    param (
        [string]$DomainController
    )

    $result = @{
        ItemNumber =  "ADS014"
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
Write-Output $result | ConvertTo-Json -Depth 10