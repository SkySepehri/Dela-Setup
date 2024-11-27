function Check-NTLMConfiguration {
    [CmdletBinding()]
    param (
        [string]$DomainController
    )

    # try {
    #     # Query NTLM configuration settings using WMI
    #     $NTLMConfig = Get-WmiObject -Class Win32_ComputerSystem -ComputerName $DomainController

    #     if ($NTLMConfig) {
    #         # Extract relevant NTLM configuration properties
    #         $lmCompatibilityLevel = $NTLMConfig.Properties['lmcompatibilitylevel'].Value
    #         $ntlmMinClientSec = $NTLMConfig.Properties['ntlmminclientsecurity'].Value
    #         $ntlmMinServerSec = $NTLMConfig.Properties['ntlmminserversecurity'].Value

    #         # Prepare the result object
    #         $result = @{
    #             Description = "Check NTLM configuration settings."
    #             Severity = "Informational"
    #             LikelihoodOfCompromise = "Low"
    #             Findings = @{
    #                 LMCompatibilityLevel = $lmCompatibilityLevel
    #                 NTLMMinClientSecurity = $ntlmMinClientSec
    #                 NTLMMinServerSecurity = $ntlmMinServerSec
    #             }
    #             FindingSummary = "NTLM configuration settings retrieved successfully."
    #             Remediation = "Review and adjust NTLM configuration settings as necessary."
    #             Status = "Pass"
    #         }
    #     } else {
    #         $result = @{
    #             Description = "Check NTLM configuration settings."
    #             Severity = "High"
    #             LikelihoodOfCompromise = "High"
    #             Findings = $null
    #             FindingSummary = "Error: NTLM configuration settings not found."
    #             Remediation = "Investigate and resolve the issue."
    #             Status = "Fail"
    #         }
    #     }

    #     return $result
    # }
    # catch {
    #     $result = @{
    #         Description = "Error checking NTLM configuration."
    #         Severity = "High"
    #         LikelihoodOfCompromise = "High"
    #         Findings = $null
    #         FindingSummary = "Error: $_"
    #         Remediation = "Investigate and resolve the issue."
    #         Status = "Fail"
    #     }

    #     Write-Error "Error checking NTLM configuration: $_"
    #     return $result
    # }

    $result = @{
        ItemNumber = "ADS013"
        UseCase = "NTLM Misconfiguration "
        WeightedScore = 9
        TechnicalInformation = "NTLM (NT LAN Manager) is an authentication protocol used by Windows systems. Misconfigured NTLM settings can expose systems to security risks, such as pass-the-hash attacks or relay attacks, where attackers intercept and use NTLM authentication credentials to gain unauthorized access to network resources."
        Category = "Authentication & Permission Policies"
        TechnicalDetails = $null # will fullfill later 
        RemedediationSolution = 
        "Set the Lan Manager authentication level to: Send NTLMv2 responses only. Refuse LM & NTLM

In addition, implement network segmentation and monitoring to detect and prevent misuse of NTLM credentials. Regularly audit and update security policies to mitigate risks associated with NTLM authentication."
        MITREMapping = "[MITRE] T1557: Adversary-in-the-Middle"
        Status = $null
        ErrorMsg = $null 
    }

    try {
        $NTLMConfig = Get-WmiObject -Class Win32_ComputerSystem -ComputerName $DomainController

        if ($NTLMConfig) {
            $lmCompatibilityLevel = $NTLMConfig.Properties['lmcompatibilitylevel'].Value
            $ntlmMinClientSec = $NTLMConfig.Properties['ntlmminclientsecurity'].Value
            $ntlmMinServerSec = $NTLMConfig.Properties['ntlmminserversecurity'].Value

            $result.TechnicalDetails = @{
                LMCompatibilityLevel = $lmCompatibilityLevel
                NTLMMinClientSecurity = $ntlmMinClientSec
                NTLMMinServerSecurity = $ntlmMinServerSec
            }

            if ($lmCompatibilityLevel -eq 5 -and $ntlmMinClientSec -eq 537395200 -and $ntlmMinServerSec -eq 537395200) {
                $result.Status = "Pass"
            } else {
                $result.Status = "Fail"
            }
        } else {
            $result.Status = "Fail"
            $result.ErrorMsg = "NTLM configuration settings not found."
        }
    }
    catch {
        $result.Status = "Error"
        $result.ErrorMsg = "Error checking NTLM configuration: $_"
    }

    return $result
}

# Example usage
$result = Check-NTLMConfiguration -DomainController "AgentDomainControllerName"
Write-Output $result
