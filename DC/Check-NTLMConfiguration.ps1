function Check-NTLMConfiguration {
    [CmdletBinding()]
    param (
        [string]$DomainController
    )

    $result = @{
        ItemNumber = "ADS017"
        UseCase = "NTLM Misconfiguration"
        WeightedScore = 9
        TechnicalInformation = "NTLM (NT LAN Manager) is an authentication protocol used by Windows systems. Misconfigured NTLM settings can expose systems to security risks, such as pass-the-hash attacks or relay attacks, where attackers intercept and use NTLM authentication credentials to gain unauthorized access to network resources."
        Category = "Authentication & Permission Policies"
        TechnicalDetails = $null # will fill later
        RemediationSolution = "Set the Lan Manager authentication level to: Send NTLMv2 responses only. Refuse LM & NTLM.

In addition, implement network segmentation and monitoring to detect and prevent misuse of NTLM credentials. Regularly audit and update security policies to mitigate risks associated with NTLM authentication."
        MITREMapping = "[MITRE] T1557: Adversary-in-the-Middle"
        Status = $null
        ErrorMsg = $null
    }

    try {
        $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"

        $ntlmRegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"

        $currentLMLevel = (Get-ItemProperty -Path $registryPath).LmCompatibilityLevel
        $currentNTLMClientSec = (Get-ItemProperty -Path $ntlmRegistryPath).NtlmMinClientSec
        $currentNTLMServerSec = (Get-ItemProperty -Path $ntlmRegistryPath).NtlmMinServerSec

        write-host $currentLMLevel
        write-host $currentNTLMClientSec
        write-host $currentNTLMServerSec


        

        # Check compliance
        if ($currentLMLevel -eq 5 -and $currentNTLMClientSec -eq 537395200 -and $currentNTLMServerSec -eq 537395200) {
            $result.Status = "Pass"
        } else {
            $result.Status = "Fail"
        }
    }
    catch {
        $result.Status = "Error"
        $result.ErrorMsg = "Error checking NTLM configuration: $_"
    }

    return $result
}

# Example usage
Check-NTLMConfiguration -DomainController "Vul-DC"

Write-Output $result | ConvertTo-Json -Depth 10
