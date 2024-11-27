function Check-LDAPSigningDisabled {
    [CmdletBinding()]
    param (
        [string]$ComputerName = $null
    )

    $result = @{
        Description            = "Checks if LDAP signing is disabled on the Domain Controller."
        Severity               = "High"
        LikelihoodOfCompromise = "High"
        Findings               = $null
        FindingSummary         = $null
        Score                  = $null
        Remediation            = "Enable LDAP signing for enhanced security."
        Status                 = $null
    }

    try {
        # Define the script block to be executed on the remote or local machine
        $scriptBlock = {
            try {
                $ldapSigning = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -Name 'LDAPServerIntegrity'
                if ($ldapSigning.LDAPServerIntegrity -eq 0) {
                    return @{ Status = "Fail"; FindingSummary = "Fail: LDAP signing is disabled on the Domain Controller." }
                } else {
                    return @{ Status = "Pass"; FindingSummary = "Pass: LDAP signing is enabled on the Domain Controller." }
                }
            } catch {
                return @{ Status = "Fail"; FindingSummary = "Error: $($_.Exception.Message)" }
            }
        }

        if ($ComputerName) {
            # Execute the script block on the remote computer
            $remoteResult = Invoke-Command -ComputerName $ComputerName -ScriptBlock $scriptBlock

            # Merge the remote result with the local result
            $result.Status = $remoteResult.Status
            $result.FindingSummary = $remoteResult.FindingSummary
        } else {
            # Execute the script block locally
            $localResult = & $scriptBlock

            # Merge the local result with the main result
            $result.Status = $localResult.Status
            $result.FindingSummary = $localResult.FindingSummary
        }

    } catch {
        $errstr = $_.Exception.Message
        $result.Status = "Fail"
        $result.FindingSummary = "Error: $errstr"
    }

    return $result
}

$result = Check-LDAPSigningDisabled -ComputerName "DomainControllerName"
Write-Output $result
