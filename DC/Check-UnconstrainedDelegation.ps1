function Check-UnconstrainedDelegation {
    [CmdletBinding()]
    param()

    # $result = @{
    #     Description            = "Checks for Unconstrained Delegation settings in Active Directory."
    #     Severity               = "High"
    #     LikelihoodOfCompromise = "High"
    #     Findings          = @()
    #     FindingSummary          = $null
    #     Score                  = $null
    #     Remediation            = "Review and secure Unconstrained Delegation settings to prevent unauthorized access."
    #     Status                 = $null
    # }

    $result = @{
        ItemNumber = "ADS003"
        UseCase = "Unconstrained Delegation"
        WeightedScore = 5
        TechnicalInformation = "Ensures no account can impersonate any other account. Unconstrained delegation allows a captured Kerberos TGT to access any service the user has access to. If an attacker captures the TGT of an administrator or domain controller, they can potentially compromise the entire domain, especially if the connection can be forced via the spooler service."
        Category = "Object Privilege & Configuration"
        TechnicalDetails = $null # will fullfill later 
        RemedediationSolution = 
        "Unconstrained authentication delegation allows an account to authenticate to any Kerberos service acting on behalf of any user who has tried to authenticate to that account. It allows that account to elevate privileges and compromise the forest. By default, unconstrained authentication delegation is only granted to domain controllers, and must not be granted to any other account.
        For all of the accounts listed above, remove the TRUSTED_FOR_DELEGATION flag in their userAccountControl attribute. This can be performed through the Delegation tab of the Active directory Users and Computers management console. If a Kerberos delegation really is required, use a constrained one."
        MITREMapping = "[MITRE] T1187: Forced Authentication"
        Status = $null
        ErrorMsg = $null 
    }

    $settings = @{
        'domainController.name' = "DC01"
    }

    # try {
    #     # Get all users with unconstrained delegation enabled
    #     $unconstrainedUsers = Get-ADGroup -Server $settings.'domainController.name' -Filter {UserAccountControl -band 0x80000} -Properties SamAccountName

    #     if ($unconstrainedUsers) {
    #         $result.Status = "Fail"
    #         $result.FindingSummary = "Fail: Users with unconstrained delegation enabled:"
    #         $unconstrainedUsers | ForEach-Object {
    #             Write-Host $_.SamAccountName
    #             $result.FindingSummary += "`n$($_.SamAccountName)"
    #             $result.Findings += $_
    #         }
    #     } else {
    #         Write-Host "No users with unconstrained delegation enabled."
    #         $result.Status = "Pass"
    #         $result.FindingSummary = "Pass: No users with unconstrained delegation enabled."
    #     }
    # } catch {
    #     $errstr = $_.Exception.Message
    #     $result.Status = "Fail"
    #     $result.FindingSummary = "Error: $errstr"
    # }
    try {
        $unconstrainedUsers = Get-ADGroup -Server $settings.'domainController.name' -Filter {UserAccountControl -band 0x80000} -Properties SamAccountName
    
        if ($unconstrainedUsers) {
            $result.Status = "Fail"
            $result.TechnicalDetails = "Users with unconstrained delegation enabled:`n"
            $unconstrainedUsers | ForEach-Object {
                $result.TechnicalDetails += "$($_.SamAccountName)`n"
            }
        } else {
            $result.Status = "Pass"
            $result.TechnicalDetails = "No users with unconstrained delegation enabled."
        }
    } catch {
        $result.Status = "Fail"
        $result.ErrorMsg = $_.Exception.Message
        $result.TechnicalDetails = "An error occurred while checking for unconstrained delegation."
    }

    return $result
}

# Example usage
$result = Check-UnconstrainedDelegation
Write-Output $result