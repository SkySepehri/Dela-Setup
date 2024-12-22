# Ensure the ActiveDirectory module is imported
Import-Module ActiveDirectory

function Check-AccountLockoutPolicy {
    [CmdletBinding()]
    param()

    $result = @{
        ItemNumber = "ADS023"
        UseCase = "Account Lockout Policy"
        WeightedScore = 5
        TechnicalInformation = "This function checks the account lockout policy in Active Directory. The account lockout policy helps protect against brute force attacks by locking out user accounts after a specified number of failed login attempts. If this policy is misconfigured or not set, attackers can repeatedly attempt to guess passwords without being locked out, increasing the risk of unauthorized access."
        Category = "Authentication & Permission Policies"
        TechnicalDetails = $null # will fulfill later 
        RemedediationSolution = "Review and configure the account lockout policy settings to ensure that user accounts are locked out after a reasonable number of failed login attempts, and adjust the lockout duration and observation window as needed."
        MITREMapping = "[MITRE] T1110: Brute Force"
        Status = $null
        ErrorMsg = $null 
    }

    try {
        # Get the account lockout policy
        $policy = Get-ADDefaultDomainPasswordPolicy

        # Check the lockout threshold
        if ($policy.LockoutThreshold -eq 0) {
            $result.Status = "Fail"
            $result.TechnicalDetails = "Account lockout threshold is not set."
        } else {
            $result.Status = "Pass"
            $result.TechnicalDetails = "Account lockout threshold is set to $($policy.LockoutThreshold) invalid logon attempts."
        }

        # Additional checks for lockout duration and observation window can be added here
    } catch {
        $result.Status = "Error"
        $result.ErrorMsg = $_.Exception.Message
    }

    return $result
}

# Example usage
$result = Check-AccountLockoutPolicy
Write-Output $result | ConvertTo-Json -Depth 10

# Command to run the test case and achieve a "pass" status
# Set-ADDefaultDomainPasswordPolicy -Identity $currentDomain.DistinguishedName -LockoutThreshold 0 -LockoutDuration 0 -LockoutObservationWindow 0

# Command to run the test case and achieve a "pass" status
# Set-ADDefaultDomainPasswordPolicy -Identity Vul-DC -LockoutThreshold 5 -LockoutDuration 30 -LockoutObservationWindow 15
