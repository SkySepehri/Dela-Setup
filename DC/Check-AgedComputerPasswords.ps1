function Check-AgedComputerPasswords {
    [CmdletBinding()]
    param()
  
    # $result = @{
    #     Description            = "Checks for aged computer passwords in the Active Directory."
    #     Severity               = "High"
    #     LikelihoodOfCompromise = "High"
    #     Findings          = $null
    #     FindingSummary          = $null
    #     Score                  = $null
    #     Remediation            = "Investigate and address any computers with aged passwords."
    #     Status                 = $null
    # }

    $result = @{
        ItemNumber = "ADS002"
        UseCase = "Aged Computer Passwords"
        WeightedScore = 25
        TechnicalInformation = "Aged computer passwords in Active Directory refer to machine account passwords that have not been updated for an extended period. If left unchanged, these stale passwords can be exploited by attackers to maintain persistent access to the network."
        Category = "Account Hygiene"
        TechnicalDetails = $null # will fullfill later 
        RemedediationSolution = 
        "Regularly checking and updating computer passwords reduces the risk of unauthorized access through compromised accounts."
        MITREMapping = "[MITRE] T1201: Password Policy Discovery "
        Status = $null
        ErrorMsg = $null 
    }

    $settings = @{
        'domainController.name' = "DC01"
    }
  
    try {
        # Get all computers in the domain
        $computers = Get-ADComputer -Server $settings.'domainController.name' -Filter *
  
        # Get the maximum password age from the domain password policy
        $maxPwdAge = (Get-ADDefaultDomainPasswordPolicy).MaxPasswordAge
  
        # Calculate the maximum password age in days
        $maxPwdAgeDays = $maxPwdAge.Days
  
        # Get the current date
        $currentDate = Get-Date
  
        # Calculate the maximum password age cutoff date
        $cutoffDate = $currentDate.AddDays(-$maxPwdAgeDays)
  
        # Check each computer for aged passwords
        $agedPasswords = foreach ($computer in $computers) {
            $passwordLastSet = $computer.PasswordLastSet
  
            if ($passwordLastSet -lt $cutoffDate) {
                $computer
            }
        }
  
        # if ($agedPasswords.Count -gt 0) {
        #     $result.Status = "Fail"
        #     $result.Findings = $agedPasswords
        #     $result.TechnicalDetails = "Fail: Aged computer passwords found in the Active Directory."
        # } else {
        #     $result.Status = "Pass"
        #     $result.TechnicalDetails = "Pass: No aged computer passwords found in the Active Directory."
        # }

        if ($agedPasswords.Count -gt 0) {
            $result.Status = "Fail"
            $result.TechnicalDetails = "Fail: Aged computer passwords found in the Active Directory. Affected computers: $($agedPasswords | ForEach-Object { $_.Name } | Join-String -Separator ', ')"
        } else {
            $result.Status = "Pass"
            $result.TechnicalDetails = "Pass: No aged computer passwords found in the Active Directory."
        }
        
  
    } catch {
        $errstr = $_.Exception.Message
        $result.Status = "Fail"
        $result.TechnicalDetails = "Error: $errstr"
    }
  
    return $result
  }

# Example usage
$result = Check-AgedComputerPasswords
Write-Output $result