function Check-BuiltInGuestAccountEnabled {
    [CmdletBinding()]
    param()
    
    # $result = @{
    #     Description            = "Checks if the built-in Guest account is enabled in Active Directory."
    #     Severity               = "High"
    #     LikelihoodOfCompromise = "High"
    #     Findings          = $null
    #     FindingSummary          = $null
    #     Score                  = $null
    #     Remediation            = "Disable the built-in Guest account for enhanced security."
    #     Status                 = $null
    # }

    $result = @{
        ItemNumber = "ADS001"
        UseCase = "Built-in Guest Account Enabled"
        WeightedScore = 5
        TechnicalInformation = "The Guest account in Active Directory is a built-in account with limited access, often disabled by default. If enabled, it can be exploited by attackers to gain unauthorized access, as it typically lacks strong security controls. Ensuring the Guest account is disabled helps prevent attackers from leveraging it for malicious activities."
        Category = "Account Hygiene"
        TechnicalDetails = $null # will fullfill later 
        RemedediationSolution = 
        "Disable the built-in Guest account for enhanced security.
        Instructions to Disable the Built-in Guest Account in On-Premises AD
        Open Active Directory Users and Computers
        Locate Guest Account:
        In the left pane, navigate to the Users container or the appropriate organizational unit (OU) where the Guest account is located.
        Right-Click Guest Account:
        Find the Guest account (usually named Guest), right-click on it, and select Properties.
        Disable Account:
        In the Properties window, check the box for Account is disabled.
        Apply Changes"
        MITREMapping = "[MITRE] T1078: Valid Accounts"
        Status = $null
        ErrorMsg = $null 
    }
    
    try {
        # Check if the built-in Guest account in Active Directory is enabled
        $guestAccount = Get-ADUser -Filter { SamAccountName -eq "Guest" } -Properties Enabled

        if ($guestAccount.Enabled) {
            $result.Status = "Fail"
            $result.TechnicalDetails = "Fail: The built-in Guest account is enabled."
        } else {
            $result.Status = "Pass"
            $result.TechnicalDetails = "Pass: The built-in Guest account is not enabled."
        }
    
    } catch {
        $errstr = $_.Exception.Message
        $result.Status = "Fail"
        $result.TechnicalDetails = "Error: $errstr"
    }
    
    return $result
    }

# Example usage
$result =  Check-BuiltInGuestAccountEnabled
Write-Output $result | ConvertTo-Json -Depth 10
