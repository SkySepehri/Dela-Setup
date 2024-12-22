function Check-AgedComputerPasswords {
    [CmdletBinding()]
    param (
        [string]$Server
    )

    $result = @{
        ItemNumber = "ADS002"
        UseCase = "Check Aged Computer Passwords"
        WeightedScore = 5
        TechnicalInformation = "Aged computer passwords in Active Directory refer to machine account passwords that have not been updated for an extended period. If left unchanged, these stale passwords can be exploited by attackers to maintain persistent access to the network."
        Category = "Account Hygiene"
        TechnicalDetails = $null # will fulfill later 
        RemedediationSolution = "Regularly checking and updating computer passwords reduces the risk of unauthorized access through compromised accounts."
        MITREMapping = "[MITRE] T1201: Password Policy Discovery"
        Status = $null
        ErrorMsg = $null 
    }

    try {
        # Get the current date
        $currentDate = Get-Date

        # Query Active Directory for computer accounts with passwords older than 30 days
        $agedComputerPasswords = Get-ADComputer -Server $Server -Filter * -Properties PasswordLastSet | Where-Object {
            ($currentDate - $_.PasswordLastSet).Days -gt 30
        }

        if ($agedComputerPasswords.Count -gt 0) {
            $result.Status = "Fail"
            $result.TechnicalDetails = $agedComputerPasswords | Select-Object Name, PasswordLastSet
        } else {
            $result.Status = "Pass"
            $result.TechnicalDetails = "No computer accounts with aged passwords found."
        }
    } catch {
        $result.Status = "Error"
        $result.ErrorMsg = $_.Exception.Message
    }

    return $result
}

# Example usage
$Server = "Vul-DC"
$result = Check-AgedComputerPasswords -Server $Server
Write-Output $result