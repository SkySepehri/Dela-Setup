function Detect-SameDomainSIDHistory {
    # $result = @{
    #     Description            = "Detects potential forest-to-forest compromise by checking for suspicious entries in the SIDHistory attribute."
    #     Severity               = "High"
    #     LikelihoodOfCompromise = "High"
    #     Findings               = $null
    #     FindingSummary         = $null
    #     Score                  = $null
    #     Remediation            = "If suspicious entries are found in SIDHistory, investigate and remediate as necessary."
    #     Status                 = $null
    # }

    $result = @{
        ItemNumber = "ADS025"
        UseCase = "Suspicious Same Domain SID History"
        WeightedScore = 25
        TechnicalInformation = "SIDHistory is an attribute that tracks security identifiers (SIDs) when objects are migrated between domains or forests. Suspicious entries in SIDHistory can indicate potential forest-to-forest compromises, as attackers may use these entries to gain unauthorized access or escalate privileges."
        Category = "Forest & Trust Configuration"
        TechnicalDetails = $null # will fullfill later 
        RemedediationSolution = 
        "Regularly checking for unusual or unauthorized entries helps detect and prevent cross-forest security breaches."
        MITREMapping = "[MITRE] T1134.005: Access Token Manipulation: SID-History Injection"
        Status = $null
        ErrorMsg = $null 
    }

    try {
        $findings = @()

        # Step 1: Import the Active Directory module
        Import-Module ActiveDirectory

        # Step 2: Get the current domain SID
        [string]$DomainSID = (Get-ADDomain).DomainSID.Value

        # Step 3: Search for users with suspicious SIDHistory entries
        $suspiciousUsers = Get-ADUser -Filter "SIDHistory -Like '*'" -Properties SIDHistory | 
            Where { $_.SIDHistory -Like "$DomainSID-*"}

        if ($suspiciousUsers.Count -gt 0) {
                $technicalDetails = "Suspicious SIDHistory entries detected. Immediate investigation required.`n"
                $suspiciousUsers | ForEach-Object {
                    $technicalDetails += "User $($_.SamAccountName) has a suspicious SIDHistory entry.`n"
                }
                $result.Status = "Fail"
            } else {
                $technicalDetails = "No suspicious SIDHistory entries detected."
                $result.Status = "Pass"
            }
        
            $result.TechnicalDetails = $technicalDetails
        }
        catch {
            $result.TechnicalDetails = "Error: $($_.Exception.Message)"
            $result.Status = "Error"
        }

    #     # Step 4: Check if there are any findings
    #     if ($suspiciousUsers.Count -gt 0) {
    #         $suspiciousUsers | ForEach-Object {
    #             $findings += "User $($_.SamAccountName) has a suspicious SIDHistory entry."
    #         }
    #         $result.Status = "Fail"
    #         $result.FindingSummary = "Suspicious SIDHistory entries detected. Immediate investigation required."
    #     } else {
    #         $result.Status = "Pass"
    #         $result.FindingSummary = "No suspicious SIDHistory entries detected."
    #     }

    #     $result.Findings = $findings
    # }
    # catch {
    #     $result.FindingSummary = "Error: $($_.Exception.Message)"
    #     $result.Status = "Error"
    # }

    return $result
}

# Example usage
$result = Detect-SameDomainSIDHistory
Write-Output $result