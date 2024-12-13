function Check-ShadowPrincipalMembers {
    # $result = @{
    #     Description            = "Checks which users or principals are members of shadow principals in the domain."
    #     Severity               = "Medium to High"
    #     LikelihoodOfCompromise = "Medium"
    #     Findings               = $null
    #     FindingSummary         = $null
    #     Score                  = $null
    #     Remediation            = "Review and remove unauthorized users or principals from shadow principal configurations."
    #     Status                 = $null
    # }

    $result = @{
        ItemNumber = "ADS034"
        UseCase = "PAM Trust -  Shadow Principal Members"
        WeightedScore = 25
        TechnicalInformation = "Shadow principals are unauthorized or hidden accounts that can potentially bypass security controls and gain illicit access. Checking which users or principals are members of shadow principals helps identify and address these covert accounts."
        Category = "Forest & Trust Configuration"
        TechnicalDetails = $null # will fullfill later 
        RemedediationSolution = 
        "Regularly auditing these memberships ensures that no unauthorized or malicious entities are operating within the domain, thereby enhancing overall security."
        MITREMapping = "[MITRE] T1134: Access Token Manipulation"
        Status = $null
        ErrorMsg = $null 
    }

    # try {
    #     $findings = @()

    #     # Step 1: Run the command to get shadow principal members
    #     $shadowPrincipals = Get-ADObject -SearchBase ("CN=Shadow Principal Configuration,CN=Services," + (Get-ADRootDSE).configurationNamingContext) -Filter * -Properties * |
    #                         Select-Object Name, member, msDS-ShadowPrincipalSid

    #     # Step 2: Check if any shadow principals are found
    #     if ($shadowPrincipals.Count -gt 0) {
    #         $shadowPrincipals | ForEach-Object {
    #             $findings += "Shadow Principal: $($_.Name), Members: $($_.member -join ', '), Shadow Principal SID: $($_.'msDS-ShadowPrincipalSid')"
    #         }
    #         $result.Status = "Warning"
    #         $result.FindingSummary = "Shadow principals and their members detected. Review required."
    #     } else {
    #         $result.Status = "Pass"
    #         $result.FindingSummary = "No shadow principals detected."
    #     }

    #     $result.Findings = $findings
    # }
    # catch {
    #     $result.FindingSummary = "Error: $($_.Exception.Message)"
    #     $result.Status = "Error"
    # }

    # return $result

    
    try {
        $shadowPrincipals = Get-ADObject -SearchBase ("CN=Shadow Principal Configuration,CN=Services," + (Get-ADRootDSE).configurationNamingContext) -Filter * -Properties * |
                            Select-Object Name, member, msDS-ShadowPrincipalSid

        if ($shadowPrincipals.Count -gt 0) {
            $technicalDetails = "Shadow principals and their members detected:`n"
            $shadowPrincipals | ForEach-Object {
                $technicalDetails += "Shadow Principal: $($_.Name), Members: $($_.member -join ', '), Shadow Principal SID: $($_.'msDS-ShadowPrincipalSid')`n"
            }
            $result.Status = "Warning"
            $result.TechnicalDetails = $technicalDetails
        } else {
            $result.Status = "Pass"
            $result.TechnicalDetails = "No shadow principals detected."
        }
    }
    catch {
        $result.TechnicalDetails = "Error occurred while checking shadow principals: $($_.Exception.Message)"
        $result.Status = "Error"
        $result.ErrorMsg = $_.Exception.Message
    }

    return $result
}

# Example usage
$result = Check-ShadowPrincipalMembers
Write-Output $result | ConvertTo-Json -Depth 10