function Check-ShadowPrincipalMembers {

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