function Check-BastionForestTrusts {
    # $result = @{
    #     Description            = "Checks if the current domain is configured as a bastion forest by examining trust relationships and detecting the presence of shadow principals."
    #     Severity               = "High"
    #     LikelihoodOfCompromise = "High"
    #     Findings               = $null
    #     FindingSummary         = $null
    #     Score                  = $null
    #     Remediation            = "If a bastion forest configuration is detected, review trust relationships and shadow principals to ensure they are properly secured."
    #     Status                 = $null
    # }

    $result = @{
        ItemNumber = "ADS033"
        UseCase = "PAM Trust - Bastion Forest Trusts"
        WeightedScore = 5
        TechnicalInformation = "A bastion forest is a domain specifically set up to manage and protect trust relationships between forests, often with heightened security measures. By examining trust relationships and detecting shadow principals (unauthorized or hidden accounts), you can determine if the current domain is configured as a bastion forest."
        Category = "Forest & Trust Configuration"
        TechnicalDetails = $null # will fullfill later 
        RemedediationSolution = 
        "Regular checks help ensure that any security mechanisms designed to protect or isolate critical domains are functioning correctly and that there are no vulnerabilities that could be exploited."
        MITREMapping = "[MITRE] T1134: Access Token Manipulation"
        Status = $null
        ErrorMsg = $null 
    }

    # try {
    #     $findings = @()

    #     # Step 1: Get trust relationships where ForestTransitive is true and SIDFiltering is disabled
    #     $vulnerableTrusts = Get-ADTrust -Filter {(ForestTransitive -eq $True) -and (SIDFilteringQuarantined -eq $False)}

    #     # Step 2: Check for Shadow Principals if vulnerable trusts are found
    #     if ($vulnerableTrusts.Count -gt 0) {
    #         $shadowPrincipals = Get-ADObject -SearchBase ("CN=Shadow Principal Configuration,CN=Services," + (Get-ADRootDSE).configurationNamingContext) -Filter * -Properties * | select Name,member,msDS-ShadowPrincipalSid

    #         if ($shadowPrincipals.Count -gt 0) {
    #             $vulnerableTrusts | ForEach-Object {
    #                 $findings += "Trust with $($_.TargetDomainName) is transitive, does not have SID filtering enabled, and shadow principals exist."
    #             }
    #             $result.Status = "Fail"
    #             $result.FindingSummary = "Bastion forest configuration detected. Immediate action required."
    #         } else {
    #             $result.Status = "Warning"
    #             $result.FindingSummary = "Vulnerable trust relationships detected but no shadow principals found. Further investigation required."
    #         }
    #     } else {
    #         $result.Status = "Pass"
    #         $result.FindingSummary = "No vulnerable trust relationships detected."
    #     }

    #     $result.Findings = $findings
    # }
    # catch {
    #     $result.FindingSummary = "Error: $($_.Exception.Message)"
    #     $result.Status = "Error"
    # }

    # return $result

    try {
        $technicalDetails = ""
    
        # Step 1: Get trust relationships where ForestTransitive is true and SIDFiltering is disabled
        $vulnerableTrusts = Get-ADTrust -Filter {(ForestTransitive -eq $True) -and (SIDFilteringQuarantined -eq $False)}
    
        # Step 2: Check for Shadow Principals if vulnerable trusts are found
        if ($vulnerableTrusts.Count -gt 0) {
            $shadowPrincipals = Get-ADObject -SearchBase ("CN=Shadow Principal Configuration,CN=Services," + (Get-ADRootDSE).configurationNamingContext) -Filter * -Properties * | select Name,member,msDS-ShadowPrincipalSid
    
            if ($shadowPrincipals.Count -gt 0) {
                $technicalDetails = "Bastion forest configuration detected. Immediate action required. The following vulnerable trusts were found:"
                $vulnerableTrusts | ForEach-Object {
                    $technicalDetails += "`nTrust with $($_.TargetDomainName) is transitive, does not have SID filtering enabled, and shadow principals exist."
                }
                $result.Status = "Fail"
            } else {
                $technicalDetails = "Vulnerable trust relationships detected but no shadow principals found. Further investigation required."
                $result.Status = "Warning"
            }
        } else {
            $technicalDetails = "No vulnerable trust relationships detected."
            $result.Status = "Pass"
        }
    
        $result.TechnicalDetails = $technicalDetails
    }
    catch {
        $result.TechnicalDetails = "Error occurred during check: $($_.Exception.Message)"
        $result.Status = "Error"
    }
    
    return $result

}

# Example usage
$result = Check-BastionForestTrusts
Write-Output $result | ConvertTo-Json -Depth 10