function Check-BastionForestManagement {
    # $result = @{
    #     Description            = "Checks if the current domain is managed by a bastion forest by examining trust attributes for PAM trust."
    #     Severity               = "High"
    #     LikelihoodOfCompromise = "High"
    #     Findings               = $null
    #     FindingSummary         = $null
    #     Score                  = $null
    #     Remediation            = "Review the trust relationships and ensure proper security configurations. If PAM trust is detected, verify that all PAM-related security controls are in place."
    #     Status                 = $null
    # }

    $result = @{
        ItemNumber = "ADS035"
        UseCase = "PAM Trust - Bastion Forest Managed"
        WeightedScore = 25
        TechnicalInformation = "A bastion forest is designed to manage and secure trust relationships between domains. To check if the current domain is managed by a bastion forest, examine trust attributes specifically for Privileged Access Management (PAM) trust. PAM trusts are used to enforce strict security measures for privileged accounts."
        Category = "Forest & Trust Configuration"
        TechnicalDetails = $null # will fullfill later 
        RemedediationSolution = 
        "Regularly verifying these trust attributes helps ensure that the domain is appropriately protected and managed according to bastion forest principles."
        MITREMapping = "[MITRE] T1134: Access Token Manipulation"
        Status = $null
        ErrorMsg = $null 
    }


    # try {
    #     $findings = @()

    #     # Step 1: Run the command to get trust relationships and their attributes
    #     $trusts = Get-ADTrust -Filter {(ForestTransitive -eq $True)} -Properties TrustAttributes, TargetDomainName

    #     # Step 2: Check if any trust attributes match the indicator for PAM trust
    #     foreach ($trust in $trusts) {
    #         if ($trust.TrustAttributes -eq 1096) {
    #             $findings += "PAM trust detected with domain: $($trust.TargetDomainName)"
    #         }
    #     }

    #     # Determine the status based on findings
    #     if ($findings.Count -gt 0) {
    #         $result.Status = "Warning"
    #         $result.FindingSummary = "PAM trust relationship detected, indicating the domain may be managed by a bastion forest."
    #     } else {
    #         $result.Status = "Pass"
    #         $result.FindingSummary = "No PAM trust relationships detected."
    #     }

    #     $result.Findings = $findings
    # }
    # catch {
    #     $result.FindingSummary = "Error: $($_.Exception.Message)"
    #     $result.Status = "Error"
    # }
    try {
        $technicalDetails = @()
    
        # Step 1: Run the command to get trust relationships and their attributes
        $trusts = Get-ADTrust -Filter {(ForestTransitive -eq $True)} -Properties TrustAttributes, TargetDomainName
    
        # Step 2: Check if any trust attributes match the indicator for PAM trust
        foreach ($trust in $trusts) {
            if ($trust.TrustAttributes -eq 1096) {
                $technicalDetails += "PAM trust detected with domain: $($trust.TargetDomainName)"
            }
        }
    
        # Determine the status based on findings
        if ($technicalDetails.Count -gt 0) {
            $result.Status = "Fail"
            $result.TechnicalDetails = "PAM trust relationship(s) detected, indicating the domain may be managed by a bastion forest. Details: " + ($technicalDetails -join "; ")
        } else {
            $result.Status = "Pass"
            $result.TechnicalDetails = "No PAM trust relationships detected."
        }
    }
    catch {
        $result.TechnicalDetails = "Error occurred during the check."
        $result.Status = "Error"
        $result.ErrorMsg = $_.Exception.Message
    }

    return $result


}

#Key Trust Attributes:
#TRUST_ATTRIBUTE_PIM_TRUST (0x00000400): Indicates a PAM trust.
#TRUST_ATTRIBUTE_TREAT_AS_EXTERNAL (0x00000040): Indicates that the trust is treated as external.
#TRUST_ATTRIBUTE_FOREST_TRANSITIVE (0x00000008): Indicates that the trust is forest-transitive.
#The combined value for a PAM trust with these attributes would be 1096 (1024 + 64 + 8).

# Example usage
$result = Check-BastionForestManagement
Write-Output $result | ConvertTo-Json -Depth 10