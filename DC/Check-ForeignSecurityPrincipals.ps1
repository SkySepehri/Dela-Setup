function Check-ForeignSecurityPrincipals {
    [CmdletBinding()]
    param()
    
    # $result = @{
    #     Description            = "Checks for Foreign Security Principals in Active Directory."
    #     Severity               = "Medium"
    #     LikelihoodOfCompromise = "Medium"
    #     Findings          = $null
    #     FindingSummary          = $null
    #     Score                  = $null
    #     Remediation            = "Review and manage Foreign Security Principals based on trust relationships."
    #     Status                 = $null
    # }

    $result = @{
        ItemNumber = "ADS025"
        UseCase = "Foreign Security Principals Misconfiguration"
        WeightedScore = 20
        TechnicalInformation = "Foreign Security Principals in Active Directory are objects that represent security principals from external domains or forests. These objects are typically used to grant permissions to users or groups outside the local domain. Checking for Foreign Security Principals helps identify any external accounts or groups that have been granted access to resources within your domain, ensuring that permissions are correctly managed and no unauthorized external entities have access."
        Category = "AD Domain & Domain Group Configuration"
        TechnicalDetails = $null # will fullfill later 
        RemedediationSolution = 
        "Review and manage Foreign Security Principals based on trust relationships.

Instructions to Review and Manage Foreign Security Principals
Open Active Directory Users and Computers
Locate Foreign Security Principals Container:
In the left pane, navigate to the ForeignSecurityPrincipals container.
View Foreign Security Principals:
Click on the ForeignSecurityPrincipals container to view the list of foreign security principals from trusted domains.
Review Permissions:
Right-click on a foreign security principal and select Properties to review its permissions and group memberships.
Manage Permissions:
To modify permissions, right-click the foreign security principal, select Add to a group or Remove from group as needed."
        MITREMapping = "[MITRE] T1078: Valid Accounts"
        Status = $null
        ErrorMsg = $null 
    }
    
    try {
        # Get Foreign Security Principals in the domain
        $foreignSecurityPrincipals = Get-ADObject -Filter {ObjectClass -eq "foreignSecurityPrincipal"}
    
        if ($foreignSecurityPrincipals.Count -gt 0) {
            $result.Status = "Fail"
            # $result.Findings = $foreignSecurityPrincipals
            # $result.FindingSummary = "Fail: Foreign Security Principals found in the Active Directory."
            $result.TechnicalDetails = "Foreign Security Principals found in the Active Directory:`n"
            $result.TechnicalDetails += ($foreignSecurityPrincipals | ForEach-Object { $_.DistinguishedName }) -join "`n"
        } else {
            $result.Status = "Pass"
            $result.TechnicalDetails  = "Pass: No Foreign Security Principals found in the Active Directory."
        }
    
    } catch {
        $errstr = $_.Exception.Message
        $result.Status = "Fail"
        $result.TechnicalDetails  = "Error: $errstr"
    }
    
    return $result
    }

# Example usage
$result = Check-ForeignSecurityPrincipals
Write-Output $result | ConvertTo-Json -Depth 10