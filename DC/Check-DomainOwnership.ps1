$settings = @{
    'domainController.name' = "DC01"
    'domainController.forest' = "example.com"
}

function Check-DomainOwnership {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$settings
    )
    
    # $result = @{
    #     Description            = "Checks ownership of a specific domain in Active Directory."
    #     Severity               = "High"
    #     LikelihoodOfCompromise = "High"
    #     Findings          = $null
    #     FindingSummary          = $null
    #     Score                  = $null
    #     Remediation            = "Investigate and address any unauthorized ownership changes."
    #     Status                 = $null
    # }

    $result = @{
        ItemNumber = "ADS019"
        UseCase = "Domain Ownership"
        WeightedScore = 5
        TechnicalInformation = "Domain ownership in Active Directory refers to which entity or user has control over the domain settings. Improper or unauthorized ownership can be exploited by attackers to manipulate domain configurations, leading to potential security breaches. Verifying domain ownership ensures that only authorized administrators have control, reducing the risk of malicious changes."
        Category = "Object Privilege & Configuration"
        TechnicalDetails = $null # will fullfill later 
        RemedediationSolution = "Investigate and address any unauthorized ownership changes."
        MITREMapping = "[MITRE] T1033: System Owner/User Directory"
        Status = $null
        ErrorMsg = $null 
    }
    
    # try {
    #     # Get the forest root domain
    #     $forestRootDomain = (Get-ADForest -Server $settings.'domainController.name').RootDomain
    
    #     if ($settings.'domainController.forest' -eq $forestRootDomain) {
    #         $result.Status = "Pass"
    #         $result.FindingSummary = "Pass: The specified domain is the forest root domain and is owned appropriately."
    #     } else {
    #         $result.Status = "Fail"
    #         $result.FindingSummary = "Fail: The specified domain is not the forest root domain or ownership is unauthorized."
    #     }
    
    # } catch {
    #     $errstr = $_.Exception.Message
    #     $result.Status = "Fail"
    #     $result.FindingSummary = "Error: $errstr"
    # }

    try {
            # Get the forest root domain
            $forestRootDomain = (Get-ADForest -Server $settings.'domainController.name').RootDomain
        
            if ($settings.'domainController.forest' -eq $forestRootDomain) {
                # Write-Host $forestRootDomain
                # Write-Host $settings.'domainController.forest'
                $result.Status = "Pass"
            } else {
                $result.Status = "Fail"
                $TechnicalDetails = "The current domain '" + $settings.'domainController.forest' + "' does not match the forest root domain '" + $forestRootDomain + "'."
            }
        
        } catch {
            $errstr = $_.Exception.Message
            $result.Status = "Not applicable"
            $result.ErrorMsg = "Error: $errstr"
    }
    Write-Host $result.TechnicalDetails
    return $result
    }

# Example usage
$result = Check-DomainOwnership -settings $settings
Write-Output $result