function Check-DomainOwnership {
    [CmdletBinding()]
    param (
        [Hashtable]$settings
    )
    
    $result = @{
        ItemNumber = "ADS006"
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

    try {
            # Get the forest root domain
            $forestRootDomain = (Get-ADForest -Server $settings.'domainController.name').RootDomain
        
            if ($settings.'domainController.name' -eq $forestRootDomain) {
                $result.Status = "Pass"
            } else {
                $result.Status = "Fail"
                $TechnicalDetails = "The current domain '" + $settings.'domainController.name' + "' does not match the forest root domain '" + $forestRootDomain + "'."
            }
        
        } catch {
            $errstr = $_.Exception.Message
            $result.Status = "Not applicable"
            $result.ErrorMsg = "Error: $errstr"
    }
    Write-Host $result.TechnicalDetails
    return $result
    }


$settings = @{
    'domainController.name' = $args[0]
}

$result = Check-DomainOwnership -settings $settings
Write-Output $result | ConvertTo-Json -Depth 10
