function Check-ADDisplaySpecifiers {
    [CmdletBinding()]
    param()
  

    $result = @{
        ItemNumber = "ADS024"
        UseCase = "AD Display Specifiers Misconfiguration"
        WeightedScore = 20
        TechnicalInformation = "AD Display Specifiers in Active Directory define the attributes used to display user, group, and computer objects in the Active Directory Users and Computers (ADUC) console. If these specifiers are misconfigured, they can potentially expose sensitive information or be used to mislead administrators about object properties."
        Category = "AD Domain & Domain Group Configuration"
        TechnicalDetails = $null # will fullfill later 
        RemedediationSolution = 
        "Regularly review and audit AD Display Specifiers to ensure they are configured correctly and do not expose sensitive information. Update or remove any outdated or unnecessary specifiers and ensure that only authorized personnel have access to modify these settings."
        MITREMapping = "[MITRE] T1098: Account Manipulation"
        Status = $null
        ErrorMsg = $null 
    }
  
    try {
        # Get the default naming context for the domain
        $defaultNamingContext = (Get-ADRootDSE).defaultNamingContext
  
        # Construct the search base
        $searchBase = "CN=DisplaySpecifiers,CN=Configuration,$defaultNamingContext"
  
        # Get AD Display Specifiers
        $displaySpecifiers = Get-ADObject -SearchBase $searchBase -Filter {ObjectClass -eq "displaySpecifier"}
  
        if ($displaySpecifiers.Count -gt 0) {
            # Limit the output to the first 5 Display Specifiers (change the number as needed)
            $limitedSpecifiers = $displaySpecifiers | Select-Object -First 5
        
            $result.Status = "Fail"
            $result.TechnicalDetails = "AD Display Specifiers found in Active Directory. Display Specifiers Count: $($displaySpecifiers.Count)`n`nFirst 5 Display Specifiers:`n" + ($limitedSpecifiers | Format-List | Out-String)
        } else {
            $result.Status = "Pass"
            $result.TechnicalDetails = "Pass: No AD Display Specifiers found in Active Directory."
        }
  
    } catch {
        $errstr = $_.Exception.Message
        $result.Status = "Fail"
        $result.TechnicalDetails = "Error: $errstr"
    }
  
    return $result
  }

# Example usage
$result = Check-ADDisplaySpecifiers
Write-Output $result | ConvertTo-Json -Depth 10