function Check-AdminSDHolderInheritance {
    [CmdletBinding()]
    param()
  
    # $result = @{
    #     Description            = "Checks if inheritance is enabled on the AdminSDHolder object in Active Directory."
    #     Severity               = "High"
    #     LikelihoodOfCompromise = "High"
    #     Findings          = $null
    #     FindingSummary          = $null
    #     Score                  = $null
    #     Remediation            = "Enable inheritance on the AdminSDHolder object to ensure consistent security settings."
    #     Status                 = $null
    # }

    $result = @{
        ItemNumber = "ADS009"
        UseCase = "Inheritance enabled on AdminSDHolder"
        WeightedScore = 5
        TechnicalInformation = "The AdminSDHolder object in Active Directory protects privileged accounts by applying strict permissions. If inheritance is enabled on this object, it can unintentionally allow less restrictive permissions to flow down, weakening security. Attackers may exploit this to gain unauthorized access to high-privilege accounts."
        Category = "Object Privilege & Configuration"
        TechnicalDetails = $null # will fullfill later 
        RemedediationSolution = 
        "General Case:
The adminSDHolder object sets permissions on privileged AD objects to protect them from misconfigurations. Modifying its default permissions is discouraged. Dangerous permissions should be removed using tools like adsiedit.msc or ldp utility.

Specific Cases:
In an administrative forest, stricter access rights may be granted to trusted groups if permission inheritance is disabled. For flagged Exchange access rights (e.g., WRITE_SPN), apply the latest cumulative updates. If Azure ADConnect (MSOL) accounts are flagged, reconfigure access rights using the provided PowerShell cmdlets.

Context: Control Path Exposure
Control paths represent access permissions that attackers could exploit. Review these to prevent unauthorized access. Some paths may be fixed through domain controller updates or registry settings.

Known Fixes:
KB5008383 addresses OWNER and WRITE_OWNER control paths.
Various Exchange Server control paths (WRITE_SPN, WRITE_ALT_IDENTITY) are fixed through updates. Remove legacy Exchange groups (Exchange Enterprise Servers) if migrated from versions earlier than 2010.
Exchange Server Specifics:
Apply relevant security updates and run /PrepareAllDomains to address control path issues:

Exchange Server 2019/2016: Install May 2022 SU (KB5014261).
Exchange Server 2013: Install May 2022 SU (KB5014260).
Legacy Exchange Server 2010 is no longer supported.
For other control paths, manual investigation is needed. A list of Exchange Server security updates is available."
        MITREMapping = "[MITRE] T1078: Valid Accounts"
        Status = $null
        ErrorMsg = $null 
    }
  
    try {
        # Get the default naming context for the domain
        $defaultNamingContext = (Get-ADRootDSE).defaultNamingContext
  
        # Construct the search base
        $searchBase = "CN=AdminSDHolder,CN=System,$defaultNamingContext"
  
        # Get the AdminSDHolder object
        $adminSDHolder = Get-ADObject -SearchBase $searchBase -Filter {ObjectClass -eq "adminSDHolder"}
  
        if (-not [string]::IsNullOrWhiteSpace($adminSDHolder)) {
            # Check if inheritance is enabled
            $inheritanceEnabled = $adminSDHolder.DenyEveryone -ne $true
  
            if ($inheritanceEnabled) {
                $result.Status = "Pass"
                $result.TechnicalDetails  = "Pass: Inheritance is enabled on the AdminSDHolder object."
            } else {
                $result.Status = "Fail"
                $result.TechnicalDetails  = "Fail: Inheritance is not enabled on the AdminSDHolder object."
            }
        } else {
            $result.Status = "Fail"
            $result.TechnicalDetails = "Fail: AdminSDHolder object not found."
        }
  
    } catch {
        $errstr = $_.Exception.Message
        $result.Status = "Fail"
        $result.TechnicalDetails  = "Error: $errstr"
    }
  
    return $result
  }

# Example usage
$result = Check-AdminSDHolderInheritance
Write-Output $result | ConvertTo-Json -Depth 10