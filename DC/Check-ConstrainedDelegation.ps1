# Function to check password policy
function Check-ConstrainedDelegation {
    [CmdletBinding()]
    param(
        [string]$DomainController = $null
    )

    # $result = @{
    #     Description            = "Checks for Constrained Delegation settings in Active Directory."
    #     Severity               = "High"
    #     LikelihoodOfCompromise = "High"
    #     Findings               = $null
    #     FindingSummary         = $null
    #     Score                  = $null
    #     Remediation            = "Review and secure Constrained Delegation settings to prevent unauthorized access."
    #     Status                 = $null
    # }

    $result = @{
        ItemNumber = "ADS005"
        UseCase = "Constrained Delegation"
        WeightedScore = 5
        TechnicalInformation = "Ensures no constrained delegations  transition are applied to Domain Controllers (DCs). This setup allows a delegate to impersonate users without proper service limitations, potentially enabling domain control by impersonating a domain admin and making unauthorized modifications via LDAP. The configuration is managed through the msDS-AllowedToDelegateTo attribute and a flag in userAccountControl."
        Category = "Object Privilege & Configuration"
        TechnicalDetails = $null # will fullfill later 
        RemedediationSolution = 
        "Constrained delegation with protocol transition or having constrained authentication delegationsto a domain controller service must not be allowed.Edit the msDS-AllowedToDelegateTo attribute for the accounts listed below to remove the SPNs associated with the domain controllers involved.This can be fixed with PowerShell too,the following command can be used to remove such a delegation on a target computer named COMPUTER: Set-ADComputer COMPUTER -PrincipalsAllowedToDelegateToAccount $Null"
        MITREMapping = "[MITRE] T1187: Forced Authentication"
        Status = $null
        ErrorMsg = $null 
    }

    try {
        # Import the Active Directory module
        Import-Module ActiveDirectory -ErrorAction Stop

        # Get all computer objects
        # $computers = if ($DomainController) {
        #     Get-ADComputer -Server $settings.'domainController.name' -Filter * -Server $DomainController
        # } else {
        #     Get-ADComputer -Server $settings.'domainController.name' -Filter *
        # }

        # if (-not $computers) {
        #     throw "No computer objects found."
        # }

        # # Check Constrained Delegation settings for each computer
        # $constrainedDelegationEnabled = $computers | ForEach-Object {
        #     Write-Host "Checking computer: $($_.Name)"
        #     $delegationSetting = if ($DomainController) {
        #         Get-ADObject -Identity $_.DistinguishedName -Properties msDS-AllowedToDelegateTo -Server $DomainController
        #     } else {
        #         Get-ADObject -Identity $_.DistinguishedName -Properties msDS-AllowedToDelegateTo
        #     }

        #     if ($delegationSetting."msDS-AllowedToDelegateTo") {
        #         Write-Host "Delegation setting for $($_.Name): $($delegationSetting."msDS-AllowedToDelegateTo" | Out-String)"
        #         return $true
        #     } else {
        #         return $false
        #     }
        # }

        # if ($constrainedDelegationEnabled -contains $true) {
        #     $result.Status = "Fail"
        #     $result.FindingSummary = "Fail: Constrained Delegation is enabled on one or more computer accounts."
        # } else {
        #     $result.Status = "Pass"
        #     $result.FindingSummary = "Pass: Constrained Delegation is not enabled on any computer accounts."
        # }
        $constrainedDelegationComputers = @()

        $computers | ForEach-Object {
            Write-Host "Checking computer: $($_.Name)"
            $delegationSetting = if ($DomainController) {
                Get-ADObject -Identity $_.DistinguishedName -Properties msDS-AllowedToDelegateTo -Server $DomainController
            } else {
                Get-ADObject -Identity $_.DistinguishedName -Properties msDS-AllowedToDelegateTo
            }

            if ($delegationSetting."msDS-AllowedToDelegateTo") {
                Write-Host "Delegation setting for $($_.Name): $($delegationSetting."msDS-AllowedToDelegateTo" | Out-String)"
                $constrainedDelegationComputers += @{
                    Name = $_.Name
                    DelegationSettings = $delegationSetting."msDS-AllowedToDelegateTo"
                }
            }
        }

        if ($constrainedDelegationComputers.Count -gt 0) {
            $result.Status = "Fail"
            $result.TechnicalDetails = "Constrained Delegation is enabled on the following computer accounts:`n"
            foreach ($computer in $constrainedDelegationComputers) {
                $result.TechnicalDetails += "Computer: $($computer.Name)`n"
                $result.TechnicalDetails += "Delegation Settings: $($computer.DelegationSettings -join ', ')`n`n"
            }
        } else {
            $result.Status = "Pass"
            $result.TechnicalDetails = "Constrained Delegation is not enabled on any computer accounts."
        }

    } catch {
        $errstr = $_.Exception.Message
        $result.Status = "Fail"
        $result.FindingSummary = "Error: $errstr"
    }

    return $result
}

# Example usage
$result = Check-ConstrainedDelegation -DomainController "AgentDomainController"
Write-Output $result | ConvertTo-Json -Depth 10