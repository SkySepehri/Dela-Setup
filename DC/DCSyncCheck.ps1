function DCSyncCheck {
    [CmdletBinding()]
    param (
        [string]$Domain
    )

    $result = @{
        ItemNumber = "ADS037"
        UseCase = "DCSync attack detection"
        WeightedScore = 20
        TechnicalInformation = "DCSync is a technique used to replicate the Active Directory Domain Controller’s (DC) data to an attacker’s machine, allowing them to extract sensitive information such as password hashes and Kerberos tickets. This attack can be leveraged to gain elevated privileges or move laterally within the network by impersonating accounts and decrypting stored credentials."
        Category = "Lateral Movement Analysis"
        TechnicalDetails = $null # will fullfill later 
        RemedediationSolution = 
        "Implement strict access controls to limit which accounts can replicate domain data. Regularly audit permissions for the Replicating Directory Changes and Replicating Directory Changes All rights. Use strong monitoring and alerting systems to detect unauthorized DCSync activity and ensure security best practices are followed for all administrative accounts."
        MITREMapping = "[MITRE] T1003.006: OS Credential Dumping: DCSync"
        Status = $null
        ErrorMsg = $null 
    }

    # try {
    #     # Get the security descriptor of the Active Directory object
    #     $ADDomain = Get-ADDomain -Identity $Domain

    #     if ($ADDomain -eq $null) {
    #         throw "Failed to retrieve Active Directory domain information."
    #     }

    #     $DN = $ADDomain.DistinguishedName

    #     if ([string]::IsNullOrWhiteSpace($DN)) {
    #         throw "Distinguished name (DN) is empty."
    #     }

    #     # Construct the DN with correct formatting
    #     $DNString = ($DN -replace "DC=", ",dc=")
        
    #     $acl = Get-Acl "ad:\$DNString"

    #     # Filter access rules to include only those with either permission
    #     $filteredRules = $acl.Access | Where-Object { $_.ObjectType -eq "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2" -or $_.ObjectType -eq "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2" }

    #     # Select unique IdentityReferences (users/groups)
    #     $usersWithEitherPermission = $filteredRules.IdentityReference | Select-Object -Unique

    #     # Initialize an array to store users with either permission
    #     $usersWithPermission = @()

    #     # Iterate through each user/group with either permission
    #     foreach ($user in $usersWithEitherPermission) {
    #         # Check if the user has either permission
    #         $hasReplicatingChanges = $filteredRules | Where-Object { $_.IdentityReference -eq $user -and $_.ObjectType -eq "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2" }
    #         $hasAllReplicatingChanges = $filteredRules | Where-Object { $_.IdentityReference -eq $user -and $_.ObjectType -eq "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2" }

    #         # Exclude legitimate accounts with both permissions
    #         if ($hasReplicatingChanges -or $hasAllReplicatingChanges -and ($user -ne "Domain Admins" -and $user -ne "Enterprise Admins" -and $user -ne "Administrators")) {
    #             $usersWithPermission += $user 
    #         }
    #     }

    #     if ($usersWithPermission.Count -gt 0) {
    #         #$usersWithPermission | ConvertTo-Json
    #         # Construct the result object for success
    #         $result = @{
    #             Description = "Mimikatz DCSync impersonates a Domain Controller and requests account password data from the targeted DC. Users have been found with replication permissions that could indicate DCSync activity"
    #             Severity = "High"
    #             LikelihoodOfCompromise = "Med"
    #             Findings = $usersWithPermission
    #             FindingSummary = "Investigate the highlighted users for DCSync Network traffic to IP addresses that are not legitimate Domain Controllers. Event ID 4662 events for this user should also be investigated. Logging for EID 4662 is not enabled by default as it creates large volumes of events."                
    #             Remediation = "Investigate the relevant users for DCSync network activity."
    #             Status = "Fail"
    #         }
    #     } else {
    #         # Construct the result object for failure
    #         $result = @{
    #             Description = "."
    #             Severity = "Low"
    #             LikelihoodOfCompromise = "Low"
    #             Findings = $null
    #             FindingSummary = "DCSync permission combinations are not detected."                
    #             Remediation = "Investigate and resolve the issue."
    #             Status = "Pass"
    #         }
    #     }

    #     return $result
    # }
    # catch {
    #     # Construct the error object if an exception occurs
    #     $errorMessage = "Error occurred while checking for DCSync permission: $_"
    #     $errorResult = @{
    #         Description = ""
    #         Severity = ""
    #         LikelihoodOfCompromise = ""
    #         Findings = $null
    #         FindingSummary = "Error: $errorMessage"            
    #         Remediation = "Investigate and resolve the issue."
    #         Status = "Fail"
    #     }

    #     return $errorResult
    # }
    try {
        $ADDomain = Get-ADDomain -Identity $Domain
        if ($null -eq $ADDomain) {
            throw "Failed to retrieve Active Directory domain information."
        }

        $DN = $ADDomain.DistinguishedName
        if ([string]::IsNullOrWhiteSpace($DN)) {
            throw "Distinguished name (DN) is empty."
        }

        $DNString = ($DN -replace "DC=", ",dc=")
        $acl = Get-Acl "ad:\$DNString"

        $filteredRules = $acl.Access | Where-Object { $_.ObjectType -eq "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2" -or $_.ObjectType -eq "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2" }
        $usersWithEitherPermission = $filteredRules.IdentityReference | Select-Object -Unique
        $usersWithPermission = @()

        foreach ($user in $usersWithEitherPermission) {
            $hasReplicatingChanges = $filteredRules | Where-Object { $_.IdentityReference -eq $user -and $_.ObjectType -eq "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2" }
            $hasAllReplicatingChanges = $filteredRules | Where-Object { $_.IdentityReference -eq $user -and $_.ObjectType -eq "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2" }

            if ($hasReplicatingChanges -or $hasAllReplicatingChanges -and ($user -ne "Domain Admins" -and $user -ne "Enterprise Admins" -and $user -ne "Administrators")) {
                $usersWithPermission += $user 
            }
        }

        if ($usersWithPermission.Count -gt 0) {
            $result.TechnicalDetails = "Users found with replication permissions that could indicate DCSync activity: $($usersWithPermission -join ', ')"
            $result.Status = "Fail"
        } else {
            $result.TechnicalDetails = "No suspicious DCSync permission combinations detected."
            $result.Status = "Pass"
        }
    }
    catch {
        $result.ErrorMsg = "Error occurred while checking for DCSync permission: $_"
        $result.Status = "Error"
    }

    return $result


}

# Example usage
$result = DCSyncCheck -Domain "AgentDomainName"
Write-Output $result | ConvertTo-Json -Depth 10