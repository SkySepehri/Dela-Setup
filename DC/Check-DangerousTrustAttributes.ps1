function Check-DangerousTrustAttributes {
    [CmdletBinding()]
    param()
    
    $result = @{
        ItemNumber = "ADS027"
        UseCase = "Dangerous Trust Attribute Set"
        WeightedScore = 20
        TechnicalInformation = "Trusts with dangerous attributes in Active Directory involve configurations that can expose the network to security risks, such as excessive permissions or unsecure trust relationships. Attackers can exploit these vulnerabilities to gain unauthorized access or escalate privileges."
        Category = "AD Domain & Domain Group Configuration"
        TechnicalDetails = $null # will fullfill later 
        RemedediationSolution = 
        "Regularly checking for and securing these trusts helps prevent potential breaches and maintains a robust security posture."
        MITREMapping = "[MITRE] T1482: Domain Trust Discovery"
        Status = $null
        ErrorMsg = $null 
    }
    
    try {
        # Get all trusts in the forest
        $trusts = Get-ADTrust -Filter *
    
        # Check each trust for Dangerous attributes
        $dangerousTrusts = foreach ($trust in $trusts) {
            if ($trust.TrustAttributes -band [System.DirectoryServices.ActiveDirectory.TrustAttributes]::NonTransitive -and
                $trust.TrustDirection -eq "Bidirectional") {
                $trust
            }
        }
    
        if ($dangerousTrusts.Count -gt 0) {
            $result.Status = "Fail"
            # $result.Findings = $dangerousTrusts
            # $result.FindingSummary = "Fail: Dangerous trust attributes found in Active Directory trusts."
            $result.TechnicalDetails = "Dangerous trust attributes found in Active Directory trusts: " + ($dangerousTrusts | ForEach-Object { $_.Name } | Join-String -Separator ", ")
        } else {
            $result.Status = "Pass"
            $result.TechnicalDetails  = "Pass: No dangerous trust attributes found in Active Directory trusts."
        }
    
    } catch {
        $errstr = $_.Exception.Message
        $result.Status = "Fail"
        $result.TechnicalDetails  = "Error: $errstr"
    }
    
    return $result
    }

# Example usage
$result = Check-DangerousTrustAttributes
Write-Output $result | ConvertTo-Json -Depth 10