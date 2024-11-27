function Check-WeakCertificateEncryption {
    [CmdletBinding()]
    param()
    
    # $result = @{
    #     Description            = "Checks for weak certificate encryption in the local certificate store."
    #     Severity               = "High"
    #     LikelihoodOfCompromise = "High"
    #     Findings          = $null
    #     FindingSummary          = $null
    #     Score                  = $null
    #     Remediation            = "Replace certificates using weak encryption algorithms with stronger alternatives."
    #     Status                 = $null
    # }

    $result = @{
        ItemNumber = "ADS017"
        UseCase = "Weak Certificate Encryption"
        WeightedScore = 5
        TechnicalInformation = "Weak certificate encryption in the local certificate store can leave sensitive data vulnerable to decryption by attackers. If certificates use outdated or insecure algorithms, they can be exploited to compromise encrypted communications or data integrity. "
        Category = "Authentication & Permission Policies"
        TechnicalDetails = $null # will fullfill later 
        RemedediationSolution = 
        "Regularly checking for weak encryption and updating certificates to use strong algorithms ensures better protection against cryptographic attacks."
        MITREMapping = "[MITRE] T1552: Unsecured Credentials"
        Status = $null
        ErrorMsg = $null 
    }
    
    try {
        # Define a list of weak encryption algorithms
        $weakAlgorithms = @("RSA 1024", "RSA 2048", "SHA1", "MD5")
    
        # Get certificates from the local certificate store
        $certificates = Get-ChildItem -Path Cert:\LocalMachine\My
    
        # Check each certificate for weak encryption algorithms
        $weakCertificates = foreach ($cert in $certificates) {
            $algorithm = $cert.PublicKey.Key.KeyExchangeAlgorithm
    
            if ($weakAlgorithms -contains $algorithm) {
                $cert
            }
        }
    
        if ($weakCertificates.Count -gt 0) {
            # $result.Status = "Fail"
            # $result.Findings = $weakCertificates
            # $result.FindingSummary = "Fail: Weak certificate encryption algorithms found in the local certificate store."
            $result.Status = "Fail"
            $result.TechnicalDetails = "Weak certificate encryption algorithms found in the local certificate store. Affected certificates: " + ($weakCertificates | ForEach-Object { $_.Subject } | Join-String -Separator ", ")
        } else {
            $result.Status = "Pass"
            $result.TechnicalDetails = "Pass: No weak certificate encryption algorithms found in the local certificate store."
        }
    
    } catch {
        $errstr = $_.Exception.Message
        $result.Status = "Fail"
        $result.TechnicalDetails = "Error: $errstr"
    }
    
    return $result
    }

# Example usage
$result = Check-WeakCertificateEncryption
Write-Output $result