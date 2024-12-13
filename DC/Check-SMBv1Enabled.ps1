function Check-SMBv1Enabled {
    [CmdletBinding()]
    param()
    
    $result = @{
        ItemNumber = "ADS015"
        UseCase = "Check if SMBv1 is Enabled"
        WeightedScore = 5
        TechnicalInformation = "This function checks if the SMBv1 protocol is enabled on the system. SMBv1 is an outdated and insecure protocol that can expose the system to vulnerabilities and security risks. It is recommended to use newer versions like SMBv2 or SMBv3 for better security."
        Category = "Object Privilege & Configuration"
        TechnicalDetails = $null # will fulfill later 
        RemedediationSolution = "Disable SMBv1 if it is not required and ensure that SMBv2 or SMBv3 is used to enhance the security of the system."
        MITREMapping = "[MITRE] T1210: Exploitation of Remote Services"
        Status = $null
        ErrorMsg = $null 
    }
    
    try {
        # Check if SMBv1 is enabled
        $smbv1Enabled = Get-SmbServerConfiguration | Select-Object -ExpandProperty EnableSMB1Protocol

        if ($smbv1Enabled) {
            $result.Status = "Fail"
            $result.TechnicalDetails = "SMBv1 is enabled on the system."
        } else {
            $result.Status = "Pass"
            $result.TechnicalDetails = "SMBv1 is not enabled on the system."
        }
    } catch {
        $result.Status = "Error"
        $result.ErrorMsg = $_.Exception.Message
    }

    return $result
}

# Example usage
$result = Check-SMBv1Enabled
Write-Output $result | ConvertTo-Json -Depth 10