function Check-SMBSigning {
    [CmdletBinding()]
    param()
    
    $result = @{
        ItemNumber = "ADS019"
        UseCase = "Disabled SMB Signing and Relaying NTLMv2 Hashes"
        WeightedScore = 5
        TechnicalInformation = "SMB signing is a security feature that helps protect against man-in-the-middle attacks by ensuring that SMB (Server Message Block) communication is authenticated and tamper-evident. If SMB signing is disabled, attackers can intercept or modify network traffic. Checking if SMB signing is enabled on the system helps ensure that data integrity and authenticity are maintained, reducing the risk of attacks on SMB communications.
When SMB signing is disabled, it makes it possible to use Responder with Multirelay.py script to perform an NTLMv2 hashes relay and get a shell access on the machine. Also called LLMNR/NBNS Poisoning"
        Category = "Authentication & Permission Policies"
        TechnicalDetails = $null # will fullfill later 
        RemedediationSolution = 
        "Enable SMB signing for enhanced security.
To fix SMB signing misconfiguration in Active Directory:
Enable SMB signing via Group Policy:
Edit Default Domain Policy or create a new one
Enable relevant policies under Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Security Options
Apply policy: Run gpupdate /force on all machines
Verify Domain Controllers configuration
Check client configuration:
reg query HKLM\System\CurrentControlSet\Services\LanManServer\Parameters | findstr /I securitysignature

Monitor for issues after implementation
Consider phased rollout for large environments
Update non-Windows systems (e.g., Samba configuration)
Reboot affected systems
This approach enhances network security against SMB relay attacks by properly configuring SMB signing across the Active Directory environment."
        MITREMapping = "[MITRE] T1557: Adversary-in-the-Middle"
        Status = $null
        ErrorMsg = $null 
    }
    
    try {
        # Check if SMB signing is enabled
        $smbSigningEnabled = Get-SmbServerConfiguration | Select-Object -ExpandProperty RequireSecuritySignature
    
        if ($smbSigningEnabled -eq $true) {
            $result.Status = "Pass"
            $result.TechnicalDetails = "Pass: SMB signing is enabled on the system."
        } else {
            $result.Status = "Fail"
            $result.TechnicalDetails = "Fail: SMB signing is not enabled on the system."
        }
    
        # Additional checks specific to SMB signing can be added here
    
    } catch {
        $errstr = $_.Exception.Message
        $result.Status = "Fail"
        $result.TechnicalDetails = "Error: $errstr"
    }
    
    return $result
}

# Example usage
$result = Check-SMBSigning
Write-Output $result| ConvertTo-Json -Depth 10

# Command to disable SMB signing
# Set-SmbServerConfiguration -RequireSecuritySignature $false -Force
