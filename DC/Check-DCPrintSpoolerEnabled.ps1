function Check-DCPrintSpoolerEnabled {
    [CmdletBinding()]
    param()
    
    $result = @{
        ItemNumber = "ADS030"
        UseCase = "DC Print Spooler Misconfiguration"
        WeightedScore = 50
        TechnicalInformation = "This technique involves exploiting vulnerabilities in software to execute code on a target system. The Print Spooler service, particularly the vulnerabilities associated with it (such as CVE-2021-34527, known as PrintNightmare), allows attackers to execute arbitrary code with SYSTEM privileges. By exploiting this vulnerability, attackers can gain unauthorized access, escalate privileges, and potentially compromise the entire domain."
        Category = "Forensic Analysis"
        TechnicalDetails = $null # will fullfill later 
        RemedediationSolution = 
        "Regularly checking and disabling the Print Spooler service on Domain Controllers helps mitigate these security risks.

Here are concise instructions to disable the Print Spooler service on Domain Controllers using Group Policy:
Open Group Policy Management
Right-click Domain Controllers OU and select Create a GPO
Name the GPO Disable Print Spooler
Edit the GPO
Navigate to Computer Config > Windows Settings > Security Settings > System Services
Double-click Print Spooler
Select Define this policy setting and Disabled
Click OK
Run gpupdate /force to apply changes"
        MITREMapping = "[MITRE] T1203: Exploitation for Client Execution"
        Status = $null
        ErrorMsg = $null 
    }
    
    try {
        # Check if the Print Spooler service is enabled on the Domain Controller
        $printSpoolerEnabled = (Get-Service -Name Spooler).StartType -eq 'Automatic'
    
        if ($printSpoolerEnabled) {
            $result.Status = "Fail"
            $result.TechnicalDetails = "Fail: The Print Spooler service is enabled on the Domain Controller."
        } else {
            $result.Status = "Pass"
            $result.TechnicalDetails = "Pass: The Print Spooler service is not enabled on the Domain Controller."
        }
    
        # Additional checks specific to Print Spooler can be added here
    
    } catch {
        $errstr = $_.Exception.Message
        $result.Status = "Fail"
        $result.TechnicalDetails = "Error: $errstr"
    }
    
    return $result
    }

# Example usage
$result = Check-DCPrintSpoolerEnabled
Write-Output $result | ConvertTo-Json -Depth 10