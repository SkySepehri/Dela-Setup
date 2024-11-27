function Check-PTASpyPresence {
    # $result = @{
    #     Description            = "Checks for the presence of PTA Spy on the machine."
    #     Severity               = "High"
    #     LikelihoodOfCompromise = "High"
    #     Findings               = $null
    #     FindingSummary         = $null
    #     Score                  = $null
    #     Remediation            = "If PTA Spy is detected, immediately remove the tool, investigate the source, and ensure all relevant security controls are in place."
    #     Status                 = $null
    # }

    $result = @{
        ItemNumber = "ADS009"
        UseCase = "Azure AD Connect - Pass-Through Authentication"
        WeightedScore = 5
        TechnicalInformation = "PTA Spy is a tool used by attackers to capture and monitor security tokens or credentials in a Privileged Token Access (PTA) environment. Checking for the presence of PTA Spy on a machine helps identify potential security breaches or malicious activities aimed at compromising sensitive access controls."
        Category = "Object Privilege & Configuration"
        TechnicalDetails = $null # will fullfill later 
        RemedediationSolution = 
        "Monitor for PTA Spy Tool: Regularly scan and monitor systems for the presence of PTA Spy or similar tools that may be deployed by attackers to capture tokens or credentials.

Token Protection: Implement strong security measures to protect security tokens and privileged credentials, including encryption and strict access control mechanisms.

Limit Token Lifetime: Ensure that privileged tokens have short lifetimes, reducing the window of opportunity for attackers to capture and exploit them.

Auditing and Logging: Any connection from the Azure AD Connect Sync user that is not using the application Id cb1056e2-e479-49de-ae31-7812af012ed8 or the target resource Windows Azure Active Directory must be treated suspiciously.

"
        MITREMapping = "[MITRE] T1556.007: Modify Authentication Process - Hybrid Identity"
        Status = $null
        ErrorMsg = $null 
    }

    # try {
    #     $findings = @()

    #     # Step 1: Check if PassthroughAuthPSModule is installed
    #     $ptaModule = Get-Module -Name "PassthroughAuthPSModule" -ListAvailable
    #     if ($ptaModule) {
    #         $findings += "PassthroughAuthPSModule is installed on this machine."
    #     } else {
    #         $findings += "PassthroughAuthPSModule is NOT installed on this machine."
    #     }

    #     # Step 2: Check if PTA Spy directory exists
    #     $ptaSpyPath = "C:\PTASpy"
    #     if (Test-Path $ptaSpyPath) {
    #         $findings += "PTA Spy directory exists at $ptaSpyPath."
    #     } else {
    #         $findings += "PTA Spy directory does NOT exist."
    #     }

    #     # Determine the status and score based on findings
    #     if ($ptaModule -and (Test-Path $ptaSpyPath)) {
    #         $result.Status = "Fail"
    #         $result.FindingSummary = "PTA Spy components detected on this machine. Immediate action is required."
    #     } else {
    #         $result.Status = "Pass"
    #         $result.FindingSummary = "No PTA Spy components detected on this machine."
    #     }

    #     $result.Findings = $findings
    # }
    # catch {
    #     $result.FindingSummary = "Error: $($_.Exception.Message)"
    #     $result.Status = "Error"
    # }

    try {
        $technicalDetails = ""
    
        # Step 1: Check if PassthroughAuthPSModule is installed
        $ptaModule = Get-Module -Name "PassthroughAuthPSModule" -ListAvailable
        if ($ptaModule) {
            $technicalDetails += "PassthroughAuthPSModule is installed on this machine. "
        } else {
            $technicalDetails += "PassthroughAuthPSModule is NOT installed on this machine. "
        }
    
        # Step 2: Check if PTA Spy directory exists
        $ptaSpyPath = "C:\PTASpy"
        if (Test-Path $ptaSpyPath) {
            $technicalDetails += "PTA Spy directory exists at $ptaSpyPath. "
        } else {
            $technicalDetails += "PTA Spy directory does NOT exist. "
        }
    
        # Determine the status and add summary to technical details
        if ($ptaModule -and (Test-Path $ptaSpyPath)) {
            $result.Status = "Fail"
            $technicalDetails += "PTA Spy components detected on this machine. Immediate action is required."
        } else {
            $result.Status = "Pass"
            $technicalDetails += "No PTA Spy components detected on this machine."
        }
    
        $result.TechnicalDetails = $technicalDetails.Trim()
    }
    catch {
        $result.TechnicalDetails = "Error: $($_.Exception.Message)"
        $result.Status = "Error"
    }

    return $result
}

# Example usage
$result = Check-PTASpyPresence
Write-Output $result