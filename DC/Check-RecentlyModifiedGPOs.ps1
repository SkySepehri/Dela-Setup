function Check-RecentlyModifiedGPOs {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [int]$daysThreshold = 7
    )

    $result = @{
        ItemNumber = "ADS013"
        UseCase = "Trace of Suspicious GPOs Modification"
        WeightedScore = 5
        TechnicalInformation = "Group Policy Objects (GPOs) are configurations in Active Directory that manage user and computer settings across a network. Recent modifications to GPOs can indicate potential attacks or unauthorized changes. Attackers may alter GPOs to deploy malicious settings, escalate privileges, or disrupt system operations, potentially leading to security breaches or system compromise."
        Category = "Object Privilege & Configuration"
        TechnicalDetails = $null # will fullfill later 
        RemedediationSolution = 
        "Review recent changes to Group Policy Objects and ensure they are authorized.
        Instructions to Review GPO Changes
        Enable Auditing:
        Enable auditing of DS Objects, Group Policy Container Objects, and SYSVOL folder changes.
        Monitor GPO Changes:
        Use native tools like Event Viewer to monitor event ID 5136 (Directory Service Changes) for GPO modifications.
        Alternatively, use a comprehensive AD auditing solution like ADAudit Plus for real-time monitoring and reporting of GPO changes.
        Review GPO Change Reports:
        In ADAudit Plus, navigate to Reports -> GPO Setting Changes to view out-of-the-box reports on GPO modifications.
        These reports provide details on the GPO name, modification time, and user who made the change.
        Analyze Unauthorized Changes:
        Investigate any suspicious GPO changes, such as modifications made by unauthorized users or changes to sensitive settings.
        Use Policy Analyzer to compare GPO settings and identify unauthorized changes.
        Remediate Issues:
        If unauthorized changes are detected, revert them to the previous authorized state.
        Implement access controls and approval workflows for making GPO changes to prevent future unauthorized modifications."
        MITREMapping = "[MITRE] T1484: Domain or Tenant Policy Modification"
        Status = $null
        ErrorMsg = $null 
    }
    

    try {
        # Calculate the date threshold
        $thresholdDate = (Get-Date).AddDays(-$daysThreshold)
    
        # Get recently modified GPOs
        $recentlyModifiedGPOs = Get-GPO -All | Where-Object { $_.ModificationTime -ge $thresholdDate }
    
        if ($recentlyModifiedGPOs.Count -gt 0) {
            $result.Status = "Fail"
            $result.TechnicalDetails = "Recently modified Group Policy Objects found: `n"
            $result.TechnicalDetails += ($recentlyModifiedGPOs | ForEach-Object { "GPO: $($_.DisplayName), Modified: $($_.ModificationTime)" }) -join "`n"
        } else {
            $result.Status = "Pass"
            $result.TechnicalDetails = "No recently modified Group Policy Objects found within the specified threshold of $daysThreshold days."
        }
    
    } catch {
        $errstr = $_.Exception.Message
        $result.Status = "Fail"
        $result.TechnicalDetails = "Error occurred while checking for recently modified GPOs: $errstr"
        $result.ErrorMsg = $errstr
    }
    
    return $result
}

# Example usage
$result = Check-RecentlyModifiedGPOs -daysThreshold 7
Write-Output $result | ConvertTo-Json -Depth 10