function Check-SPNChangeForGC {
    [CmdletBinding()]
    param(
        [string]$serverName,
        [string]$logName,
        [int]$daysBack
    )

    $result = @{
        ItemNumber = "ADS011"
        UseCase = "SPN Changes for Global Catalog"
        WeightedScore = 5
        TechnicalInformation = "Monitoring SPN changes for Global Catalog servers helps detect potential misconfigurations or malicious activity. Attackers can exploit SPN changes to impersonate services or disrupt authentication processes."
        Category = "Authentication & Permission Policies"
        TechnicalDetails = $null # will fulfill later 
        RemedediationSolution = "Regularly monitor and review SPN changes to ensure they are legitimate and authorized."
        MITREMapping = "[MITRE] T1550: Use Alternate Authentication Material"
        Status = $null
        ErrorMsg = $null 
    }

    try {
        # Query the event log for SPN change events
        $events = Get-WinEvent -ComputerName $serverName -FilterHashtable @{
            LogName = $logName
            StartTime = (Get-Date).AddDays(-$daysBack)
            Id = 4742  # Example event ID for SPN changes
        }

        # Filter events for GC SPN modifications
        $gcSpnEvents = $events | Where-Object {
            $_.Message -like "*GC/*"
        }

        if ($gcSpnEvents.Count -gt 0) {
            $result.Status = "Fail"
            $result.TechnicalDetails = "Found $($gcSpnEvents.Count) event(s) with GC SPN modifications in $logName log in the last $daysBack days. Affected events: " + ($gcSpnEvents | ForEach-Object { $_.Message } | Join-String -Separator ", ")
        } else {
            $result.Status = "Pass"
            $result.TechnicalDetails = "No events found with GC SPN modifications in $logName log in the last $daysBack days."
        }

    } catch {
        $result.Status = "Error"
        $result.ErrorMsg = $_.Exception.Message
    }

    return $result
}

# Example usage
$result = Check-SPNChangeForGC -serverName "AgentServerName" -logName "Security" -daysBack 7
Write-Output $result | ConvertTo-Json -Depth 10