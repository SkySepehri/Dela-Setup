function Check-EventLog {
    param (
        [string]$logName = "Security",
        [int[]]$eventID,
        [int]$daysBack = 31,
        [string]$serverName = $env:COMPUTERNAME
    )

    $startTime = (Get-Date).AddDays(-$daysBack)
    $xpathFilter = "*[System[EventID=$($eventID[0])] and System[TimeCreated[@SystemTime>'$($startTime.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ"))']]]"
    
    $events = Get-WinEvent -ComputerName $serverName -LogName $logName -FilterXPath $xpathFilter -ErrorAction SilentlyContinue

    if ($events) {
        Write-Host "Found $($events.Count) event(s) with ID $($eventID -join ',') in $logName log in the last $daysBack days:"
        return $events
    } else {
        Write-Host "No events found with ID $($eventID -join ',') in $logName log in the last $daysBack days"
        return @()
    }
}

function Check-GoldenSAML {
    param (
        [string]$serverName,
        [string]$logName = "Security",
        [int[]]$adfsEventIds = @(1200, 1202),
        [int]$dcEventId = 4769
    )

    # Initialize the result hash table
    $result = @{
        ItemNumber = "ADS029"
        UseCase = "Detect potential Golden SAML attacks by analyzing and correlating security events."
        WeightedScore = 5
        TechnicalInformation = "This function checks for specific ADFS and domain controller events to identify potential Golden SAML attacks."
        Category = "Security Monitoring"
        TechnicalDetails = @() # will be filled later
        RemedediationSolution = "Review audit policies to ensure relevant events are being logged and properly correlated."
        MITREMapping = "T1552.004"
        Status = "Pass"
        ErrorMsg = $null 
    }

    try {
        # Check for ADFS events related to Golden SAML
        $adfsEvents = Check-EventLog -serverName $serverName -logName $logName -eventID $adfsEventIds

        # If ADFS events are found
        if ($adfsEvents.Count -gt 0) {
            # Check for domain controller events
            $dcEvents = Check-EventLog -serverName $serverName -logName $logName -eventID $dcEventId

            # Iterate through each ADFS event
            foreach ($adfsEvent in $adfsEvents) {
                # Search for corresponding domain controller event
                $correspondingDC = $dcEvents | Where-Object { $_.TimeCreated -eq $adfsEvent.TimeCreated }

                # If no corresponding domain controller event is found
                if (-not $correspondingDC) {
                    # Add the finding to the result
                    $result["TechnicalDetails"] += [PSCustomObject]@{
                        EventTime = $adfsEvent.TimeCreated
                        AdditionalInfo = "A potential Golden SAML attack may have been detected!"
                    }
                    $result["Status"] = "Fail"
                }
            }
        }

        # If no suspicious activity was detected, set status to "Pass"
        if ($result["TechnicalDetails"].Count -eq 0) {
            $result["Status"] = "Pass"
            $result["TechnicalDetails"] = "No potential Golden SAML attacks detected."
        }

    } catch {
        $result.Status = "Error"
        $result.ErrorMsg = "Error occurred while checking for Golden SAML attacks. Error: $($_.Exception.Message)"
    }

    return $result
}

# Example usage
$result = Check-GoldenSAML -serverName "Vul-DC"
Write-Output $result | ConvertTo-Json -Depth 10