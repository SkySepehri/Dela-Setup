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

function Check-CertificateExport {
    param (
        [string]$serverName,
        [string]$logName = "Security",
        [int[]]$certificateEventIds = @(1007),
        [int[]]$powershellEventIds = @(4103, 4104),
        [int[]]$securityEventIds = @(4688)
    )

    $result = @{
        ItemNumber = "ADS039"
        UseCase = "Certificate Export Events in ADFS"
        WeightedScore = 5
        TechnicalInformation = "Identifying certificate export events in ADFS is crucial for detecting potential security breaches. Certificates are critical for securing communications and authenticating users. If an attacker can export certificates, they can potentially impersonate users or decrypt sensitive communications, leading to unauthorized access and data breaches."
        Category = "Object Privilege & Configuration"
        TechnicalDetails = $null # will fulfill later 
        RemedediationSolution = "Monitor for events related to certificate exports and investigate any suspicious activity. Ensure that only authorized personnel have access to export certificates and that proper logging and alerting mechanisms are in place."
        MITREMapping = "[RE] T1552.004: Unsecured Credentials: Private Keys"
        Status = $null
        ErrorMsg = $null 
    }

    try {
        # Check for certificate export events
        $certificateExportEvents = Check-EventLog -serverName $serverName -logName $logName -eventID $certificateEventIds

        # Check for PowerShell command line events
        $powershellLogs = Check-EventLog -serverName $serverName -logName $logName -eventID $powershellEventIds

        # Check for security events
        $securityLogs = Check-EventLog -serverName $serverName -logName $logName -eventID $securityEventIds

        $commandLineLogs = @()  # Initialize to empty array

        foreach ($event in $securityLogs) {
            # Extract the Message object from the event data
            $messageData = $event.Message

            # Check for certificate export events
            if ($messageData -match "CertUtil -exportPFX") {
                $commandLineLogs += $event
            }
        }

        if ($certificateExportEvents.Count -gt 0 -or $commandLineLogs.Count -gt 0) {
            $result.Status = "Fail"
            $result.TechnicalDetails = "Certificate export events found: " + ($certificateExportEvents | ForEach-Object { $_.Message } | Out-String) + ($commandLineLogs | ForEach-Object { $_.Message } | Out-String)
        } else {
            $result.Status = "Pass"
            $result.TechnicalDetails = "No certificate export events found."
        }

    } catch {
        $result.Status = "Error"
        $result.ErrorMsg = $_.Exception.Message
    }

    return $result
}

# Example usage
$result = Check-CertificateExport -serverName "Vul-DC"
Write-Output $result | ConvertTo-Json -Depth 10