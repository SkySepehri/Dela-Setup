function Check-EventLogForNTDSDSA {
    param (
        [string]$logName = "Security",
        [int]$daysBack = 30,
        [string]$Server
    )

    $startTime = (Get-Date).AddDays(-$daysBack)
    $events = Get-WinEvent -ComputerName $Server -FilterHashtable @{LogName=$logName; StartTime=$startTime; ID=4662} -ErrorAction SilentlyContinue

    if ($events) {
        $ntdsdsaEvents = $events | Where-Object { $_.Message -like "*f0f8ffab-1191-11d0-a060-00aa006c33ed*" }
        if ($ntdsdsaEvents) {
            Write-Host "Found $($ntdsdsaEvents.Count) event(s) with Event ID 4662 containing 'NTDSDSA' in $logName log on $Server in the last $daysBack days:"
            $ntdsdsaEvents
        }
        else {
            Write-Host "No events found with Event ID 4662 containing 'NTDSDSA' in $logName log on $Server in the last $daysBack days"
        }
    }
    else {
        Write-Host "No events found with Event ID 4662 in $logName log on $Server in the last $daysBack days"
    }
    return $ntdsdsaEvents
}

function Check-SPNChangeForGC {
    param (
        [string]$logName = "Security",
        [int]$daysBack = 30,
        [string]$Server
    )

    $startTime = (Get-Date).AddDays(-$daysBack)
    $events = Get-WinEvent -ComputerName $Server -FilterHashtable @{LogName=$logName; StartTime=$startTime; ID=4742} -ErrorAction SilentlyContinue

    if ($events) {
        $gcSpnEvents = $events | Where-Object {
            $_.Message -like "*GC/*"
        }

        if ($gcSpnEvents) {
            Write-Host "Found $($gcSpnEvents.Count) event(s) with GC SPN modifications in $logName log on $Server in the last $daysBack days:"
            $gcSpnEvents
        }
        else {
            Write-Host "No events found with GC SPN modifications in $logName log on $Server in the last $daysBack days"
        }
    }
    else {
        Write-Host "No events found with Event ID 4742 (AD Object Modified) in $logName log on $Server in the last $daysBack days"
    }

    return $gcSpnEvents
}


function Check-DCShadowIOC {
    param (
        [string]$Server
    )

    $ntdsdsaEvents = Check-EventLogForNTDSDSA -serverName $Server
    $gcSpnEvents = Check-SPNChangeForGC -serverName $Server

    # Merge the two arrays
    $mergedEvents = $ntdsdsaEvents + $gcSpnEvents

    if ($ntdsdsaEvents -or $gcSpnEvents) {
        $result = @{
            Description = "DCShadow is a technique used by attackers to inject changes into Active Directory domain controllers without the need for elevated privileges. Detected events indicate potential DCShadow activity."
            Severity = "High"
            LikelihoodOfCompromise = "High"
            Findings = $null
            FindingSummary = "Investigate the detected events stored in the DCShadow_events.txt file further to determine the scope and impact of the potential DCShadow activity. Immediate remediation actions may be necessary to prevent further compromise."
            Remediation = "Isolate affected systems, rollback unauthorized changes, and implement additional security controls to prevent future DCShadow attacks."
            Status = "Fail"
        }
    } else {
        $result = @{
            Description = "No DCShadow indicators found."
            Severity = "Info"
            LikelihoodOfCompromise = "Low"
            Findings = $null
            FindingSummary = "No indicators of DCShadow activity detected in the security logs."
            
            Remediation = "Continue monitoring security logs and implement proactive security measures to mitigate the risk of DCShadow attacks."
            Status = "Pass"
        }
    }

    return $result 
}


$result = Check-DCShadowIOC -Server 'Vul-DC'
Write-Output $result