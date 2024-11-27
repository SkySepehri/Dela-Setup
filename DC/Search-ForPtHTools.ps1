function Search-ForPtHTools {
    param (
        [string]$outputFile = "PtH_Tools_Found.txt"
    )

    # List of common PtH tools to search for
    $pthTools = @(
        "Mimikatz.exe", 
        "ProcDump.exe", 
        "WCE.exe", 
        "Gsecdump.exe", 
        "Responder.exe", 
        "Cain.exe", 
        "Abel.exe", 
        "Empire.ps1", 
        "msfconsole.exe", 
        "Rubeus.exe", 
        "kekeo.exe", 
        "crackmapexec.exe"
    )

    # Function to search for files in a directory
    function Search-Files {
        param (
            [string]$path
        )

        $foundTools = @()

        Get-ChildItem -Path $path -File -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
            if ($pthTools -contains $_.Name) {
                Write-Host "Found PtH Tool: $($_.FullName)" -ForegroundColor Red
                $foundTools += $_.FullName
            }
        }

        return $foundTools
    }

    # Get a list of all fixed drives with operational status OK and drive letters assigned
    $drives = Get-Volume | Where-Object {$_.DriveType -eq 'Fixed' -and $_.DriveLetter -ne $null -and $_.OperationalStatus -eq 'OK' } | Select-Object -ExpandProperty DriveLetter

    # Starting the search in each drive
    $allFoundTools = @()
    foreach ($drive in $drives) {
        Write-Host "Starting search for PtH tools in $($drive):\" -ForegroundColor Yellow
        $foundToolsOnDrive = Search-Files -path "$($drive):\"
        $allFoundTools += $foundToolsOnDrive
    }

    # Create the overall result object
    $result = @{
        Description = "Pass the Hash Tools Found"
        Severity = "High"
        LikelihoodOfCompromise = "High"
        Findings = $allFoundTools | ConvertTo-Json
        FindingSummary = "Pass the Hash tools were found on the system."        
        Remediation = "Investigate and remove any unauthorized tools."
        Status = if ($allFoundTools.Count -gt 0) { "Fail" } else { "Pass" }
    }
    
    return $result
}

# Example usage
$result = Search-ForPtHTools -outputFile "PtH_Tools_Found.txt"
Write-Output $result