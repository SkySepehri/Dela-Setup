# Install and import the SqlServer module
if (-not (Get-Module -ListAvailable -Name SqlServer)) {
    Install-Module -Name SqlServer -Force -AllowClobber
}
Import-Module SqlServer

function Check-MSSQLAbuse {
    [CmdletBinding()]
    param(
        [string]$SQLInstance
    )

    $result = @{
        ItemNumber = "MSSQL001"
        UseCase = "Detection of Potential MSSQL Abuse"
        WeightedScore = 5
        TechnicalInformation = "This function checks if the xp_cmdshell feature is enabled on SQL Server instances. xp_cmdshell allows the execution of operating system commands directly from SQL Server, which can be leveraged by attackers to execute malicious commands and gain control over the server if misconfigured."
        Category = "Object Privilege & Configuration"
        TechnicalDetails = $null
        RemediationSolution = "Disable xp_cmdshell if it is not required and ensure that only trusted users have sysadmin privileges on the SQL Server."
        MITREMapping = "[MITRE] T1210: Exploitation of Remote Services"
        Status = "Pass"
        ErrorMsg = $null
    }

    try {
        # Check if xp_cmdshell is enabled using Windows Authentication
        $isXPCmdShellEnabled = Invoke-Sqlcmd -ServerInstance $SQLInstance -Query "EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell';" -ErrorAction Stop
        if ($isXPCmdShellEnabled.ConfigValue -eq 1) {
            $result.Status = "Fail"
            $result.TechnicalDetails = "xp_cmdshell is enabled on the instance $SQLInstance."
        } else {
            $result.TechnicalDetails = "xp_cmdshell is disabled on the instance $SQLInstance."
        }
    } catch {
        $result.Status = "Error"
        $result.TechnicalDetails = "Error occurred during MSSQL abuse check: $_"
    }

    return $result
}

# Example usage
$result = Check-MSSQLAbuse -SQLInstance "AgentSQLInstance"
Write-Output $result