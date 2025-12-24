
Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn;
function New-AuditLogReport {
    [CmdletBinding()]
    param(
        [Parameter(Position=0, Mandatory=$true, ValueFromPipeline=$true)]
        [Microsoft.Exchange.Management.SystemConfigurationTasks.AdminAuditLogEvent]
        $AuditLogEntry
    )

    begin {

        $rows = @()
    }

    process {
        
        $paramText = $null
        $paramText += ($AuditLogEntry.CmdletParameters | ForEach-Object {
            "{0} : {1}" -f $_.Name, $_.Value
        }) -join '; '

       
        $rows += [pscustomobject]@{
            Caller         = $AuditLogEntry.Caller.Split("/")[-1]
            RunDate        = $AuditLogEntry.RunDate
            Succeeded      = $AuditLogEntry.Succeeded
            Cmdlet         = $AuditLogEntry.CmdletName
            Parameters     = $paramText
            ObjectModified = $AuditLogEntry.ObjectModified
        }
    }

    end {
        
        $rows
    }
}


$csvName = "Exchange_AdminAudit_{0}.csv" -f (Get-Date -Format 'yyyyMMdd')
$csvPath = "C:\Temp\$csvName"
. $env:ExchangeInstallPath\bin\RemoteExchange.ps1
Connect-ExchangeServer -auto -AllowClobber
Search-AdminAuditLog -StartDate ((Get-Date).AddDays(-1)) -EndDate (Get-Date) |
    New-AuditLogReport |
    Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8

Write-Host "Admin Audit CSV oluşturuldu: $csvPath"
