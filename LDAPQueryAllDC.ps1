# Search All Domain Controllers
$DCs = Get-ADDomainController -Filter *

# List
$AllResults = @()

foreach ($dc in $DCs) {
    Write-Host "`nQuery: $($dc.HostName)" -ForegroundColor Cyan

    try {
        $logs = Invoke-Command -ComputerName $dc.HostName -ScriptBlock {
            $events = Get-WinEvent -FilterHashtable @{
                LogName = 'Directory Service';
                Id = 2889;
                StartTime = (Get-Date).AddDays(-7)
            }

            $parsed = @()

            foreach ($event in $events) {
                $msg = $event.Message -split "`r?`n"

                $ip = ""
                $user = ""
                for ($i = 0; $i -lt $msg.Count; $i++) {
                    if ($msg[$i] -match "Client IP address:") {
                        $ip = $msg[$i + 1].Trim()
                    }
                    elseif ($msg[$i] -match "Identity the client attempted to authenticate as:") {
                        $user = $msg[$i + 1].Trim()
                    }
                }

                if ($ip -and $user) {
                    $parsed += [PSCustomObject]@{
                        TimeCreated = $event.TimeCreated
                        DCName      = $env:COMPUTERNAME
                        ClientIP    = $ip
                        Username    = $user
                    }
                }
            }

            return $parsed
        }

        $AllResults += $logs
    }
    catch {
        Write-Warning "error: $($dc.HostName) denied. $_"
    }
}

# Write CSV
$exportPath = "C:\Temp\LDAP_Cleartext_2889_Parsed.csv"
$AllResults | Select-Object TimeCreated, DCName, ClientIP, Username |
Export-Csv -Path $exportPath -NoTypeInformation -Encoding UTF8

Write-Host "`n✅ Completed. Output: $exportPath" -ForegroundColor Green
