# === DNS ZONE EXPORT and BACKUP ===
$Date = Get-Date -Format "yyyy-MM-dd"
$BasePath = "C:\Reports\DNS\$Date"
$DnsBackupPath = "$BasePath\DNS_Export"
Write-Output "[$(Get-Date)] Create Folders: $BasePath"
New-Item -Path $DnsBackupPath -ItemType Directory -Force | Out-Null
Write-Output "[$(Get-Date)] Starting DNS Zone Export..."
$DnsZone = (Get-ADDomain -Current LocalComputer).DNSRoot

try {
    Export-DnsServerZone -Name $DnsZone -FileName "$DnsZone.export" -ErrorAction Stop
    Copy-Item -Path "C:\Windows\System32\DNS\*.export" -Destination "$DnsBackupPath" -Force
    Remove-Item -Path "C:\Windows\System32\DNS\*.export" -ErrorAction Stop
    Write-Output "[$(Get-Date)] DNS export completed: $DnsZone"
} catch {
    Write-Output "[$(Get-Date)] DNS export Error: $DnsZone - $_"
}

Write-Output "[$(Get-Date)] All task completed: $BasePath"
