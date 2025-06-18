# === 1. Basic Settings ===
$Date = Get-Date -Format "yyyy-MM-dd"
$BasePath = "C:\Reports\$Date"
$GpoBackupPath = "$BasePath\GPO_Backups"
New-Item -Path $GpoBackupPath -ItemType Directory -Force | Out-Null


Write-Output "[$(Get-Date)] Create Folders: $BasePath"

# === 2. Create a Lists ===
$Gpos = Get-GPO -All
$LinkedGpoList = @()
$UnlinkedGpoList = @()
$NoSettingsGpoList = @()
$DisabledGpoList = @()
$GpoWmiList = @()

# === 3. Domain and OU Connections ===
$DomainName = (Get-ADDomain).DistinguishedName
$DomainLinks = (Get-GPInheritance -Target $DomainName).GpoLinks
foreach ($link in $DomainLinks) {
    $LinkedGpoList += [PSCustomObject]@{
        GPOName   = $link.DisplayName
        LinkScope = "Domain"
        Enabled   = $link.Enabled
        Enforced  = $link.Enforced
    }
}

$OUs = Get-ADOrganizationalUnit -Filter * -Properties DistinguishedName
foreach ($ou in $OUs) {
    $OUName = $ou.DistinguishedName
    $Links = (Get-GPInheritance -Target $OUName).GpoLinks
    foreach ($link in $Links) {
        $LinkedGpoList += [PSCustomObject]@{
            GPOName   = $link.DisplayName
            LinkScope = "OU: $OUName"
            Enabled   = $link.Enabled
            Enforced  = $link.Enforced
        }
    }
}

# === 4. GPO BACKUP ===
foreach ($Gpo in $Gpos) {
    $GpoName = $Gpo.DisplayName -replace '[\\/:*?"<>|]', '_'
    $GpoFolder = "$GpoBackupPath\$GpoName"

    New-Item -Path $GpoFolder -ItemType Directory -Force | Out-Null
    Backup-GPO -Guid $Gpo.Id -Path $GpoFolder -ErrorAction Stop
    Get-GPOReport -Guid $Gpo.Id -ReportType Html -Path "$GpoFolder\$GpoName.html"

    # XML Parse
    $ReportXml = Get-GPOReport -Guid $Gpo.Id -ReportType Xml
    [xml]$XmlDoc = $ReportXml

    if (-not $XmlDoc.GPO.Computer.ExtensionData -and -not $XmlDoc.GPO.User.ExtensionData) {
        $NoSettingsGpoList += [PSCustomObject]@{
            GPOName = $Gpo.DisplayName
            GPOId   = $Gpo.Id
        }
    }

    if ($Gpo.GpoStatus -eq 'AllSettingsDisabled') {
        $DisabledGpoList += [PSCustomObject]@{
            GPOName = $Gpo.DisplayName
            GPOId   = $Gpo.Id
        }
    }

    if (-not ($LinkedGpoList | Where-Object { $_.GPOName -eq $Gpo.DisplayName })) {
        $UnlinkedGpoList += [PSCustomObject]@{
            GPOName = $Gpo.DisplayName
            GPOId   = $Gpo.Id
        }
    }

    if ($Gpo.WmiFilter) {
        $GpoWmiList += [PSCustomObject]@{
            GPOName     = $Gpo.DisplayName
            GPOId       = $Gpo.Id
            WmiFilter   = $Gpo.WmiFilter.Name
            Description = $Gpo.WmiFilter.Description
        }
    }

    Write-Output "[$(Get-Date)] Backup and parse completed: $GpoName"
}

# === 5. Export All GPO Reports HTML ===
Get-GPOReport -All -ReportType Html -Path "$GpoBackupPath\AllGpoReports.html"

# === 6. CSV EXPORT ===
$LinkedGpoList     | Export-Csv "$GpoBackupPath\GPO_LinkedScopes.csv" -NoTypeInformation -Encoding UTF8
$UnlinkedGpoList   | Export-Csv "$GpoBackupPath\UnlinkedGPOs.csv"     -NoTypeInformation -Encoding UTF8
$NoSettingsGpoList | Export-Csv "$GpoBackupPath\NoSettingsGPOs.csv"   -NoTypeInformation -Encoding UTF8
$DisabledGpoList   | Export-Csv "$GpoBackupPath\DisabledGPOs.csv"     -NoTypeInformation -Encoding UTF8
$GpoWmiList        | Export-Csv "$GpoBackupPath\GPO_WmiFilters.csv"   -NoTypeInformation -Encoding UTF8

Write-Output "[$(Get-Date)] CSV export completed."
