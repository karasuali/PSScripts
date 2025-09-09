<#
.SYNOPSIS
  Bulk-generate and (optionally) apply the KB5014754 *recommended* altSecurityIdentities mapping
  for users listed in a CSV, but only for users who already have Published Certificates (userCertificate=*).

.DESCRIPTION
  - CSV-driven: supports sAMAccountName, userPrincipalName, or distinguishedName as the identity.
  - AD query is server-side filtered to only retrieve users with (userCertificate=*).
  - Selects the most current authentication certificate from Published Certificates:
      * Prefers non-expired with Client Auth (1.3.6.1.5.5.7.3.2) or Smart Card Logon (1.3.6.1.4.1.311.20.2.2);
        else newest by NotBefore.
  - Builds ONLY the KB5014754 recommended strong mapping:
        X509:<I>{IssuerDNReversed}<SR>{SerialReversedByByte}
    (No SKI, no SHA1-PUKEY, no weak mappings.)
  - Optionally applies mapping to altSecurityIdentities (Append or Replace).
  - Emits results to screen and optional CSV.

.NOTES
  - Compatible with Windows PowerShell 5.1 and PowerShell 7+.
  - Requires RSAT ActiveDirectory PowerShell module.
  - Run with privileges to read userCertificate and (if applying) write altSecurityIdentities.

EXAMPLE
Preview
.\Set-AltSecID-FromPublishedCert-Bulk.ps1 -CsvPath C:\Temp\users.csv -IdType SamAccountName -OutCsvPath .\result-preview.csv
Apply
.\Set-AltSecID-FromPublishedCert-Bulk.ps1 -CsvPath C:\Temp\users.csv -IdType sAMAccountName -ApplyToUser -ApplyMode Replace -OutCsvPath C:\Temp\results-replaced.csv

.REFERENCES
  KB5014754 (strong mapping forms; reversal rules; Set-ADUser example)
  https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [Parameter(Mandatory)]
    [string]$CsvPath,

    [Parameter()]
    [ValidateSet('sAMAccountName','userPrincipalName','distinguishedName')]
    [string]$IdType = 'sAMAccountName',

    [Parameter()]
    [string]$IdentityColumn = 'Identity',

    [switch]$ApplyToUser,
    [ValidateSet('Append','Replace')]
    [string]$ApplyMode = 'Append',

    [Parameter()]
    [string]$OutCsvPath
)

#region Helpers
function Ensure-ActiveDirectoryModule {
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        throw "ActiveDirectory module not found. Install RSAT (Active Directory module for Windows PowerShell)."
    }
    Import-Module ActiveDirectory -ErrorAction Stop
}

function Get-ReversedHex {
    [CmdletBinding()] param([Parameter(Mandatory)][string]$Hex)
    $h = ($Hex -replace '\s','').ToUpper()
    if ($h.Length % 2 -ne 0) { $h = '0' + $h }     # pad to even length
    $bytes = for ($i=0; $i -lt $h.Length; $i+=2) { $h.Substring($i,2) }
    [Array]::Reverse($bytes)
    ($bytes -join '')
}

function Convert-DnToReversed {
    <#
      Converts "CN=X,OU=Y,DC=a,DC=b" => "DC=b,DC=a,OU=Y,CN=X"
      Preserves escaped commas "\,".
    #>
    [CmdletBinding()] param([Parameter(Mandatory)][string]$Dn)
    $placeholder = [Guid]::NewGuid().ToString('N')
    $escaped = $Dn -replace '\\\,', $placeholder
    $parts = $escaped -split ',\s*'
    [Array]::Reverse($parts)
    ($parts -join ',').Replace($placeholder,'\,') -replace ',\s+', ','
}

function Select-LatestAuthCert {
    [CmdletBinding()]
    param([System.Security.Cryptography.X509Certificates.X509Certificate2[]]$Certs)

    if (-not $Certs) { return $null }

    $now = Get-Date
    $ekuClientAuth = '1.3.6.1.5.5.7.3.2'       # Client Authentication
    $ekuSmartCard  = '1.3.6.1.4.1.311.20.2.2'  # Smart Card Logon

    $preferred = $Certs | Where-Object {
        $_.NotAfter -gt $now -and (
            (($_.EnhancedKeyUsageList | ForEach-Object Value) -contains $ekuClientAuth) -or
            (($_.EnhancedKeyUsageList | ForEach-Object Value) -contains $ekuSmartCard)
        )
    }
    if ($preferred -and $preferred.Count -gt 0) {
        return $preferred | Sort-Object NotBefore -Descending | Select-Object -First 1
    } else {
        return $Certs | Sort-Object NotBefore -Descending | Select-Object -First 1
    }
}

function Escape-LdapValue {
    <#
      Minimal RFC4515 escaping for filter equality:
        \  => \5c
        *  => \2a
        (  => \28
        )  => \29
        NUL (0x00) => \00
    #>
    param([Parameter(Mandatory)][string]$Value)
    $v = $Value -replace '\\','\5c'
    $v = $v -replace '\*','\2a'
    $v = $v -replace '\(','\28'
    $v = $v -replace '\)','\29'
    $v = $v -replace ([char]0), '\00'
    return $v
}

function Build-OrFilterChunk {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Attribute,
        [Parameter(Mandatory)][string[]]$Values
    )
    $inner = ''
    foreach ($val in $Values) {
        if ($null -ne $val -and $val -ne '') {
            $inner += '(' + $Attribute + '=' + (Escape-LdapValue $val) + ')'
        }
    }
    return "(|$inner)"
}

function Get-UsersWithPublishedCertsByList {
    <#
      Builds LDAP filters in chunks: (&(objectClass=user)(userCertificate=*)(|(<id>=v1)(<id>=v2)...))
      Returns AD users with userCertificate populated that match the provided values.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$IdAttribute,
        [Parameter(Mandatory)][string[]]$IdValues,
        [int]$ChunkSize = 128
    )

    $all = @()
    if (-not $IdValues -or $IdValues.Count -eq 0) { return $all }

    $chunks = @()
    for ($i = 0; $i -lt $IdValues.Count; $i += $ChunkSize) {
        $end = [Math]::Min($i + $ChunkSize - 1, $IdValues.Count - 1)
        $chunks += ,($IdValues[$i..$end])
    }

    $j = 0
    foreach ($chunk in $chunks) {
        $j++
        $or = Build-OrFilterChunk -Attribute $IdAttribute -Values $chunk
        $ldap = "(&(objectClass=user)(userCertificate=*)$or)"
        Write-Verbose ("Query chunk {0}/{1} with {2} value(s)." -f $j, $chunks.Count, $chunk.Count)
        $all += Get-ADUser -LDAPFilter $ldap -Properties userCertificate,altSecurityIdentities,userPrincipalName,sAMAccountName
    }
    $all
}
#endregion Helpers

try {
    Ensure-ActiveDirectoryModule

    if (-not (Test-Path $CsvPath)) { throw "CSV not found: $CsvPath" }

    $rows = Import-Csv -Path $CsvPath
    if (-not $rows -or $rows.Count -eq 0) { throw "CSV is empty: $CsvPath" }
    if ($rows[0].PSObject.Properties.Name -notcontains $IdentityColumn) {
        throw "CSV must have a column named '$IdentityColumn'."
    }

    # Collect identities (unique, non-empty)
    $ids = $rows | ForEach-Object { $_.$IdentityColumn } | Where-Object { $_ } | Select-Object -Unique
    if (-not $ids -or $ids.Count -eq 0) { throw "No identities found under column '$IdentityColumn'." }

    # Get only users that have Published Certificates (server-side filter userCertificate=*)
    $adUsers = Get-UsersWithPublishedCertsByList -IdAttribute $IdType -IdValues $ids

    # Index AD results by the requested id type for quick lookups (case-insensitive via ToLower)
    $byKey = @{}
    foreach ($u in $adUsers) {
        switch ($IdType) {
            'sAMAccountName'    { $key = $u.SamAccountName }
            'userPrincipalName' { $key = $u.UserPrincipalName }
            'distinguishedName' { $key = $u.DistinguishedName }
        }
        if ($key) { $byKey[$key.ToLower()] = $u }
    }

    $results = New-Object System.Collections.Generic.List[object]
    $counter = 0

    foreach ($row in $rows) {
        $counter++
        $id = $row.$IdentityColumn
        $status = 'Skipped'
        $message = ''
        $mapping = $null
        $thumb   = $null
        $u       = $null

        if (-not $id) {
            $status = 'InvalidRow'
            $message = "Missing identity value in CSV row."
        } else {
            $lookup = $id.ToLower()
            $u = $byKey[$lookup]

            if (-not $u) {
                $status = 'NotFoundOrNoPublishedCert'
                $message = "Not returned by (userCertificate=*) filter or not found."
            } else {
                # Parse Published Certificates to X509 objects
                $certs = @()
                foreach ($raw in $u.userCertificate) {
                    try {
                        $certs += New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($raw)
                    } catch {
                        if ($message -eq '') {
                            $message = "One userCertificate failed to parse: $($_.Exception.Message)"
                        } else {
                            $message = $message + " | One userCertificate failed to parse: $($_.Exception.Message)"
                        }
                    }
                }

                if (-not $certs -or $certs.Count -eq 0) {
                    $status = 'NoValidCerts'
                    if ($message -eq '') { $message = 'Published Certificates present but none parsed.' }
                } else {
                    $cert = Select-LatestAuthCert -Certs $certs
                    if (-not $cert) {
                        $status = 'NoSuitableCert'
                        if ($message -eq '') { $message = 'No certificate selected by policy.' }
                    } else {
                        $issuerRev = Convert-DnToReversed -Dn $cert.Issuer
                        $serialRev = Get-ReversedHex -Hex $cert.SerialNumber
                        $mapping   = "X509:<I>$issuerRev<SR>$serialRev"
                        $thumb     = $cert.Thumbprint

                        if ($ApplyToUser) {
                            if ($ApplyMode -eq 'Replace') {
                                if ($PSCmdlet.ShouldProcess($u.DistinguishedName, "Replace altSecurityIdentities")) {
                                    Set-ADUser -Identity $u.DistinguishedName -Replace @{ altSecurityIdentities = $mapping }
                                    $status  = 'Replaced'
                                    $message = 'altSecurityIdentities replaced with recommended mapping.'
                                }
                            } else {
                                # Append only if missing
                                $existing = @($u.altSecurityIdentities) | ForEach-Object { if ($_){ $_.ToString() } }
                                if ($mapping -notin $existing) {
                                    if ($PSCmdlet.ShouldProcess($u.DistinguishedName, "Add altSecurityIdentities '$mapping'")) {
                                        Set-ADUser -Identity $u.DistinguishedName -Add @{ altSecurityIdentities = $mapping }
                                        $status  = 'Added'
                                        $message = 'Recommended mapping appended.'
                                    }
                                } else {
                                    $status  = 'Unchanged'
                                    $message = 'Recommended mapping already present.'
                                }
                            }
                        } else {
                            $status  = 'Generated'
                            $message = 'Mapping generated; not applied (preview).'
                        }
                    }
                }
            }
        }

        $results.Add([pscustomobject]@{
            Row                 = $counter
            RequestedId         = $id
            IdType              = $IdType
            SamAccountName      = if ($u) { $u.SamAccountName } else { $null }
            UserPrincipalName   = if ($u) { $u.UserPrincipalName } else { $null }
            DistinguishedName   = if ($u) { $u.DistinguishedName } else { $null }
            CertificateThumb    = $thumb
            Mapping             = $mapping
            Status              = $status
            Message             = $message
        })
    }

    # Output to screen  (✅ fixed: -AutoSize in one token, properties passed correctly)
    $results | Format-Table Row,RequestedId,Status,Message -AutoSize

    # Optional export
    if ($OutCsvPath) {
        $results | Export-Csv -Path $OutCsvPath -NoTypeInformation -Encoding UTF8
        Write-Host "Results written to $OutCsvPath"
    }

} catch {
    Write-Error $_.Exception.Message
    throw
}
