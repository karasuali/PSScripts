<#
.SYNOPSIS
  Generate KB5014754-compliant altSecurityIdentities mapping using only the recommended form:
    X509:<I>{IssuerDNReversed}<SR>{SerialReversedByByte}

.DESCRIPTION
  - Reads the most current authentication certificate from userCertificate (Published Certificates).
  - Builds the single recommended mapping string.
  - Optionally applies it to altSecurityIdentities (Append or Replace).

.NOTES
  Requires RSAT ActiveDirectory module.
  Written by Ali Karasu

# Preview mapping only

.\Get-AltSecIDMappingsFrom-PublishedCert.ps1 -Identity 'ali.karasu'

# Apply (append mode)
.\Get-AltSecIDMappingsFrom-PublishedCert.ps1 -Identity 'ali.karasu' -ApplyToUser

# Apply (replace mode)
.\Get-AltSecIDMappingsFrom-PublishedCert.ps1 -Identity 'ali.karasu' -ApplyToUser -ApplyMode Replace
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory)]
    [string]$Identity,

    [switch]$ApplyToUser,
    [ValidateSet('Append','Replace')]
    [string]$ApplyMode = 'Append'
)

function Ensure-ActiveDirectoryModule {
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        throw "ActiveDirectory module not found. Install RSAT."
    }
    Import-Module ActiveDirectory -ErrorAction Stop
}

function Get-ReversedHex {
    param([string]$Hex)
    $h = ($Hex -replace '\s','').ToUpper()
    if ($h.Length % 2 -ne 0) { $h = '0' + $h }
    $bytes = for ($i=0; $i -lt $h.Length; $i+=2) { $h.Substring($i,2) }
    [Array]::Reverse($bytes)
    ($bytes -join '')
}

function Convert-DnToReversed {
    param([string]$Dn)
    $placeholder = [Guid]::NewGuid().ToString('N')
    $escaped = $Dn -replace '\\\,', $placeholder
    $parts = $escaped -split ',\s*'
    [Array]::Reverse($parts)
    ($parts -join ',').Replace($placeholder,'\,') -replace ',\s+', ','
}

Ensure-ActiveDirectoryModule

# Get user and certs
$user = Get-ADUser -Identity $Identity -Properties userCertificate,altSecurityIdentities
if (-not $user.userCertificate) { throw "No certificates found for $Identity." }

$certs = @()
foreach ($raw in $user.userCertificate) {
    try { $certs += [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($raw) } catch {}
}
if (-not $certs) { throw "No valid certificates parsed." }

# Pick newest valid cert
$targetCert = $certs | Sort-Object NotBefore -Descending | Select-Object -First 1

# Build recommended mapping
$issuerRev = Convert-DnToReversed -Dn $targetCert.Issuer
$serialRev = Get-ReversedHex -Hex $targetCert.SerialNumber
$mapping   = "X509:<I>$issuerRev<SR>$serialRev"

# Output info
[pscustomobject]@{
    User                  = $user.SamAccountName
    DistinguishedName     = $user.DistinguishedName
    CertificateThumbprint = $targetCert.Thumbprint
    Mapping               = $mapping
}

# Apply if requested
if ($ApplyToUser) {
    if ($ApplyMode -eq 'Replace') {
        if ($PSCmdlet.ShouldProcess($user.DistinguishedName, "Replace altSecurityIdentities")) {
            Set-ADUser -Identity $user.DistinguishedName -Replace @{ altSecurityIdentities = $mapping }
        }
    } else {
        $existing = @($user.altSecurityIdentities)
        if ($mapping -notin $existing) {
            if ($PSCmdlet.ShouldProcess($user.DistinguishedName, "Add altSecurityIdentities '$mapping'")) {
                Set-ADUser -Identity $user.DistinguishedName -Add @{ altSecurityIdentities = $mapping }
            }
        }
    }
}
