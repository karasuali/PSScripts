NETLOGON / SYSVOL Password Finder

$paths = @("C:\Windows\SYSVOL", "C:\Windows\SYSVOL_DFSR", "C:\Windows\NTDS", "\\domain.local\NETLOGON")
$patterns = @("password", "passwd", "pwd", "credential", "secret")
foreach ($path in $paths) {
    Get-ChildItem -Path $path -Recurse -Include *.bat, *.cmd, *.vbs, *.ps1, *.txt -ErrorAction SilentlyContinue |
    ForEach-Object {
        foreach ($pattern in $patterns) {
            Select-String -Path $_.FullName -Pattern $pattern -CaseSensitive:$false |
            ForEach-Object {
                Write-Host "Possible password found in: $($_.Path) - Line: $($_.Line)"
            }
        }
    }
}
