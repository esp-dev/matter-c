param(
    [Parameter(Mandatory=$true)][string]$Executable,
    [Parameter(Mandatory=$true)][string]$InterfaceAlias
)
$ErrorActionPreference='Stop'
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
$principal=[Security.Principal.WindowsPrincipal]::new($identity)
if(-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this script from an elevated PowerShell.'
}
$program=(Resolve-Path -LiteralPath $Executable).Path
if([IO.Path]::GetFileName($program) -ne 'matter-desktop.exe') {
    throw 'Select the built matter-desktop.exe, not another program.'
}
$adapter=@(Get-NetAdapter -Name $InterfaceAlias -ErrorAction Stop)
if($adapter.Count -ne 1) { throw 'Select exactly one network interface.' }
$sha=[Security.Cryptography.SHA256]::Create()
try { $digest=$sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($program.ToLowerInvariant())) }
finally { $sha.Dispose() }
$suffix=([BitConverter]::ToString($digest)).Replace('-','').Substring(0,16)
$name='matter-c-desktop-'+$suffix
# Replace only the rule owned by this exact executable path.
$existing=Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue
if($existing) { $existing | Remove-NetFirewallRule }
New-NetFirewallRule -Name $name -DisplayName 'Matter C desktop simulators' `
    -Direction Inbound -Action Allow -Protocol UDP -LocalPort 5353,'5546-5599' `
    -Program $program -InterfaceAlias $adapter.Name -RemoteAddress LocalSubnet `
    -Profile Any | Out-Null
Write-Output ('Allowed local-subnet UDP 5353 and 5546-5599 for '+$program+' on '+$adapter.Name)
