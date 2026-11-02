# Run from an elevated SSH shell; no GUI and no secret required.
$ErrorActionPreference='Stop'
$base='C:\ProgramData\PushGateWin'
$key='HKLM:\SOFTWARE\PushGateWin'
$auth='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication'
$ids=@('{ABA410A1-5289-4DF6-A631-B53277425A01}','{ABA410A2-5289-4DF6-A631-B53277425A01}','{ABA410A3-5289-4DF6-A631-B53277425A01}')
$snapshot=Join-Path $base 'before.json'
if(-not(Test-Path $snapshot)){throw 'Ownership snapshot missing; refusing to remove registrations'}
$owner=Get-Content -Raw -LiteralPath $snapshot | ConvertFrom-Json
if($owner.product -cne 'PushGateWin-v1'){throw 'Ownership snapshot mismatch'}
if(Test-Path $key){Set-ItemProperty $key FilterEnabled -Type DWord -Value 0}
# Only keys created by this installer. Leave files and recovery records intact.
foreach($id in $ids){
 foreach($root in @("$auth\Credential Providers","$auth\Credential Provider Filters",'HKLM:\SOFTWARE\Classes\CLSID')){
  $path=Join-Path $root $id
  if(Test-Path $path){Remove-Item -LiteralPath $path -Recurse -Force}
 }
}
$snapshot=Join-Path $base 'before.json'
if(Test-Path $snapshot){
 $before=Get-Content -Raw -LiteralPath $snapshot | ConvertFrom-Json
 $winlogon='HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
 if($before.autoExisted){Set-ItemProperty $winlogon AutoAdminLogon -Type String -Value ([string]$before.autoValue)}
 else{Remove-ItemProperty $winlogon AutoAdminLogon -ErrorAction SilentlyContinue}
}
$stock="$auth\Credential Providers\{60B78E88-EAD8-445C-9CFD-0B87F74EA6CD}"
if(-not(Test-Path $stock)){throw 'Stock password provider is missing; removal needs manual recovery'}
if((Get-ItemProperty $stock -Name Disabled -ErrorAction SilentlyContinue).Disabled -eq 1){throw 'Stock password provider is disabled; this installer did not disable it'}
foreach($id in $ids){if(Test-Path "$auth\Credential Providers\$id"){throw 'Provider removal failed'}}
# Winlogon recreates only its logon UI; user applications and sessions stay intact.
# This makes removal effective even when the old secure-desktop UI is hung.
Get-Process -Name LogonUI -ErrorAction SilentlyContinue | Stop-Process -Force
Write-Output 'Removed new providers and filter; stock password provider remains registered. Logon UI refreshed; files preserved.'
