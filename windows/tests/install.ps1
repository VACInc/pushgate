# Destructive only to this task's new lab configuration; never run on a user PC.
param([Parameter(Mandatory=$true)][string]$Bundle)
$ErrorActionPreference='Stop'
if($env:COMPUTERNAME -ine 'pgwin'){throw 'Install tests run only on the isolated pgwin guest'}
$base='C:\ProgramData\PushGateWin'
if(Test-Path $base){throw 'Existing configuration found; refusing to overwrite it'}
$beforeAuto=(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name AutoAdminLogon -ErrorAction SilentlyContinue).AutoAdminLogon
New-Item -ItemType Directory -Path $base | Out-Null
$sid=([Security.Principal.NTAccount]::new($env:COMPUTERNAME,'pgtest')).Translate([Security.Principal.SecurityIdentifier]).Value
$prefix=$sid.Substring(0,$sid.LastIndexOf('-'))
@('PUSHGATE_SERVER=https://invalid.example','PUSHGATE_CLIENT_ID=fixture',(('PUSHGATE_CLIENT_'+'SECRET')+'=fixture'),'PUSHGATE_APPROVER_USERNAME=fixture','PUSHGATE_SYSTEM_NAME=pgwin','PUSHGATE_TIMEOUT=2','PUSHGATE_PRINCIPAL_USERNAME=fixture',('PUSHGATE_WINDOWS_MACHINE_SID='+$prefix)) | Set-Content "$base\client.env" -Encoding ASCII
@{version=1;sid=$sid;used=$true;attempts=0;next_try=0;salt='';verifier=''} | ConvertTo-Json | Set-Content "$base\recovery.json"
Import-Module (Join-Path $Bundle "src\Client.psm1") -Force
$readback=Read-PushGateConfig
if(-not(Test-LocalAccount $readback $sid)){throw "Fixture configuration did not round-trip"}
Write-Output "PASS fixture configuration round-trip"
$stage=Join-Path $Bundle 'install-stage'
New-Item -ItemType Directory -Path $stage | Out-Null
foreach($name in @('Install.ps1','Remove.ps1')){Copy-Item (Join-Path $Bundle "deploy\$name") $stage}
foreach($name in @('Gate.ps1','Client.psm1')){Copy-Item (Join-Path $Bundle "src\$name") $stage}
Copy-Item (Join-Path $Bundle 'PushGateWin.dll') $stage
$auth='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication'
$stock="$auth\Credential Providers\{60B78E88-EAD8-445C-9CFD-0B87F74EA6CD}"
$ids=@('{ABA410A1-5289-4DF6-A631-B53277425A01}','{ABA410A2-5289-4DF6-A631-B53277425A01}')
$snapshot=$null
foreach($round in 1,2){
 & "$stage\Install.ps1" -Account $env:USERNAME
 foreach($id in $ids){if(-not(Test-Path "$auth\Credential Providers\$id")){throw 'Pilot registration missing'}}
 if((Get-ItemProperty 'HKLM:\SOFTWARE\PushGateWin').FilterEnabled -ne 0){throw 'Pilot enabled filtering'}
 if(-not(Test-Path $stock)){throw 'Pilot removed stock provider'}
 $hash=(Get-FileHash "$base\before.json").Hash
 if($snapshot -and $hash -cne $snapshot){throw 'Reinstall changed original recovery snapshot'}
 $snapshot=$hash
 & "$stage\Remove.ps1"
 foreach($id in $ids){if(Test-Path "$auth\Credential Providers\$id"){throw 'Removal left a provider registered'}}
 if(-not(Test-Path $stock)){throw 'Removal lost stock provider'}
 $after=(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name AutoAdminLogon -ErrorAction SilentlyContinue).AutoAdminLogon
 if($after -ne $beforeAuto){throw 'Original autologon flag was not restored'}
 Write-Output "PASS pilot install/removal round $round"
}
& "$stage\Remove.ps1"
Write-Output 'PASS idempotent removal; stock provider and original snapshot preserved'
