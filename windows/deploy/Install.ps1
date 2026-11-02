param([Parameter(Mandatory=$true)][string]$Account)
# Pilot registration keeps the system password provider available. Full
# filtering must be enabled separately after both
# disposable-VM and target acceptance receipts are reviewed.
$ErrorActionPreference='Stop'
$gatedSid=([Security.Principal.NTAccount]::new($env:COMPUTERNAME,$Account)).Translate([Security.Principal.SecurityIdentifier]).Value
if(-not (Get-LocalUser -Name $Account -ErrorAction Stop)){throw 'Approval account must be local'}
$base='C:\ProgramData\PushGateWin';$bin='C:\Program Files\PushGateWin'
$auth='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication'
$stock="$auth\Credential Providers\{60B78E88-EAD8-445C-9CFD-0B87F74EA6CD}"
if(-not(Test-Path $stock)){throw 'Stock password provider must be present'}
if((Get-ItemProperty $stock -Name Disabled -ErrorAction SilentlyContinue).Disabled -eq 1){throw 'Stock password provider must be enabled'}
if(-not(Test-Path "$base\client.env") -or -not(Test-Path "$base\recovery.json")){throw 'Provision bound integration and recovery verifier first'}
$saved=$null
if(Test-Path "$base\before.json"){
 $saved=Get-Content -Raw -LiteralPath "$base\before.json" | ConvertFrom-Json
 if($saved.product -cne 'PushGateWin-v1'){throw 'Existing snapshot is not owned by this installer'}
}
if(Test-Path 'HKLM:\SOFTWARE\PushGateWin'){
 if(-not $saved -or (Get-ItemProperty 'HKLM:\SOFTWARE\PushGateWin').FilterEnabled -ne 0){throw 'Already active or ownership unknown'}
}
foreach($id in @('{ABA410A1-5289-4DF6-A631-B53277425A01}','{ABA410A2-5289-4DF6-A631-B53277425A01}','{ABA410A3-5289-4DF6-A631-B53277425A01}')){
 foreach($root in @("$auth\Credential Providers","$auth\Credential Provider Filters",'HKLM:\SOFTWARE\Classes\CLSID')){
  if(Test-Path "$root\$id"){throw 'A target registration already exists; refusing overwrite'}
 }
}
if(Test-Path $bin){
 foreach($file in Get-ChildItem -LiteralPath $bin -Force){
  $candidate=Join-Path $PSScriptRoot $file.Name
  if(-not $saved -or $file.PSIsContainer -or $file.Name -notin @('PushGateWin.dll','Gate.ps1','Client.psm1','Remove.ps1') -or -not(Test-Path $candidate)){throw 'Installation directory has unowned content'}
  if((Get-FileHash $file.FullName).Hash -cne (Get-FileHash $candidate).Hash){throw 'Existing artifact differs; use a reviewed update'}
 }
}

function Set-PrivateAcl([string]$path,[bool]$directory){
 $owner=[Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
 $acl=if($directory){[Security.AccessControl.DirectorySecurity]::new()}else{[Security.AccessControl.FileSecurity]::new()}
 $acl.SetOwner($owner);$acl.SetAccessRuleProtection($true,$false)
 foreach($id in @('S-1-5-18','S-1-5-32-544')){
  $sid=[Security.Principal.SecurityIdentifier]::new($id)
  $rule=if($directory){[Security.AccessControl.FileSystemAccessRule]::new($sid,'FullControl','ContainerInherit,ObjectInherit','None','Allow')}else{[Security.AccessControl.FileSystemAccessRule]::new($sid,'FullControl','Allow')}
  [void]$acl.AddAccessRule($rule)
 }
 Set-Acl -LiteralPath $path -AclObject $acl
}
foreach($dir in @($base,$bin)){
 New-Item -ItemType Directory -Force -Path $dir | Out-Null
 Set-PrivateAcl $dir $true
}
foreach($name in @('client.env','recovery.json')){Set-PrivateAcl (Join-Path $base $name) $false}
foreach($name in @('PushGateWin.dll','Gate.ps1','Client.psm1','Remove.ps1')){
 $source=Join-Path $PSScriptRoot $name
 if(-not(Test-Path $source)){throw "Missing installation input: $name"}
 if(-not(Test-Path (Join-Path $bin $name))){Copy-Item -LiteralPath $source -Destination (Join-Path $bin $name)}
 Set-PrivateAcl (Join-Path $bin $name) $false
}
$winlogon='HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
$auto=Get-ItemProperty $winlogon -Name AutoAdminLogon -ErrorAction SilentlyContinue
if(-not $saved){
@{product='PushGateWin-v1';autoExisted=($null -ne $auto);autoValue=if($auto){[string]$auto.AutoAdminLogon}else{''}} | ConvertTo-Json | Set-Content -LiteralPath "$base\before.json" -Encoding UTF8
}
New-Item 'HKLM:\SOFTWARE\PushGateWin' -Force | Out-Null
Set-ItemProperty 'HKLM:\SOFTWARE\PushGateWin' FilterEnabled -Type DWord -Value 0
Set-ItemProperty 'HKLM:\SOFTWARE\PushGateWin' GatedAccountSid -Type String -Value $gatedSid
# Do not disable automatic sign-in on the real machine until pilot recovery and
# acceptance gates pass. Global provider filtering is not supported.
$entries=@(
 @('{ABA410A1-5289-4DF6-A631-B53277425A01}','PushGate password',"$auth\Credential Providers"),
 @('{ABA410A2-5289-4DF6-A631-B53277425A01}','PushGate remote unlock',"$auth\Credential Providers"),
 @('{ABA410A3-5289-4DF6-A631-B53277425A01}','PushGate filter',"$auth\Credential Provider Filters")
)
foreach($entry in $entries){
 $id=$entry[0];$name=$entry[1];$root=$entry[2]
 New-Item "$root\$id" -Force | Out-Null;Set-Item "$root\$id" -Value $name
 $com="HKLM:\SOFTWARE\Classes\CLSID\$id\InprocServer32"
 New-Item $com -Force | Out-Null;Set-Item $com -Value "$bin\PushGateWin.dll"
 Set-ItemProperty $com ThreadingModel -Value 'Apartment'
}
Write-Output 'Pilot registered; stock password provider remains available. RDP and remote-unlock requests route to the wrapper.'
