# Prepare this host's existing SSH integration for the sign-in gate. Values stay
# local; only the salted one-time verifier arrives through VerifierFile.
param(
 [Parameter(Mandatory=$true)][string]$VerifierFile,
 [Parameter(Mandatory=$true)][string]$Account,
 [Parameter(Mandatory=$true)][string]$Server,
 [Parameter(Mandatory=$true)][string]$SystemName,
 [Parameter(Mandatory=$true)][string]$IntegrationFile
)
$ErrorActionPreference='Stop'
if($Server -notmatch '^https://[A-Za-z0-9.-]+(:[0-9]+)?/?$'){throw 'Server must be an HTTPS origin'}
$Server=$Server.TrimEnd('/')
foreach($value in @($Account,$SystemName)){if($value -match '[\r\n]' -or -not $value){throw 'Account and system name must be single-line values'}}
$base='C:\ProgramData\PushGateWin'
if(Test-Path $base){throw 'Sign-in configuration already exists; refusing overwrite'}
$verifier=Get-Content -Raw -LiteralPath $VerifierFile | ConvertFrom-Json
$account=[Security.Principal.NTAccount]::new($env:COMPUTERNAME,$Account)
$sid=$account.Translate([Security.Principal.SecurityIdentifier]).Value
if($verifier.version -ne 1 -or $verifier.sid -cne $sid -or $verifier.used){throw 'Recovery verifier does not match this account'}
if(([Convert]::FromBase64String($verifier.salt)).Length -ne 32 -or
   ([Convert]::FromBase64String($verifier.verifier)).Length -ne 32){throw 'Invalid recovery verifier'}
$source=@{}
foreach($line in [IO.File]::ReadAllLines($IntegrationFile)){
 $text=$line.Trim();if($text.StartsWith('#') -or -not $text.Contains('=')){continue}
 $i=$text.IndexOf('=');$source[$text.Substring(0,$i).Trim()]=$text.Substring($i+1).Trim()
}
foreach($key in @('PUSHGATE_CLIENT_ID','PUSHGATE_CLIENT_SECRET','PUSHGATE_APPROVER_USERNAME','PUSHGATE_SYSTEM_NAME')){
 if(-not $source[$key]){throw 'Existing host integration is incomplete'}
}
if($source['PUSHGATE_SYSTEM_NAME'] -cne $SystemName){throw 'Existing integration belongs to another host'}
function Protect-Path([string]$path,[bool]$directory){
 $acl=if($directory){[Security.AccessControl.DirectorySecurity]::new()}else{[Security.AccessControl.FileSecurity]::new()}
 $acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'));$acl.SetAccessRuleProtection($true,$false)
 foreach($id in @('S-1-5-18','S-1-5-32-544')){
  $principal=[Security.Principal.SecurityIdentifier]::new($id)
  $rule=if($directory){[Security.AccessControl.FileSystemAccessRule]::new($principal,'FullControl','ContainerInherit,ObjectInherit','None','Allow')}else{[Security.AccessControl.FileSystemAccessRule]::new($principal,'FullControl','Allow')}
  [void]$acl.AddAccessRule($rule)
 }
 Set-Acl -LiteralPath $path -AclObject $acl
}
New-Item -ItemType Directory -Path $base | Out-Null
Protect-Path $base $true
$lines=@(('PUSHGATE_SERVER='+$Server),'PUSHGATE_TIMEOUT=65',('PUSHGATE_PRINCIPAL_USERNAME='+$Account),('PUSHGATE_WINDOWS_MACHINE_SID='+$sid.Substring(0,$sid.LastIndexOf('-'))))
foreach($key in @('PUSHGATE_CLIENT_ID','PUSHGATE_CLIENT_SECRET','PUSHGATE_APPROVER_USERNAME','PUSHGATE_SYSTEM_NAME')){$lines+=($key+'='+$source[$key])}
[IO.File]::WriteAllLines((Join-Path $base 'client.env'),$lines,[Text.UTF8Encoding]::new($false))
Protect-Path (Join-Path $base 'client.env') $false
Copy-Item -LiteralPath $VerifierFile -Destination (Join-Path $base 'recovery.json')
Protect-Path (Join-Path $base 'recovery.json') $false
$source.Clear();[Array]::Clear($lines,0,$lines.Length)
Write-Output 'Sign-in configuration prepared locally; no provider registered and no filter enabled.'
