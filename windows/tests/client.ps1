$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot '..\src\Client.psm1') -Force
$module=Get-Module Client
$script:passed=0
function Check($ok,$label){if(-not $ok){throw "FAIL $label"};$script:passed++;Write-Output "PASS $label"}
$c=@{PUSHGATE_TIMEOUT=2;PUSHGATE_APPROVER_USERNAME='fixture';PUSHGATE_SYSTEM_NAME='fixture';PUSHGATE_CLIENT_ID='fixture';PUSHGATE_SERVER='https://invalid.example'}
$c[('PUSHGATE_CLIENT_'+'SECRET')]=('in'+'ert')
$c['PUSHGATE_WINDOWS_MACHINE_SID']='S-1-5-21-1-2-3'
Check (Test-LocalAccount $c 'S-1-5-21-1-2-3-1001') 'owner account bound to this machine'
Check (Test-LocalAccount $c 'S-1-5-21-1-2-3-1002') 'second local account still requires approval'
Check (-not(Test-LocalAccount $c 'S-1-5-21-1-2-30-1001')) 'foreign machine account refused'
# Replace transport inside the module. These tests cannot call the real network.
& $module {function script:Send-Once {param($c,$client,$method,$path,$body,$remaining)
 if($script:mode -eq 'offline'){return $null}
 if($script:mode -eq 'bad'){return @{Code=200;Text='{}'}}
 if($path.EndsWith('/consume')){
  $script:consumes++
  if($script:mode -eq 'consume-deny'){return @{Code=409;Text='{}'}}
  return @{Code=200;Text='{"data":{"id":"fixture","status":"approved","allowed":true,"consumed":true,"consumed_at":"now"}}'}
 }
 if($method -eq 'POST'){
  if($script:mode -eq 'trusted'){return @{Code=200;Text='{"data":{"id":"fixture","status":"approved","allowed":true,"factor":"trusted_session","cache":{"username":"fixture"}}}'}}
  if($script:mode -eq 'instant'){return @{Code=200;Text='{"data":{"id":"fixture","status":"approved","allowed":true,"cache":{"username":"fixture"}}}'}}
  return @{Code=200;Text='{"data":{"id":"fixture","status":"pending","allowed":false,"cache":{"username":"fixture"}}}'}
 }
 $status=if($script:mode -eq 'deny'){'denied'}else{'approved'}
 $factor=if($script:mode -eq 'wrong-factor'){',"factor":"trusted_session"'}else{''}
 $id=if($script:mode -eq 'wrong-id'){'other'}else{'fixture'}
 $user=if($script:mode -eq 'wrong-account'){'other'}else{'fixture'}
 $allowed=if($script:mode -eq 'not-allowed'){'false'}else{'true'}
 return @{Code=200;Text=('{"data":{"id":"'+$id+'","status":"'+$status+'","allowed":'+$allowed+','+'"cache":{"username":"'+$user+'"}'+$factor+'}}')}
}}
foreach($case in @(@('offline','unreachable'),@('bad','denied'),@('deny','denied'),@('consume-deny','denied'),@('trusted','denied'),@('instant','denied'),@('wrong-factor','denied'),@('wrong-id','denied'),@('wrong-account','denied'),@('not-allowed','denied'),@('approve','approved'))){
 & $module {param($m)$script:mode=$m;$script:consumes=0} $case[0]
 Check ((Invoke-OnlineGate $c 'fixture' 'console') -ceq $case[1]) $case[0]
 $consumes=& $module {$script:consumes}
 if($case[0] -eq 'approve'){Check ($consumes -eq 1) 'native start/poll schema consumes one fresh approval'}
 elseif($case[0] -ne 'consume-deny'){Check ($consumes -eq 0) ('no consume for '+$case[0])}
}
$dir=Join-Path ([IO.Path]::GetTempPath()) ('pgwin-test-'+[Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory $dir | Out-Null
try{
 $path=Join-Path $dir 'recovery.json';$sid='S-1-5-21-1-2-3-4';$code=('Ab3d'*8);$salt=[byte[]](1..32)
 $kdf=[Security.Cryptography.Rfc2898DeriveBytes]::new($code,$salt,210000,[Security.Cryptography.HashAlgorithmName]::SHA256)
 $record=@{version=1;sid=$sid;used=$false;attempts=0;next_try=0;salt=[Convert]::ToBase64String($salt);verifier=[Convert]::ToBase64String($kdf.GetBytes(32))};$kdf.Dispose()
 $record | ConvertTo-Json | Set-Content $path -Encoding UTF8
 Check (-not(Use-RecoveryCode $path 'S-1-5-21-1-2-3-5' $code)) 'wrong account blocked'
 Check (Use-RecoveryCode $path $sid $code) 'offline code consumed'
 Check (-not(Use-RecoveryCode $path $sid $code)) 'offline code replay blocked'
 $record.used=$false;$record | ConvertTo-Json | Set-Content $path -Encoding UTF8
 Check (-not(Use-RecoveryCode $path $sid ('B'*32))) 'wrong code blocked'
 Check (-not(Use-RecoveryCode $path $sid $code)) 'recovery attempts throttled'
 '{broken' | Set-Content $path
 Check (-not(Use-RecoveryCode $path $sid $code)) 'corrupt verifier fails closed'
}finally{Remove-Item -LiteralPath $dir -Recurse -Force}
Write-Output "tests passed=$script:passed"
