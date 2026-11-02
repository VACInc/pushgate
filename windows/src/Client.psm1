Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$ConfigPath='C:\ProgramData\PushGateWin\client.env'
function Read-PushGateConfig {
    $c = @{}
    foreach ($line in [IO.File]::ReadAllLines($ConfigPath)) {
        $t = $line.Trim()
        if ($t -eq '' -or $t.StartsWith('#') -or -not $t.Contains('=')) { continue }
        $i = $t.IndexOf('=')
        $c[$t.Substring(0, $i).Trim()] = $t.Substring($i + 1).Trim()
    }
    foreach ($k in 'PUSHGATE_SERVER', 'PUSHGATE_CLIENT_ID', 'PUSHGATE_CLIENT_SECRET', 'PUSHGATE_APPROVER_USERNAME', 'PUSHGATE_SYSTEM_NAME', 'PUSHGATE_WINDOWS_MACHINE_SID', 'PUSHGATE_PRINCIPAL_USERNAME') {
        if (-not $c[$k]) { throw "missing $k" }
    }
    if ($c['PUSHGATE_SERVER'] -notmatch '^https://[A-Za-z0-9.-]+(:[0-9]+)?/?$') { throw 'server must be https origin' }
    $c['PUSHGATE_SERVER'] = $c['PUSHGATE_SERVER'].TrimEnd('/')
    $t = 70; [void][int]::TryParse([string]$c['PUSHGATE_TIMEOUT'], [ref]$t)
    if ($t -lt 1 -or $t -gt 300) { $t = 70 }
    $c['PUSHGATE_TIMEOUT'] = $t
    return $c
}

function Send-Once($c, $client, [string]$method, [string]$path, [byte[]]$body, [double]$remaining) {
    # An empty byte[] returned through the pipeline arrives as $null.
    if ($null -eq $body) { $body = [byte[]]::new(0) }
    $ts = [string][DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    $nb = New-Object byte[] 16
    [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($nb)
    $nonce = -join ($nb | ForEach-Object { $_.ToString('x2') })
    $prefix = [Text.Encoding]::UTF8.GetBytes(($method.ToUpperInvariant(), $path, $ts, $nonce, '') -join "`n")
    $hmac = New-Object Security.Cryptography.HMACSHA256 (, [Text.Encoding]::UTF8.GetBytes($c['PUSHGATE_CLIENT_SECRET']))
    [void]$hmac.TransformBlock($prefix, 0, $prefix.Length, $null, 0)
    [void]$hmac.TransformFinalBlock($body, 0, $body.Length)
    $sig = -join ($hmac.Hash | ForEach-Object { $_.ToString('x2') })
    $req = New-Object Net.Http.HttpRequestMessage ([Net.Http.HttpMethod]::new($method)), ($c['PUSHGATE_SERVER'] + $path)
    [void]$req.Headers.TryAddWithoutValidation('X-PushGate-Client-Id', $c['PUSHGATE_CLIENT_ID'])
    [void]$req.Headers.TryAddWithoutValidation('X-PushGate-Timestamp', $ts)
    [void]$req.Headers.TryAddWithoutValidation('X-PushGate-Nonce', $nonce)
    [void]$req.Headers.TryAddWithoutValidation('X-PushGate-Signature', $sig)
    if ($method -ne 'GET') {
        $req.Content = New-Object Net.Http.ByteArrayContent (, $body)
        $req.Content.Headers.ContentType = [Net.Http.Headers.MediaTypeHeaderValue]::new('application/json')
    }
    $cts = New-Object Threading.CancellationTokenSource ([TimeSpan]::FromMilliseconds([Math]::Max(1, [Math]::Min(5000, $remaining * 1000))))
    try {
        $resp = $client.SendAsync($req, $cts.Token).GetAwaiter().GetResult()
        $code = [int]$resp.StatusCode
        $text = $resp.Content.ReadAsStringAsync().GetAwaiter().GetResult()
    } catch {
        return $null
    }
    if (500, 502, 503, 504 -contains $code) { return $null }
    return @{ Code = $code; Text = $text }
}

function Send-Retry($c, $client, [string]$method, [string]$path, $sw, [double]$deadline, [scriptblock]$bodyFn) {
    $delay = 0.5
    while ($true) {
        $remaining = $deadline - $sw.Elapsed.TotalSeconds
        if ($remaining -le 0) { return $null }
        $body = if ($bodyFn) { & $bodyFn } else { [byte[]]@() }
        $r = Send-Once $c $client $method $path $body $remaining
        if ($r) { return $r }
        $remaining = $deadline - $sw.Elapsed.TotalSeconds
        if ($remaining -le 0) { return $null }
        Start-Sleep -Milliseconds ([int]([Math]::Min($delay, $remaining) * 1000))
        $delay = [Math]::Min($delay * 2, 3.0)
    }
}

function Get-AuthData($r, [string]$user, [string]$id) {
    if (-not $r -or $r.Code -lt 200 -or $r.Code -gt 299) { throw 'bad response' }
    $p = $r.Text | ConvertFrom-Json
    $d = $p.data
    if (-not $d -or -not ($d.id -is [string]) -or $d.id.Trim() -eq '') { throw 'no id' }
    if ($id -and $d.id -ne $id) { throw 'id mismatch' }
    if (-not ($d.status -is [string])) { throw 'no status' }
    if (-not $d.cache -or $d.cache.username -ne $user) { throw 'cache binding' }
    return $d
}


function Test-Approved($d) {
    return ($d.status -ceq 'approved') -and ($d.allowed -is [bool]) -and $d.allowed
}

function Invoke-OnlineGate($c, [string]$user, [string]$source) {
    # Only an unreachable start permits offline recovery. Once a request exists,
    # every failure, timeout, malformed response or denial is a terminal denial.
    Add-Type -AssemblyName System.Net.Http
    $handler = New-Object Net.Http.HttpClientHandler
    $handler.UseProxy = $false
    $handler.AllowAutoRedirect = $false
    $client = New-Object Net.Http.HttpClient ($handler)
    $client.Timeout = [Threading.Timeout]::InfiniteTimeSpan
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $deadline = [double]$c['PUSHGATE_TIMEOUT']
    try {
        $body = [ordered]@{
            username=$user; approver_username=$c['PUSHGATE_APPROVER_USERNAME'];
            system=$c['PUSHGATE_SYSTEM_NAME']; pam_service='sign-in';
            source_ip=$source; offline_code=$null; client_timeout_seconds=$deadline
        }
        $bytes = [Text.Encoding]::UTF8.GetBytes(($body | ConvertTo-Json -Compress))
        $r = Send-Once $c $client 'POST' '/api/v1/auth/requests' $bytes ([Math]::Min(5,$deadline))
        if ($null -eq $r) { return 'unreachable' }
        $d = Get-AuthData $r $user $null
        # A fresh push starts pending. Never accept an immediate cached decision.
        # The server's native start/poll schema omits factor; the pending-to-approved
        # transition plus account binding and one-time consumption proves this flow.
        if ($d.status -cne 'pending') { return 'denied' }
        $id = $d.id
        while ($sw.Elapsed.TotalSeconds -lt $deadline) {
            if ($d.status -cne 'pending') {
                if (-not (Test-Approved $d)) { return 'denied' }
                if ($d.PSObject.Properties['factor'] -and $d.factor -cne 'push') { return 'denied' }
                $r = Send-Once $c $client 'POST' ('/api/v1/auth/requests/'+[Uri]::EscapeDataString($id)+'/consume') ([byte[]]@()) ($deadline-$sw.Elapsed.TotalSeconds)
                if ($null -eq $r -or $sw.Elapsed.TotalSeconds -ge $deadline) { return 'denied' }
                if ($r.Code -lt 200 -or $r.Code -gt 299) { return 'denied' }
                $k = ($r.Text | ConvertFrom-Json).data
                if (-not $k -or $k.id -cne $id) { return 'denied' }
                if ((Test-Approved $k) -and $k.consumed -is [bool] -and $k.consumed -and $k.consumed_at -is [string] -and $k.consumed_at) { return 'approved' }
                return 'denied'
            }
            Start-Sleep -Milliseconds 400
            if ($sw.Elapsed.TotalSeconds -ge $deadline) { return 'denied' }
            $r = Send-Once $c $client 'GET' ('/api/v1/auth/requests/'+[Uri]::EscapeDataString($id)) ([byte[]]@()) ($deadline-$sw.Elapsed.TotalSeconds)
            $d = Get-AuthData $r $user $id
        }
        return 'denied'
    } catch { return 'denied' } finally { $client.Dispose(); $handler.Dispose() }
}

function Use-RecoveryCode([string]$path, [string]$sid, [string]$code) {
    # Caller has checked the entire base directory's owner/DACL. No plaintext
    # codes on disk. A separate never-replaced lock serializes all processes.
    if ($code -cnotmatch '^[A-Za-z0-9]{32}$') { return $false }
    $lock=$null; $file=$null
    try {
        $lock=[IO.File]::Open($path+'.lock',[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
        $file=[IO.FileStream]::new($path,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None,4096,[IO.FileOptions]::WriteThrough)
        if ($file.Length -gt 65536) { return $false }
        $reader=[IO.StreamReader]::new($file,[Text.Encoding]::UTF8,$true,4096,$true)
        $state=$reader.ReadToEnd() | ConvertFrom-Json
        $reader.Dispose()
        if ($state.version -ne 1 -or $state.sid -cne $sid -or $state.used) { return $false }
        if ([DateTimeOffset]::UtcNow.ToUnixTimeSeconds() -lt [long]$state.next_try) { return $false }
        $salt=[Convert]::FromBase64String($state.salt)
        if ($salt.Length -ne 32) { return $false }
        $derive=[Security.Cryptography.Rfc2898DeriveBytes]::new($code,$salt,210000,[Security.Cryptography.HashAlgorithmName]::SHA256)
        try { $actual=$derive.GetBytes(32) } finally { $derive.Dispose() }
        $expected=[Convert]::FromBase64String($state.verifier)
        if ($expected.Length -ne 32) { return $false }
        $different=0
        for ($i=0;$i -lt 32;$i++) { $different=$different -bor ($actual[$i] -bxor $expected[$i]) }
        $state.attempts=[long]$state.attempts+1
        $state.next_try=[DateTimeOffset]::UtcNow.ToUnixTimeSeconds()+[Math]::Min(3600,5*[Math]::Pow(2,[Math]::Min(10,$state.attempts)))
        $state.used=($different -eq 0)
        $bytes=[Text.Encoding]::UTF8.GetBytes(($state | ConvertTo-Json -Compress))
        $file.Position=0; $file.Write($bytes,0,$bytes.Length); $file.SetLength($bytes.Length); $file.Flush($true)
        # Durable consumption precedes credential release. A torn write is invalid
        # JSON and refuses future use, rather than resurrecting the recovery code.
        return $state.used
    } catch { return $false } finally { if ($file) {$file.Dispose()}; if ($lock) {$lock.Dispose()} }
}
function Test-LocalAccount($c, [string]$sid) {
    $prefix=[string]$c['PUSHGATE_WINDOWS_MACHINE_SID']
    return ($prefix -cmatch '^S-1-5-21-\d+-\d+-\d+$') -and
        ($sid -cmatch '^S-1-5-21-(\d+-){3}\d+$') -and
        $sid.StartsWith($prefix+'-',[StringComparison]::Ordinal)
}
Export-ModuleMember -Function Read-PushGateConfig,Invoke-OnlineGate,Use-RecoveryCode,Test-LocalAccount
