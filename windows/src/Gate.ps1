$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
try {
    Import-Module (Join-Path $PSScriptRoot 'Client.psm1') -Force
    $line=[Console]::In.ReadLine()
    if (-not $line -or $line.Length -gt 4096) { throw 'invalid input' }
    $request=$line | ConvertFrom-Json
    if ($request.user -cnotmatch '^[A-Za-z0-9_.@-]{1,128}$' -or
        $request.sid -notmatch '^S-1-5-21-(\d+-){3}\d+$' -or
        $request.source -notmatch '^(console|RDP [A-Za-z0-9.:_-]{1,255})$') { throw 'invalid context' }
    $scope=[string](Get-ItemPropertyValue -LiteralPath 'HKLM:\SOFTWARE\PushGateWin' -Name GatedAccountSid)
    if ($request.sid -cne $scope) { throw 'account is outside the approval scope' }
    $c=Read-PushGateConfig
    if (-not (Test-LocalAccount $c $request.sid)) { throw 'account binding mismatch' }
    # No offline material is ever sent to the server.
    $result=Invoke-OnlineGate $c $c['PUSHGATE_PRINCIPAL_USERNAME'] $request.source
    if ($result -ceq 'approved') { [Console]::Out.WriteLine('APPROVED'); exit 0 }
    if ($result -ceq 'unreachable' -and $request.code -and
        (Use-RecoveryCode 'C:\ProgramData\PushGateWin\recovery.json' $request.sid $request.code)) {
        [Console]::Out.WriteLine('APPROVED'); exit 0
    }
} catch { }
[Console]::Out.WriteLine('DENIED')
exit 1
