# Windows code signing preparation

Status: prepared, disabled, not enrolled, not signed. No application submitted.
Checked 2026-11-01 against the public [PushGate repository](https://github.com/VACInc/pushgate)
and [release](https://github.com/VACInc/pushgate/releases/tag/v1.0.2).

## Eligibility check

[Foundation terms](https://signpath.org/terms) call themselves a draft but are the
published requirements. Free service and the Foundation certificate have separate
conditions; acceptance is discretionary, especially for a new project's reputation.

| Requirement | Evidence / remaining gate |
| --- | --- |
| OSI license, no commercial dual licensing | Public repo declares Apache-2.0. Maintainer must confirm all components and dependencies; this is not a complete license audit. |
| Active maintenance | Public commits through 2026-10-31. |
| Already released in the form to sign | **Not met for Windows.** Public release v1.0.2 has no binary assets; public main has no windows directory and no windows-signin branch. Server/Android publication does not qualify the private Windows DLL. |
| Public own-source verifiable build | **Not met for Windows.** Publish reviewed, sanitized Windows source and build scripts before enabling this workflow. Do not upload private builds or copy private config. |
| No malware, unwanted software, vulnerability exploitation/bypass | Product documents MFA. Maintainer must disclose credential-provider behavior, recovery and optional fail-open/trusted-session modes and obtain provider acceptance; do not imply eligibility guaranteed. |
| Warnings, privacy and uninstall | Public server README explains its trust model and optional notification services. Windows needs public install warnings, exact system changes, uninstall/recovery instructions and privacy description. |
| MFA and accountable team | Cannot verify publicly. Confirm repository/SignPath MFA, authors, reviewers and manual release approvers. |
| Public code signing policy | Missing from public README. Publish it on home and release pages after approval; do not claim free signing already provided. |
| Product metadata restrictions | Private build recipe has no version resource. Add product name PushGate and consistent product version, compile the resource, and enforce both in SignPath artifact configuration. |
| Reputation | New repository, zero stars at inspection. Not an automatic rejection, not proof of acceptance. |

## Application draft, DO NOT SUBMIT

Project: PushGate. Website/source: https://github.com/VACInc/pushgate
License: Apache-2.0. Current public release: https://github.com/VACInc/pushgate/releases/tag/v1.0.2

We maintain a self-hosted push-approval MFA system. We seek Foundation code signing
for our Windows credential-provider DLL, built from publicly reviewable source
on GitHub-hosted Actions runners. The DLL adds operator-configured approval to
Windows sign-in; deployment changes credential-provider registration. Installation
must preserve a tested recovery path and provide documented removal. We will
request signing only for our own DLL, not Microsoft's providers, other projects'
libraries, test tools or arbitrary uploaded binaries.

Readiness disclosure: Windows code is not yet in the public repository or a public
binary release. This draft is for preparation, not a claim that those prerequisites
are satisfied. Before submission we will publish sanitized source, version metadata,
installation/removal documentation, license inventory and a Windows release.

Signing will require a trusted release approver for each request, a restricted
SignPath policy, and an authenticated GitHub artifact from the reviewed source tag.
All participating members will use MFA. Proposed role owner is the repository
maintainer; exact people/groups and verified MFA remain to be supplied.

Privacy: the installed client contacts the server selected by its administrator
with sign-in/account and host metadata. Optional notification integrations can
involve third-party providers and must be disclosed with their policies. No broad
"no network transfer" promise is made. Confirm the Windows implementation and
publish the final privacy policy before applying.

Contact/name/email: maintainer to supply through the application form; not copied
from private account data. Reputation and external-user references: none verified.

## Disabled workflow and activation checklist

`.github/workflows/windows-signing.yml` is manual-only. With SIGNPATH_READY unset
it does no work. It only accepts win-v tags in the canonical public repository.
It publishes no release and makes no request until explicitly enabled and run.
A branch push does not submit an application or signing request.

Before enabling:

1. Meet the eligibility gaps above and obtain Foundation acceptance.
2. Publish Windows sources. Keep the existing cross-build interface:
   `make -C windows all build/load.exe`. Build `windows/src/version.rc` into the
   DLL; mere presence is insufficient. Public CI must run native security tests
   independently before a release is approved.
3. Configure SignPath's trusted GitHub integration for this repository. Restrict
   artifact contents to PushGateWin.dll, expected PE architecture/product metadata,
   release tag patterns and approved workflows. Require manual approval for every
   release, and reviewed source changes. No automatic-approval policy.
4. Create protected `windows-signing` environment with trusted required reviewers,
   self-review disabled, and release-tag-only deployment rules. Configure its
   SIGNPATH_API_TOKEN secret; configure SIGNPATH_ORGANIZATION_ID, SIGNPATH_POLICY,
   and SIGNPATH_CERT_THUMBPRINT variables from the approved provider settings.
   Configure SIGNPATH_READY=true only after these gates. Never put credentials
   in source or command arguments.
5. Add the required code signing policy to home/download pages, including the
   provider attribution, actual team role links and privacy policy. After service
   activation use their exact attribution: "Free code signing provided by
   SignPath.io, certificate by SignPath Foundation", with links to
   https://signpath.io and https://signpath.org.
6. Dispatch on a reviewed win-v tag. Verify native CI for that same commit first.
   Review the SignPath request manually. Only the tagged GitHub-hosted build's
   artifact ID is submitted, never a local binary or caller-supplied download URL.
7. Require both workflow jobs green; independently verify and release the exact
   signed artifact. The candidate upload precedes verification, so an artifact's
   mere existence is never release approval.

Official integration and pinned action reference:
https://docs.signpath.io/trusted-build-systems/github
https://github.com/SignPath/github-action-submit-signing-request/tree/v3.0

## Signature verification

On Windows, verify the actual delivered file, not a separately rebuilt DLL:

```powershell
$dll = (Resolve-Path .\PushGateWin.dll).Path
$s = Get-AuthenticodeSignature -LiteralPath $dll
$s | Format-List Status,StatusMessage,SignerCertificate,TimeStamperCertificate
if ($s.Status -ne 'Valid') { throw 'Signature not valid' }
# Compare to the independently recorded approved certificate thumbprint.
if ($s.SignerCertificate.Thumbprint -ne $expectedThumbprint) { throw 'Wrong signer' }
if (-not $s.TimeStamperCertificate) { throw 'Timestamp missing' }
Get-FileHash -Algorithm SHA256 -LiteralPath $dll
signtool verify /pa /all /v $dll
if ($LASTEXITCODE -ne 0) { throw 'Authenticode verification failed' }
```

Signature validity, timestamp and publisher match are distinct from Windows
Smart App Control allowing a LogonUI load. A signature cannot promise approval
by every future Windows security policy.

## Windows update acceptance

No Windows update, reboot, registration change or security-policy change is part
of this preparation. Historical fresh LogonUI loads under SAC do not prove a load
across an update. Future Windows update compatibility cannot be guaranteed.

For each approved update window, record before and after: exact OS build/UBR,
installed KBs, boot time, DLL SHA256 and signature, credential-provider registration,
SAC enforcement, and CodeIntegrity events. Preserve the stock password provider
and a working management path. After the update and reboot, observe a new LogonUI
process actually loading the same DLL and perform a real approval and denial for
the protected test account. Record the account-scope bypass separately. Never
force-lock the owner's active session or manufacture a phone decision.

Read-only evidence commands for an elevated Windows shell:

```powershell
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' |
  Select-Object DisplayVersion,CurrentBuild,UBR
Get-CimInstance Win32_OperatingSystem | Select-Object LastBootUpTime
Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 5
Get-Process LogonUI -ErrorAction SilentlyContinue | ForEach-Object {
  $_.Modules | Where-Object ModuleName -eq 'PushGateWin.dll' |
    Select-Object ModuleName,FileName
}
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-CodeIntegrity/Operational'; Id=3077,3033,3089
  StartTime=(Get-Date).AddHours(-2)
} -ErrorAction SilentlyContinue | Where-Object Message -match 'PushGateWin'
```

No matching event alone proves nothing; require positive fresh-process load and
real sign-in outcome. Keep before/after receipts private because event logs and
paths can identify accounts. If the DLL is blocked, preserve logs and use the
stock recovery path. Do not disable SAC or weaken policy to make the check pass.
