# Windows credential provider candidate

Unreleased, unsigned candidate. Do not install this on a primary workstation to
establish signing eligibility. Use a disposable Windows test system first.

This optional provider wraps Windows password authentication and requires a fresh
push approval for one explicitly configured local account SID. Other accounts
use their normal password path. The stock password provider remains available;
this configuration does not prevent the protected account from selecting it.
Global provider filtering is unsupported. Automatic sign-in is not disabled.

The provider changes credential-provider and COM registration and installs files
under `C:\Program Files\PushGateWin` and protected configuration under
`C:\ProgramData\PushGateWin`. Registration affects console and RDP sign-in.
A broken provider can interrupt sign-in. Preserve a tested management/recovery
path and the stock password provider. Do not disable Smart App Control to install.

## Build and test

On Linux with `g++-mingw-w64-x86-64-posix` and GNU Make:

```sh
make -C windows all build/unit.exe build/packed.exe build/load.exe build/scope.exe
```

The DLL embeds ProductName `PushGate` and ProductVersion `0.1.0.0`. Change numeric
and string versions together in `src/version.rc` for each release. Do not sign
unit tests or dependencies with the project's signing policy.

On a disposable Windows runner, run `unit.exe`, `scope.exe` and `packed.exe` from
`build`, `load.exe <absolute-DLL-path>`, then `tests/parse.ps1` and
`tests/client.ps1`. The latter replaces the network transport with test doubles.
`tests/install.ps1` changes registrations and is restricted to a dedicated lab
machine/account; it is not part of safe desktop checks. `tests/old_*.py` build
known regression mutants whose unit binaries must fail on Windows.

The native CI workflow builds and runs the safe tests without installing or
registering the provider. This proves the DLL's own test process can load it,
not that Smart App Control accepts it in LogonUI on the user's system.

## Provision, install and remove

`deploy/Provision.ps1` requires an existing host integration file, a matching
SID-bound recovery verifier, explicit local Account, HTTPS Server, and SystemName.
It imports only the integration keys required by the client; the credential and
recovery values stay on the machine. Never pass a secret on the command line.
Provisioning rejects an existing destination. Recovery verifiers use a 32-byte
salt and PBKDF2-HMAC-SHA256, 210000 rounds, 32 bytes, with version=1, sid, used=false,
attempts=0 and next_try=0. Generate/store the recovery code with your trusted
credential tooling and test it in the lab before installation; do not put it in
source, logs or a release package.

Stage `Install.ps1`, `Remove.ps1`, `Gate.ps1`, `Client.psm1` and the verified signed
`PushGateWin.dll` together. Run `Install.ps1 -Account <local-account>` elevated
only after provisioning and reviewing the changes. It refuses unowned existing
files/registrations and records an ownership snapshot; there is no in-place
upgrade operation in this candidate. Review existing-install updates separately.

Remove with the installed `Remove.ps1` from a tested elevated management shell.
It unregisters only owned components, restores the recorded autologon setting,
preserves files and recovery records, and refreshes LogonUI. User applications
are preserved, but the sign-in UI restarts. Removal requires a matching ownership
snapshot and an enabled stock password provider. No service or updater is added.

## Privacy and licenses

The client sends account SID/name and sign-in context to the HTTPS server chosen
by the installer. An administrator-provisioned integration authenticates requests.
Passwords are validated locally by Windows, not sent to the push server. The
operator's configured notification services may receive notification metadata;
see the server README for optional UnifiedPush/Firebase behavior and review
those providers' privacy terms before enabling them. This Windows DLL adds no
telemetry/analytics endpoint. Recovery verifier state stays on the local machine.

Own source inherits the repository's Apache-2.0 license. Windows system libraries
are supplied by Windows and not redistributed. The statically linked toolchain
runtime has separate licenses; see `licenses/mingw-w64.txt` and
`licenses/gcc-runtime.txt`, copied from the actual build toolchain packages.
They include permissive runtime terms and the GCC Runtime Library Exception;
the entire compiler is not relicensed under Apache-2.0. Ship these notices with
the binary. The signing application must disclose those components accurately.

Code signing preparation and verification: [signing policy](../docs/windows-signing.md).
