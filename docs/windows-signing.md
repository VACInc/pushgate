# Windows code signing preparation

[PushGate](https://github.com/VACInc/pushgate) Windows 0.1.0 remains a staged unsigned candidate. An application was submitted to SignPath Foundation on 2026-11-12. No signing request submitted. No Windows binary release is public yet.

See [Code signing policy](code-signing-policy.md) for roles, privacy, artifact restrictions and pending provider status. Contact and identity details belong only in the private application, never this repository.

Own source uses Apache-2.0. Redistribute the bundled toolchain runtime notices. Provider eligibility is discretionary. This credential provider adds push approval for one configured local account but preserves stock password sign-in, which can bypass that additional approval. No global filtering or guaranteed future Windows-update compatibility is claimed.

Before application submission: publish reviewed own Windows source, run native CI for that exact commit, test installation and removal on a disposable Windows system, publish the reviewed unsigned Windows candidate with warnings, notices and policy links. Confirm repository MFA. The published program terms require an already released artifact in the form being signed. A server/Android release does not satisfy this Windows gate.

After acceptance: configure the provider's trusted GitHub provenance, exact DLL artifact and PE metadata restrictions, certificate identity, manual per-release approval, and MFA. The sole maintainer VACInc owns author, reviewer and signing-approver roles unless the provider requires a different arrangement. Do not configure a self-review prohibition that makes the sole-maintainer workflow impossible; agree the supported manual approval design with the provider first. No signing configuration is enabled by this document.

Keep `.github/workflows/windows-signing.yml` disabled with SIGNPATH_READY unset until settings are separately reviewed and read back. Only reviewed win-v release tags in the canonical repository may run it. It accepts the GitHub-built DLL artifact, verifies the returned signature, expected certificate, timestamp and DLL load, and does not publish a release. Verify exact delivered bytes before any signed publication.

Native unit/DLL-load CI proves a test process can load the DLL. It does not prove Smart App Control permits LogonUI loading it. A real before/after Windows update test needs separate explicit maintenance approval, OS/KB/boot/DLL/signature/CodeIntegrity receipts, a new LogonUI load, a real protected-account approval and denial, and tested stock-login recovery. Never reboot, lock the owner's session or weaken security policy just to establish signing eligibility.

Official requirements: https://signpath.org/terms
Application: https://signpath.org/apply
GitHub integration: https://docs.signpath.io/trusted-build-systems/github
