# Code signing policy

Project: [PushGate](https://github.com/VACInc/pushgate).
Status: application draft, no signing service or certificate granted. Releases remain unsigned unless their release notes explicitly identify a verified signature.

Author, reviewer and release-signing approver: [VACInc](https://github.com/VACInc).
External contributions, build scripts and workflow changes require maintainer review. Every signing request requires the maintainer's manual approval. All participating source and signing accounts must use MFA before signing is enabled. No unattended release approval.

Only the project's own PushGateWin.dll, built on GitHub-hosted runners from a reviewed win-v release tag, may be signed. Restrict artifact name/count, AMD64 architecture, ProductName PushGate, ProductVersion for the release, original filename and approved certificate. Verify signature chain, timestamp, expected certificate and exact release hash before release. Never sign dependencies or test executables using this policy.

[Privacy and licenses](../windows/README.md#privacy-and-licenses): the Windows client sends account and host/sign-in context to the HTTPS server selected by its administrator. Passwords are checked locally by Windows. Configured notification services may receive metadata. The DLL adds no analytics endpoint. Recovery verifier data stays local. The operator must review privacy terms for optional notification services before enabling them.

Application provider: [SignPath.io](https://signpath.io); certificate program: [SignPath Foundation](https://signpath.org). Acceptance is pending. Once accepted and active, replace this status with the required exact attribution: “Free code signing provided by SignPath.io, certificate by SignPath Foundation”, preserving both links.

Certificates in this program are issued in SignPath Foundation's name. Expected Windows signature publisher: SignPath Foundation, subject to the actual issued certificate. CompanyName in PE metadata is PushGate contributors; that does not control the certificate publisher. No guaranteed Smart App Control or future-update acceptance.
