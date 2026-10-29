# PushGate 1.0.1

Self-hosted push-approval MFA for SSH/PAM. A server, Android phone and Wear OS clients, a PAM helper, a Python SDK and a browser admin console are included.

## How it works

1. After the SSH primary factor, PAM signs a short-lived login request with the host integration's HMAC credential.
2. The server records the request and delivers it to enrolled devices through a signed WebSocket, optionally using UnifiedPush or Firebase for background delivery.
3. The approver checks the account, host and source, then approves or denies. The device signs the decision with its private key.
4. PAM polls and consumes the grant. Approval is single-use, expires, and is revalidated against current user/device state before access is granted.

No hosted PushGate account is needed. SQL is authoritative; Redis is optional fanout. SQLite is suitable for a single instance; PostgreSQL supports shared server instances.

## Threat model

PushGate protects against possession of a primary SSH credential without access to an enrolled approver. HMAC covers method, path, timestamp, nonce and body; shared SQL nonce constraints prevent transport replay. Device decisions are signed and scoped to a request.

Trust the server, its database, the PAM host, the TLS endpoint, and the enrolled device. Root on the SSH host can bypass PAM. An admin or compromised server can change approval policy. Push approval is not phishing-resistant: an inattentive approver can authorize an attacker's request. Notification providers see routing/notification metadata; they do not receive a signing key. Availability failures deny access by default, so keep a tested local recovery console. Optional fail-open, trusted sessions and offline factors intentionally weaken the online-push guarantee.

## Quick start

Install Docker with Compose v2. Choose a free local port before starting. From this directory, generate unique bootstrap and database credentials into a private file without printing them:

```sh
umask 077
python3 - <<'PY'
import secrets
with open('.env', 'x') as output:
    for name in ('PUSHGATE_BOOTSTRAP_TOKEN', 'PUSHGATE_POSTGRES_PASSWORD'):
        output.write(name + '=' + secrets.token_hex(32) + '\n')
PY
docker compose up -d --build
```

Open <http://localhost:8000>. Retrieve the bootstrap value locally from your private `.env` to sign in. The sample binds only loopback; it does not expose a phone-accessible public endpoint. Put it behind your own HTTPS reverse proxy before enrolling a phone or configuring a remote PAM host. Create a scoped admin key and disable bootstrap access when provisioning is complete. Compose requires a bootstrap credential; remove that requirement in your deployment when switching entirely to scoped keys.

Create a user and device in the console, then scan its short-lived enrollment QR with your Android build. Create a separate integration for each protected host. Install the PAM helper using a root-owned secret file:

```sh
sudo sh pam/install.sh --server https://mfa.example.com \
  --client-id YOUR_INTEGRATION_ID --client-secret-file /root/pushgate-integration-secret
```

Inspect the example PAM stacks in `deploy/pam.d` before integrating `pam_exec.so`. Preserve the primary SSH factor and test both approve and deny from a separate session while a recovery console stays open. The installer does not choose your SSH authentication policy. An integration secret alone does not prove the user's primary factor.

## Configuration

See [all server settings](docs/configuration.md), [PAM examples](pam/pushgate.env.example), [production guidance](docs/production.md), [scoped provisioning](docs/provisioner.md), and [optional proxy authentication](docs/proxy.md).

- No usable secrets ship. Bootstrap requires at least 32 characters. Global fail mode is closed; trusted sessions are off.
- UnifiedPush HTTPS endpoints require `PUSHGATE_UNIFIEDPUSH_ALLOWED_HOSTS`. Empty means disabled. Allow only trusted distributors with trusted DNS/egress; do not allow arbitrary user-selected hosts.
- Firebase requires your own project, phone configuration and short-lived access token; server token refresh is an operator responsibility. No cloud API is required for foreground WebSocket use.
- CORS and interactive API documentation are disabled by default. Same-origin admin UI works without CORS. Enable exact origins for separate-origin development. `PUSHGATE_API_DOCS_ENABLED=true` exposes the API schema and docs intentionally.
- Proxy authentication is off by default. Enable it only behind a header-stripping authenticated proxy on a restricted backend network.
- Built-in rate limits are per-process and bounded; add reverse-proxy connection limits for production. `/healthz` checks liveness, not SQL readiness.

## Security fixes in 1.0.1

F1 isolates login attempts and makes consumption single-use. An explicit attempt ID permits start retry deduplication; repeated consume returns 409, including after a lost success response. F2 cancels grants on user lockout and rechecks the approving device before consumption. F3 reconciles phone streams from shared SQL every five seconds. F4 bounds PostgreSQL statements at 15 seconds and lock waits at five seconds, unless explicitly overridden. F5 hides SQL bound values from error rendering. See [changelog](CHANGELOG.md) and [security policy](SECURITY.md).

## Build and test

The server image builds using only this tree:

```sh
docker build -f server/Dockerfile -t pushgate:1.0.1 .
```

Python runtime and PAM requirements are pinned with hashes; npm uses its lockfile; Android uses strict dependency locks and checksum verification. See [contributing](CONTRIBUTING.md) for test commands and isolation requirements. The CI workflow checks Python, browser tests, Android unit tests and the image build without publishing images or requiring secrets. Android device instrumentation needs a separately provisioned disposable emulator.

Public Android IDs are `org.pushgate.phone` and `org.pushgate.wear`. They install as new apps and need fresh enrollment. Use your own release-signing identity. Their distinct IDs mean they communicate with the server independently; cross-app Wear Data Layer is not supported.

Apache-2.0 licensed. See [LICENSE](LICENSE) and [NOTICE](NOTICE). Dependencies and the Gradle wrapper retain their own licenses.
