# Changelog

## Unreleased

- Server-side requester names: with `PUSHGATE_SOURCE_NAME_SUFFIX` set, a raw client address in `source_ip` is shown as the shortest forward-confirmed PTR machine name under that suffix, for every helper. Cached, prewarmed, capped at `PUSHGATE_SOURCE_NAME_TIMEOUT_MS` (300 ms) per login; explicit resolvers or the system resolver. Display only: dedupe and trusted sessions keep the value the helper sent. See docs/configuration.md.
- Phone Settings: Debug logging uses standard settings rows (a switch row, a "Keep logs for" picker, Share log) that fit at any font size. Screenshots and screen recording are allowed on every phone screen except the enrollment QR scanner.
- Phone and watch approval notifications name the host once ("user requests host from address"); an optional request reason, when the server supplies one, shows on a second line.

## 1.0.2

- Update the TLS trust bundle to certifi 2026.10.19.
- Require a CSRF header for proxy-authenticated admin writes.
- Reject trusted sessions from revoked push devices, including revocation before consume.
- Repair isolated web tests and Android SDK setup in CI.

## 1.0.1

- Renamed internal identifiers
- Changed project license to Apache-2.0

- F1: isolate login attempts; only an explicit attempt ID deduplicates start retries. Consume each approval once; a repeated consume returns 409. Lost responses fail closed.
- F2: user lockout cancels pending and unconsumed approved grants. Consumption rechecks principal, approver and signing device under transaction locks.
- F3: reconcile connected phone streams against shared SQL state every five seconds; missed cross-process events recover without reconnecting.
- F4: PostgreSQL statement and lock deadlines default to 15 and 5 seconds. Explicit connection options override them; schema upgrades lift the statement deadline only within their transaction.
- F5: suppress SQL bound values in exception rendering.
- Public packaging: generic configuration, new Android application IDs, exact dependency locks, source-only CI, default-deny UnifiedPush hosts, same-origin browser API, disabled interactive API docs.
