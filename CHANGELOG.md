# Changelog

## 1.0.1

- Renamed internal identifiers
- Changed project license to Apache-2.0

- F1: isolate login attempts; only an explicit attempt ID deduplicates start retries. Consume each approval once; a repeated consume returns 409. Lost responses fail closed.
- F2: user lockout cancels pending and unconsumed approved grants. Consumption rechecks principal, approver and signing device under transaction locks.
- F3: reconcile connected phone streams against shared SQL state every five seconds; missed cross-process events recover without reconnecting.
- F4: PostgreSQL statement and lock deadlines default to 15 and 5 seconds. Explicit connection options override them; schema upgrades lift the statement deadline only within their transaction.
- F5: suppress SQL bound values in exception rendering.
- Public packaging: generic configuration, new Android application IDs, exact dependency locks, source-only CI, default-deny UnifiedPush hosts, same-origin browser API, disabled interactive API docs.
