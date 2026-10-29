# Contributing

Use Python 3.12 and Node 22. Install `requirements.lock` and `requirements-dev.lock` with `pip install --require-hashes -r FILE`. Run `python -m pytest qa pam sdk`, `ruff check --select E9,F63,F7,F82 server pam sdk qa`, and `npm ci && npm test && npm run build` in `admin-web`.
Tests must use temporary databases, generated fixture keys and mock notification transports. Never point a test at production or a personal notification topic. Use a network-isolated container or namespace for tests after fetching dependencies.
For PostgreSQL regression coverage set `PUSHGATE_TEST_POSTGRES_URL` to an empty disposable database and run `qa/test_audit_2026_10_28.py`. Never use a live database; this suite creates and mutates rows.
Android tests run with Java 17 and SDK 35 using `./gradlew testDebugUnitTest` in each app directory. Device instrumentation requires a disposable emulator; it is separate from host unit tests.
Keep fixes small and include a regression test. Do not commit secrets, signing artifacts, generated APKs, dependency caches or personal infrastructure details.
