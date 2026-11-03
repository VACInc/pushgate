# Push delivery and recovery

Phone streams use fresh signed timestamp/nonce handshakes. Transient transport failures retry with capped backoff; authorization and protocol failures remain terminal. Closing a stream cancels retries and fences stale callbacks. The UI reports connected only after an authenticated pending snapshot.

Server disconnect handling releases subscribers. Queue overflow forces replay rather than silently dropping approvals. Redis subscription waits for acknowledgement; subscription loss closes the stream so clients reconnect and replay. Replay pages contain at most 100 requests and recheck device authorization. SQL reconciliation every five seconds repairs events missed between server processes. Background push tries every device of the approver: a dead token or a failing provider on one device never skips the others, and the first error is logged once all were tried.

Foreground WebSocket delivery cannot wake a suspended Android app. Configure a trusted UnifiedPush distributor or your own Firebase project for background delivery. The optional notification wakeup is only a prompt to open the app, never an approval capability. The ntfy wake-up (`PUSHGATE_NTFY_URL`) posts one notification per enrolled device per push attempt, all to the same topic, until the request is answered or expires: an approver with two devices and `PUSHGATE_PUSH_RETRY_COUNT=1` (two attempts) gets four wake-ups for one login.

Run the Python and Android unit tests described in CONTRIBUTING.md. `PUSHGATE_TEST_REDIS_URL` enables the real Redis regression; point it only at a disposable instance because the test interrupts Pub/Sub connections.

Before production use, test receipt, deny, approve, timeout and reconnect on your own phone, including while its screen is off. A passing server health check alone does not prove background delivery.
