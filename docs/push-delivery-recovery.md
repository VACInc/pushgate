# Push delivery and recovery

Phone streams use fresh signed timestamp/nonce handshakes. Transient transport failures retry with capped backoff; authorization and protocol failures remain terminal. Closing a stream cancels retries and fences stale callbacks. The UI reports connected only after an authenticated pending snapshot.

Server disconnect handling releases subscribers. Queue overflow forces replay rather than silently dropping approvals. Redis subscription waits for acknowledgement; subscription loss closes the stream so clients reconnect and replay. Replay pages contain at most 100 requests and recheck device authorization. SQL reconciliation every five seconds repairs events missed between server processes.

Foreground WebSocket delivery cannot wake a suspended Android app. Configure a trusted UnifiedPush distributor or your own Firebase project for background delivery. The optional notification wakeup is only a prompt to open the app, never an approval capability.

Run the Python and Android unit tests described in CONTRIBUTING.md. `PUSHGATE_TEST_REDIS_URL` enables the real Redis regression; point it only at a disposable instance because the test interrupts Pub/Sub connections.

Before production use, test receipt, deny, approve, timeout and reconnect on your own phone, including while its screen is off. A passing server health check alone does not prove background delivery.
