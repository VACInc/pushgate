"""Optional real Redis check; use an isolated instance, never production Redis."""
import asyncio
import os
import uuid

import pytest

from server.app.push import FanoutDisconnected, RedisPushFanout


@pytest.mark.skipif(not os.getenv("PUSHGATE_TEST_REDIS_URL"), reason="isolated Redis URL not configured")
def test_cross_worker_delivery_survives_idle_and_releases_subscription():
    async def scenario():
        url = os.environ["PUSHGATE_TEST_REDIS_URL"]
        receiver = RedisPushFanout(url)
        sender = RedisPushFanout(url)
        device = f"test-{uuid.uuid4()}"
        queue = await receiver.subscribe(device)
        try:
            # Past the old 500ms command socket deadline, on a separate worker.
            await asyncio.sleep(2)
            payload = {"type": "auth_request", "data": {"id": "after-idle"}}
            await sender.publish([device], payload)
            assert await asyncio.wait_for(queue.get(), 2) == payload
            # This URL must point at an isolated test instance: interrupt its
            # Pub/Sub transport and require replay instead of a silent gap.
            await sender._publisher.client_kill_filter(_type="pubsub")
            assert isinstance(await asyncio.wait_for(queue.get(), 5), FanoutDisconnected)
        finally:
            tasks = list(receiver._tasks.values())
            receiver.unsubscribe(device, queue)
            await asyncio.gather(*tasks, return_exceptions=True)
            counts = await sender._publisher.pubsub_numsub(f"pushgate:device:{device}")
            assert counts[0][1] == 0
            await receiver._publisher.aclose()
            await sender._publisher.aclose()
    asyncio.run(scenario())
