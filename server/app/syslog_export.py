from __future__ import annotations

import json
import socket
from typing import Any


class SyslogExporter:
    def __init__(self, enabled: bool, host: str, port: int, app_name: str = "pushgate") -> None:
        self.enabled = enabled
        self.host = host
        self.port = port
        self.app_name = app_name

    def emit(self, event_type: str, payload: dict[str, Any]) -> None:
        if not self.enabled:
            return
        message = f"<134>{self.app_name}: {event_type} {json.dumps(payload, sort_keys=True, separators=(',', ':'))}"
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.sendto(message.encode("utf-8"), (self.host, self.port))
        except OSError:
            return
