"""Optional outbound relay client.

Configure ``HERMES_BRIDGE_RELAY_URL`` with a ``wss://`` (or ``https://``)
endpoint to make the Mac initiate a persistent connection.  The existing
bridge token is sent as ``Authorization: Bearer <token>``.  Relay messages
use the same versioned envelope as ``/api/v1/ws`` (currently version 1).
When the URL is unset, this module is completely inactive.
"""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import Awaitable, Callable
from urllib.parse import urlparse

LOG = logging.getLogger(__name__)


def relay_url(value: str | None) -> str | None:
    """Normalize an opt-in relay URL and reject unsupported schemes."""
    if not value:
        return None
    parsed = urlparse(value)
    if parsed.scheme == "https":
        return "wss://" + value[len("https://"):]
    if parsed.scheme not in {"ws", "wss"} or not parsed.netloc:
        raise ValueError("HERMES_BRIDGE_RELAY_URL must be a ws://, wss://, or https:// URL")
    return value


class RelayClient:
    def __init__(self, url: str, token: str, handle: Callable[[dict], Awaitable[list[dict]]]):
        self.url = relay_url(url)
        assert self.url is not None
        self.token = token
        self.handle = handle
        self._stop = asyncio.Event()

    async def run(self) -> None:
        """Maintain the connection; transient failures use exponential backoff."""
        # Keep the LAN-only bridge importable when optional relay dependencies
        # have not been installed yet; requirements.txt includes this package
        # for deployments that enable the relay.
        import websockets

        delay = 1.0
        while not self._stop.is_set():
            try:
                async with websockets.connect(
                    self.url,
                    additional_headers={"Authorization": f"Bearer {self.token}"},
                    ping_interval=20,
                    ping_timeout=20,
                ) as socket:
                    delay = 1.0
                    async for raw in socket:
                        try:
                            message = json.loads(raw)
                            for response in await self.handle(message):
                                await socket.send(json.dumps(response))
                        except (json.JSONDecodeError, TypeError, KeyError) as exc:
                            await socket.send(json.dumps({"version": 1, "type": "chat.error", "payload": {"code": "INVALID_MESSAGE", "message": str(exc)}}))
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                LOG.warning("relay connection failed: %s; retrying in %.1fs", exc, delay)
                try:
                    await asyncio.wait_for(self._stop.wait(), timeout=delay)
                except asyncio.TimeoutError:
                    delay = min(delay * 2, 30.0)

    def stop(self) -> None:
        self._stop.set()
