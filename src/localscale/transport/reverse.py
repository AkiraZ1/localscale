"""Outbound HTTP callbacks for temporarily paired Android devices."""
from __future__ import annotations
import time
from dataclasses import dataclass
from urllib.parse import urlparse
import httpx

@dataclass(frozen=True)
class DeviceRegistration:
    callback_url: str
    device_token: str
    expires_at: float

class ReverseClient:
    def __init__(self, *, timeout: float = 10.0) -> None:
        self.timeout = timeout

    async def send(self, registration: DeviceRegistration, payload: dict) -> dict:
        """POST one callback payload using the device token as Bearer auth."""
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.post(registration.callback_url, json=payload,
                                         headers={"Authorization": f"Bearer {registration.device_token}"})
        response.raise_for_status()
        return {"status_code": response.status_code}

def validate_callback_url(value: str) -> str:
    """Validate without opening a connection or inferring reachability."""
    value = value.strip()
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("callback_url must be an absolute HTTP(S) URL")
    return value

def expired(registration: DeviceRegistration, now: float | None = None) -> bool:
    return (time.time() if now is None else now) >= registration.expires_at
