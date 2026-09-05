"""Opt-in Tor v3 Onion Service supervisor and client-auth file handling.

Keys are supplied by the pairing/secure-storage layer; this module never
creates or logs real credentials.  Tests may use synthetic X25519-shaped keys.
"""
from __future__ import annotations

import asyncio
import base64
import binascii
import json
import os
import re
import shutil
from dataclasses import dataclass
from pathlib import Path

_KEY_RE = re.compile(r"^[A-Z2-7]{52}$")
_DEVICE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


def _validate_key(value: str, label: str = "X25519 key") -> str:
    key = value.strip().upper()
    if not _KEY_RE.fullmatch(key):
        raise ValueError(f"{label} must be 52 unpadded base32 characters")
    try:
        decoded = base64.b32decode(key + "====", casefold=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError(f"{label} is not valid base32") from exc
    if len(decoded) != 32:
        raise ValueError(f"{label} must decode to 32 bytes")
    return key


def _safe_device_id(value: str) -> str:
    if not _DEVICE_RE.fullmatch(value):
        raise ValueError("device id contains invalid characters")
    return value


@dataclass(frozen=True)
class TorConfig:
    enabled: bool
    bridge_port: int
    root_dir: Path
    tor_binary: str
    startup_timeout: float = 30.0
    socks_port: int | None = None
    client_auth_enabled: bool = False
    # (device_id, X25519 public key), supplied by an authenticated pairing layer.
    authorized_clients: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        if not 1 <= self.bridge_port <= 65535:
            raise ValueError("bridge port must be between 1 and 65535")
        socks_port = self.socks_port
        if socks_port is None:
            socks_port = self.bridge_port + 1 if self.bridge_port < 65535 else 65534
            object.__setattr__(self, "socks_port", socks_port)
        if not 1 <= socks_port <= 65535:
            raise ValueError("Tor SOCKS port must be between 1 and 65535")
        if socks_port == self.bridge_port:
            raise ValueError("Tor SOCKS port must differ from bridge port")
        if self.authorized_clients and not self.client_auth_enabled:
            raise ValueError("authorized clients require Tor client auth opt-in")
        normalized = tuple((_safe_device_id(device), _validate_key(key, "client public key"))
                           for device, key in self.authorized_clients)
        if len({device for device, _ in normalized}) != len(normalized):
            raise ValueError("duplicate authorized device id")
        object.__setattr__(self, "authorized_clients", normalized)

    @classmethod
    def from_env(cls, bridge_port: int) -> "TorConfig":
        enabled = os.getenv("HERMES_BRIDGE_TOR", "0").strip().lower() in {"1", "true", "yes", "on"}
        root = Path(os.path.expanduser(os.getenv("HERMES_BRIDGE_TOR_DIR", "~/.hermes/tor")))
        binary = os.getenv("HERMES_BRIDGE_TOR_BIN", "tor")
        try:
            timeout = max(1.0, float(os.getenv("HERMES_BRIDGE_TOR_STARTUP_TIMEOUT", "30")))
        except ValueError:
            timeout = 30.0
        raw_socks = os.getenv("HERMES_BRIDGE_TOR_SOCKS_PORT")
        try:
            socks = int(raw_socks) if raw_socks is not None else None
        except ValueError as exc:
            raise ValueError("Tor SOCKS port must be an integer") from exc
        auth_enabled = os.getenv("HERMES_BRIDGE_TOR_CLIENT_AUTH", "0").strip().lower() in {"1", "true", "yes", "on"}
        clients: tuple[tuple[str, str], ...] = ()
        raw_clients = os.getenv("HERMES_BRIDGE_TOR_AUTHORIZED_CLIENTS", "")
        if raw_clients.strip():
            try:
                payload = json.loads(raw_clients)
                if not isinstance(payload, dict):
                    raise ValueError
                clients = tuple((str(device), str(key)) for device, key in payload.items())
            except (json.JSONDecodeError, ValueError) as exc:
                raise ValueError("Tor authorized clients must be a JSON object") from exc
        return cls(enabled, bridge_port, root, binary, timeout, socks, auth_enabled, clients)


@dataclass(frozen=True)
class TorState:
    status: str = "disabled"
    hostname: str | None = None
    pid: int | None = None
    error: str | None = None
    client_auth: str = "disabled"
    reachable: bool = False


class TorSupervisor:
    def __init__(self, config: TorConfig):
        self.config = config
        self._process: asyncio.subprocess.Process | None = None
        auth = "configured" if config.client_auth_enabled and config.authorized_clients else ("not_configured" if config.client_auth_enabled else "disabled")
        self._state = TorState("disabled" if not config.enabled else "stopped", client_auth=auth)

    @property
    def state(self) -> TorState:
        process = self._process
        if process is not None and process.returncode is not None and self._state.status == "running":
            return TorState("failed", error=f"tor exited with code {process.returncode}", client_auth=self._state.client_auth)
        if self._state.status == "running":
            try:
                hostname = self.hostname_path.read_text(encoding="utf-8").strip()
            except OSError:
                hostname = ""
            if not hostname.endswith(".onion"):
                return TorState("failed", error="Tor Onion Service hostname is missing", client_auth=self._state.client_auth)
        return self._state

    @property
    def hostname_path(self) -> Path:
        return self.config.root_dir / "onion" / "hostname"

    @property
    def authorized_clients_dir(self) -> Path:
        return self.config.root_dir / "onion" / "authorized_clients"

    @property
    def client_onion_auth_dir(self) -> Path:
        return self.config.root_dir / "client-auth"

    def configure_authorized_client(self, device_id: str, public_key: str) -> Path:
        """Install one server-side auth file; caller must provide the key."""
        if not self.config.client_auth_enabled:
            raise RuntimeError("Tor client authorization is disabled")
        device = _safe_device_id(device_id)
        key = _validate_key(public_key, "client public key")
        directory = self.authorized_clients_dir
        directory.mkdir(parents=True, exist_ok=True)
        os.chmod(directory, 0o700)
        path = directory / f"{device}.auth"
        path.write_text(f"descriptor:x25519:{key}\n", encoding="ascii")
        os.chmod(path, 0o600)
        return path

    def remove_authorized_client(self, device_id: str) -> None:
        path = self.authorized_clients_dir / f"{_safe_device_id(device_id)}.auth"
        try:
            path.unlink()
        except FileNotFoundError:
            pass

    def write_client_auth(self, onion_hostname: str, private_key: str) -> Path:
        """Write a client credential in Tor's ClientOnionAuthDir format."""
        hostname = onion_hostname.strip().lower()
        if not re.fullmatch(r"[a-z2-7]{56}\.onion", hostname):
            raise ValueError("invalid v3 onion hostname")
        key = _validate_key(private_key, "client private key")
        directory = self.client_onion_auth_dir
        directory.mkdir(parents=True, exist_ok=True)
        os.chmod(directory, 0o700)
        path = directory / f"{hostname}.auth_private"
        path.write_text(f"descriptor:x25519:{key}\n", encoding="ascii")
        os.chmod(path, 0o600)
        return path

    def _write_torrc(self) -> Path:
        root = self.config.root_dir
        data_dir, onion_dir = root / "data", root / "onion"
        for directory in (root, data_dir, onion_dir):
            directory.mkdir(parents=True, exist_ok=True)
            os.chmod(directory, 0o700)
        if self.config.client_auth_enabled:
            self.authorized_clients_dir.mkdir(parents=True, exist_ok=True)
            os.chmod(self.authorized_clients_dir, 0o700)
            for device, key in self.config.authorized_clients:
                self.configure_authorized_client(device, key)
        torrc = root / "torrc"
        torrc.write_text(
            f"DataDirectory {data_dir}\nSocksPort 127.0.0.1:{self.config.socks_port}\n"
            f"HiddenServiceDir {onion_dir}\nHiddenServiceVersion 3\n"
            + f"HiddenServicePort 80 127.0.0.1:{self.config.bridge_port}\n", encoding="utf-8")
        os.chmod(torrc, 0o600)
        return torrc

    async def start(self) -> TorState:
        if not self.config.enabled:
            self._state = TorState("disabled", client_auth=self._state.client_auth)
            return self._state
        if self.config.client_auth_enabled and not self.config.authorized_clients:
            self._state = TorState("failed", error="Tor client authorization has no authorized devices", client_auth="not_configured")
            return self._state
        if self._process is not None and self._process.returncode is None:
            return self.state
        if shutil.which(self.config.tor_binary) is None and not Path(self.config.tor_binary).is_file():
            self._state = TorState("failed", error="Tor executable not found", client_auth=self._state.client_auth)
            return self._state
        self._state = TorState("starting", client_auth=self._state.client_auth)
        try:
            torrc = self._write_torrc()
            self._process = await asyncio.create_subprocess_exec(self.config.tor_binary, "-f", str(torrc), stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
            deadline = asyncio.get_running_loop().time() + self.config.startup_timeout
            while asyncio.get_running_loop().time() < deadline:
                if self._process.returncode is not None:
                    raise RuntimeError(f"Tor exited with code {self._process.returncode}")
                try: hostname = self.hostname_path.read_text(encoding="utf-8").strip()
                except OSError: hostname = ""
                if hostname.endswith(".onion") and len(hostname) > len(".onion"):
                    self._state = TorState("running", hostname=hostname, pid=self._process.pid, client_auth=self._state.client_auth)
                    return self._state
                # Keep the polling cadence from overshooting the configured
                # deadline on a busy event loop.  A fixed sleep can turn a
                # valid, just-created hostname into a spurious startup
                # failure when the timeout is short.
                remaining = deadline - asyncio.get_running_loop().time()
                if remaining <= 0:
                    break
                await asyncio.sleep(min(0.1, remaining))
            raise TimeoutError("Tor Onion Service hostname was not created")
        except Exception as exc:
            await self.stop()
            self._state = TorState("failed", error=str(exc), client_auth=self._state.client_auth)
            return self._state

    async def stop(self) -> None:
        process, self._process = self._process, None
        if process is not None and process.returncode is None:
            process.terminate()
            try: await asyncio.wait_for(process.wait(), timeout=5)
            except asyncio.TimeoutError:
                process.kill(); await process.wait()
        self._state = TorState("stopped" if self.config.enabled else "disabled", client_auth=self._state.client_auth)
