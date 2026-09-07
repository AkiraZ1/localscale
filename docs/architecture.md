# LocalScale architecture

## Scope and design rules

LocalScale is a local service with a Flutter Web control page and a protocol-owning agent. The agent owns service state, role selection, protocol framing, peer validation, Onion connectivity, and persistence. Flutter Web is a control client: it renders state and requests transitions; it does not implement the peer protocol or infer connectivity from UI state.

The design has two deliberately separate planes:

- **Local control plane:** loopback HTTP between the Flutter Web page and the LocalScale agent. This is the only API exposed to the control page.
- **Peer/data plane:** the protocol connection between LocalScale instances. In Host mode it is reachable through a Tor Onion service; in Cliente mode the instance makes outbound connections to the Host's public v3 `.onion` address.

The local control plane must never be bound to `0.0.0.0`, a LAN address, or an Onion listener. Onion traffic must not be used to expose the administrative API.

## Components and ownership

| Component | Responsibility | Must not own |
|---|---|---|
| `localscaled` / LocalScale agent | Bind loopback, lifecycle, mode, protocol, peer session, Tor integration, health, diagnostics, logs | Browser windows or UI presentation |
| Protocol module | Versioned messages, framing, handshake phase, role restrictions, node identity, timestamps/nonces, MTU negotiation | HTTP routing or Flutter state |
| Flutter Web control page | Display `ServiceStatus`, select Host/Cliente, Start, Stop, Sync, refresh, show errors | Protocol parsing, private keys, Tor configuration |
| Tor deployment | Onion service/client transport and hostname material | LocalScale mode policy or admin authorization |

The protocol module is the source of truth for peer behavior. The control API is an adapter over that state and must not create a second, conflicting state machine.

## Local control API contract

The implementation-ready OpenAPI 3.1 contract is [`docs/api/local-v1.yaml`](api/local-v1.yaml). It is the contract for the loopback agent API and local Google OIDC hand-off; it is not the remote control-plane API or the peer/data protocol. Each route records its implementation status, so documentation of a route must not be read as evidence that the current scaffold implements it.

The browser-facing API is versioned under `/api/v1`:

- `GET /api/v1/status` returns an object with `mode`, `state`, and `onion_endpoint` (string or null).
- `POST /api/v1/mode` accepts `{"mode":"host"}` or `{"mode":"cliente"}` and returns the resulting status. Mode changes should be rejected while a transition is unsafe; the UI must display the returned error rather than assume success.
- `POST /api/v1/service/start` requests start and returns the current lifecycle status. The response may be `starting`; the page polls status until `running` or `error`.
- `POST /api/v1/service/stop` requests an orderly stop and returns the current status. The response may be `stopping`.
- `POST /api/v1/sync` requests a protocol sync/peer refresh and returns status or a structured error.
- `GET /health` is a process/readiness probe. It is local-only and must not be treated as evidence that a peer session is established.
- `GET /diagnostics` is local-only and returns safe operational facts; it must not disclose private keys, secrets, or sensitive protocol material.

Every response should include an explicit HTTP status and JSON content type for API routes. Errors should identify a stable category (for example `invalid_mode`, `busy`, `not_ready`, or `onion_unavailable`) and a human-readable message. The UI must tolerate additional response fields.

Loopback enforcement applies at the socket and HTTP layers. Accept `localhost`, `127.0.0.1`, and `::1` as appropriate for the bound listener, but reject non-loopback `Host` values and requests arriving through a non-loopback bind. CORS should be unnecessary when the page is served by the agent; if it is needed during development, restrict it to the known local origin rather than using a wildcard.

## Service lifecycle

The authoritative states are `stopped`, `starting`, `running`, `stopping`, and `error`.

1. **Start:** bind the loopback listener, load validated configuration, initialize the selected role, start or connect to Tor as required, then initialize the protocol session. Publish `starting` before asynchronous work and `running` only after local readiness checks pass.
2. **Health:** `/health` proves that the process can answer locally. Readiness additionally requires configuration validity and role-specific transport setup. A Host may be locally ready before a Cliente has completed its peer handshake; expose peer/session detail in status or diagnostics instead of conflating it with process health.
3. **Running:** serve the control API and maintain protocol/Tor work. The control page refreshes state after every action and on a bounded polling interval.
4. **Stop:** mark `stopping`, stop accepting new work, close the protocol session, remove temporary transport state, and stop managed child processes if LocalScale owns them. Return `stopped` only after cleanup; use `error` if cleanup cannot complete.
5. **Failure:** retain a useful error category and correlation timestamp in diagnostics/logs. A failed start must not leave a listener, stale lock, or partially published Onion endpoint.

### Exactly one local web page

A normal desktop launch opens **exactly one** local control-page URL after the listener is bound and health/readiness is available. The launcher must pass the selected port into that one URL and must not open one page per retry, mode change, or health poll. If a browser launch fails, log the failure and print the URL; do not retry by opening additional tabs.

The page is a local control page, not the Onion endpoint. Hostname publication or Cliente connection must never trigger a second browser window. `--no-open` disables all browser launching and is required for automation/headless use.

## Pairing and discovery

The current acceptance scenario is **Linux Host → macOS Cliente**. The Host
creates a short-lived, signed, one-use invitation containing version, node IDs,
the current public Onion, public-key fingerprint, proposed virtual IP, nonce and
expiry. The Cliente imports it through the control page by paste or QR and must
confirm the fingerprint. The invitation envelope must not contain a static
`invitation_secret`, private key, OAuth token, or refresh token; persisted peer
state stores protected key material rather than a plaintext shared secret.

An in-app development fixture is allowed only when selected through the UI. It
must be regenerated per run with random nonce/expiry and is disabled in
production. Re-importing an invitation must fail as replay. This flow is part
of the functional test; direct API calls, shell commands, and screenshots are
only bootstrap/diagnostic evidence.

Optional same-account discovery uses incremental consent for Google Drive's
`https://www.googleapis.com/auth/drive.appdata` scope and a signed, TTL-bound
manifest in `appDataFolder`. The base OIDC login remains `openid email profile`.
Drive is a control-plane mailbox, never a data relay; after discovery all peer
traffic remains on Tor v3. Never publish secrets or tokens in the manifest.

## Host and Cliente modes

- **Host:** owns the authoritative local service and publishes a Tor v3 Onion service. It may expose a narrowly scoped protocol upstream through Tor. The Onion hostname is public connection information; the service directory and private key remain local and protected by Tor. The control API remains loopback-only.
- **Cliente:** consumes the Host's public v3 `.onion` address and makes outbound Tor connections. It does not create a HiddenServiceDir and must never receive Host private-key material. Its `onion_endpoint` is normally null; a successful peer connection is reported as peer/session state, not as a locally published address.

Mode names are intentionally `host` and `cliente` throughout the Flutter/API contract. Any internal protocol role mapping must be explicit (`Host` and `Cliente`) and tested at the protocol boundary. Changing mode should be an agent operation, not a Flutter-only preference.

Configuration and authorization are separate from connectivity. `approved` and
`peer_configured` do not imply `connected`. The UI may report `connected` only
when the transport session is active, the handshake and role are validated,
`peer_connected=true`, and a recent data exchange/`last_handshake_at` is
available. Otherwise expose a transitional or error state with its cause.

## Onion boundary and trust

Tor is an external transport dependency, not the administrative API. Host deployment maps the Onion service port to a local, authenticated protocol upstream. Cliente validates the configured `.onion` address and connects outbound. Both roles must enforce protocol version, handshake phase, node identity, timestamp/replay window, nonce rules, role restrictions, and negotiated MTU before accepting peer traffic. Cryptographic operations remain an explicit protocol dependency; an unsupported crypto provider is a hard capability error, not a successful handshake.

Never log private keys, authentication tokens, complete handshake secrets, or full sensitive payloads. Treat the public Onion hostname as shareable but still validate it before use.

## Platform and packaging expectations

The agent is a native LocalScale process. The desktop package starts it on Linux, macOS, and Windows, binds loopback, waits for readiness, and launches the Flutter Web page once. Platform-specific browser launch uses the platform default mechanism; failure is non-fatal if the URL is printed. A packaged desktop build should provide a supervised child process, clean shutdown, and a stable per-user config/data/log directory. Service-manager integration is documented in `docs/operations.md`; it must not change the local-only boundary.

## Pre-production integration backlog

- **M-A — durable handshake nonce allocation:** implement a concrete crash-safe, durable `NonceAllocator` with atomic persistence and recovery semantics, then wire it into the actual root/control-plane/agent handshake path. The protocol crate's caller-owned trait and test-only allocator are not an implementation; production handshake integration must not proceed until this item is complete and tested.

## Current development status

The repository contains a Rust `localscaled` binary and library with a loopback listener, versioned `/api/v1` status/mode/service/sync/peer routes, health/version/diagnostics routes, durable peer authorization, bundled-Tor lifecycle, authenticated transport, and protocol tests for framing, handshake validation, replay protection, nonce durability, role restrictions, and MTU bounds. Flutter Web now uses the real same-origin loopback transport when served as the control page, while native clients use their platform-specific loopback port. The Rust fallback HTML remains a minimal diagnostic page; release packaging must deploy the Flutter Web assets separately or use the configured Flutter host page.

Native Windows execution and production Google-account login are not claimed as validated on this Linux host. The remaining release work is native Windows runtime validation, deployment of the Flutter assets through the chosen installer, and an operator-supplied Google OAuth runtime configuration tested through an already authenticated browser profile.
