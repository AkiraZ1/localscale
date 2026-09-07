# LocalScale

LocalScale is a local-first Host/Cliente service with a Flutter Web control page and a versioned peer protocol. The administrative API stays on loopback. Optional external connectivity uses Tor Onion transport, keeping the control surface separate from peer traffic.

> **Current validation scenario:** Linux is the Host (`10.42.0.1`) and macOS is
> the Cliente (`10.42.0.2`). The pairing acceptance test is performed in both
> apps through the invitation/QR UI. Production pairing is opt-in and requires
> the secure flow described below.

> **Development status:** The Rust agent, versioned `/api/v1` contract, real Flutter Web loopback transport, durable peer authorization, authenticated Onion transport, and bundled Tor packaging are implemented and covered by automated tests. Native Windows execution and production Google-account login still require their respective native/runtime environments; they are not claimed as validated here. See [current status](docs/architecture.md#current-development-status).

## Architecture at a glance

- **Agent:** Rust `localscaled` owns lifecycle, mode, protocol, Tor integration, health, diagnostics, and logs.
- **Flutter Web:** local control page for status, Host/Cliente selection, Start, Stop, and Sync. It is a client of the agent, not a protocol implementation.
- **Host:** publishes a Tor v3 Onion service; its private key stays in the Tor-managed service directory.
- **Cliente:** connects outbound to the Host's public v3 `.onion` address and never receives Host key material.
- **Boundary:** local HTTP is loopback-only. Never expose the control port to a LAN, reverse proxy, or Onion service.
- **Pairing:** the Host creates a short-lived, signed, one-use invitation; the Cliente imports it by paste or QR and confirms the public-key fingerprint. Static invitation secrets are not supported.
- **Optional discovery:** with explicit incremental consent, the same Google account may use Drive `appDataFolder` for signed, short-lived discovery manifests. Drive is not a data relay; peer traffic remains Tor v3.

## Start behavior

A normal desktop start binds the agent to loopback, waits for local readiness, prints the local URL, and opens exactly one local control page. Browser launch is best effort; if it fails, use the printed URL. Use `--no-open` for headless operation, service managers, CI, or when a browser is already managed externally. Use `--port <port>` to select a port; the current default is 8765.

The local page is not the Onion endpoint. Host publication and Cliente connection must never open another browser page.

For the in-app smoke test, open the Linux app as Host, generate an invitation,
then open the macOS app as Cliente and import it by paste/QR. Wait for
`configured → dialing → handshaking → connected`, run the app's sync/ping action,
and verify the event on both sides. A fixture may be selected only in a
development profile; it must be regenerated per run with random nonce/expiry
and must never contain `invitation_secret`, OAuth tokens, or private keys.

## Local API contract

The implementation target for the Flutter Web page is:

- `GET /api/v1/status`
- `POST /api/v1/mode` with `host` or `cliente`
- `POST /api/v1/service/start`
- `POST /api/v1/service/stop`
- `POST /api/v1/sync`
- `GET /health`
- `GET /diagnostics`

Lifecycle state is explicit: `stopped`, `starting`, `running`, `stopping`, or `error`. Health means the local process is responsive; it does not prove a peer handshake. For the full boundary and ownership rules, see [architecture](docs/architecture.md).

`approved` and `peer_configured` are policy/configuration states, not network
connectivity. The UI may show `connected` only when the transport session is
active, `peer_connected=true`, the handshake and role are validated, and a
recent data exchange is recorded. `/health`, `/api/v1/devices`, or a screenshot
alone cannot establish connectivity.

## Development

The repository includes the Rust agent (`localscaled`), protocol tests, deployment templates, and a Flutter Web control-page model.

- **Self-contained native web control interface:** `localscaled` natively serves a zero-dependency, modern dark-mode control interface on loopback (`http://127.0.0.1:<port>/`), offering real-time status polling, mode switching (Host/Cliente), lifecycle controls (Start/Stop/Sync), Onion endpoint clipboard copying, and safe diagnostics viewing out of the box without requiring external frontend assets or toolchains to be installed.
- **Automated verification:** Run `cargo test` to execute the full suite of 63 unit and integration tests covering protocol framing, loopback enforcement, CSRF origin verification, and Tor process lifecycle.

## Operations

See [docs/operations.md](docs/operations.md) for:

- desktop and headless startup;
- health and role-specific readiness checks;
- Host and Cliente configuration;
- logs and safe diagnostics;
- upgrade and rollback;
- Linux, macOS, Windows, and container startup expectations.

Do not place private keys or credentials in environment templates or logs. Keep Host Onion state persistent and protected; a Cliente needs only the Host's public Onion address.
