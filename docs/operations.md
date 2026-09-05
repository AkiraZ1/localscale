# LocalScale operations

This runbook covers the LocalScale agent, its local Flutter Web control page, and the Tor Onion transport. Commands below assume a built binary named `localscaled`; packaged installations may place it elsewhere.

## Start and access

### Desktop mode

Start `localscaled` with its default loopback port, or choose a free port with `--port <port>`. On successful bind it prints the local URL and opens exactly one browser page. The page is the LocalScale control page served for local administration. Do not open the Onion hostname in the browser.

Use `--no-open` when another process owns the UI, when running a service manager, or when no graphical session is available. In that mode the agent still starts and prints the URL; operators can open that URL manually from the same machine if a browser is available.

The browser-open operation is best effort. A missing `xdg-open`, `open`, or Windows shell integration does not mean that the agent failed. Check health using the URL printed by the process and inspect logs before restarting. Never implement browser-open retries that can create multiple tabs.

### Headless mode

Headless operation is the default for servers and CI:

- pass `--no-open`;
- bind only to loopback;
- use a process supervisor or container health check against local `/health`;
- use API calls or an approved local automation client for `/api/v1/status`, `/api/v1/mode`, `/api/v1/service/start`, `/api/v1/service/stop`, and `/api/v1/sync`;
- do not expose the control port through a reverse proxy, LAN bind, or Onion service.

A headless process has no browser requirement. If Tor is required, it must be available to the service account and its data directories must be writable with the expected permissions.

## Readiness and lifecycle checks

Check process health first, then role-specific readiness:

1. Confirm the process is listening on the configured loopback port.
2. Request local `GET /health`; expect HTTP success and the LocalScale service identity.
3. Request `GET /api/v1/status`; record `mode`, `state`, and `onion_endpoint`.
4. For Host, verify Tor is running, the Onion service hostname exists, and the configured local upstream is ready.
5. For Cliente, verify Tor client connectivity, the configured Host v3 `.onion` address, and the outbound protocol handshake.
6. Treat `starting` and `stopping` as transitional. Poll with a timeout and report `error` rather than claiming success.

`/health` is a local process/readiness probe; it does not prove that a Host is reachable from outside or that a Cliente has completed a peer handshake. Peer/session state must be checked separately in status/diagnostics and logs.

## Mode operations

### Host

Select `host` through the control page or the local API before starting. Verify:

- `LOCALSCALE_ONION_MODE=host`;
- `LOCALSCALE_ONION_SERVICE_DIR` is a protected Tor-managed directory;
- the service port and local upstream are intentional;
- the upstream readiness URL answers locally;
- no private key is present in environment files, logs, backups, or Cliente machines.

After start, wait for the generated hostname in the Tor service directory's `hostname` file and confirm the status surface reports the public endpoint. Share only the public v3 `.onion` hostname with a Cliente operator.

### Cliente

Select `cliente` before starting and set the Host's public v3 `.onion` address. Verify:

- `LOCALSCALE_ONION_MODE=client` in deployment configuration where that template is used;
- `LOCALSCALE_ONION_HOSTNAME` is the Host public address, not a local private key path;
- the Cliente has no Host `HiddenServiceDir` or private key;
- Tor can make outbound connections;
- the protocol handshake and role validation complete.

Cliente mode is outbound-only with respect to the Host. Do not open firewall ports or publish the local control port to make it work.

## Local API boundary

The local API is an administrative boundary, not a peer protocol. Bind it to `127.0.0.1` (or the platform's equivalent loopback address) and reject non-loopback requests and non-loopback `Host` headers. Keep the API and the Onion transport on separate listeners and separate configuration paths.

The expected Flutter Web routes are documented in the [OpenAPI contract](api/local-v1.yaml), which also defines the local Google OIDC start/callback hand-off and stable error categories. These routes are a loopback-only local agent boundary; they are not the remote control-plane API and must not be exposed through a reverse proxy, LAN bind, or Onion service.

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/v1/status` | Read mode, lifecycle state, and endpoint |
| POST | `/api/v1/mode` | Set `host` or `cliente` |
| POST | `/api/v1/service/start` | Start the selected role |
| POST | `/api/v1/service/stop` | Stop cleanly |
| POST | `/api/v1/sync` | Request peer/protocol sync |
| GET | `/health` | Local health/readiness |
| GET | `/diagnostics` | Safe support data |

The current Rust scaffold also exposes legacy `/`, `/config`, `/status`, `/mode`, `/version`, `/onion`, and `/diagnostics` routes. Treat those legacy routes as compatibility/development behavior until the `/api/v1` adapter is integrated. Never grant the legacy or versioned API an external bind. Control-page actions must use returned state and errors, not optimistic UI transitions.

## Logs and data

Use a per-user or service-account LocalScale directory with separate configuration, state, Tor data, and logs. Keep permissions restrictive, especially for Host Onion service data. Prefer structured records containing timestamp, severity, component, lifecycle transition, mode, and a correlation/request identifier.

At minimum, log:

- startup arguments after removing secrets, selected port, and bind result;
- one browser-open attempt and its result (without opening a second page);
- lifecycle transitions and failure categories;
- Tor process/transport readiness and hostname availability;
- protocol version/phase failures, replay rejection, role rejection, and MTU negotiation failures;
- orderly shutdown and cleanup failures.

Do not log private keys, tokens, nonces where they could enable replay, full peer payloads, or credentials. Rotate logs using the host platform's normal mechanism or a bounded size policy. Preserve logs and the relevant diagnostics response when filing a support report.

## Diagnostics procedure

When the page cannot connect:

1. Confirm the agent process is present and the printed URL uses loopback.
2. Check the listener and request local `/health`.
3. Check that only one page was opened and that the browser is using the printed port.
4. Read the latest startup and lifecycle log entries.
5. Request `/diagnostics`; redact paths, hostnames, identifiers, and addresses according to the support policy before sharing.
6. Request `/api/v1/status` and record the exact `state` and `mode`.
7. If Host, check Tor status, `hostname`, service directory permissions, and local upstream readiness.
8. If Cliente, validate the v3 `.onion` hostname, Tor outbound access, clock accuracy, and handshake/role errors.
9. Stop cleanly, remove only documented stale runtime artifacts, and retry once. Do not delete Host key material as a troubleshooting step.

A 200 response from `/health` with a failed Onion connection is expected to mean “local process alive, peer transport unavailable”; escalate based on the specific transport/peer diagnostic.

## Upgrade and rollback

1. Record the current LocalScale version, configuration paths, mode, Onion hostname (public hostname only), and a recent diagnostics snapshot.
2. Stop LocalScale cleanly and confirm `stopped`; do not replace a running binary.
3. Back up configuration and state using permissions that preserve Host private-key secrecy. Do not copy Host private keys to Cliente systems.
4. Install the new binary/package alongside the old one, validate ownership and executable permissions, and keep the previous artifact available.
5. Start with `--no-open` first, check `/health`, `/api/v1/status`, and role-specific Tor/protocol readiness, then use desktop launch behavior if applicable.
6. Confirm exactly one control page is opened only on the normal graphical launch path.
7. If health, lifecycle, Tor, or protocol checks fail, stop the new version and restore the previous binary and compatible configuration/state. Re-run the same checks and record the rollback reason.

Upgrades must not rotate or relocate Host Onion keys implicitly. Any protocol or state-schema migration needs an explicit, reversible migration step and a tested rollback path. A successful package install is not a successful upgrade until health and role checks pass.

## Platform startup expectations

- **Linux:** a desktop launcher may invoke `localscaled`; browser opening uses the default handler. A systemd-style service must use `--no-open`, a dedicated unprivileged account, loopback bind, restart limits, and a local health check.
- **macOS:** launch from the app/login-item path with a user session for browser opening. A background launch agent must use `--no-open` and retain access to the user's LocalScale/Tor data directory.
- **Windows:** desktop launch uses the default browser mechanism. A service/task without an interactive desktop must use `--no-open`, a dedicated account, and a local health check.
- **Containers/servers:** run headless, mount persistent Host Onion state, do not publish the control port, and make Tor availability a declared dependency.

Packaging and startup integration must preserve the same lifecycle contract: bind, become locally healthy, open at most one page in interactive mode, and supervise clean shutdown.

## Current development status

The repository has a Rust `localscaled` scaffold and protocol tests, deployment environment templates for Host and Cliente Onion modes, and a Flutter Web control-page model. The scaffold currently binds loopback, defaults to port 8765, supports `--port` and `--no-open`, and opens the browser once after binding. The Flutter app currently uses `FakeLocalAgentTransport`, so it is not yet connected to a real agent.

The main integration gap is contract alignment: the Rust scaffold exposes legacy unversioned routes and uses a legacy `client` mode payload, while the Flutter API client expects `/api/v1/...` and the canonical `cliente` value. The next implementation work is to make the protocol-owning agent expose the versioned local adapter, wire real lifecycle/Tor state, and replace the fake Flutter transport. Until then, label the project development status and do not operate it as a production network service.
