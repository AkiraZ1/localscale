# LocalScale Onion connectivity

LocalScale can expose a Host through a Tor v3 onion service, or connect as a
Client to a Host's published `.onion` address. The LocalScale runtime uses a Tor executable bundled with the installed agent
or desktop application. Runtime code never searches `PATH` and never invokes
system `tor`, `torsocks`, or `arti`; a missing bundled binary is a hard error.
These deployment artifacts are configuration contracts only and do **not**
enable, reload, or alter the operating system's Tor service.

## Bundled runtime locations

The packaging step must place the real, platform-signed Tor binary at these
exact locations relative to the installed application bundle (the repository
does not contain or fake these binary artifacts):

- Linux: `<bundle>/tor/tor`
- macOS: `<bundle>/Contents/Resources/tor/tor` (the runtime also accepts
  `<bundle>/tor/tor` for non-`.app` distributions)
- Windows: `<bundle>/tor/tor.exe`

The release wrappers also install the `localscaled` agent alongside Tor:

- Linux: `<bundle>/localscaled`
- macOS app: `<bundle>/Contents/MacOS/localscaled`
- macOS flat bundle: `<bundle>/localscaled`

Use `deploy/packaging/linux/package-release.sh` or
`deploy/packaging/macos/package-release.sh` with a built agent binary; they
fail closed unless both the agent and Tor runtime pass validation.

**Binary artifacts are currently missing from this source repository.** Release
packaging must supply and verify the appropriate Tor artifact before shipping;
development and tests must not fall back to a system installation.

## Files

- `deploy/templates/host.env.example`: Host-mode, non-secret environment.
- `deploy/templates/client.env.example`: Client-mode, non-secret environment.
- `deploy/templates/torrc.onion-v3.example`: dedicated Tor v3 service template.
- `deploy/scripts/validate-onion.sh`: local static validation; never opens a
  Tor data directory or reads/prints private key material.

Copy templates to an untracked deployment directory, then edit the safe values.
Do not commit generated `hostname`, `hs_ed25519_*`, or client authorization
files.

## Modes and environment

| Variable | Host | Client | Meaning |
|---|---:|---:|---|
| `LOCALSCALE_ONION_MODE` | required: `host` | required: `client` | Selects the contract. |
| `LOCALSCALE_ONION_SERVICE_DIR` | required | required | Private runtime directory owned by the dedicated Tor process. The LocalScale validator never reads it. A Client must not be given the Host directory. |
| `LOCALSCALE_ONION_SERVICE_PORT` | `80` | `80` | Onion-facing port. |
| `LOCALSCALE_ONION_UPSTREAM` | `127.0.0.1:8080` | `127.0.0.1:8080` | LocalScale listener reached by Tor or the client adapter. Keep the upstream loopback-only. |
| `LOCALSCALE_ONION_HOSTNAME` | absent | required | Host's 56-character v3 address, without `http://`; the Host obtains it from Tor's generated `hostname` file. |
| `LOCALSCALE_ONION_READY_URL` | local health URL | onion URL | URL used by readiness checks. Do not use it as an authorization mechanism. |
| `LOCALSCALE_ONION_OPEN_BROWSER` | `false` | `true` | Whether the UI may offer/open the Onion URL after readiness. |

Never add private key variables to `.env` files. Host private material belongs
only in the dedicated Tor service directory with restrictive ownership and
permissions. A Client receives the public hostname (and, only if configured by
the application, an independently provisioned client authorization credential),
never the Host's service directory.

## Onion v3 service configuration

`torrc.onion-v3.example` uses:

```text
SocksPort 0
ClientOnly 0
HiddenServiceDir /var/lib/localscale/onion
HiddenServiceVersion 3
HiddenServicePort 80 127.0.0.1:8080
```

Run this configuration only as a separately managed, dedicated Tor instance
(or an explicitly isolated container/process). Do not use `systemctl enable`,
`systemctl restart`, `service tor ...`, or modify `/etc/tor/torrc` as part of
LocalScale deployment. The upstream listener must bind to loopback; exposing
it on a LAN interface bypasses the Onion boundary.

## Startup, readiness, and browser contract

1. Start LocalScale's loopback listener and expose its health endpoint.
2. Start the dedicated Tor process with the copied v3 configuration and a
   writable service directory. Startup is not ready merely because Tor spawned.
3. **Host readiness:** require the generated public `hostname` file to exist,
   contain exactly one valid v3 `.onion` hostname, and require a successful
   request to `LOCALSCALE_ONION_READY_URL` through the local listener.
4. **Client readiness:** require the configured hostname to match the v3 form
   (`[a-z2-7]{56}.onion`) and require an HTTP request through the Onion route to
   return the expected LocalScale health response.
5. On timeout, report a generic connectivity error and troubleshooting hints;
   never include service-directory contents, private-key text, or credentials
   in logs.
6. Only after readiness may the UI present the Onion URL. With
   `LOCALSCALE_ONION_OPEN_BROWSER=true`, open `http://<hostname>/` using the
   user's configured Onion-capable browser. Never open the browser during
   preflight or expose a private service path.

Readiness should be retried with bounded backoff and a finite deadline. A
successful TCP connection to a local Tor control port alone is not sufficient.

## Rotation and revocation checklist

### Rotate a Host identity

- [ ] Announce a maintenance window and record the old public hostname without
      copying any private material.
- [ ] Stop the dedicated LocalScale Tor process only; do not touch system Tor.
- [ ] Back up the service directory through the approved secret-management
      process, with access logging and restrictive permissions.
- [ ] Generate a new v3 service identity in a new directory (do not hand-edit
      key files); verify the directory owner/mode.
- [ ] Start the dedicated process, wait for the new hostname, and run readiness.
- [ ] Publish the new hostname to Clients over an authenticated channel.
- [ ] Revoke/remove the old hostname from application allowlists and client
      configuration after the overlap window.
- [ ] Securely destroy the old key backup according to the organization's
      retention policy; verify no key material entered logs, artifacts, or Git.

### Revoke a Client authorization credential

- [ ] Identify the affected Client credential by inventory ID, not by printing
      its secret.
- [ ] Remove/revoke it at the Host authorization policy (if client auth is in
      use), then restart/reload only the dedicated Tor instance as required.
- [ ] Remove the credential from the Client's secret store and deployment.
- [ ] Issue a replacement through the approved secret channel and verify access
      using readiness, not by logging the credential.
- [ ] Record timestamp, owner, reason, and verification result without secret
      values.

## Validation

From the repository root:

```sh
./deploy/scripts/validate-onion.sh --templates
./deploy/scripts/validate-onion.sh --mode host
./deploy/scripts/validate-onion.sh --mode client
python3 -m unittest discover -s deploy/tests -v
```

The validator performs static checks only. It does not invoke Tor, query a
control port, inspect the system service, traverse a service directory, or
read/print private Onion keys.
