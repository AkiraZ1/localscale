# LocalScale desktop control surface

Flutter Web is the primary control surface. The same project reserves desktop shells for Linux, macOS, and Windows; generated shell runners are intentionally not checked in until Flutter SDK tooling is available.

## Prerequisites

Install Flutter (stable, 3.19 or newer) and add `flutter/bin` to PATH before running the commands below.

## Generate desktop shells

From this directory:

```sh
flutter create --platforms=linux,macos,windows .
flutter pub get
flutter doctor -v
```

The command creates the standard Linux, macOS, and Windows runners without changing the Web control surface.

## Build Web assets

```sh
flutter pub get
flutter test
flutter build web --release --base-href /
```

The output is `build/web/`. Desktop authentication uses a system-browser OAuth flow against the loopback agent. The agent redirects the browser to a one-shot loopback callback carrying only a short-lived opaque handoff; Flutter exchanges that handoff at `/auth/session/bridge` and stores only the resulting opaque local session. HttpOnly cookies remain server-owned. Web deliberately fails closed because it has no desktop loopback/browser adapter.

`lib/core/device_directory.dart` is the shared, injectable seam for device registration and authorized peer discovery. The current backend does not yet expose those endpoints, so no peer addresses are fabricated and the directory is not wired into the UI. A future implementation must use the stable `issuer|sub` identity key, an independently generated device ID/public key, and server-side authorization/revocation checks.

## Package into the Rust agent

Run from the repository root after a successful Web build:

```sh
rm -rf src/web
mkdir -p src/web
cp -a apps/desktop/build/web/. src/web/
cargo build --release
```

The Rust agent should serve `src/web/` as its local control page. Keep `src/` changes in the Rust agent workstream; this README only documents the packaging boundary.

## API boundary

`lib/local_agent_api.dart` defines the typed dependency-injected contract:

- `GET /api/v1/status`
- `POST /api/v1/mode` with `{ "mode": "host" | "cliente" }`
- `POST /api/v1/service/start`
- `POST /api/v1/service/stop`
- `POST /api/v1/sync`

Responses are JSON objects with `mode`, `state`, and optional `onion_endpoint`. Tests cover parsing, invalid modes, typed operations, and Host/Cliente selection.

## Tooling status

- Flutter SDK: available in the implementation environment.
- Dart SDK: available in the implementation environment.
- Flutter tests and Web build: pass in this checkout.
- Rust packaging: not run as part of this slice.
- OAuth/session bridge: implemented for desktop adapters; the default Rust binary remains unconfigured and returns 503 until an AuthHandler is injected.
- Device registration and authorized peer discovery: shared contract only; backend endpoints remain a backlog item.
