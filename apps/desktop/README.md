# LocalScale desktop control surface

Flutter Web is the primary control surface. The same project reserves desktop shells for Linux, macOS, and Windows; generated shell runners are intentionally not checked in until Flutter SDK tooling is available.

## Prerequisites

The current environment does **not** have `flutter` or `dart` on PATH. No SDK was installed because installing system-wide tooling would require an explicit package-management decision. Install Flutter (stable, 3.19 or newer) and add `flutter/bin` to PATH before running the commands below.

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

The output is `build/web/`. The UI currently uses `FakeLocalAgentTransport`; it makes no OAuth or network calls. Replace it at the application composition root with a transport backed by the Rust local API when that API contract is ready.

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

- Flutter SDK: unavailable in the implementation environment.
- Dart SDK: unavailable in the implementation environment.
- Flutter tests and Web build: not runnable here; run the exact commands above after SDK installation.
- Rust packaging: not run because `build/web/` cannot be produced without Flutter.
- OAuth and real network transport: deliberately not implemented in this vertical slice.
