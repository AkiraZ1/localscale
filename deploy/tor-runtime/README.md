# Reproducible Tor runtime bundle

This directory contains no Tor binaries. `manifest.json` pins the stable Tor
Expert Bundle 15.0.21 (Tor 0.4.9.11), and records SHA-256 values copied from
Tor Project's signed `sha256sums-signed-build.txt`. The `.asc` URL is retained
in the manifest for signature verification by release tooling.

Fetch and stage one target into an installer/application bundle:

```sh
python3 deploy/tor-runtime/fetch.py linux-x86_64 --output <bundle>
python3 deploy/tor-runtime/check-package.sh linux-x86_64 <bundle>
```

Use `--cache DIR` to share downloaded archives, or `--offline` to make a
network-free build fail closed when the pinned archive is absent. The script
verifies SHA-256 before extraction, rejects absolute/parent-traversal/link
members, and copies the complete Expert Bundle directory (Tor plus its
runtime libraries/data) rather than only the executable.

## Required layouts

These are intentionally the exact paths used by `src/tor_runtime.rs`:

* Linux: `<bundle>/tor/tor`
* macOS: `<bundle>/Contents/Resources/tor/tor`
* Windows: `<bundle>/tor/tor.exe`

The platform wrapper scripts under `deploy/packaging/` are the intended
installer hooks. They must run after the application bundle has been created.
A release is **incomplete** until the fetched, verified binaries are embedded
in each platform installer; source-only builds are not shippable.

The Tor Project artifacts remain subject to their upstream license and signing
policy. Keep the downloaded cache outside version control.
