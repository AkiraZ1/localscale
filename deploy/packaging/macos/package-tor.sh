#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)
bundle=${1:?bundle root}
arch=${2:-x86_64}
case "$arch" in
  x86_64) target=macos-x86_64 ;;
  arm64|aarch64) target=macos-aarch64 ;;
  *) echo "unsupported macOS architecture: $arch" >&2; exit 2 ;;
esac
if [ -n "${TOR_BUNDLE_CACHE:-}" ]; then
  python3 "$root/deploy/tor-runtime/fetch.py" "$target" --output "$bundle" --cache "$TOR_BUNDLE_CACHE"
else
  python3 "$root/deploy/tor-runtime/fetch.py" "$target" --output "$bundle"
fi
exec "$root/deploy/tor-runtime/check-package.sh" "$target" "$bundle"
