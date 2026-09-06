#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)
bundle=${1:?bundle root}
arch=${2:-x86_64}
app_layout=0
if [ -d "$bundle/Contents" ] || case "$bundle" in *.app) true;; *) false;; esac; then
  app_layout=1
fi
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
if [ "$app_layout" -eq 0 ]; then
  mkdir -p "$bundle/tor"
  cp -R "$bundle/Contents/Resources/tor/." "$bundle/tor/"
  rm -rf "$bundle/Contents"
  printf '%s\n' "staged macOS agent runtime at $bundle/tor/tor"
fi
if [ "$app_layout" -eq 1 ]; then
  exec "$root/deploy/tor-runtime/check-package.sh" "$target" "$bundle"
fi
exec "$root/deploy/tor-runtime/check-package.sh" macos-agent "$bundle"
