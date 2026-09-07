#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)
bundle=${1:?bundle root}
if [ -n "${TOR_BUNDLE_CACHE:-}" ]; then
  python3 "$root/deploy/tor-runtime/fetch.py" windows-x86_64 --output "$bundle" --cache "$TOR_BUNDLE_CACHE"
else
  python3 "$root/deploy/tor-runtime/fetch.py" windows-x86_64 --output "$bundle"
fi
exec "$root/deploy/tor-runtime/check-package.sh" windows-x86_64 "$bundle"
