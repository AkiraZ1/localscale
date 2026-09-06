#!/bin/sh
# Build a complete macOS release bundle around a prebuilt localscaled agent.
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)
bundle=${1:?bundle root}
agent=${2:?agent binary (localscaled)}
arch=${3:-x86_64}
if [ ! -f "$agent" ] || [ -L "$agent" ] || [ ! -x "$agent" ]; then
  echo "agent binary must be a regular executable: $agent" >&2
  exit 1
fi
if [ -d "$bundle/Contents" ] || case "$bundle" in *.app) true;; *) false;; esac; then
  agent_path="$bundle/Contents/MacOS/localscaled"
else
  agent_path="$bundle/localscaled"
fi
mkdir -p "$(dirname "$agent_path")"
install -m 0755 "$agent" "$agent_path"
"$root/deploy/packaging/macos/package-tor.sh" "$bundle" "$arch"
[ -x "$agent_path" ] || { echo "release is incomplete: missing $agent_path" >&2; exit 1; }
if [ -d "$bundle/Contents" ]; then
  case "$arch" in
    x86_64) target=macos-x86_64 ;;
    arm64|aarch64) target=macos-aarch64 ;;
    *) echo "unsupported macOS architecture: $arch" >&2; exit 2 ;;
  esac
  "$root/deploy/tor-runtime/check-package.sh" "$target" "$bundle"
else
  "$root/deploy/tor-runtime/check-package.sh" macos-agent "$bundle"
fi
printf '%s\n' "complete macOS release bundle: $bundle"
