#!/bin/sh
# Build a complete Linux release bundle around a prebuilt localscaled agent.
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)
bundle=${1:?bundle root}
agent=${2:?agent binary (localscaled)}
if [ ! -f "$agent" ] || [ -L "$agent" ] || [ ! -x "$agent" ]; then
  echo "agent binary must be a regular executable: $agent" >&2
  exit 1
fi
mkdir -p "$bundle"
install -m 0755 "$agent" "$bundle/localscaled"
"$root/deploy/packaging/linux/package-tor.sh" "$bundle"
[ -x "$bundle/localscaled" ] || { echo "release is incomplete: missing $bundle/localscaled" >&2; exit 1; }
"$root/deploy/tor-runtime/check-package.sh" linux-x86_64 "$bundle"
printf '%s\n' "complete Linux release bundle: $bundle"
