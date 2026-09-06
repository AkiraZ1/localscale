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
install -m 0755 "$root/deploy/packaging/linux/start-agent-linux.py" "$bundle/start-agent-linux.py"
install -m 0644 "$root/deploy/packaging/linux/localscale-agent.desktop.in" "$bundle/localscale-agent.desktop.in"
install -m 0755 "$root/deploy/packaging/linux/install-autostart.sh" "$bundle/install-autostart.sh"
"$root/deploy/packaging/linux/package-tor.sh" "$bundle"
[ -x "$bundle/localscaled" ] || { echo "release is incomplete: missing $bundle/localscaled" >&2; exit 1; }
[ -x "$bundle/start-agent-linux.py" ] || { echo "release is incomplete: missing $bundle/start-agent-linux.py" >&2; exit 1; }
[ -x "$bundle/install-autostart.sh" ] || { echo "release is incomplete: missing $bundle/install-autostart.sh" >&2; exit 1; }
[ -f "$bundle/localscale-agent.desktop.in" ] || { echo "release is incomplete: missing $bundle/localscale-agent.desktop.in" >&2; exit 1; }
"$root/deploy/tor-runtime/check-package.sh" linux-x86_64 "$bundle"
printf '%s\n' "complete Linux release bundle: $bundle"
