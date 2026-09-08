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
  # `flutter build macos` ad-hoc signs and seals the app bundle as a
  # whole, but that happens *before* this script drops localscaled (and
  # bundled Tor, via package-tor.sh above) into Contents/MacOS and
  # Contents/Resources — so those files end up inside a signed bundle
  # without ever being covered by that signature themselves. Older macOS
  # tolerated this; current AMFI/Code-Transparency enforcement does not:
  # the kernel silently kills the child the instant the app tries to exec
  # it ("AMFI: ... has no CMS blob? ... Unrecoverable CT signature issue,
  # bailing out" in the unified log), with no error surfaced to the app
  # at all — the fork/exec call itself still "succeeds" from the app's
  # point of view, so this is invisible without checking system logs.
  # Re-sign the whole bundle (ad-hoc, matching what `flutter build` itself
  # used — this project isn't notarized) now that every executable it
  # contains is actually in place, so the seal covers all of them
  # consistently. This must run for every build that ships (a real
  # release DMG included), not only a developer's local install — the
  # bug it fixes has nothing to do with how the bundle later gets
  # installed.
  #
  # `--entitlements` is required here: without it, this re-sign silently
  # replaces the entitlements `flutter build macos` originally embedded
  # (from Runner/Release.entitlements — notably
  # com.apple.security.app-sandbox=false, which the desktop app needs to
  # spawn localscaled as a child process at all) with none at all. That
  # regression is exactly as invisible as the one this whole fix targets:
  # no error, the app just silently never spawns its own agent.
  entitlements="$root/apps/desktop/macos/Runner/Release.entitlements"
  [ -f "$entitlements" ] || { echo "missing entitlements file: $entitlements" >&2; exit 1; }
  codesign --force --deep --sign - --entitlements "$entitlements" "$bundle"
fi
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
