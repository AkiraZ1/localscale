#!/bin/sh
# Build and install the LocalScale desktop app for the *current* user on
# macOS. The daemon (localscaled) is bundled inside the .app and spawned by
# the Flutter app itself (see apps/desktop/lib/local_agent_transport_io.dart),
# so there is no separate daemon install step or launchd unit here — only the
# desktop app needs to land somewhere the user can open it.
#
# Installed layout (no root required, no hardcoded username):
#   $HOME/Applications/LocalScale.app
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
HOME_DIR=${HOME:?HOME must be set}
INSTALL_DIR=${LOCALSCALE_MACOS_APPS_DIR:-"$HOME_DIR/Applications"}
APP_NAME="LocalScale.app"
FLUTTER_BIN=${FLUTTER_BIN:-flutter}

SKIP_BUILD=0
usage() {
  cat >&2 <<EOF
Usage: $0 [--skip-build] [--flutter PATH] [--apps-dir DIR]

  --skip-build   reuse the existing target/release and Flutter build output
  --flutter PATH path to the flutter executable (default: 'flutter' on PATH)
  --apps-dir DIR install destination (default: \$HOME/Applications)
EOF
  exit 2
}
while [ "$#" -gt 0 ]; do
  case "$1" in
    --skip-build) SKIP_BUILD=1 ;;
    --flutter) shift; FLUTTER_BIN=${1:?--flutter requires a path} ;;
    --apps-dir) shift; INSTALL_DIR=${1:?--apps-dir requires a path} ;;
    -h|--help) usage ;;
    *) echo "unknown argument: $1" >&2; usage ;;
  esac
  shift
done

log() { printf '[install-macos] %s\n' "$*" >&2; }

if [ "$SKIP_BUILD" -eq 0 ]; then
  log "building localscaled (cargo build --release)"
  (cd "$ROOT" && cargo build --release --bin localscaled)
fi
AGENT_BINARY="$ROOT/target/release/localscaled"
[ -x "$AGENT_BINARY" ] || { echo "missing built agent binary: $AGENT_BINARY" >&2; exit 1; }

if [ "$SKIP_BUILD" -eq 0 ]; then
  if ! command -v "$FLUTTER_BIN" >/dev/null 2>&1 && [ ! -x "$FLUTTER_BIN" ]; then
    echo "flutter executable not found: $FLUTTER_BIN (pass --flutter or set FLUTTER_BIN)" >&2
    exit 1
  fi
  log "building desktop app (flutter build macos --release)"
  (cd "$ROOT/apps/desktop" && "$FLUTTER_BIN" build macos --release)
fi

BUILT_APP="$ROOT/apps/desktop/build/macos/Build/Products/Release/localscale_desktop.app"
[ -d "$BUILT_APP" ] || { echo "missing built app bundle: $BUILT_APP" >&2; exit 1; }

log "embedding agent binary + tor runtime into the app bundle"
"$ROOT/deploy/packaging/macos/package-release.sh" "$BUILT_APP" "$AGENT_BINARY" "$(uname -m | sed 's/^arm64$/arm64/;s/^x86_64$/x86_64/')" >/dev/null

# `flutter build macos` leaves its raw output under apps/desktop/build/ —
# macOS indexes that as a second, independent "LocalScale" app in Spotlight
# and Launchpad (same name, different bundle, not the one this script
# installs and not repackaged with the embedded Tor runtime). Left
# registered, it is easy to open by mistake and looks identical to the real
# install, which is confusing and can surface stale/inconsistent state.
# De-register it (harmless if lsregister is unavailable or already clean).
LSREGISTER="/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister"
if [ -x "$LSREGISTER" ]; then
  "$LSREGISTER" -u "$BUILT_APP" >/dev/null 2>&1 || true
  DEBUG_APP="$ROOT/apps/desktop/build/macos/Build/Products/Debug/localscale_desktop.app"
  [ -d "$DEBUG_APP" ] && "$LSREGISTER" -u "$DEBUG_APP" >/dev/null 2>&1 || true
fi

mkdir -p "$INSTALL_DIR"
TARGET="$INSTALL_DIR/$APP_NAME"

log "stopping any running instance"
pkill -f "$APP_NAME/Contents/MacOS/" 2>/dev/null || true
pkill -f localscale_desktop 2>/dev/null || true
# A plain SIGTERM to localscaled does not run its normal shutdown path (no
# signal handler is installed), so its bundled Tor child is left running
# instead of being terminated. That orphaned Tor process keeps holding the
# SOCKS/control ports and the onion service's data directory, so the next
# localscaled this script installs can time out waiting for its own Tor to
# become ready and get stuck retrying a peer connection forever. Clean up
# any bundled Tor process left over from a prior install/run explicitly.
pkill -f "$APP_NAME/Contents/Resources/tor/tor" 2>/dev/null || true
sleep 1

log "installing to $TARGET"
rm -rf "$TARGET"
cp -R "$BUILT_APP" "$TARGET"

log "done. Launch with: open \"$TARGET\""
log "re-run any time with: $0"
