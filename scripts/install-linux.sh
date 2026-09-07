#!/bin/sh
# Build and install LocalScale (daemon + desktop app) for the *current* user
# on Linux, using only standard XDG locations computed at run time — never a
# hardcoded username or absolute path baked in ahead of time.
#
# Installed layout (all under $HOME, no root required):
#   ~/.local/opt/localscale-agent/     agent bundle (localscaled + tor runtime + launcher)
#   ~/.local/bin/localscaled           symlink -> the bundle's localscaled
#   ~/.local/opt/localscale-desktop/   Flutter desktop app bundle
#   ~/.local/bin/localscale-desktop    symlink -> the app's launcher binary
#   ~/.config/systemd/user/localscale-agent.service   optional boot-time supervisor
#
# The systemd unit is generated from a template (envsubst) with the actual
# installed path substituted in — it is never hand-authored with a fixed path.
# Day-to-day, the desktop app is expected to spawn/supervise its own agent
# (see apps/desktop/lib/local_agent_transport_io.dart: ensureLocalAgentRestarted);
# the unit here is only an optional convenience so the agent is also available
# before the desktop app is launched (e.g. headless use, boot-time start).
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
HOME_DIR=${HOME:?HOME must be set}
XDG_DATA_HOME=${XDG_DATA_HOME:-"$HOME_DIR/.local/share"}
XDG_BIN_HOME="$HOME_DIR/.local/bin"
XDG_OPT_HOME="$HOME_DIR/.local/opt"
XDG_CONFIG_HOME=${XDG_CONFIG_HOME:-"$HOME_DIR/.config"}

AGENT_INSTALL_DIR="$XDG_OPT_HOME/localscale-agent"
DESKTOP_INSTALL_DIR="$XDG_OPT_HOME/localscale-desktop"
SYSTEMD_USER_DIR="$XDG_CONFIG_HOME/systemd/user"
UNIT_NAME="localscale-agent.service"

SKIP_BUILD=0
SKIP_SYSTEMD=0
SKIP_DESKTOP=0
FLUTTER_BIN=${FLUTTER_BIN:-flutter}

usage() {
  cat >&2 <<EOF
Usage: $0 [--skip-build] [--skip-systemd] [--skip-desktop] [--flutter PATH]

  --skip-build     reuse existing target/release and build/linux artifacts
  --skip-systemd   install binaries only, do not touch systemd --user
  --skip-desktop   install/build only the agent, skip the Flutter app
  --flutter PATH   path to the flutter executable (default: 'flutter' on PATH)
EOF
  exit 2
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --skip-build) SKIP_BUILD=1 ;;
    --skip-systemd) SKIP_SYSTEMD=1 ;;
    --skip-desktop) SKIP_DESKTOP=1 ;;
    --flutter) shift; FLUTTER_BIN=${1:?--flutter requires a path} ;;
    -h|--help) usage ;;
    *) echo "unknown argument: $1" >&2; usage ;;
  esac
  shift
done

log() { printf '[install-linux] %s\n' "$*" >&2; }

log "project root: $ROOT"
log "agent install dir:   $AGENT_INSTALL_DIR"
log "desktop install dir: $DESKTOP_INSTALL_DIR"

if [ "$SKIP_BUILD" -eq 0 ]; then
  log "building localscaled (cargo build --release)"
  (cd "$ROOT" && cargo build --release --bin localscaled)
fi

AGENT_BINARY="$ROOT/target/release/localscaled"
[ -x "$AGENT_BINARY" ] || { echo "missing built agent binary: $AGENT_BINARY" >&2; exit 1; }

log "packaging agent bundle"
rm -rf "$AGENT_INSTALL_DIR"
mkdir -p "$AGENT_INSTALL_DIR"
"$ROOT/deploy/packaging/linux/package-release.sh" "$AGENT_INSTALL_DIR" "$AGENT_BINARY"

mkdir -p "$XDG_BIN_HOME"
ln -sf "$AGENT_INSTALL_DIR/localscaled" "$XDG_BIN_HOME/localscaled"
log "linked $XDG_BIN_HOME/localscaled -> $AGENT_INSTALL_DIR/localscaled"

# Opt-in virtual-network bridge (LOCALSCALE_ENABLE_TUN=1, off by default —
# see spawn_tun_bridge in src/main.rs) opens /dev/net/tun via TUNSETIFF and
# runs `ip addr`/`ip link`/`ip route`, both of which need CAP_NET_ADMIN.
# Grant it directly to the installed binary rather than requiring the whole
# daemon to run as root or under sudo; harmless (and a no-op capability)
# for everyone who leaves the feature disabled.
# setcap lives in /usr/sbin, which a non-interactive shell (e.g. an SSH
# command, or this script run from cron) often doesn't have on PATH even
# though the binary is installed — check the standard sbin locations
# directly instead of relying on `command -v` alone.
SETCAP_BIN=$(command -v setcap 2>/dev/null || true)
for candidate in /usr/sbin/setcap /sbin/setcap; do
  [ -n "$SETCAP_BIN" ] && break
  [ -x "$candidate" ] && SETCAP_BIN="$candidate"
done
if [ -n "$SETCAP_BIN" ]; then
  # +eip, not just +ep: the daemon shells out to `ip addr`/`ip route` (see
  # tun_linux.rs) rather than reimplementing netlink itself, and a plain
  # exec'd child does not inherit capabilities unless they're both
  # inheritable on the file (the "i") and raised into this process's
  # ambient set at runtime (see ensure_net_admin_ambient in tun_linux.rs).
  if sudo -n "$SETCAP_BIN" cap_net_admin+eip "$AGENT_INSTALL_DIR/localscaled" 2>/dev/null \
    || "$SETCAP_BIN" cap_net_admin+eip "$AGENT_INSTALL_DIR/localscaled" 2>/dev/null; then
    log "granted cap_net_admin to localscaled (needed only if LOCALSCALE_ENABLE_TUN=1)"
  else
    log "could not setcap localscaled (not fatal — only needed for the opt-in TUN bridge, run: sudo $SETCAP_BIN cap_net_admin+eip '$AGENT_INSTALL_DIR/localscaled')"
  fi
else
  log "setcap not found; skipping (only needed for the opt-in TUN bridge)"
fi

if [ "$SKIP_DESKTOP" -eq 0 ]; then
  if ! command -v "$FLUTTER_BIN" >/dev/null 2>&1 && [ ! -x "$FLUTTER_BIN" ]; then
    echo "flutter executable not found: $FLUTTER_BIN (pass --flutter or set FLUTTER_BIN)" >&2
    exit 1
  fi
  if [ "$SKIP_BUILD" -eq 0 ]; then
    log "building desktop app (flutter build linux --release)"
    (cd "$ROOT/apps/desktop" && "$FLUTTER_BIN" build linux --release)
  fi
  BUNDLE_SRC="$ROOT/apps/desktop/build/linux/x64/release/bundle"
  [ -d "$BUNDLE_SRC" ] || { echo "missing built desktop bundle: $BUNDLE_SRC" >&2; exit 1; }
  log "installing desktop app bundle"
  rm -rf "$DESKTOP_INSTALL_DIR"
  mkdir -p "$DESKTOP_INSTALL_DIR"
  cp -r "$BUNDLE_SRC"/. "$DESKTOP_INSTALL_DIR"/
  DESKTOP_BIN=$(find "$DESKTOP_INSTALL_DIR" -maxdepth 1 -type f -perm -u+x -name '*desktop*' | head -n1)
  if [ -n "${DESKTOP_BIN:-}" ]; then
    ln -sf "$DESKTOP_BIN" "$XDG_BIN_HOME/localscale-desktop"
    log "linked $XDG_BIN_HOME/localscale-desktop -> $DESKTOP_BIN"
  fi
fi

if [ "$SKIP_SYSTEMD" -eq 0 ]; then
  if ! command -v systemctl >/dev/null 2>&1; then
    log "systemctl not found; skipping systemd unit installation"
  else
    mkdir -p "$SYSTEMD_USER_DIR"
    UNIT_PATH="$SYSTEMD_USER_DIR/$UNIT_NAME"
    LAUNCHER="$AGENT_INSTALL_DIR/start-agent-linux.py"
    tmp="$SYSTEMD_USER_DIR/.$UNIT_NAME.tmp.$$"
    trap 'rm -f "$tmp"' EXIT HUP INT TERM
    # Every path below is substituted from variables computed above at
    # install time ($HOME_DIR, $AGENT_INSTALL_DIR, $LAUNCHER) — nothing here
    # is a literal username or machine-specific path.
    cat >"$tmp" <<EOF
[Unit]
Description=LocalScale local agent (localscaled)
Documentation=https://github.com/localscale
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/env python3 $LAUNCHER --no-open
WorkingDirectory=$AGENT_INSTALL_DIR
Restart=on-failure
RestartSec=2
Environment=HOME=$HOME_DIR

[Install]
WantedBy=default.target
EOF
    chmod 0644 "$tmp"
    mv -f "$tmp" "$UNIT_PATH"
    trap - EXIT HUP INT TERM
    log "generated systemd user unit: $UNIT_PATH"

    systemctl --user daemon-reload
    systemctl --user enable "$UNIT_NAME"
    # `enable --now` only starts the unit if it wasn't already running — on a
    # re-install (the common case) it silently leaves the *old* binary's
    # process in place, so the freshly built agent never actually takes
    # effect until something else happens to restart it later. Always
    # restart explicitly so a re-run of this script is guaranteed to load
    # what was just built.
    systemctl --user restart "$UNIT_NAME"
    log "restarted $UNIT_NAME (systemctl --user status $UNIT_NAME to check)"
  fi
fi

log "done."
log "agent binary:   $XDG_BIN_HOME/localscaled -> $AGENT_INSTALL_DIR/localscaled"
if [ "$SKIP_DESKTOP" -eq 0 ]; then
  log "desktop app:    $DESKTOP_INSTALL_DIR"
fi
log "re-run any time with: $0"
