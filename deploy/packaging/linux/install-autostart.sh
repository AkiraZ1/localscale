#!/bin/sh
# Install or remove the per-user XFCE-compatible LocalScale autostart entry.
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
template=$root/localscale-agent.desktop.in
entry_name=localscale-agent.desktop

fail() { printf '%s\n' "$*" >&2; exit 1; }
usage() { printf 'usage: %s install BUNDLE_ROOT [HOME] | uninstall [HOME]\n' "$0" >&2; exit 2; }

[ "$#" -ge 1 ] || usage
command=$1
case "$command" in install|uninstall) ;; *) usage ;; esac

home=${HOME:-}
bundle=
if [ "$command" = install ]; then
    [ "$#" -ge 2 ] && bundle=$2 || usage
    [ "$#" -ge 3 ] && home=$3
else
    [ "$#" -ge 2 ] && home=$2
fi
[ -n "$home" ] || fail "HOME is required"
case "$home:$bundle" in *'\n'*|*'\r'*|*'|'*|*'&'*|*'\\'*) fail "paths contain unsupported characters" ;; esac
case "$home" in /*) ;; *) fail "HOME must be an absolute path" ;; esac

autostart=$home/.config/autostart
entry=$autostart/$entry_name

if [ "$command" = uninstall ]; then
    if [ -e "$entry" ] || [ -L "$entry" ]; then
        grep -Fqx 'X-LocalScale-Managed=true' "$entry" || fail "refusing to remove unmanaged $entry"
        rm -f -- "$entry"
    fi
    exit 0
fi

case "$bundle" in /*) ;; *) fail "bundle root must be an absolute path" ;; esac
[ -d "$bundle" ] || fail "bundle root is not a directory: $bundle"
bundle=$(CDPATH= cd -- "$bundle" && pwd -P)
start_agent=$bundle/start-agent-linux.py
[ -f "$start_agent" ] || fail "missing bundled launcher: $start_agent"
[ ! -L "$start_agent" ] || fail "bundled launcher must not be a symlink"
case "$bundle:$start_agent" in *'\n'*|*'\r'*) fail "paths must not contain newlines" ;; esac

mkdir -p "$autostart"
if [ -L "$entry" ]; then
    fail "refusing to replace symlink: $entry"
fi
# The temporary file is in the destination directory, so rename is atomic.
tmp=$autostart/.${entry_name}.tmp.$$
trap 'rm -f -- "$tmp"' EXIT HUP INT TERM
sed -e "s|@START_AGENT@|$start_agent|g" -e "s|@BUNDLE_ROOT@|$bundle|g" "$template" >"$tmp"
chmod 0644 "$tmp"
if [ -e "$entry" ] && cmp -s "$tmp" "$entry"; then
    rm -f -- "$tmp"
else
    mv -f -- "$tmp" "$entry"
fi
trap - EXIT HUP INT TERM
printf '%s\n' "$entry"
