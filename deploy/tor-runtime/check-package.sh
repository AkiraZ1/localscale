#!/bin/sh
# Validate that every release bundle contains the resolver's exact Tor path.
set -eu
platform=${1:?platform (linux-x86_64, macos-x86_64, macos-aarch64, or windows-x86_64)}
bundle=${2:?installed bundle root}
case "$platform" in
  linux-x86_64|windows-x86_64) path="$bundle/tor/tor"; [ "$platform" = windows-x86_64 ] && path="$bundle/tor/tor.exe" ;;
  macos-x86_64|macos-aarch64) path="$bundle/Contents/Resources/tor/tor" ;;
  *) echo "unknown platform: $platform" >&2; exit 2 ;;
esac
if [ ! -f "$path" ]; then
  echo "missing bundled Tor executable: $path" >&2
  echo "release is incomplete: embed fetched Tor binaries in the installer" >&2
  exit 1
fi
case "$platform" in
  windows-x86_64) : ;;
  *) [ -x "$path" ] || { echo "Tor executable is not executable: $path" >&2; exit 1; } ;;
esac
printf '%s: verified %s\n' "$platform" "$path"
