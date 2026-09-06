#!/bin/sh
# Validate that every release bundle contains the resolver's exact Tor path.
set -eu
platform=${1:?platform (linux-x86_64, macos-x86_64, macos-aarch64, or windows-x86_64)}
bundle=${2:?installed bundle root}
case "$platform" in
  linux-x86_64|windows-x86_64) path="$bundle/tor/tor"; [ "$platform" = windows-x86_64 ] && path="$bundle/tor/tor.exe" ;;
  macos-x86_64|macos-aarch64) path="$bundle/Contents/Resources/tor/tor" ;;
  macos-agent) path="$bundle/tor/tor" ;;
  *) echo "unknown platform: $platform" >&2; exit 2 ;;
esac
if [ ! -f "$path" ] || [ -L "$path" ]; then
  echo "missing or unsafe bundled Tor executable: $path" >&2
  echo "release is incomplete: embed fetched Tor binaries in the installer" >&2
  exit 1
fi
case "$platform" in
  windows-x86_64)
    # A path-only check can accidentally package an ELF/Mach-O binary as
    # tor.exe. Validate the PE signature and e_lfanew before shipping.
    python3 - "$path" <<'PY'
import pathlib, sys
path = pathlib.Path(sys.argv[1])
data = path.read_bytes()
if len(data) < 64 or data[:2] != b"MZ":
    raise SystemExit(f"Windows Tor executable is not a PE image: {path}")
pe_offset = int.from_bytes(data[0x3c:0x40], "little")
if pe_offset > len(data) - 4 or data[pe_offset:pe_offset + 4] != b"PE\0\0":
    raise SystemExit(f"Windows Tor executable has an invalid PE header: {path}")
PY
    ;;
  *) [ -x "$path" ] || { echo "Tor executable is not executable: $path" >&2; exit 1; } ;;
esac
printf '%s: verified %s\n' "$platform" "$path"
