# Windows build and Tor package validation

The Windows Tor wrapper stages the pinned `windows-x86_64` Expert Bundle from
`deploy/tor-runtime/manifest.json` and requires this exact installed layout:

```text
<bundle>/tor/tor.exe
```

`deploy/tor-runtime/fetch.py` verifies the archive's SHA-256 checksum before
extracting it, rejects unsafe tar members, and copies the complete Tor runtime
directory. `deploy/tor-runtime/check-package.sh windows-x86_64 <bundle>` then
checks that `tor.exe` is a regular non-symlink file with a valid DOS `MZ`
header and PE signature at `e_lfanew`. This prevents an ELF or Mach-O binary
from being mislabeled as a Windows executable.

Run the package validation with:

```sh
python3 deploy/tor-runtime/fetch.py windows-x86_64 --output <bundle>
deploy/tor-runtime/check-package.sh windows-x86_64 <bundle>
python3 deploy/tor-runtime/tests/test_pipeline.py
```

The Windows artifact was fetched during validation and passed the manifest
SHA-256 check, staged to `tor/tor.exe`, and passed PE-header validation.

## Native execution blocker

This validation host is Linux, not Windows. It has no Windows runtime (Wine),
Windows linker/toolchain, Flutter Windows SDK, or installed Rust Windows
standard-library target, so a native `localscaled.exe` build and Tor process
lifecycle test cannot be honestly performed here. `cargo check --target
x86_64-pc-windows-gnu` was attempted and failed because that target's `core`
crate is not installed. The remaining required gate is a Windows CI/runner
(or Windows machine) that installs the target/toolchain, builds the agent and
Flutter package, embeds the fetched bundle, launches `localscaled.exe`, and
runs the Host/Cliente Tor lifecycle checks.
