#!/usr/bin/env python3
import hashlib, importlib.util, json, subprocess, sys, tarfile, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("fetch", ROOT / "fetch.py")
fetch = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fetch)


def main():
    manifest = json.loads((ROOT / "manifest.json").read_text())
    assert manifest["version"] == "15.0.21"
    assert set(manifest["artifacts"]) == {"linux-x86_64", "macos-x86_64", "macos-aarch64", "windows-x86_64"}
    assert all(len(a["sha256"]) == 64 for a in manifest["artifacts"].values())
    assert all(a["url"].startswith("https://archive.torproject.org/") for a in manifest["artifacts"].values())
    with tempfile.TemporaryDirectory() as temp:
        temp = Path(temp)
        source = temp / "bundle" / "tor"
        source.mkdir(parents=True)
        (source / "tor").write_bytes(b"fixture")
        archive = temp / "fixture.tar.gz"
        with tarfile.open(archive, "w:gz") as out:
            out.add(temp / "bundle", arcname="bundle")
        target = temp / "out" / "tor"
        runtime = fetch.stage(archive, target, "tor")
        assert runtime == target / "tor" and runtime.read_bytes() == b"fixture"
        bad = temp / "bad.tar.gz"
        bad.write_bytes(archive.read_bytes()[:-1])
        try:
            fetch.verify(bad, hashlib.sha256(archive.read_bytes()).hexdigest())
        except SystemExit:
            pass
        else:
            raise AssertionError("checksum mismatch was accepted")
    check = ROOT / "check-package.sh"
    missing = subprocess.run([str(check), "linux-x86_64", str(Path(tempfile.gettempdir()) / "does-not-exist")], capture_output=True, text=True)
    assert missing.returncode != 0 and "release is incomplete" in missing.stderr

    # Release wrappers must reject an absent agent before producing a partial
    # artifact. This protects the self-contained release contract without
    # downloading Tor in the fixture test.
    for wrapper in (ROOT.parent / "packaging/linux/package-release.sh", ROOT.parent / "packaging/macos/package-release.sh"):
        rejected = subprocess.run([str(wrapper), str(Path(tempfile.gettempdir()) / "bundle")], capture_output=True, text=True)
        assert rejected.returncode != 0 and "agent binary" in rejected.stderr

    linux_release = (ROOT.parent / "packaging/linux/package-release.sh").read_text()
    macos_release = (ROOT.parent / "packaging/macos/package-release.sh").read_text()
    assert "localscaled" in linux_release and "package-tor.sh" in linux_release
    assert "localscaled" in macos_release and "package-tor.sh" in macos_release

    # Windows validation must distinguish a real PE tor.exe from a Linux/macOS
    # executable copied into the bundle by mistake.
    windows_bundle = Path(tempfile.mkdtemp())
    windows_tor = windows_bundle / "tor" / "tor.exe"
    windows_tor.parent.mkdir(parents=True)
    windows_tor.write_bytes(b"MZ" + b"\0" * 58 + (64).to_bytes(4, "little") + b"PE\0\0")
    valid = subprocess.run([str(check), "windows-x86_64", str(windows_bundle)], capture_output=True, text=True)
    assert valid.returncode == 0, valid.stderr
    windows_tor.write_bytes(b"\x7fELF" + b"\\0" * 128)
    wrong_format = subprocess.run([str(check), "windows-x86_64", str(windows_bundle)], capture_output=True, text=True)
    assert wrong_format.returncode != 0 and "PE" in wrong_format.stderr

    def run_check(platform, path):
        return subprocess.run([str(check), platform, str(path)], capture_output=True, text=True)

    def make_executable(path, data):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        path.chmod(0o755)

    # Unix validation must reject a same-path executable in the wrong format.
    linux_bundle = temp / "linux-bundle"
    linux_tor = linux_bundle / "tor" / "tor"
    make_executable(linux_tor, b"not an ELF executable")
    wrong_linux_format = run_check("linux-x86_64", linux_bundle)
    assert wrong_linux_format.returncode != 0 and "ELF" in wrong_linux_format.stderr
    make_executable(linux_tor, b"\x7fELF" + b"\\0" * 128)
    valid_linux = run_check("linux-x86_64", linux_bundle)
    assert valid_linux.returncode == 0, valid_linux.stderr

    mac_bundle = temp / "mac-bundle"
    mac_tor = mac_bundle / "Contents" / "Resources" / "tor" / "tor"
    make_executable(mac_tor, b"not a Mach-O executable")
    wrong_mac_format = run_check("macos-x86_64", mac_bundle)
    assert wrong_mac_format.returncode != 0 and "Mach-O" in wrong_mac_format.stderr
    # Accept the native 64-bit little-endian header and universal/fat headers.
    for magic in (b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca"):
        make_executable(mac_tor, magic + b"\\0" * 128)
        valid_mac = run_check("macos-x86_64", mac_bundle)
        assert valid_mac.returncode == 0, valid_mac.stderr

    print("tor-runtime static and fixture tests: ok")

if __name__ == "__main__":
    main()
