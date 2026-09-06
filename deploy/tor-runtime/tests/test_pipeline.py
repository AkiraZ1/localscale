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
    print("tor-runtime static and fixture tests: ok")

if __name__ == "__main__":
    main()
