#!/usr/bin/env python3
"""Fetch, authenticate, and stage an official Tor Expert Bundle.

No binary is stored in Git. The output is deliberately absent until this
command downloads and verifies the pinned artifact.
"""
from __future__ import annotations
import argparse, hashlib, json, os, shutil, sys, tarfile, tempfile
from pathlib import Path
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parent
MANIFEST = ROOT / "manifest.json"


def fail(message: str) -> None:
    raise SystemExit(f"error: {message}")


def download(url: str, destination: Path) -> None:
    req = Request(url, headers={"User-Agent": "LocalScale-Tor-Bundler/1"})
    with urlopen(req, timeout=120) as response, destination.open("wb") as out:
        shutil.copyfileobj(response, out, length=1024 * 1024)


def verify(path: Path, expected: str) -> None:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    actual = digest.hexdigest()
    if actual != expected:
        fail(f"SHA-256 mismatch for {path.name}: expected {expected}, got {actual}")


def safe_members(archive: tarfile.TarFile) -> list[tarfile.TarInfo]:
    members = archive.getmembers()
    for member in members:
        name = Path(member.name)
        if name.is_absolute() or ".." in name.parts or member.issym() or member.islnk():
            fail(f"unsafe archive member: {member.name}")
    return members


def stage(archive_path: Path, target: Path, executable_name: str) -> Path:
    with tempfile.TemporaryDirectory(prefix="localscale-tor-") as temp:
        extracted = Path(temp) / "extracted"
        extracted.mkdir()
        with tarfile.open(archive_path, "r:gz") as archive:
            members = safe_members(archive)
            archive.extractall(extracted, members=members, filter="data")
        candidates = [p for p in extracted.rglob(executable_name) if p.is_file() and p.parent.name == "tor"]
        if len(candidates) != 1:
            fail(f"expected one {executable_name} in archive, found {len(candidates)}")
        source_dir = candidates[0].parent
        if target.exists():
            shutil.rmtree(target)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(source_dir, target)
        runtime = target / executable_name
        if not runtime.is_file():
            fail(f"staged runtime missing: {runtime}")
        if os.name != "nt":
            runtime.chmod(runtime.stat().st_mode | 0o111)
        return runtime


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("platform", choices=["linux-x86_64", "macos-x86_64", "macos-aarch64", "windows-x86_64"])
    parser.add_argument("--output", type=Path, required=True, help="installed bundle root")
    parser.add_argument("--cache", type=Path, default=ROOT / "cache")
    parser.add_argument("--offline", action="store_true", help="only use an already cached archive")
    args = parser.parse_args()
    manifest = json.loads(MANIFEST.read_text())
    artifact = manifest["artifacts"][args.platform]
    archive = args.cache / artifact["file"]
    args.cache.mkdir(parents=True, exist_ok=True)
    if not archive.exists():
        if args.offline:
            fail(f"missing cached artifact: {archive}")
        print(f"downloading {artifact['url']}", file=sys.stderr)
        download(artifact["url"], archive)
    verify(archive, artifact["sha256"])
    runtime_dir = args.output / Path(artifact["runtime_path"]).parent
    runtime = stage(archive, runtime_dir, Path(artifact["runtime_path"]).name)
    print(f"staged {args.platform}: {runtime}")
    return 0


if __name__ == "__main__":
    main()
