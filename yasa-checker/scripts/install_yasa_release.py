#!/usr/bin/env python3
"""Install YASA-Engine from the public GitHub release.

The script downloads one of the official v0.3.1 release zip files, extracts it
under .yasa-tools/yasa-v0.3.1, verifies sha256sum.txt when possible, locates a
likely YASA executable, and writes .yasa-agent.json.

Run only after explicit user approval.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform as py_platform
import shutil
import stat
import sys
import urllib.request
import zipfile
from pathlib import Path


ASSETS = {
    "linux-x64": "yasa-linux-x64.zip",
    "macos-x64": "yasa-macos-x64.zip",
    "macos-arm64": "yasa-macos-arm64.zip",
}


def detect_platform() -> str:
    sysname = py_platform.system().lower()
    machine = py_platform.machine().lower()

    if sysname == "linux" and machine in ("x86_64", "amd64"):
        return "linux-x64"
    if sysname == "darwin" and machine in ("x86_64", "amd64"):
        return "macos-x64"
    if sysname == "darwin" and machine in ("arm64", "aarch64"):
        return "macos-arm64"

    raise SystemExit(f"Unsupported platform: system={sysname}, machine={machine}. Use --platform.")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def download(url: str, dst: Path) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    with urllib.request.urlopen(url, timeout=60) as resp:
        with dst.open("wb") as f:
            shutil.copyfileobj(resp, f)


def make_executables(root: Path) -> None:
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        name = p.name.lower()
        if "yasa" in name or name.endswith(".sh"):
            try:
                mode = p.stat().st_mode
                p.chmod(mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
            except Exception:
                pass


def verify_sha256sum(root: Path) -> list[str]:
    issues: list[str] = []
    sum_files = list(root.rglob("sha256sum.txt"))
    if not sum_files:
        return ["sha256sum.txt not found; skipped file-level verification."]

    for sum_file in sum_files:
        base = sum_file.parent
        for raw in sum_file.read_text(encoding="utf-8", errors="replace").splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.replace("*", " ").split()
            if len(parts) < 2:
                continue
            expected, rel = parts[0], parts[-1]
            target = (base / rel).resolve()
            # Skip self-referencing entries (sha256sum.txt listing itself)
            if target == sum_file.resolve():
                continue
            if not target.exists() or not target.is_file():
                issues.append(f"Missing file listed in {sum_file}: {rel}")
                continue
            actual = sha256_file(target)
            if actual.lower() != expected.lower():
                issues.append(f"SHA256 mismatch for {target}: expected {expected}, got {actual}")
    return issues


def find_yasa_executable(root: Path) -> Path | None:
    candidates = []
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if "yasa" not in p.name.lower():
            continue
        if os.access(p, os.X_OK):
            candidates.append(p)
    if not candidates:
        return None
    candidates.sort(key=lambda p: (0 if "engine" in p.name.lower() else 1, len(str(p))))
    return candidates[0]


def setup_deps(engine_root: Path, cwd: Path) -> None:
    """Create deps/uast4py and deps/uast4go directories that YASA engine
    expects at the project root, linking to the installed binaries."""
    for name in ("uast4py", "uast4go"):
        # Find binary in the extracted engine directory
        candidates = list(engine_root.rglob(f"{name}*"))
        if not candidates:
            continue
        src = candidates[0]
        dst_dir = cwd / "deps" / name
        dst_dir.mkdir(parents=True, exist_ok=True)
        dst = dst_dir / name
        if not dst.exists():
            shutil.copy2(src, dst)
            dst.chmod(dst.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
            print(f"  Linked {src.name} -> {dst}")


def write_config(path: Path, engine: Path, workspace: str, report_dir: str) -> None:
    cfg = {
        "yasa_engine": str(engine),
        "yasa_command": None,
        "uastSDKPath": None,
        "workspace_dir": workspace,
        "report_dir": report_dir,
        "default_entrypoint_mode": "ONLY_CUSTOM",
        "supports_callgraph": True,
        "supports_sarif": True,
    }
    path.write_text(json.dumps(cfg, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", default="v0.3.1")
    parser.add_argument("--platform", choices=sorted(ASSETS), default=None)
    parser.add_argument("--install-dir", type=Path, default=Path(".yasa-tools"))
    parser.add_argument("--config", type=Path, default=Path(".yasa-agent.json"))
    parser.add_argument("--workspace", default=".yasa-workspace")
    parser.add_argument("--report-dir", default=".yasa-workspace/report")
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()

    platform_name = args.platform or detect_platform()
    asset = ASSETS[platform_name]
    url = f"https://github.com/antgroup/YASA-Engine/releases/download/{args.version}/{asset}"

    target_root = args.install_dir / f"yasa-{args.version}"
    zip_path = args.install_dir / asset

    if target_root.exists() and not args.force:
        raise SystemExit(f"Install directory already exists: {target_root}. Use --force to overwrite.")

    args.install_dir.mkdir(parents=True, exist_ok=True)
    print(f"Downloading {url}")
    download(url, zip_path)
    print(f"Downloaded: {zip_path} ({zip_path.stat().st_size} bytes)")

    if target_root.exists():
        shutil.rmtree(target_root)
    target_root.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(zip_path, "r") as z:
        z.extractall(target_root)

    make_executables(target_root)

    verification_issues = verify_sha256sum(target_root)
    hard_issues = [x for x in verification_issues if not x.startswith("sha256sum.txt not found")]
    if hard_issues:
        print("Verification warnings (non-fatal):", file=sys.stderr)
        for issue in hard_issues:
            print(f"- {issue}", file=sys.stderr)
        verification_issues.append(
            f"{len(hard_issues)} file(s) failed SHA256 verification."
        )

    exe = find_yasa_executable(target_root)
    if not exe:
        raise SystemExit(f"Could not locate YASA executable under {target_root}")

    write_config(args.config, exe, args.workspace, args.report_dir)

    # Setup deps directory for YASA engine's python-ast-builder
    cwd = args.config.resolve().parent
    setup_deps(target_root, cwd)

    out = {
        "installed": True,
        "version": args.version,
        "platform": platform_name,
        "asset": asset,
        "install_root": str(target_root),
        "zip_path": str(zip_path),
        "yasa_engine": str(exe),
        "config": str(args.config),
        "deps_dir": str(cwd / "deps"),
        "verification_notes": verification_issues,
    }
    print(json.dumps(out, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
