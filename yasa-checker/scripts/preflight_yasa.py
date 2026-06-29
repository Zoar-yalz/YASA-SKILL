#!/usr/bin/env python3
"""Preflight checker for YASA availability.

This script does not install YASA. It locates configured or discoverable YASA
commands and reports whether the skill can run in full, config-only, or
evidence-only mode.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any


CONFIG_FILE = ".yasa-agent.json"


def load_config(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {"_config_error": str(exc)}


def is_executable(path: Path) -> bool:
    return path.exists() and path.is_file() and os.access(path, os.X_OK)


def find_local_yasa(root: Path) -> str | None:
    tools = root / ".yasa-tools"
    if not tools.exists():
        return None
    candidates = []
    for p in tools.rglob("*"):
        if p.is_file() and os.access(p, os.X_OK) and "yasa" in p.name.lower():
            candidates.append(p)
    if not candidates:
        return None
    candidates.sort(key=lambda p: (0 if "engine" in p.name.lower() else 1, len(str(p))))
    return str(candidates[0])


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path.cwd())
    args = parser.parse_args()

    root = args.root.resolve()
    cfg_path = root / CONFIG_FILE
    cfg = load_config(cfg_path)

    problems: list[str] = []
    warnings: list[str] = []
    sources: dict[str, str | None] = {}

    if "_config_error" in cfg:
        problems.append(f"Invalid {CONFIG_FILE}: {cfg['_config_error']}")

    env_engine = os.environ.get("YASA_ENGINE")
    env_wrapper = os.environ.get("YASA_WRAPPER")
    path_engine = shutil.which("yasa-engine") or shutil.which("YASA-Engine") or shutil.which("yasa")
    local_engine = find_local_yasa(root)

    cfg_engine = cfg.get("yasa_engine")
    cfg_command = cfg.get("yasa_command")

    sources["config_file"] = str(cfg_path) if cfg_path.exists() else None
    sources["cfg_engine"] = cfg_engine
    sources["cfg_command"] = cfg_command
    sources["env_engine"] = env_engine
    sources["env_wrapper"] = env_wrapper
    sources["path_engine"] = path_engine
    sources["local_engine"] = local_engine

    selected = None
    selected_kind = None

    for kind, value in [
        ("cfg_command", cfg_command),
        ("cfg_engine", cfg_engine),
        ("env_wrapper", env_wrapper),
        ("env_engine", env_engine),
        ("path_engine", path_engine),
        ("local_engine", local_engine),
    ]:
        if not value:
            continue
        if kind in ("cfg_engine", "env_engine", "local_engine"):
            p = Path(value)
            if not p.is_absolute():
                p = (root / p).resolve()
            if is_executable(p):
                selected = str(p)
                selected_kind = kind
                break
        elif kind == "path_engine":
            selected = value
            selected_kind = kind
            break
        else:
            selected = value
            selected_kind = kind
            break

    workspace_dir = cfg.get("workspace_dir") or os.environ.get("YASA_WORKSPACE") or ".yasa-workspace"
    report_dir = cfg.get("report_dir") or str(Path(workspace_dir) / "report")
    uast = cfg.get("uastSDKPath") or os.environ.get("YASA_UAST_SDK_PATH")

    for d in [root / workspace_dir, root / report_dir]:
        try:
            d.mkdir(parents=True, exist_ok=True)
            test = d / ".write_test"
            test.write_text("ok", encoding="utf-8")
            test.unlink()
        except Exception as exc:
            problems.append(f"Directory is not writable: {d} ({exc})")

    if uast:
        uast_path = Path(uast)
        if not uast_path.is_absolute():
            uast_path = root / uast_path
        if not uast_path.exists():
            warnings.append(f"Configured uastSDKPath does not exist: {uast}")

    if not selected:
        problems.append("No YASA executable or wrapper found. Configure .yasa-agent.json, YASA_ENGINE, YASA_WRAPPER, PATH, or install under .yasa-tools/.")

    ok = not problems
    mode = "full" if ok else "config-only"

    out = {
        "ok": ok,
        "mode": mode,
        "selected_command": selected,
        "selected_kind": selected_kind,
        "workspace_dir": workspace_dir,
        "report_dir": report_dir,
        "uastSDKPath": uast,
        "sources": sources,
        "problems": problems,
        "warnings": warnings,
        "next_steps": [] if ok else [
            "Install YASA from the official release, or provide a wrapper command.",
            "Run scripts/install_yasa_release.py or scripts/write_local_config.py.",
            "Until then, generate/validate rule_config.json only and do not claim scan results.",
        ],
    }

    print(json.dumps(out, indent=2, ensure_ascii=False))
    raise SystemExit(0 if ok else 1)


if __name__ == "__main__":
    main()
