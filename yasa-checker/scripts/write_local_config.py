#!/usr/bin/env python3
"""Write a repository-local .yasa-agent.json config file."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=Path(".yasa-agent.json"))
    parser.add_argument("--yasa-engine", default=None)
    parser.add_argument("--yasa-command", default=None)
    parser.add_argument("--uast-sdk-path", default=None)
    parser.add_argument("--workspace", default=".yasa-workspace")
    parser.add_argument("--report-dir", default=".yasa-workspace/report")
    parser.add_argument("--entrypoint-mode", default="ONLY_CUSTOM")
    args = parser.parse_args()

    config = {
        "yasa_engine": args.yasa_engine,
        "yasa_command": args.yasa_command,
        "uastSDKPath": args.uast_sdk_path,
        "workspace_dir": args.workspace,
        "report_dir": args.report_dir,
        "default_entrypoint_mode": args.entrypoint_mode,
        "supports_callgraph": True,
        "supports_sarif": True,
    }

    args.output.write_text(json.dumps(config, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"Wrote {args.output}")


if __name__ == "__main__":
    main()
