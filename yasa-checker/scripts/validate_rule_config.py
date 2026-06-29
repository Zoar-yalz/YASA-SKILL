#!/usr/bin/env python3
"""Validate common YASA rule_config.json mistakes."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def check_rule(rule: dict[str, Any], idx: int, language: str) -> list[dict[str, str]]:
    issues: list[dict[str, str]] = []

    def add(severity: str, message: str) -> None:
        issues.append({"severity": severity, "rule": str(idx), "message": message})

    if not rule.get("checkerIds"):
        add("error", "Missing checkerIds.")

    sources = rule.get("sources")
    if not isinstance(sources, dict):
        add("error", "Missing or invalid sources object.")
    elif not any(sources.get(k) for k in ("TaintSource", "FuncCallReturnValueTaintSource", "FuncCallArgTaintSource")):
        add("warning", "No non-empty source bucket found.")

    sinks = rule.get("sinks")
    if not isinstance(sinks, dict):
        add("error", "Missing or invalid sinks object.")
    elif not sinks.get("FuncCallTaintSink"):
        add("warning", "sinks.FuncCallTaintSink is empty.")

    entrypoints = rule.get("entrypoints")
    if entrypoints is None:
        add("warning", "No entrypoints field; YASA may fall back to auto entrypoint collection.")
    elif not isinstance(entrypoints, list):
        add("error", "entrypoints must be a list.")
    else:
        if not entrypoints:
            add("warning", "entrypoints is empty.")
        for j, ep in enumerate(entrypoints):
            if not isinstance(ep, dict):
                add("error", f"entrypoints[{j}] is not an object.")
                continue
            fn = ep.get("functionName")
            fp = ep.get("filePath")
            if not fn:
                add("error", f"entrypoints[{j}] missing functionName.")
            if not fp:
                add("error", f"entrypoints[{j}] missing filePath.")
            if language == "python":
                if isinstance(fn, str) and ("." in fn or "::" in fn):
                    add("error", f"entrypoints[{j}].functionName should be bare for Python: {fn!r}.")
                if isinstance(fp, str) and fp and not fp.startswith("/"):
                    add("error", f"entrypoints[{j}].filePath should start with '/': {fp!r}.")
                if "attribute" in ep:
                    add("error", f"entrypoints[{j}] contains attribute; Python entrypoints should not.")

    return issues


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("rule_config", type=Path)
    parser.add_argument("--language", default="python")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    data = load_json(args.rule_config)
    issues: list[dict[str, str]] = []

    if not isinstance(data, list):
        issues.append({"severity": "error", "rule": "-", "message": "Top-level rule_config must be a list."})
    else:
        for idx, rule in enumerate(data):
            if not isinstance(rule, dict):
                issues.append({"severity": "error", "rule": str(idx), "message": "Rule is not an object."})
            else:
                issues.extend(check_rule(rule, idx, args.language.lower()))

    if args.json:
        print(json.dumps({"issues": issues, "ok": not any(i["severity"] == "error" for i in issues)}, indent=2, ensure_ascii=False))
        return

    if not issues:
        print("OK: no structural issues found.")
        return

    for issue in issues:
        print(f"[{issue['severity'].upper()}] rule {issue['rule']}: {issue['message']}")

    if any(i["severity"] == "error" for i in issues):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
