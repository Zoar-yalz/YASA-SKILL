#!/usr/bin/env python3
"""Normalize a RuleGen selection JSON into a YASA rule_config.json."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


DEFAULT_CHECKERS = {
    "python": "taint_flow_python_input",
    "nodejs": "taint_flow_js_input",
    "javascript": "taint_flow_js_input",
    "typescript": "taint_flow_js_input",
}

SOURCE_BUCKETS = [
    "TaintSource",
    "FuncCallReturnValueTaintSource",
    "FuncCallArgTaintSource",
]


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def normalize_file_path(file_path: str) -> str:
    file_path = (file_path or "").strip()
    if file_path and not file_path.startswith("/"):
        file_path = "/" + file_path.lstrip("./")
    return file_path


def normalize_python_function_name(name: str) -> str:
    name = (name or "").split("\\n")[0].strip()
    if "." in name:
        name = name.split(".")[-1]
    if "::" in name:
        name = name.split("::")[-1].strip()
    return name


def normalize_entrypoint(ep: dict[str, Any], language: str) -> dict[str, Any]:
    function = ep.get("functionName", ep.get("function", ""))
    file_path = ep.get("filePath", ep.get("file", ""))
    out = {"functionName": function, "filePath": normalize_file_path(file_path)}
    if language.lower() == "python":
        out["functionName"] = normalize_python_function_name(out["functionName"])
    return out


def build_rule_config(selection: dict[str, Any], language: str, checker_id: str | None) -> list[dict[str, Any]]:
    language = language.lower()
    checker_id = checker_id or DEFAULT_CHECKERS.get(language)
    if not checker_id:
        raise SystemExit(f"No default checker for language={language!r}; pass --checker-id.")

    sources = {bucket: [] for bucket in SOURCE_BUCKETS}
    for src in selection.get("selected_sources", []):
        if not isinstance(src, dict):
            continue
        kind = src.get("kind", "TaintSource")
        if kind not in sources:
            sources[kind] = []
        normalized = {k: v for k, v in src.items() if k != "kind"}
        normalized.setdefault("scopeFile", "all")
        normalized.setdefault("scopeFunc", "all")
        sources[kind].append(normalized)

    sinks = {"FuncCallTaintSink": []}
    for snk in selection.get("selected_sinks", []):
        if not isinstance(snk, dict):
            continue
        item = dict(snk)
        item.setdefault("args", ["*"])
        sinks["FuncCallTaintSink"].append(item)

    entrypoints = [
        normalize_entrypoint(ep, language)
        for ep in selection.get("selected_entrypoints", [])
        if isinstance(ep, dict)
    ]

    return [{
        "checkerIds": [checker_id],
        "sources": sources,
        "sinks": sinks,
        "entrypoints": entrypoints,
    }]


def normalize_existing_config(config: list[Any], language: str) -> list[Any]:
    for rule in config:
        if isinstance(rule, dict) and isinstance(rule.get("entrypoints"), list):
            rule["entrypoints"] = [
                normalize_entrypoint(ep, language)
                for ep in rule["entrypoints"]
                if isinstance(ep, dict)
            ]
    return config


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path)
    parser.add_argument("-o", "--output", type=Path, required=True)
    parser.add_argument("--language", default="python")
    parser.add_argument("--checker-id", default=None)
    args = parser.parse_args()

    data = read_json(args.input)

    if isinstance(data, dict) and any(k in data for k in ("selected_entrypoints", "selected_sources", "selected_sinks")):
        out = build_rule_config(data, args.language, args.checker_id)
    elif isinstance(data, list):
        out = normalize_existing_config(data, args.language)
    else:
        raise SystemExit("Input is neither RuleGen selection JSON nor YASA rule_config list.")

    write_json(args.output, out)
    print(f"Wrote normalized rule config: {args.output}")


if __name__ == "__main__":
    main()
