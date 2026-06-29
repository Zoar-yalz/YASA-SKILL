#!/usr/bin/env python3
"""Extract common YASA scan metrics from scan_summary.json or logs."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path


PATTERNS = {
    "valid_entrypoints": re.compile(r"Valid entrypoints:\s*(\d+)", re.I),
    "sources_marked": re.compile(r"Sources marked:\s*(\d+)", re.I),
    "sinks_matched": re.compile(r"Sinks matched:\s*(\d+)", re.I),
    "findings": re.compile(r"Findings:\s*(\d+)", re.I),
    "scan_findings": re.compile(r"Scan:\s*(\d+)\s*findings", re.I),
}

# Map scan_summary.json fields to metric keys
JSON_FIELD_MAP = {
    "entryPointCount": "valid_entrypoints",
    "markedSourceCount": "sources_marked",
    "matchedSinkCount": "sinks_matched",
    "findingCount": "findings",
}


def extract_from_json(data: dict) -> dict[str, int | bool | None]:
    metrics: dict[str, int | bool | None] = {
        "valid_entrypoints": None,
        "sources_marked": None,
        "sinks_matched": None,
        "findings": None,
        "match_entrypoint_fail": None,
    }
    for json_key, metric_key in JSON_FIELD_MAP.items():
        if json_key in data:
            metrics[metric_key] = data[json_key]
    return metrics


def extract(text: str) -> dict[str, int | bool | None]:
    metrics: dict[str, int | bool | None] = {
        "valid_entrypoints": None,
        "sources_marked": None,
        "sinks_matched": None,
        "findings": None,
        "match_entrypoint_fail": bool(re.search(r"match\s+entryPoint\s+fail", text, re.I)),
    }

    for key, pattern in PATTERNS.items():
        matches = pattern.findall(text)
        if not matches:
            continue
        value = int(matches[-1])
        if key == "scan_findings":
            metrics["findings"] = value
        else:
            metrics[key] = value
    return metrics


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("logfile", nargs="?", type=Path, help="Log file. Reads stdin if omitted.")
    parser.add_argument("--markdown", action="store_true")
    args = parser.parse_args()

    text = args.logfile.read_text(encoding="utf-8", errors="replace") if args.logfile else sys.stdin.read()

    # Try JSON first (scan_summary.json format)
    try:
        data = json.loads(text)
        if isinstance(data, dict) and "findingCount" in data:
            metrics = extract_from_json(data)
        else:
            metrics = extract(text)
    except (json.JSONDecodeError, ValueError):
        metrics = extract(text)

    if args.markdown:
        print("| Metric | Value |")
        print("|---|---:|")
        for k, v in metrics.items():
            print(f"| {k} | {v} |")
    else:
        print(json.dumps(metrics, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
