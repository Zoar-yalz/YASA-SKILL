#!/usr/bin/env python3
"""Convert SARIF results into compact evidence packages."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8", errors="replace"))


def loc_to_dict(loc: dict[str, Any]) -> dict[str, Any]:
    phys = loc.get("physicalLocation", {}) if isinstance(loc, dict) else {}
    artifact = phys.get("artifactLocation", {}) if isinstance(phys, dict) else {}
    region = phys.get("region", {}) if isinstance(phys, dict) else {}
    msg = loc.get("message", {}) if isinstance(loc, dict) else {}
    return {
        "file": artifact.get("uri", ""),
        "line": region.get("startLine"),
        "column": region.get("startColumn"),
        "message": msg.get("text", ""),
    }


def result_to_evidence(result: dict[str, Any], index: int) -> dict[str, Any]:
    locations = [loc_to_dict(x) for x in result.get("locations", []) if isinstance(x, dict)]
    code_flow = []

    for cf in result.get("codeFlows", []) or []:
        for tf in cf.get("threadFlows", []) or []:
            for step_idx, tfl in enumerate(tf.get("locations", []) or []):
                loc = tfl.get("location", {}) if isinstance(tfl, dict) else {}
                item = loc_to_dict(loc)
                item["step"] = step_idx
                tmsg = tfl.get("message", {}) if isinstance(tfl, dict) else {}
                if tmsg.get("text") and not item.get("message"):
                    item["message"] = tmsg.get("text")
                code_flow.append(item)

    source = code_flow[0] if code_flow else (locations[0] if locations else {})
    sink = code_flow[-1] if code_flow else (locations[-1] if locations else {})

    return {
        "finding_id": result.get("guid") or result.get("fingerprints", {}).get("primaryLocationLineHash") or str(index),
        "rule_id": result.get("ruleId", ""),
        "message": (result.get("message") or {}).get("text", ""),
        "source": source,
        "sink": sink,
        "locations": locations,
        "code_flow": code_flow,
        "missing_evidence": [
            item for item, cond in [
                ("code_flow", not code_flow),
                ("source_location", not source),
                ("sink_location", not sink),
            ] if cond
        ],
    }


def sarif_to_evidence(sarif: dict[str, Any]) -> list[dict[str, Any]]:
    evidence = []
    for run in sarif.get("runs", []) or []:
        for result in run.get("results", []) or []:
            if isinstance(result, dict):
                evidence.append(result_to_evidence(result, len(evidence)))
    return evidence


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("sarif", type=Path)
    parser.add_argument("-o", "--output", type=Path, required=True)
    args = parser.parse_args()

    evidence = sarif_to_evidence(load_json(args.sarif))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(evidence, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"Wrote {len(evidence)} evidence packages: {args.output}")


if __name__ == "__main__":
    main()
